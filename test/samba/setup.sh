#!/bin/bash
# Populate the vouch Samba AD test DC with policy, users, groups and ACLs.
# Runs on the host against the running container via `podman exec`.
# Safe to re-run: existing users/groups/memberships/ACEs are left alone.
set -euo pipefail

CONTAINER="${CONTAINER:-vouch-samba-test}"
BASE_DN="DC=vouch,DC=test"
USERS_DN="CN=Users,${BASE_DN}"

# schemaIDGUIDs (verified against the Samba schema).
GUID_LOCKOUT_TIME="28630ebf-41d5-11d1-a9c1-0000f80367c1"   # attribute lockoutTime
GUID_UAC="bf967a68-0de6-11d0-a285-00aa003049e2"            # attribute userAccountControl
GUID_USER_CLASS="bf967aba-0de6-11d0-a285-00aa003049e2"     # class user

st() { podman exec "${CONTAINER}" samba-tool "$@"; }

echo "setup: password and lockout policy"
# Complexity off: AD complexity rejects passwords containing the account name
# (e.g. Passw0rd-alice! for alice). Min age 0 so tests can change passwords freely.
st domain passwordsettings set \
    --complexity=off \
    --min-pwd-age=0 \
    --account-lockout-threshold=3 \
    --account-lockout-duration=30 \
    --reset-account-lockout-after=30 >/dev/null

echo "setup: users"
for u in svc-vouch alice bob carol dadmin; do
    if st user show "${u}" >/dev/null 2>&1; then
        echo "  ${u} exists"
    else
        st user create "${u}" "Passw0rd-${u}!" --use-username-as-cn >/dev/null
        echo "  ${u} created"
    fi
done

echo "setup: groups"
for g in Helpdesk Helpdesk-L1 Protected-Users-Vouch; do
    st group show "${g}" >/dev/null 2>&1 || st group add "${g}" >/dev/null
done

add_member() { # group member
    if st group listmembers "$1" 2>/dev/null | grep -qx "$2"; then
        return 0
    fi
    st group addmembers "$1" "$2" >/dev/null
    echo "  $2 -> $1"
}
add_member Helpdesk Helpdesk-L1
add_member Helpdesk-L1 bob
add_member Protected-Users-Vouch dadmin

echo "setup: ACLs for svc-vouch"
SVC_SID="$(st user show svc-vouch --attributes=objectSid | awk '/^objectSid:/ {print $2}')"
if [ -z "${SVC_SID}" ]; then
    echo "setup: could not find svc-vouch objectSid" >&2
    exit 1
fi
# Object ACEs on CN=Users, inherited (CI) by user objects only:
#   WP on lockoutTime         - unlock
#   WP on userAccountControl  - disable / enable
#   RP on lockoutTime is already granted to Authenticated Users by default.
for attr_guid in "${GUID_LOCKOUT_TIME}" "${GUID_UAC}"; do
    ace="(OA;CI;WP;${attr_guid};${GUID_USER_CLASS};${SVC_SID})"
    if st dsacl get --objectdn="${USERS_DN}" 2>/dev/null | grep -qiF "${ace}"; then
        echo "  ACE present: ${ace}"
    else
        st dsacl set --action=allow --objectdn="${USERS_DN}" --sddl="${ace}" >/dev/null
        echo "  ACE added:   ${ace}"
    fi
done

echo "setup: done"
