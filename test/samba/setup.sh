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
GUID_DESCRIPTION="bf967950-0de6-11d0-a285-00aa003049e2"    # attribute description
GUID_RESULTANT_PSO="b77ea093-88d0-4780-9a98-911f8e8b1dca"  # attribute msDS-ResultantPSO
GUID_PSO_THRESHOLD="b8c8c35e-4a19-4a95-99d0-69fe4446286f"  # attribute msDS-LockoutThreshold
GUID_USER_CLASS="bf967aba-0de6-11d0-a285-00aa003049e2"     # class user
GUID_PSO_CLASS="3bcd9db8-f84b-451c-952f-6c52b81f9ec6"      # class msDS-PasswordSettings
PSC_DN="CN=Password Settings Container,CN=System,${BASE_DN}"

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
for u in svc-vouch alice bob carol dadmin erin; do
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

echo "setup: fine-grained password policy for erin (threshold 5, above the domain's 3)"
if st domain passwordsettings pso show vouch-test-pso >/dev/null 2>&1; then
    echo "  vouch-test-pso exists"
else
    st domain passwordsettings pso create vouch-test-pso 1 --complexity=off \
        --account-lockout-threshold=5 --account-lockout-duration=30 \
        --reset-account-lockout-after=30 >/dev/null
    echo "  vouch-test-pso created"
fi
st domain passwordsettings pso apply vouch-test-pso erin >/dev/null 2>&1 || true

echo "setup: ACLs for svc-vouch"
SVC_SID="$(st user show svc-vouch --attributes=objectSid | awk '/^objectSid:/ {print $2}')"
if [ -z "${SVC_SID}" ]; then
    echo "setup: could not find svc-vouch objectSid" >&2
    exit 1
fi
# The same permission set extras/Grant-VouchServiceAccount.ps1 grants, so the integration
# tests prove it's enough. Inherit-only object ACEs (CIIO, PowerShell's "Descendents") on CN=Users,
# for user objects only:
#   WP on lockoutTime          - clear the lockout
#   WP on userAccountControl   - fail-safe disable
#   WP on description          - explain a fail-safe disable
#   RP on msDS-ResultantPSO    - find the account's fine-grained password policy
# and on the Password Settings Container, inherited by password-settings objects:
#   RP on msDS-LockoutThreshold - read that policy's lockout threshold
# Everything else vouch reads is covered by Authenticated Users' default read access.
grant() { # dn ace
    if st dsacl get --objectdn="$1" 2>/dev/null | grep -qiF "$2"; then
        echo "  ACE present: $2"
    else
        st dsacl set --action=allow --objectdn="$1" --sddl="$2" >/dev/null
        echo "  ACE added:   $2"
    fi
}
for right_guid in "WP;${GUID_LOCKOUT_TIME}" "WP;${GUID_UAC}" "WP;${GUID_DESCRIPTION}" "RP;${GUID_RESULTANT_PSO}"; do
    grant "${USERS_DN}" "(OA;CIIO;${right_guid%%;*};${right_guid#*;};${GUID_USER_CLASS};${SVC_SID})"
done
grant "${PSC_DN}" "(OA;CIIO;RP;${GUID_PSO_THRESHOLD};${GUID_PSO_CLASS};${SVC_SID})"

echo "setup: done"
