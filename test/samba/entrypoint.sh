#!/bin/bash
# Provision the VOUCH.TEST domain on first start, then run samba in the foreground.
set -euo pipefail

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    echo "entrypoint: provisioning ${SAMBA_REALM} (${SAMBA_DOMAIN})"
    rm -f /etc/samba/smb.conf
    # acl_xattr:security_acl_name: rootless podman cannot set security.* xattrs
    # (EPERM in a user namespace), so store the sysvol NT ACLs in user.NTACL.
    samba-tool domain provision \
        --server-role=dc \
        --realm="${SAMBA_REALM}" \
        --domain="${SAMBA_DOMAIN}" \
        --adminpass="${SAMBA_ADMIN_PASSWORD}" \
        --dns-backend=SAMBA_INTERNAL \
        --option="acl_xattr:security_acl_name = user.NTACL"

    # Allow simple binds over plain LDAP (389) - test only!
    # (provision drops this from --option, so add it to [global] directly.)
    sed -i '/^\[global\]/a\	ldap server require strong auth = no' /etc/samba/smb.conf
    cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
    echo "entrypoint: provisioning done"
fi

testparm -s --parameter-name="ldap server require strong auth" 2>/dev/null | grep -qi '^no$' || {
    echo "entrypoint: smb.conf must set 'ldap server require strong auth = no'" >&2
    exit 1
}

exec samba -i --debug-stdout
