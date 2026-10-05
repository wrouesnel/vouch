# Samba AD test domain controller

A disposable Samba Active Directory DC in a rootless podman container, for
vouch's LDAP integration tests. **Test only: weak passwords, plain-LDAP simple
binds allowed.**

| Item | Value |
|------|-------|
| Image / container | `localhost/vouch-samba-test` / `vouch-samba-test` |
| LDAP | `ldap://127.0.0.1:10389` (simple binds allowed) |
| LDAPS | `ldaps://127.0.0.1:10636` (Samba's self-signed cert, CN `dc1.vouch.test`) |
| Realm / domain / base DN | `VOUCH.TEST` / `VOUCH` / `DC=vouch,DC=test` |
| Administrator | `Administrator@vouch.test` / `Admin-Passw0rd!` |
| Samba | 4.22 (Debian trixie) |

## Usage

```sh
test/samba/start.sh      # build image if missing, run, wait for LDAP, run setup.sh
test/samba/stop.sh       # remove the container (the domain goes with it)
REBUILD=1 test/samba/start.sh   # force an image rebuild
```

`start.sh` reuses an existing container, so run `stop.sh` first for a clean
domain. A fresh start takes about 15 seconds. `setup.sh` can be re-run safely.

For LDAPS, trust Samba's CA with
`podman cp vouch-samba-test:/var/lib/samba/private/tls/ca.pem .`, or skip
verification (`LDAPTLS_REQCERT=never`).

## What setup.sh creates

- Policy: lockout threshold 3, lockout duration 30 min, reset window 30 min.
  Complexity is off because AD complexity rejects a password that contains the
  account name. Minimum password age is 0.
- Users in `CN=Users,DC=vouch,DC=test` (CN = username), each with password
  `Passw0rd-<name>!`: `svc-vouch`, `alice`, `bob`, `carol`, `dadmin`, `erin`.
- Groups: `Helpdesk` ⊃ `Helpdesk-L1` ⊃ `bob` (nested), and
  `Protected-Users-Vouch` ⊃ `dadmin`.
- A fine-grained password policy, `vouch-test-pso`, with lockout threshold 5 (above the
  domain's 3), applied to `erin`, to test reading the threshold from a PSO.
- The same permission set `extras/Grant-VouchServiceAccount.ps1` grants. Inherit-only object
  ACEs (`CIIO`, PowerShell's `Descendents`) on `CN=Users` for user objects:
  ```
  (OA;CIIO;WP;28630ebf-41d5-11d1-a9c1-0000f80367c1;bf967aba-0de6-11d0-a285-00aa003049e2;<svc-vouch SID>)  write lockoutTime
  (OA;CIIO;WP;bf967a68-0de6-11d0-a285-00aa003049e2;bf967aba-0de6-11d0-a285-00aa003049e2;<svc-vouch SID>)  write userAccountControl
  (OA;CIIO;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967aba-0de6-11d0-a285-00aa003049e2;<svc-vouch SID>)  write description
  (OA;CIIO;RP;b77ea093-88d0-4780-9a98-911f8e8b1dca;bf967aba-0de6-11d0-a285-00aa003049e2;<svc-vouch SID>)  read msDS-ResultantPSO
  ```
  and on `CN=Password Settings Container,CN=System` for password settings objects:
  ```
  (OA;CIIO;RP;b8c8c35e-4a19-4a95-99d0-69fe4446286f;3bcd9db8-f84b-451c-952f-6c52b81f9ec6;<svc-vouch SID>)  read msDS-LockoutThreshold
  ```
  These are set with `samba-tool dsacl set`, and the GUIDs were checked against this schema's
  `schemaIDGUID`s. Without the last grant, `svc-vouch` can see that a PSO applies to `erin`
  but can't read its threshold. Keep this list in step with the PowerShell script:
  `TestSambaServiceAccountIsLeastPrivilege` checks the account can't do anything beyond it.

## Rootless podman workarounds (in the Containerfile and entrypoint)

1. **idmap range.** Samba's DC idmap hands out unix IDs from 3000000, but
   rootless podman maps only 65536 IDs (`/etc/subuid`). Provisioning chowns
   sysvol to those IDs, the chown fails, and `samba-tool` panics with
   `Security context active token stack underflow!`. The Containerfile edits
   `/usr/share/samba/setup/idmap_init.ldif` to use the range 30000–60000.
2. **NT ACL xattrs.** A user namespace can't set `security.*` (or `trusted.*`)
   xattrs (EPERM), so the sysvol ACL setup failed with `NT_STATUS_ACCESS_DENIED`.
   The fix is to provision with `acl_xattr:security_acl_name = user.NTACL`.
3. `samba-tool provision --option="ldap server require strong auth = no"`
   didn't persist into smb.conf, so the entrypoint adds the line to `[global]`
   itself. It then checks the setting with `testparm` on every start.

No root, sudo or host changes are needed. The `samba_dnsupdate ...
WERR_DNS_ERROR_RECORD_ALREADY_EXISTS` errors in the logs are harmless.

## Empirical AD lockout behaviour (Samba 4.22)

All failed binds return LDAP result **49 Invalid credentials**. The `data`
code in the diagnostic message tells them apart. Bind DN and UPN
(`alice@vouch.test`) and `VOUCH\alice` all behave the same. The message format is:

```
80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data XXX, v1db1
```

| Case | `data` | Notes |
|------|--------|-------|
| a. wrong password, unlocked | `52e` | `badPwdCount` increments (DN and UPN binds both count) |
| b. 3rd wrong password | `52e` | then `lockoutTime` = `badPasswordTime` (FILETIME), `badPwdCount: 3`, `msDS-User-Account-Control-Computed: 16` (UF_LOCKOUT); `userAccountControl` stays 512 |
| c. locked, correct password | `775` | |
| d. locked, wrong password | `775` | **same as c**: you can't tell from a bind whether a locked user knows their password. `badPwdCount` stays at 3 |
| g. disabled (UAC 514), correct password | `533` | |
| g. disabled, wrong password | `52e` | the password is checked before the disabled flag |
| non-existent user (DN or UPN) | `52e` | same as a wrong password |
| empty password | `52e` | Samba rejects it; Windows AD may treat it as an anonymous bind, so reject empty passwords client side |

**e. Unlock as svc-vouch:** `replace: lockoutTime / lockoutTime: 0` succeeds
(rc 0). It sets `badPwdCount` to 0 and `msDS-User-Account-Control-Computed`
to 0, and alice's next bind with the correct password works.

**f. Nested groups:** a base-scope search on bob as svc-vouch with
`(memberOf:1.2.840.113556.1.4.1941:=CN=Helpdesk,CN=Users,DC=vouch,DC=test)`
returns bob, but carol isn't returned. The plain `(memberOf=CN=Helpdesk,...)`
filter doesn't match bob, and bob's `memberOf` attribute lists only
`Helpdesk-L1`.

**Delegation checks:**
- carol writing `lockoutTime` gets `Insufficient access (50)`,
  `00002098: Object CN=alice,... has no write property access`.
- svc-vouch writing `description` gets the same error, so the delegation
  covers only the attributes it grants.

## Differences from Windows AD to keep in mind

- **Non-zero `lockoutTime`.** Samba accepts `lockoutTime: 1` from svc-vouch.
  Windows AD only allows writing 0. Don't rely on Samba to reject it.
- **AdminSDHolder.** Samba doesn't run AdminSDHolder/SDProp, so the inherited
  delegation also applies to `Administrator` (svc-vouch can write its
  `lockoutTime`). On Windows AD, protected accounts (`adminCount=1`) have
  inheritance turned off, and the delegation wouldn't reach them.
  `Protected-Users-Vouch` is an ordinary group used to test vouch's own
  protected-group policy. It isn't AD's built-in "Protected Users" group.

## LDAPS certificate serial numbers

Samba generates its self-signed certificate with a random serial number, which is sometimes
negative. Go rejects such certificates by default, so the integration tests set
`//go:debug x509negativeserial=1`. Real AD certificates don't have negative serials.
