# vouch

Self-service unlock for locked Active Directory accounts. A colleague from an authorised group
vouches for the user in person, in the same browser.

![The confirmation step, where the colleague checks who they are vouching for](docs/screenshot.png)

## How it works

1. **A colleague signs in first.** They must be in one of the configured voucher groups (nested
   membership counts). This starts an unlock session in their browser.
2. **The colleague hands the device to the locked-out user, who enters their username and
   current password.** vouch binds to AD as them. If AD says the account is locked out and it's
   eligible for self-service unlock, the user's directory details are shown for the colleague to
   check. If the password simply works, the account isn't locked and nothing more is done. The
   colleague can't enter their own account here.
3. **The colleague checks the details, confirms they are with the user and have confirmed their
   identity, and enters their own username and password again.** It must be the same account
   that started the session. vouch commits an audit record, and only then clears the lockout.

### The account's status, and why the password check unlocks then re-locks

The account being unlocked starts **locked**. While it's locked, AD answers every bind `data 775`
whether or not the password is right, so a locked account's password can't be checked without
first unlocking it (confirmed against the Samba AD DC in [`test/samba`](test/samba/README.md)).

vouch handles this without ever leaving the account unlocked while it waits for the colleague:

* At the claim (step 2) it first binds as the user to confirm the account really is **locked**,
  and checks it's eligible. A bind reveals the status without changing it, so this can't be used
  to unlock or lock anyone.
* Only then does it briefly clear the lockout, bind as the user to check the password, and
  **re-lock** the account. AD doesn't allow writing a non-zero `lockoutTime`, so the re-lock is
  done the way AD itself locks accounts: failed binds up to the account's lockout threshold
  (read from its resultant password-settings object, else the domain policy). The account is
  unlocked only for the few milliseconds this takes.
* The password is checked here, once, and **discarded** — vouch keeps no password between steps.
  If it's wrong, the account is simply left locked and the user can try again.
* The final, permanent unlock happens at step 3, after the colleague confirms. Because the
  password was already verified, a wrong password can never result in an unlocked account.

The re-lock generates failed-logon events (Windows event 4625) on the domain controller, and
every one is recorded in vouch's own audit log. If the account can't be re-locked for any reason
(for example lockout is disabled, so there's no threshold to reach), vouch **disables** the
account as a fail-safe rather than leave it unlocked, and records a `relock_failed` audit event.
It also writes the account's description, so whoever finds it disabled can see when and why,
for example:

> Disabled by vouch on 2026-10-06T00:10:37Z: it could not be re-locked after its password was
> checked during a self-service unlock (audit session Td0-huzNU0Zh)

The text is `policy.disableDescription`, a template with `{date}`, `{reason}`, `{session}`,
`{voucher}`, `{target}` and `{previous}` (the old description) placeholders; set it to `-` to
leave descriptions alone. The disable and the description are written in one change, so the
account is never disabled without its explanation. If the service account can't write the
description, vouch still disables the account and logs that the description is missing.

If a fine-grained password policy applies to the account but vouch can't read its lockout
threshold, vouch refuses to touch the account at all, rather than guess the threshold.

### The unlock is gated on a committed audit record

Before it clears the lockout, vouch writes an `unlock_authorized` record to the audit sink and
waits for it to commit. **If the audit record can't be committed, the account is not unlocked**
and the colleague is told to try again. See [Audit trail](#audit-trail).

### Keeping both people in the same place

The vouching has to happen in one browser on one machine:

* All three steps share one server-side session, started by the colleague's sign-in and
  identified by a random ID in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie scoped to
  `/api/v1`. A user in another browser has no session to enter their details into.
* A session is tied to the client address and User-Agent that started it. A request from
  anywhere else cancels the session outright.
* The colleague signs in at the start and again at the end, so they have to be at the machine
  both before and after the user enters their details.
* Time limits: by default the whole exchange must finish within 5 minutes of the colleague
  signing in. The colleague must confirm within 2 minutes of the user entering their details,
  otherwise the user's details are discarded and must be entered again.
* The colleague has to tick an explicit attestation naming the user before the unlock button
  works.
* State-changing requests must be same-origin JSON (`Origin`/`Sec-Fetch-Site` checks).
  Failed attempts are rate limited per client address and per account, however it's named.
  Successful steps don't count, so a service desk machine can do many unlocks in a row.

This is presence *enforcement* in the "same browser" sense, not proof that two people were in
the room. Both people type a password on the same machine, so only use vouch on machines you'd
trust with both. The page asks password managers and browsers not to save either person's
credentials, but browsers don't always comply.

### Audit trail

Every security-relevant action is written to an audit sink as a structured event: the voucher
signing in, the password check and re-lock, the authorisation and the unlock, rejections,
presence mismatches and cancellations. Each event carries a per-session audit id (not the secret
session cookie), the client address and user-agent, the voucher, the target account and the
outcome. Passwords and session cookies are never recorded.

Configure one or more sinks under `audit:` in the config; events go to all of them:

* **file** — one JSON object per line, `fsync`'d per event.
* **sql** — one row per event (PostgreSQL via `pgx`, MySQL or SQLite). Create the table first:

  ```sql
  CREATE TABLE vouch_audit (
    id                BIGSERIAL PRIMARY KEY,
    event_time        TIMESTAMPTZ NOT NULL,
    event_type        TEXT NOT NULL,
    decision          TEXT NOT NULL,
    reason            TEXT,
    session           TEXT,
    client_ip         TEXT,
    client_user_agent TEXT,
    voucher           TEXT,
    voucher_dn        TEXT,
    target            TEXT,
    target_dn         TEXT,
    bind_result       TEXT,
    outcome           TEXT,
    message           TEXT,
    detail            JSONB
  );
  ```

  (Use `SERIAL`/`AUTO_INCREMENT` and `JSON`/`TEXT` to suit your database. `detail` holds the
  whole event as JSON.)
* **http** — POST each event as JSON, including to a **Splunk HTTP Event Collector** (`splunk:
  true` wraps the event and sends the HEC token). Failed deliveries are retried.

The **final unlock is gated on the audit record**: vouch writes the `unlock_authorized` event and
clears the lockout only if every configured sink commits it. If a sink fails, the unlock is
refused with an `audit_failed` error and the account stays locked. Non-gating events (sign-ins,
rejections) are best-effort: a sink failure is logged but doesn't block the step.

Keep credentials out of the config file with `audit.sql.dsnFile` and `audit.http.tokenFile`,
which are read from separate files. If no durable sink is configured, events go to stderr only
and vouch logs a warning at startup. vouch's own operational logs (`--log-format json`) are
separate from this audit trail.

## Active Directory setup

**Service account.** Create a dedicated, unprivileged account (e.g. `svc-vouch`) with a long
random password, and grant it exactly what vouch needs with the script in `extras/`, run as a
Domain Admin from a machine with the RSAT ActiveDirectory module:

```powershell
# Preview, then apply. Pass every OU holding users vouch may unlock.
.\extras\Grant-VouchServiceAccount.ps1 -Identity svc-vouch -TargetOU 'OU=Staff,DC=example,DC=com' -WhatIf
.\extras\Grant-VouchServiceAccount.ps1 -Identity svc-vouch -TargetOU 'OU=Staff,DC=example,DC=com'
```

It grants these five permissions and nothing else:

| Where | Inherited by | Permission | Why |
|---|---|---|---|
| each target OU | user objects | Write `lockoutTime` | clear the lockout |
| each target OU | user objects | Write `userAccountControl` | the fail-safe disable |
| each target OU | user objects | Write `description` | explain a fail-safe disable |
| each target OU | user objects | Read `msDS-ResultantPSO` | find the account's fine-grained password policy |
| `CN=Password Settings Container,CN=System` | password settings objects | Read `msDS-LockoutThreshold` | read that policy's lockout threshold |

Everything else vouch reads (users, group membership, the domain lockout policy and the
computed lockout state) is covered by Authenticated Users' default read access. The re-lock
needs no permission at all, since anyone may attempt a bind.

The script is idempotent and supports `-WhatIf` and `-Confirm`. It refuses to set up an account
that is already privileged (Domain/Enterprise/Schema Admins, Administrators, the operator
groups, or protected by AdminSDHolder). It refuses the domain root as a target, warns about any
other permission the account holds on the objects it touches (`-RemoveOtherPermissions` removes
them), and warns about password settings objects that block inheritance. `-Revoke` takes the
permissions away again.

The same five permissions are granted to the test DC by `test/samba/setup.sh`. The integration
tests show they're enough for every vouch operation, and that the account can't write any other
attribute, join a voucher group, change a password policy or reset a password. The script itself
has been parsed and checked with PSScriptAnalyzer, but not yet run against a Windows domain.

If you'd rather not run the script, these are the `dsacls` equivalents:

```bat
dsacls "OU=Staff,DC=example,DC=com" /I:S /G "EXAMPLE\svc-vouch:WP;lockoutTime;user"
dsacls "OU=Staff,DC=example,DC=com" /I:S /G "EXAMPLE\svc-vouch:WP;userAccountControl;user"
dsacls "OU=Staff,DC=example,DC=com" /I:S /G "EXAMPLE\svc-vouch:WP;description;user"
dsacls "OU=Staff,DC=example,DC=com" /I:S /G "EXAMPLE\svc-vouch:RP;msDS-ResultantPSO;user"
dsacls "CN=Password Settings Container,CN=System,DC=example,DC=com" /I:S /G "EXAMPLE\svc-vouch:RP;msDS-LockoutThreshold;msDS-PasswordSettings"
```

Don't delegate at the domain root. Accounts protected by AdminSDHolder (`adminCount=1`) don't
inherit delegations, so the service account can't touch domain admins even if they aren't in a
protected group. List them in `protectedGroups` anyway, so vouch refuses before it tries.

**Voucher groups.** Create or choose a group such as the service desk or team leads, and list
its DN in `policy.voucherGroups`. Membership is resolved with `LDAP_MATCHING_RULE_IN_CHAIN`, so
nested groups count. Primary group membership (normally Domain Users) isn't seen.

**Connection.** Use `ldaps://` or `ldap://` with `startTLS: true`. A plain `ldap://` simple
bind sends passwords in clear text, and AD's LDAP signing policy may refuse it anyway.

## Configuration

vouch reads `vouch.yml` from the working directory, or the file given by `--config-file`. The
shipped [`vouch.yml`](vouch.yml) documents every key. Unknown keys are rejected. The main
sections are:

| Section | Purpose |
|---|---|
| `web` | Listen address, optional TLS, trusted reverse proxies, and page text. |
| `directory` | Domain controller URLs, TLS trust, base DN, service account, user filter. |
| `policy` | Voucher, protected and eligible groups, time limits and rate limits. |
| `audit` | The audit sinks (file, SQL, HTTP/Splunk). The final unlock is gated on these. |

Run vouch behind HTTPS. Either set `web.tlsCertFile`/`web.tlsKeyFile`, or put it behind a
reverse proxy and list the proxy in `web.trustedProxies` so the real client address is used for
presence checks and rate limits.

Flags such as `--log-level` and `--log-format` are shown by `./vouch --help`. Each can also be
set as a `VOUCH_*` environment variable.

## Building

```sh
go run mage.go binary
./vouch --config-file vouch.yml
```

The build installs the Node.js version in `.nvmrc` into `.node/`, builds the web interface in
`web/` and embeds it in the binary. `go run mage.go -l` lists every target. CI runs `style`,
`lint`, `test` and `binary`.

## Container image

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to the GitHub Container
Registry as `ghcr.io/wrouesnel/vouch`, and can be pulled without logging in:

| Tag | Points at |
|---|---|
| `<version>` (e.g. `0.1.0`), `<major>.<minor>`, `<major>` | that release |
| `latest` | the newest release (not pre-releases) |
| `main` | the newest build of the `main` branch |
| `sha-<commit>` | a specific build |

Pin a version in production. Each pushed image carries a build-provenance attestation and an
SBOM (`docker buildx imagetools inspect ghcr.io/wrouesnel/vouch:<tag> --format '{{ json .SBOM }}'`).

The image runs as a non-root user, listens on 8080 and logs JSON. Mount your configuration over
`/app/vouch.yml` and the service account's password file next to it. `/var/log/vouch` is a volume
writable by the image's user, for the file audit sink (`audit.file.path:
/var/log/vouch/audit.log`):

```sh
docker run -d --name vouch -p 8080:8080 \
  -v "$PWD/vouch.yml:/app/vouch.yml:ro" \
  -v "$PWD/svc-vouch.password:/app/svc-vouch.password:ro" \
  -v vouch-audit:/var/log/vouch \
  ghcr.io/wrouesnel/vouch:0.1.0
```

Put it behind a TLS-terminating reverse proxy, and list the proxy's address in
`web.trustedProxies` so presence checks and rate limits see the real client address.

### Releasing

Push a version tag:

```sh
git tag -a v0.1.0 -m "vouch 0.1.0"
git push github v0.1.0
```

`.github/workflows/release.yml` then runs the full CI suite, including the Samba integration
tests. Only if that passes does it publish the versioned images (and move `latest`) and create
the GitHub Release with the binary archives. A tag with a pre-release suffix such as
`v0.2.0-rc.1` publishes `0.2.0-rc.1` without moving `latest`.

Every branch and pull request also builds the image without pushing it, so a broken Dockerfile
fails CI, and each push to `main` that passes CI publishes `main` and `sha-<commit>`. The image
build is `.github/workflows/container.yml`, called from `integration.yml` and `release.yml`.

## Development

| Path | Purpose |
|---|---|
| `api/vouch.yaml` | OpenAPI 3 definition of the API. `go generate ./pkg/api` regenerates the Echo v5 server in `pkg/api`. |
| `pkg/directory` | AD access over LDAP: lookups, binds, nested groups, verify-while-locked and unlock. `directorytest` holds an in-memory fake with AD's lockout behaviour. |
| `pkg/unlock` | The workflow: sessions, presence checks, eligibility, rate limits and the audit-gated unlock. |
| `pkg/audit` | Audit sinks (file, SQL, HTTP/Splunk) and the commit gate. |
| `pkg/server` | Echo HTTP server: API handlers, cookies, security headers, and the embedded web interface. |
| `pkg/entrypoints/vouch` | Command line, configuration and startup. |
| `web/` | TypeScript and Vite web interface. `npm run dev` serves it with the API proxied to `:8080`. |
| `test/samba/` | A disposable Samba AD DC in rootless podman, for integration tests. |

Unit tests run without a directory. The integration tests need the Samba DC:

```sh
test/samba/start.sh
VOUCH_SAMBA_URL=ldap://127.0.0.1:10389 go test -count=1 -run Samba -v ./pkg/directory/
./vouch --config-file test/samba/vouch-samba.yml   # try the UI at http://127.0.0.1:8080
test/samba/stop.sh
```

The test domain has `alice` (to unlock), `bob` (a voucher, in `Helpdesk` through a nested group),
`carol` (can't vouch) and `dadmin` (protected). Each user's password is
`Passw0rd-<name>!`. Lock `alice` out with three bad binds, for example
`ldapwhoami -x -H ldap://127.0.0.1:10389 -D CN=alice,CN=Users,DC=vouch,DC=test -w wrong`.
