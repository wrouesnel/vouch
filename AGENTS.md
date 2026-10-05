Use README.md files to understand program intent and structure.

Binary outputs must build via `go run mage.go binary`.

Build without CGO.

Use the [afero package](https://github.com/spf13/afero) to abstract filesystem
access, ideally via the [pathlib package](https://github.com/chigopher/pathlib)
except in application startup entrypoints where no configuration has been loaded
yet.

If a web application is being developed then implement all endpoints using OpenAPI 3
and use `oapi-codegen` to build Echo v5 (`go get github.com/labstack/echo/v5`) based
servers.

Use the [zap logger](https://go.uber.org/zap) for logging and favor using the
[logutil package](https://github.com/wrouesnel/go.logutil). Any function taking
a `context.Context` should use `logutil.FromCtx` to get a context-aware logger.

Implement all binary applications as exportable packages under `pkg/entrypoints/<binary name>`
and keep code under `cmd/` to an absolute minimum. Replace `-` with `_` in the binary name to
get the package name, e.g. `cmd/foo-bar` is implemented by `pkg/entrypoints/foo_bar`. Each new
binary also needs an entry in `.gitignore` for the symlink `go run mage.go binary` creates.

Test entrypoints by calling `Entrypoint(ctx, args)` directly, as in
`pkg/entrypoints/vouch/entrypoint_test.go`.

## Build commands

Run all build commands from the repository root. `go run mage.go -l` lists every target.

* `go run mage.go binary` - build for the current platform into `bin/` and symlink it into
  the repository root.
* `go run mage.go test` - run the tests. `go run mage.go coverage` merges coverage into
  `.cover.out` afterwards.
* `go run mage.go lint` - run golangci-lint (configured by `.golangci.yml`).
* `go run mage.go style` - check formatting. `go run mage.go fmt` fixes it.

CI runs `style`, `lint`, `test` and `binary`, all of which must pass.

## Web interface

A web interface is optional. If `web/package.json` exists, the build installs the Node.js
version in `.nvmrc` and builds `web/` into `web/dist` for embedding. Otherwise the web build
is skipped. Set `SKIP_WEB=1` to skip it regardless.

## This project

vouch is a self-service AD account unlock page. Read README.md for the workflow and security
model before changing `pkg/unlock`.

* The account being unlocked stays locked throughout. The password is checked at the claim by
  briefly unlocking, binding, and re-locking (`directory.VerifyWhileLocked`); the permanent
  unlock happens at confirm. Never add a path that leaves an eligible-but-unconfirmed account
  unlocked.
* The final unlock is gated on a committed audit record: `Confirm` calls `sink.Log` for
  `unlock_authorized` and only unlocks if it returns nil. A sink's `Log` must block until the
  event is durably committed. Audit sinks live in `pkg/audit`; the SQL sink's drivers are
  registered in `pkg/audit/drivers.go` (keep them pure-Go so the binary stays CGO-free).
* The service account's permissions are granted by `extras/Grant-VouchServiceAccount.ps1` and,
  identically, by `test/samba/setup.sh`. If vouch starts reading or writing another attribute,
  change both, the README's permission table, and `TestSambaServiceAccountIsLeastPrivilege`.
  Check the script with PSScriptAnalyzer (`pwsh -c 'Invoke-ScriptAnalyzer extras'`).
* Releases: push a `v*` tag to the `github` remote. `release.yml` runs CI, then publishes the
  versioned image (moving `latest` unless it's a pre-release) and the GitHub Release.

* The API is defined in `api/vouch.yaml`. After changing it, run `go generate ./pkg/api` and
  commit `pkg/api/api.gen.go`. The generate directive pins the oapi-codegen version with
  `go run`, so it needs no installed tools (the container build relies on this).
* The container image is built by `.github/workflows/container.yml`, a reusable workflow called
  after the tests pass: from `integration.yml` (builds everywhere, pushes from `main`) and from
  `release.yml` (pushes version tags). Check Dockerfile changes with `podman build .`.
* `web/` is a dependency-light TypeScript UI built by Vite. Build DOM with the `h()` helper, never
  `innerHTML`: directory data is shown on the page. Keep `web/src/api.ts` in step with the spec.
* `web/dist/.gitkeep` is committed so the Go embed compiles before the web build has run.
* Integration tests against real AD semantics run on the Samba DC in `test/samba` (rootless
  podman). They are skipped unless `VOUCH_SAMBA_URL` is set.
