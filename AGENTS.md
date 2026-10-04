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
`pkg/entrypoints/application_sample/entrypoint_test.go`.

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

## Bootstrapping a new project

This stanza to be executed once and then removed from this file once the application is
setup.

* Replace the template `github.com/wrouesnel/golang-template` module path in `go.mod` and
  all imports.
* Change the name in `version/version.go` to the application name, and update `Description`.
* Rename `golang-template.yml` to match `version.Name`, and update the config file name in
  `Dockerfile`.
* Rename `cmd/application-sample` and `pkg/entrypoints/application_sample` to the real binary
  name, and update `Name` in the entrypoint, the `.gitignore` symlink entry and the
  `Dockerfile` `ENTRYPOINT`.
* Delete `.nvmrc` if there is no web interface. If there is, uncomment the `npm` entry in
  `.github/dependabot.yml`.
* Read the README.md to understand template structure and then replace it with
  the actual README.md
