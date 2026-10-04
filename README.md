# Golang Template repository

This is a template repository outlining the basic structure to be used for
Golang applications.

The content here should be replaced with a description of the program, instructions
for building (which should just be `go run mage.go binary`) as well as usage and
implementation details.

If this is a web application, include a screen shot of the main screen linked just
below the title.

## Template structure

| Path | Purpose |
|---|---|
| `cmd/<binary>/main.go` | Minimal `main` package for each binary. It only calls the entrypoint. |
| `pkg/entrypoints/<binary>/` | The real application: command line parsing, logging, config loading and commands. |
| `pkg/` | Other exportable packages of the application. |
| `version/` | Application name, description and version. `Version` is set at link time by the build. |
| `golang-template.yml` | Default configuration file, loaded from the working directory. |
| `magefile.go`, `mage.go` | The build system. Run `go run mage.go -l` to list targets. |
| `web/` | Optional web interface. It's built and embedded if `web/package.json` exists. |
| `Dockerfile` | Container image, built and pushed by `.github/workflows/container.yml`. |
| `.github/workflows/` | CI: build and test on every push, releases on `v*` tags. |

## Building

```sh
go run mage.go binary
./application-sample
```

`go run mage.go binary` builds into `bin/` and symlinks each binary into the repository root.
`go run mage.go releaseAll` cross-compiles release archives for every platform into
`release/`.

## Configuration

The binary loads `golang-template.yml` from the working directory, or the file named by
`--config-file`, and fails if it doesn't exist. Its keys map to `EntrypointConfig` in
`pkg/entrypoints/application_sample/config.go`.
