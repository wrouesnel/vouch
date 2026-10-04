package main

import (
	"context"
	"os"

	"github.com/wrouesnel/ctxstdio"
	"github.com/wrouesnel/golang-template/pkg/entrypoints/application_sample"
)

func main() {
	// The real entry point is in the entrypoint package, which allows for efficient test integration.
	// Do not add more code to this file (it should also be excluded from coverage tracking).
	exitCode := application_sample.Entrypoint(ctxstdio.Set(context.Background(), os.Stdout, os.Stderr, os.Stdin), os.Args[1:])
	os.Exit(exitCode)
}
