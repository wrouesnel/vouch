// Package web embeds the built web interface from web/dist.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// notBuilt is served when the binary was built without the web interface.
const notBuilt = `<!doctype html><meta charset="utf-8"><title>vouch</title>
<p>The web interface wasn't built into this binary. Build with <code>go run mage.go binary</code>.</p>`

// Dist returns the web interface's files.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return placeholderFS{}
	}
	return sub
}
