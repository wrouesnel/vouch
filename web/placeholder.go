package web

import (
	"io/fs"
	"testing/fstest"
)

// placeholderFS serves notBuilt as index.html.
type placeholderFS struct{}

func (placeholderFS) Open(name string) (fs.File, error) {
	return fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(notBuilt)}}.Open(name)
}
