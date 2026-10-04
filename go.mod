module github.com/wrouesnel/golang-template

go 1.27.1

require (
	github.com/alecthomas/kong v1.16.1
	github.com/chigopher/pathlib v0.19.1
	github.com/integralist/go-findroot v0.0.0-20160518114804-ac90681525dc
	github.com/magefile/mage v1.17.2
	github.com/mholt/archiver v3.1.1+incompatible
	github.com/pkg/errors v0.9.1
	github.com/samber/lo v1.53.0
	github.com/wrouesnel/ctxstdio v0.0.0-20260925000958-306c83092f60
	github.com/wrouesnel/go.logutil v0.0.0-20260831004131-2c91cc3e879a
	github.com/wrouesnel/kongutil v0.0.0-20261002155125-2b34e3bf1495
	go.uber.org/zap v1.28.0
	go.yaml.in/yaml/v4 v4.0.0-rc.6
	golang.org/x/mod v0.17.0
)

require (
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/frankban/quicktest v1.14.6 // indirect
	github.com/goccy/go-yaml v1.17.0 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/nwaples/rardecode v1.1.3 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/spf13/afero v1.14.0 // indirect
	github.com/ulikunitz/xz v0.5.17 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/yuseferi/zax/v2 v2.5.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/text v0.23.0 // indirect
)

replace go.yaml.in/yaml/v4 => github.com/wrouesnel/yaml.go-yaml/v4 v4.0.0-20260918015114-84d82f5038cd
