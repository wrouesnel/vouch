package vouch

import (
	"github.com/chigopher/pathlib"
	"github.com/wrouesnel/vouch/pkg/directory"
	"github.com/wrouesnel/vouch/pkg/server"
	"github.com/wrouesnel/vouch/pkg/unlock"
	"go.yaml.in/yaml/v4"
)

// UnmarshalConfig wraps the yaml.Unmarshaling process for entrypoint configuration files.
// This includes ensuring that the necessary providers from other parts of the application
// are loaded.
func UnmarshalConfig(path *pathlib.Path, config *EntrypointConfig) error {
	configFile, err := path.Open()
	if err != nil {
		return err
	}
	defer configFile.Close()

	loader, err := yaml.NewLoader(configFile, YamlOption())
	if err != nil {
		return err
	}
	return loader.Load(config)
}

// YamlOption returns the correct YAML options for decoding entrypoint configuration.
func YamlOption() yaml.Option {
	return yaml.Options(yaml.WithKnownFields())
}

// EntrypointConfig unmarshals to configure the application.
type EntrypointConfig struct {
	// Web configures the HTTP server and page text.
	Web server.Config `yaml:"web"`
	// Directory configures the connection to Active Directory.
	Directory directory.Config `yaml:"directory"`
	// Policy decides who may vouch and who may be unlocked.
	Policy unlock.Policy `yaml:"policy"`
}
