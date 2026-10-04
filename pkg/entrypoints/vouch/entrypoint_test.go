package vouch_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chigopher/pathlib"

	"github.com/wrouesnel/ctxstdio"
	"github.com/wrouesnel/vouch/pkg/entrypoints/vouch"
	"github.com/wrouesnel/vouch/version"
)

// runEntrypoint invokes the entrypoint as though from the command line and captures its output.
func runEntrypoint(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	stdOut, stdErr := new(bytes.Buffer), new(bytes.Buffer)
	ctx := ctxstdio.Set(context.Background(), stdOut, stdErr, os.Stdin)
	exitCode := vouch.Entrypoint(ctx, args)
	return exitCode, stdOut.String(), stdErr.String()
}

// writeConfig writes a config file to a temporary directory and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func TestVersion(t *testing.T) {
	exitCode, stdOut, _ := runEntrypoint(t, "--version")
	if exitCode != 0 {
		t.Fatalf("exit code: got %d, want 0", exitCode)
	}
	if !strings.Contains(stdOut, version.Version) {
		t.Errorf("stdout %q does not contain version %q", stdOut, version.Version)
	}
}

// minimalConfig is a valid configuration. Startup doesn't contact the directory.
const minimalConfig = `
web:
  listen: "127.0.0.1:0"
directory:
  urls: ["ldap://127.0.0.1:1"]
  baseDN: "DC=example,DC=test"
  bindDN: "CN=svc,DC=example,DC=test"
  bindPassword: "secret"
policy:
  voucherGroups: ["CN=Helpdesk,DC=example,DC=test"]
  sessionLifetime: 3m
`

func TestRunStopsWhenCancelled(t *testing.T) {
	configPath := writeConfig(t, minimalConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	stdOut, stdErr := new(bytes.Buffer), new(bytes.Buffer)
	exitCode := vouch.Entrypoint(ctxstdio.Set(ctx, stdOut, stdErr, os.Stdin), []string{"--config-file", configPath})
	if exitCode != 0 {
		t.Fatalf("exit code: got %d, want 0: %s", exitCode, stdErr.String())
	}
}

func TestShippedConfigParses(t *testing.T) {
	config := vouch.EntrypointConfig{}
	if err := vouch.UnmarshalConfig(pathlib.NewPath("../../../vouch.yml"), &config); err != nil {
		t.Fatal(err)
	}
	if config.Policy.SessionLifetime != 5*time.Minute || len(config.Directory.URLs) != 2 {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestInvalidConfigFails(t *testing.T) {
	cases := map[string]string{
		"empty":        "{}\n",
		"unknown key":  minimalConfig + "bogus: true\n",
		"no voucher":   strings.Replace(minimalConfig, "voucherGroups", "protectedGroups", 1),
		"tls half set": strings.Replace(minimalConfig, "web:", "web:\n  tlsCertFile: x.pem", 1),
		"bad proxy":    strings.Replace(minimalConfig, "web:", "web:\n  trustedProxies: [nonsense]", 1),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			configPath := writeConfig(t, content)
			if exitCode, _, _ := runEntrypoint(t, "--config-file", configPath); exitCode != 1 {
				t.Fatalf("exit code: got %d, want 1", exitCode)
			}
		})
	}
}

func TestMissingConfigFileFails(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "missing.yml")
	if exitCode, _, _ := runEntrypoint(t, "--config-file", configPath); exitCode != 1 {
		t.Fatalf("exit code: got %d, want 1", exitCode)
	}
}

func TestInvalidFlagFails(t *testing.T) {
	exitCode, _, stdErr := runEntrypoint(t, "--no-such-flag")
	if exitCode == 0 {
		t.Fatal("exit code: got 0, want non-zero")
	}
	if !strings.Contains(stdErr, "no-such-flag") {
		t.Errorf("stderr %q does not mention the bad flag", stdErr)
	}
}
