package vouch

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chigopher/pathlib"
	"github.com/labstack/echo/v5"
	"github.com/spf13/afero"
	logutil "github.com/wrouesnel/go.logutil"
	"github.com/wrouesnel/vouch/pkg/directory"
	"github.com/wrouesnel/vouch/pkg/server"
	"github.com/wrouesnel/vouch/pkg/unlock"
	"github.com/wrouesnel/vouch/web"
	"go.uber.org/zap"
)

// DefaultListen is the address served when web.listen isn't set.
const DefaultListen = ":8080"

// RunCmd serves the unlock web interface.
type RunCmd struct{}

// resolvePath makes a path from the config file relative to the config file's directory.
func resolvePath(cli *CLIConfig, value string) *pathlib.Path {
	fs := afero.NewOsFs()
	path := pathlib.NewPath(value, pathlib.PathWithAfero(fs))
	if path.IsAbsolute() {
		return path
	}
	return pathlib.NewPath(cli.ConfigFile.String(), pathlib.PathWithAfero(fs)).Parent().Join(value)
}

// loadDirectory builds the directory client, reading the service password and CA files.
func loadDirectory(cli *CLIConfig, cfg directory.Config) (*directory.LDAP, error) {
	if cfg.BindPassword == "" && cfg.BindPasswordFile != "" {
		password, err := resolvePath(cli, cfg.BindPasswordFile).ReadFile()
		if err != nil {
			return nil, fmt.Errorf("reading bindPasswordFile: %w", err)
		}
		cfg.BindPassword = strings.TrimRight(string(password), "\r\n")
	}

	var rootCAs *x509.CertPool
	if cfg.CAFile != "" {
		pem, err := resolvePath(cli, cfg.CAFile).ReadFile()
		if err != nil {
			return nil, fmt.Errorf("reading caFile: %w", err)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("caFile contains no PEM certificates")
		}
	}
	return directory.NewLDAP(cfg, rootCAs)
}

// Run is invoked by kong with the values bound in Entrypoint.
func (r *RunCmd) Run(ctx context.Context, cli *CLIConfig, config *EntrypointConfig) error {
	l := logutil.FromCtx(ctx)

	dir, err := loadDirectory(cli, config.Directory)
	if err != nil {
		return err
	}
	svc, err := unlock.NewService(dir, config.Policy)
	if err != nil {
		return err
	}
	go svc.Run(ctx)

	webCfg := config.Web
	if webCfg.Listen == "" {
		webCfg.Listen = DefaultListen
	}
	if (webCfg.TLSCertFile == "") != (webCfg.TLSKeyFile == "") {
		return errors.New("web: tlsCertFile and tlsKeyFile must be set together")
	}
	e, err := server.New(ctx, webCfg, svc, web.Dist())
	if err != nil {
		return err
	}

	startConfig := echo.StartConfig{
		Address:         webCfg.Listen,
		HideBanner:      true,
		HidePort:        true,
		GracefulTimeout: 10 * time.Second,
	}
	l.Info("Serving", zap.String("listen", webCfg.Listen), zap.Bool("tls", webCfg.TLSCertFile != ""),
		zap.Strings("directory_urls", config.Directory.URLs))
	if webCfg.TLSCertFile != "" {
		cert, err := resolvePath(cli, webCfg.TLSCertFile).ReadFile()
		if err != nil {
			return fmt.Errorf("reading tlsCertFile: %w", err)
		}
		key, err := resolvePath(cli, webCfg.TLSKeyFile).ReadFile()
		if err != nil {
			return fmt.Errorf("reading tlsKeyFile: %w", err)
		}
		return startConfig.StartTLS(ctx, e, cert, key)
	}
	return startConfig.Start(ctx, e)
}
