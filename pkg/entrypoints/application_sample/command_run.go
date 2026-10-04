package application_sample

import (
	"context"

	logutil "github.com/wrouesnel/go.logutil"
)

// RunCmd is the default command. Replace it with the application's real behavior.
type RunCmd struct{}

// Run is invoked by kong with the values bound in Entrypoint. Get the logger with
// logutil.FromCtx: it uses the logger Entrypoint installs globally, plus any fields
// attached to ctx.
func (r *RunCmd) Run(ctx context.Context, config *EntrypointConfig) error {
	l := logutil.FromCtx(ctx)
	l.Info("Application started")
	return nil
}
