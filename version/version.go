// Package version exposes build version information. Version is set at link time by the
// build system via -ldflags "-X".
package version

// Name is the overall name of the application at the Git repository level.
const Name = "vouch"

// Description is an overall description of its function.
const Description = `Self-service Active Directory account unlock, vouched for in person by an authorised colleague`

//nolint:gochecknoglobals // overridden at link time
var Version = "v0.0.0-dev"
