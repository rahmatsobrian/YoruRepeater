// Package version holds build-time identity for the Yoru daemon.
package version

// Values are injected by build.sh via -ldflags.
var (
	GitTag    = "v1.0.0"
	GitHash   = "dev"
	BuildDate = "unknown"
	Repo      = "YoruSoft/YoruRepeater"
)

// SchemaVersion is the configuration schema the daemon expects.
const SchemaVersion = 2

// APIVersion is reported in /api/v1 responses and pins the wire contract.
const APIVersion = "1"

func String() string { return GitTag }
