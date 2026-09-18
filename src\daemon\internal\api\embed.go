package api

import "embed"

// distFS holds the compiled WebUI. It lives inside the binary so the module has
// no separate web root to install, nothing can be modified at runtime, and an
// unprivileged process cannot delete or replace the dashboard.
//
//go:embed all:dist
var distFS embed.FS
