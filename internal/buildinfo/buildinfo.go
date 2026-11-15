// Package buildinfo names the running SCRS version for generated documents.
package buildinfo

import (
	"os"
	"runtime/debug"
)

// Version is SCRS_VERSION, else the module version, else "dev".
func Version() string {
	if v := os.Getenv("SCRS_VERSION"); v != "" {
		return v
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
