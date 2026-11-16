// Package utils provides shared helpers used across the yadbp codebase.
package utils

import (
	"runtime/debug"
	"strings"
)

// Name is the program name used in version output.
const Name = "yadbp"

// shortHashLength is the number of commit hash characters displayed when the
// binary carries no release version.
const shortHashLength = 7

// Version is the release version injected at build time with
// -ldflags "-X yadbp/internal/utils.Version=1.0.0". It is empty for binaries
// that were built locally instead of by the release workflow.
var Version string

// String returns the version to display. It prefers the injected release
// version, falls back to the shortened VCS commit hash stamped into local
// builds, and returns an empty string when neither is available.
func String() string {
	if v := strings.TrimSpace(Version); v != "" {
		return strings.TrimPrefix(v, "v")
	}

	return commitHash()
}

// Header returns the "yadbp <version>" banner. When no version is available it
// returns just "yadbp".
func Header() string {
	if v := String(); v != "" {
		return Name + " " + v
	}

	return Name
}

// commitHash returns the shortened revision recorded by the Go toolchain when
// the binary was built from a VCS checkout, or an empty string otherwise.
func commitHash() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	for _, setting := range info.Settings {
		if setting.Key != "vcs.revision" {
			continue
		}

		revision := strings.TrimSpace(setting.Value)
		if len(revision) > shortHashLength {
			revision = revision[:shortHashLength]
		}
		return revision
	}

	return ""
}
