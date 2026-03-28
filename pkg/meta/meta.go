package meta

import "fmt"

const (
	Name = "flux"
)

var (
	BuildDate  string
	CommitHash string
	Version    string
	Platform   string
	GoVersion  string
)

var (
	VersionShort string
	VersionLong  string
)

func init() {
	VersionShort = fmt.Sprintf("%s %s", Name, Version)
	VersionLong = fmt.Sprintf(
		"%s %s %s (%s %s)",
		Name,
		Version,
		firstN(CommitHash, 7),
		GoVersion,
		Platform,
	)
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
