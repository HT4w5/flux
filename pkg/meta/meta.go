package meta

import "fmt"

const (
	ServerName = "fluxs"
	ClientName = "fluxc"
)

var (
	BuildDate  string = "1970-01-01 00:00:00+00:00"
	CommitHash string = "0000000000000000000000000000000000000000"
	Version    string = "N/A"
	Platform   string = "N/A"
	GoVersion  string = "N/A"
)

var (
	version string
)

func init() {
	version = fmt.Sprintf(
		" %s %s (%s %s)",
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

func VersionString(name string) string {
	return name + version
}

func PrintlnFGBlue(str string) {
	fmt.Println("\x1b[0;34m" + str + "\x1b[0m")
}

func PrintlnBGBlue(str string) {
	fmt.Println("\x1b[44m" + str + "\x1b[0m")
}

func PrintBanner() {
	// Print banner
	fmt.Println()
	PrintlnFGBlue(` ███████╗██╗     ██╗   ██╗██╗  ██╗`)
	PrintlnFGBlue(` ██╔════╝██║     ██║   ██║╚██╗██╔╝`)
	PrintlnFGBlue(` █████╗  ██║     ██║   ██║ ╚███╔╝ `)
	PrintlnFGBlue(` ██╔══╝  ██║     ██║   ██║ ██╔██╗ `)
	PrintlnFGBlue(` ██║     ███████╗╚██████╔╝██╔╝ ██╗`)
	PrintlnFGBlue(` ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝`)
	PrintlnFGBlue(` ─────────────────────────────────`)
}
