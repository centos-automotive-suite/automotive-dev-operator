// Package version reports which release a binary was built from.
package version

// Version is the release the binary was built from, such as "v0.3.0" or
// "0.3.0-dev". Builds stamp it with
//
//	-ldflags "-X github.com/centos-automotive-suite/automotive-dev-operator/internal/version.Version=<version>"
//
// It stays empty in unstamped builds such as go run.
var Version string

// ReleasesURL is where users find the caib release that matches their operator.
const ReleasesURL = "https://github.com/centos-automotive-suite/automotive-dev-operator/releases"

// Header is the response header in which the Build API reports its version.
// Servers before 0.3.0 do not send it.
const Header = "X-Build-API-Version"

// String returns Version, or "dev" for an unstamped build.
func String() string {
	if Version == "" {
		return "dev"
	}
	return Version
}
