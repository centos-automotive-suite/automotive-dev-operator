package caibcommon

import (
	"sync"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/version"
)

// serverVersionCheck makes CheckServerVersion warn at most once per run.
var serverVersionCheck = new(sync.Once)

// CheckServerVersion warns, once per run, when the Build API reported no
// version. Servers before 0.3.0 don't, and they silently drop options they
// don't know. Later ones reject such options, and failed requests name both
// versions, so a reported version needs no warning.
func CheckServerVersion(serverVersion string) {
	serverVersionCheck.Do(func() {
		if serverVersion == "" {
			clilog.Warnf("the Build API does not report its version, so it predates 0.3.0 and silently ignores options it does not know. "+
				"Install the caib release that matches the operator: %s\n", version.ReleasesURL)
		}
	})
}
