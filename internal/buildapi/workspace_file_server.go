package buildapi

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"k8s.io/client-go/rest"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/workspacemanifest"
)

const workspaceFileServerPort = 9090

// podExecForWorkspaceFileServer is the exec entry point used to start the
// workspace file server. It is a package variable so tests can stub it.
var podExecForWorkspaceFileServer = podExec

// workspaceFileServerPython serves the root given in argv[2] on the port in
// argv[1], refusing paths whose real path is outside the root.
//
// If the port is taken it exits 0, assuming an earlier build already started
// the server. It binds before daemonizing, so the exec fails when the server
// cannot start.
const workspaceFileServerPython = `import errno, functools, http.server, os, sys
port, root = sys.argv[1:3]
os.makedirs(root, exist_ok=True)
real_root = os.path.realpath(root)
def inside(p):
    real = os.path.realpath(p)
    return real == real_root or real.startswith(real_root + os.sep)
class Handler(http.server.SimpleHTTPRequestHandler):
    def send_head(self):
        path = self.translate_path(self.path)
        paths = [path]
        if os.path.isdir(path):
            paths += [os.path.join(path, index) for index in ("index.html", "index.htm")]
        if not all(inside(p) for p in paths):
            self.send_error(404, "File not found")
            return None
        return super().send_head()
class Server(http.server.ThreadingHTTPServer):
    allow_reuse_port = False
try:
    server = Server(("", int(port)), functools.partial(Handler, directory=real_root))
except OSError as e:
    if e.errno == errno.EADDRINUSE:
        sys.exit(0)
    raise
if os.fork():
    os._exit(0)
os.setsid()
null = os.open(os.devnull, os.O_RDWR)
for fd in (0, 1, 2):
    os.dup2(null, fd)
server.serve_forever()
`

// workspaceFileServerArgs runs the file server for root on port. -I keeps
// modules in the exec's working directory, such as an http.py, from replacing
// the standard library.
func workspaceFileServerArgs(port int, root string) []string {
	return []string{"python3", "-I", "-c", workspaceFileServerPython, strconv.Itoa(port), root}
}

// workspaceFileServerCommand starts the file server for the workspace export
// root. The child redirects its stdio to /dev/null so the exec returns once
// the launcher exits.
func workspaceFileServerCommand() []string {
	return workspaceFileServerArgs(workspaceFileServerPort, workspacemanifest.WorkspaceExportRoot)
}

// startWorkspaceFileServer makes sure the workspace pod serves
// /workspace/export on workspaceFileServerPort. It is safe to call for every
// build: a running server is left alone. On failure, the error carries the
// launcher's last line of output, which says why.
func startWorkspaceFileServer(ctx context.Context, restCfg *rest.Config, namespace, podName string) error {
	var out bytes.Buffer
	err := podExecForWorkspaceFileServer(ctx, restCfg, namespace, podName, workspaceContainerName, workspaceFileServerCommand(), &out)
	if err == nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if reason := strings.TrimSpace(lines[len(lines)-1]); reason != "" {
		return fmt.Errorf("%w: %s", err, reason)
	}
	return err
}
