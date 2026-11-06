package workspaceagent

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

const (
	// shellDrain is how long output may still arrive after the shell exits,
	// before background jobs that keep the terminal open are cut off.
	shellDrain = time.Second
	// shellHangup is how long a shell gets to exit after its client goes away.
	shellHangup = 5 * time.Second
)

var shellUpgrader = websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: 4096}

// handleShell runs an interactive /bin/sh in a terminal for the websocket's
// lifetime. The protocol is described at buildcontract.WorkspaceShellSize.
func (a *Agent) handleShell(w http.ResponseWriter, r *http.Request) {
	terminal, tty, err := openTerminal()
	if err != nil {
		writeError(w, err)
		return
	}
	defer func() { _ = terminal.Close() }()
	env := os.Environ()
	if os.Getenv("TERM") == "" {
		env = append(env, "TERM=xterm-256color")
	}
	pid, exited, err := startProcess([]string{"/bin/sh"}, &syscall.ProcAttr{
		Dir:   a.workdir,
		Env:   env,
		Files: []uintptr{tty.Fd(), tty.Fd(), tty.Fd()},
		Sys:   &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0},
	})
	_ = tty.Close()
	if err != nil {
		writeError(w, err)
		return
	}
	conn, err := shellUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade has answered the request.
		hangUp(terminal, pid, exited)
		return
	}
	defer func() { _ = conn.Close() }()
	conn.SetReadLimit(buildcontract.MaxWorkspaceShellMessageBytes)

	var writes sync.Mutex
	output := make(chan struct{})
	go func() {
		defer close(output)
		buf := make([]byte, 32<<10)
		for {
			n, err := terminal.Read(buf)
			if n > 0 {
				writes.Lock()
				werr := conn.WriteMessage(websocket.BinaryMessage, buf[:n])
				writes.Unlock()
				if werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	input := make(chan struct{})
	go func() {
		defer close(input)
		for {
			kind, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if kind == websocket.TextMessage {
				var size buildcontract.WorkspaceShellSize
				if json.Unmarshal(data, &size) == nil {
					resizeTerminal(terminal, size)
				}
				continue
			}
			// Once the shell ends, writes fail and drop the keystrokes; reading
			// goes on so the client's close is still answered.
			_, _ = terminal.Write(data)
		}
	}()
	// stopOutput ends the output relay. A client that does not read is cut
	// off, since nothing else would end a write to it.
	stopOutput := func() {
		_ = terminal.Close()
		select {
		case <-output:
		case <-time.After(shellDrain):
			_ = conn.Close()
			<-output
		}
	}

	select {
	case status := <-exited:
		select {
		case <-output:
		case <-time.After(shellDrain):
		}
		stopOutput()
		writes.Lock()
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, strconv.Itoa(exitCode(status))), time.Now().Add(time.Second))
		writes.Unlock()
		select {
		case <-input:
		case <-time.After(time.Second):
		}
	case <-input:
		hangUp(terminal, pid, exited)
		stopOutput()
	}
}

// hangUp ends a shell whose client is gone, the way closing a terminal does,
// and kills it if it lingers. Background jobs that ignore the hangup, such as
// ones started with nohup, keep running.
func hangUp(terminal *os.File, pid int, exited <-chan syscall.WaitStatus) {
	_ = terminal.Close()
	signalGroup(pid, syscall.SIGHUP)
	select {
	case <-exited:
	case <-time.After(shellHangup):
		_ = syscall.Kill(pid, syscall.SIGKILL)
		<-exited
	}
}

// openTerminal opens a pseudo-terminal and returns its controlling side, which
// reads and writes without blocking a thread, and the terminal for the shell.
func openTerminal() (*os.File, *os.File, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	terminal := os.NewFile(uintptr(fd), "/dev/ptmx")
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		_ = terminal.Close()
		return nil, nil, err
	}
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPTN)
	if err != nil {
		_ = terminal.Close()
		return nil, nil, err
	}
	tty, err := os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = terminal.Close()
		return nil, nil, err
	}
	return terminal, tty, nil
}

func resizeTerminal(terminal *os.File, size buildcontract.WorkspaceShellSize) {
	raw, err := terminal.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: size.Rows, Col: size.Cols})
	})
}
