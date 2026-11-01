package workspaceagent

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// children owns all waiting in the process. One loop reaps every exited
// child, including orphans reparented to a subreaper, and hands the status
// of a started command to whoever started it. A second waiter, such as
// os/exec's Cmd.Wait, would race the loop and lose exit statuses, so nothing
// else in a process using this package may wait for children.
var children = struct {
	sync.Mutex
	once    sync.Once
	waiting map[int]chan syscall.WaitStatus
}{waiting: map[int]chan syscall.WaitStatus{}}

// startCommand runs /bin/sh -c command in its own session, so the command
// leads a process group that cancellation can signal as a whole.
func startCommand(command, dir string, stdin, output *os.File) (int, <-chan syscall.WaitStatus, error) {
	children.once.Do(func() { go reapChildren() })
	// Register the PID before the reaper can look it up: it takes this lock
	// for every exit it collects.
	children.Lock()
	defer children.Unlock()
	pid, err := syscall.ForkExec("/bin/sh", []string{"/bin/sh", "-c", command}, &syscall.ProcAttr{
		Dir:   dir,
		Env:   os.Environ(),
		Files: []uintptr{stdin.Fd(), output.Fd(), output.Fd()},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		return 0, nil, err
	}
	exited := make(chan syscall.WaitStatus, 1)
	children.waiting[pid] = exited
	return pid, exited, nil
}

func reapChildren() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGCHLD)
	for {
		for {
			var status syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
			if err == syscall.EINTR {
				continue
			}
			if err != nil || pid <= 0 {
				break
			}
			children.Lock()
			if exited, ok := children.waiting[pid]; ok {
				exited <- status
				delete(children.waiting, pid)
			}
			children.Unlock()
		}
		<-signals
	}
}

// exitCode follows the shell convention: 128 plus the signal for a killed
// command.
func exitCode(status syscall.WaitStatus) int {
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return status.ExitStatus()
}

// signalGroup signals the process group led by pid. A group that has already
// exited is not an error.
func signalGroup(pid int, sig syscall.Signal) {
	_ = syscall.Kill(-pid, sig)
}

// BecomeSubreaper makes orphaned descendants of this process, such as
// background jobs left by a run, reparent to it instead of to PID 1, so the
// reaping loop collects them.
func BecomeSubreaper() error {
	const prSetChildSubreaper = 36
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0); errno != 0 {
		return errno
	}
	return nil
}
