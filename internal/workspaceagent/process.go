package workspaceagent

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// children owns waiting for started commands. One loop collects their exit
// statuses and hands each to whoever started the command. Once the process
// is a subreaper, the loop also reaps every other child, such as orphans of
// runs; a second waiter, such as os/exec's Cmd.Wait, would then race it, so
// the agent waits for nothing else. Until then it waits only for its own
// commands, leaving other children to their own waiters.
var children = struct {
	sync.Mutex
	once    sync.Once
	orphans bool
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
		children.Lock()
		if children.orphans {
			reapAny()
		} else {
			reapStarted()
		}
		children.Unlock()
		<-signals
	}
}

// reapAny collects every exited child. The caller holds children's lock.
func reapAny() {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || pid <= 0 {
			return
		}
		if exited, ok := children.waiting[pid]; ok {
			exited <- status
			delete(children.waiting, pid)
		}
	}
}

// reapStarted collects started commands that exited. The caller holds
// children's lock.
func reapStarted() {
	for pid, exited := range children.waiting {
		var status syscall.WaitStatus
		if reaped, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil); err == nil && reaped == pid {
			exited <- status
			delete(children.waiting, pid)
		}
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
	children.Lock()
	children.orphans = true
	children.Unlock()
	return nil
}
