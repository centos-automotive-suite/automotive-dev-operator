// Command workspace-agent runs workspace commands for the build API. The
// workspace controller copies it into each workspace pod.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
)

const usage = `usage: workspace-agent start|serve [flags]

  start  run the agent as a daemon and return at once
  serve  run the agent in the foreground`

type config struct {
	stateDir, workdir, listen, tokenFile, certFile, keyFile string
}

func parseFlags(name string, args []string) (config, error) {
	var cfg config
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.StringVar(&cfg.stateDir, "state-dir", "/workspace/.ado", "directory for the agent's lock, log and run records")
	flags.StringVar(&cfg.workdir, "workdir", "/workspace/src", "working directory for commands")
	flags.StringVar(&cfg.listen, "listen", ":9443", "address of the agent API")
	flags.StringVar(&cfg.tokenFile, "token-file", "/var/run/secrets/ado-agent/token", "file holding the API bearer token")
	flags.StringVar(&cfg.certFile, "tls-cert", "", "serving certificate; plain HTTP when empty")
	flags.StringVar(&cfg.keyFile, "tls-key", "", "serving certificate key")
	err := flags.Parse(args)
	return cfg, err
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "start":
		err = start(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "workspace-agent:", err)
		os.Exit(1)
	}
}

// start re-executes the agent as "serve" in a new session, with its output in
// agent.log, and returns. The kubelet waits for a postStart command until
// nothing holds its output, so the daemon must not inherit it.
func start(args []string) error {
	cfg, err := parseFlags("start", args)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.stateDir, 0o700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(cfg.stateDir, "agent.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = logFile.Close() }()
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer func() { _ = devNull.Close() }()
	self, err := os.Executable()
	if err != nil {
		return err
	}
	process, err := os.StartProcess(self, append([]string{self, "serve"}, args...), &os.ProcAttr{
		Dir:   "/",
		Files: []*os.File{devNull, logFile, logFile},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		return err
	}
	return process.Release()
}

func serve(args []string) error {
	cfg, err := parseFlags("serve", args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := os.MkdirAll(cfg.stateDir, 0o700); err != nil {
		return err
	}
	// One agent per volume. Take the lock before recovering records: a second
	// agent would mark the first one's live runs Interrupted.
	lock, err := os.OpenFile(filepath.Join(cfg.stateDir, "agent.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("another agent holds %s", lock.Name())
		}
		return err
	}
	if err := workspaceagent.BecomeSubreaper(); err != nil {
		return fmt.Errorf("becoming a child subreaper: %w", err)
	}
	token, err := os.ReadFile(cfg.tokenFile)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(token)) == "" {
		return fmt.Errorf("token file %s is empty", cfg.tokenFile)
	}
	agent, err := workspaceagent.New(filepath.Join(cfg.stateDir, "runs"), cfg.workdir, log)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              cfg.listen,
		Handler:           agent.Handler(strings.TrimSpace(string(token))),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Info("Workspace agent listening", "address", cfg.listen, "protocol", workspaceagent.ProtocolVersion)
	if cfg.certFile == "" {
		return server.ListenAndServe()
	}
	certs, err := workspaceagent.NewCertificateReloader(cfg.certFile, cfg.keyFile)
	if err != nil {
		return err
	}
	server.TLSConfig = &tls.Config{GetCertificate: certs.GetCertificate, MinVersion: tls.VersionTLS12}
	return server.ListenAndServeTLS("", "")
}
