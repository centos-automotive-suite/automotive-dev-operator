// Package logstream provides shared log streaming helpers for CLI commands.
package logstream

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
)

// State stores reconnect and stream progress state.
type State struct {
	Active       bool
	RetryCount   int
	WarningShown bool
	StartTime    time.Time
	Completed    bool
	LeaseID      string
}

// CanRetry reports whether another reconnect attempt should be made.
func (s *State) CanRetry(maxRetries int) bool {
	if s == nil {
		return false
	}
	return s.RetryCount < maxRetries && !s.Completed
}

// Reset clears retry counters for a fresh streaming attempt.
func (s *State) Reset() {
	if s == nil {
		return
	}
	s.RetryCount = 0
	s.WarningShown = false
}

// StreamLogsToStdout streams response body line-by-line to stdout.
func StreamLogsToStdout(body io.Reader, state *State, captureLeaseID bool) error {
	if state == nil {
		return fmt.Errorf("stream state is required")
	}

	firstStream := state.StartTime.IsZero()
	if firstStream {
		state.StartTime = time.Now()
		clilog.Infoln("Streaming logs...")
	}
	state.Active = true
	state.Reset()

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
		state.StartTime = time.Now()

		if !captureLeaseID {
			continue
		}

		if strings.Contains(line, "jmp shell --lease ") {
			parts := strings.Split(line, "jmp shell --lease ")
			if len(parts) > 1 {
				tokens := strings.Fields(parts[1])
				if len(tokens) > 0 {
					state.LeaseID = tokens[0]
				}
			}
		} else if strings.Contains(line, "Lease acquired: ") {
			parts := strings.Split(line, "Lease acquired: ")
			if len(parts) > 1 {
				tokens := strings.Fields(parts[1])
				if len(tokens) > 0 {
					state.LeaseID = tokens[0]
				}
			}
		}
	}
	state.Active = false

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("log stream interrupted: %w", err)
	}

	return nil
}

// HandleLogStreamError handles common stream endpoint failures.
func HandleLogStreamError(resp *http.Response, state *State, maxRetries int) error {
	if resp == nil || resp.Body == nil {
		return fmt.Errorf("log stream failed: empty response")
	}

	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("failed to read log stream error body: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close log stream error body: %w", closeErr)
	}
	msg := strings.TrimSpace(string(body))

	if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout {
		if state != nil && !state.WarningShown {
			fmt.Fprintf(os.Stderr, "log stream not ready (HTTP %d). Retrying... (attempt %d/%d)\n",
				resp.StatusCode, state.RetryCount+1, maxRetries)
			state.WarningShown = true
		}
		return fmt.Errorf("log endpoint not ready (HTTP %d)", resp.StatusCode)
	}

	if msg != "" {
		fmt.Fprintf(os.Stderr, "log stream error (%d): %s\n", resp.StatusCode, msg)
	} else {
		fmt.Fprintf(os.Stderr, "log stream error: HTTP %d\n", resp.StatusCode)
	}
	return fmt.Errorf("log stream failed with HTTP %d", resp.StatusCode)
}
