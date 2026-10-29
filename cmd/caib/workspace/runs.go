package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	caibcommon "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

type runClientCall func(func(*buildapiclient.Client) error) error

func withRunClient(fn func(*buildapiclient.Client) error) error {
	return caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, fn)
}

func newExecCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec <name> [--script <file>] [-- <command...>]",
		Short: "Execute a durable command in a workspace",
		Long: `Run a command in /workspace/src and follow its retained output.
Network failures reconnect automatically. The CLI returns the command's exit code.
Ctrl-C detaches without stopping the command; use workspace run cancel to stop it.

Arguments after -- are preserved literally. Use sh -c for shell syntax, or
--script to upload a local script and run it with Bash and set -euo pipefail.

Examples:
  caib workspace exec my-app -- make -j4
  caib workspace exec my-app --script build.sh
  caib workspace exec my-app --detach -- cargo build --release
  caib workspace exec my-app --run <run-id>
  caib workspace exec my-app --run <run-id> --offset 4096`,
		Args: cobra.MinimumNArgs(1),
		Run:  runExec,
	}
	cmd.Flags().String("run", "", "reattach to an existing run instead of starting a command")
	cmd.Flags().Int64("offset", 0, "resume at this log byte offset (with --run)")
	cmd.Flags().Bool("detach", false, "start a run and print its ID without following output")
	cmd.Flags().Duration("timeout", 0, "command timeout, up to 24h (default: operator policy, normally 2h)")
	cmd.Flags().String("script", "", "upload and run a local Bash script with set -euo pipefail")
	cmd.MarkFlagsMutuallyExclusive("run", "script")
	return cmd
}

func runExec(cmd *cobra.Command, args []string) {
	requireServer()
	id, _ := cmd.Flags().GetString("run")
	offset, _ := cmd.Flags().GetInt64("offset")
	detach, _ := cmd.Flags().GetBool("detach")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	if cmd.Flags().Changed("timeout") && (timeout <= 0 || timeout%time.Second != 0 || timeout > 24*time.Hour || id != "") {
		handleError(fmt.Errorf("--timeout must be a whole number of seconds between 1s and 24h, and cannot be used with --run"))
	}
	if offset < 0 || (id == "" && offset != 0) {
		handleError(fmt.Errorf("--offset must be non-negative and requires --run"))
	}
	if (id == "" && len(args) < 2 && !cmd.Flags().Changed("script")) || (id != "" && (len(args) != 1 || detach)) {
		handleError(fmt.Errorf("specify a command, or use --run <id> to reattach"))
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	if id == "" {
		command, err := workspaceRunCommand(cmd, args[1:])
		if err != nil {
			stop()
			handleError(err)
		}
		id = uuid.NewString()
		clilog.Statusf("Run: %s\n", id)
		req := buildcontract.WorkspaceRunRequest{ID: id, Command: command, TimeoutSeconds: int64(timeout / time.Second)}
		err = startWorkspaceRun(ctx, withRunClient, args[0], req, time.Second)
		if err != nil {
			stop()
			handleError(fmt.Errorf("create run %s: %w; inspect with caib workspace exec %s --run %s", id, err, args[0], id))
		}
	}
	if detach {
		stop()
		fmt.Println(id)
		return
	}
	var output io.Writer = os.Stdout
	if clilog.IsQuiet() {
		output = io.Discard
	}
	code, err := followWorkspaceRun(ctx, withRunClient, args[0], id, &offset, output, os.Stderr, time.Second)
	stop()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "Detached. Resume: caib workspace exec %s --run %s --offset %d\nCancel: caib workspace run cancel %s %s\n", args[0], id, offset, args[0], id)
			os.Exit(130)
		}
		handleError(fmt.Errorf("run %s: %w; resume with caib workspace exec %s --run %s --offset %d", id, err, args[0], id, offset))
	}
	if code != 0 {
		os.Exit(code)
	}
}

func newRunCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "run", Short: "List, inspect, cancel or delete durable workspace commands"}
	for _, action := range []string{"show", "cancel", "delete"} {
		cmd.AddCommand(&cobra.Command{
			Use: action + " <workspace> <run-id>", Short: action + " a workspace run", Args: cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				requireServer()
				ctx, cancel := context.WithTimeout(cmd.Context(), 40*time.Second)
				defer cancel()
				var run *buildcontract.WorkspaceRun
				err := withRunClient(func(client *buildapiclient.Client) (err error) {
					switch action {
					case "delete":
						return client.DeleteWorkspaceRun(ctx, args[0], args[1])
					case "cancel":
						run, err = client.CancelWorkspaceRun(ctx, args[0], args[1])
					default:
						run, err = client.GetWorkspaceRun(ctx, args[0], args[1])
					}
					return err
				})
				if err != nil {
					return err
				}
				if action == "delete" {
					return nil
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(run)
			},
		})
	}
	list := &cobra.Command{
		Use: "list <workspace>", Short: "List retained runs, newest first", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			requireServer()
			offset, _ := cmd.Flags().GetInt("offset")
			limit, _ := cmd.Flags().GetInt("limit")
			if offset < 0 || limit < 1 || limit > 100 {
				return fmt.Errorf("--offset must be non-negative and --limit must be between 1 and 100")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 40*time.Second)
			defer cancel()
			var runs []buildcontract.WorkspaceRun
			err := withRunClient(func(client *buildapiclient.Client) (err error) {
				runs, err = client.ListWorkspaceRuns(ctx, args[0], offset, limit)
				return err
			})
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(runs)
		},
	}
	list.Flags().Int("offset", 0, "skip this many runs")
	list.Flags().Int("limit", 100, "maximum runs to return (1-100)")
	cmd.AddCommand(list)
	return cmd
}

func startWorkspaceRun(ctx context.Context, api runClientCall, name string, req buildcontract.WorkspaceRunRequest, retryDelay time.Duration) error {
	err := retryRunRequest(ctx, retryDelay, func() error {
		requestCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		return api(func(client *buildapiclient.Client) error {
			_, err := client.CreateWorkspaceRun(requestCtx, name, req)
			return err
		})
	})
	if buildapiclient.IsRouteNotFound(err) {
		return fmt.Errorf("this server predates durable runs; upgrade the operator or use the caib version shipped with it: %w", err)
	}
	return err
}

func transientRunError(err error) bool {
	var response buildapiclient.HTTPError
	if errors.As(err, &response) {
		code := response.HTTPStatusCode()
		return code == 500 || code == 502 || code == 503 || code == 504 || code == http.StatusRequestTimeout || code == http.StatusTooManyRequests
	}
	var network net.Error
	return errors.As(err, &network) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}

func waitRunRetry(ctx context.Context, delay time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

const maxRunAttempts = 6

func retryRunRequest(ctx context.Context, delay time.Duration, call func() error) error {
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := call()
		if err == nil || !transientRunError(err) {
			return err
		}
		if attempt == maxRunAttempts {
			return fmt.Errorf("giving up after %d attempts: %w", attempt, err)
		}
		if err := waitRunRetry(ctx, delay); err != nil {
			return err
		}
		delay = min(delay*2, 8*time.Second)
	}
}

type runOutput struct {
	io.Writer
	err error
}

func (w *runOutput) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

func followWorkspaceRun(ctx context.Context, api runClientCall, name, id string, offset *int64, out, diagnostics io.Writer, retryDelay time.Duration) (int, error) {
	for {
		var run *buildcontract.WorkspaceRun
		var outputErr error
		err := retryRunRequest(ctx, retryDelay, func() error {
			// Rotate streams so a silent VPN black hole cannot leave Read stuck
			// forever. Successful rotations and delivered output reset retries.
			started := time.Now()
			expectedDuration := buildapiclient.DefaultWorkspaceRunStreamDuration
			streamCtx, cancel := context.WithCancelCause(ctx)
			timer := time.AfterFunc(expectedDuration+5*time.Second, func() { cancel(context.DeadlineExceeded) })
			var body *buildapiclient.WorkspaceRunLogStream
			streamErr := api(func(client *buildapiclient.Client) (err error) {
				body, err = client.WorkspaceRunLogs(streamCtx, name, id, true, *offset)
				return err
			})
			var received int64
			if streamErr == nil {
				expectedDuration = body.StreamDuration
				timer.Reset(expectedDuration + 5*time.Second)
				started = time.Now()
				if body.Offset > *offset {
					_, _ = fmt.Fprintf(diagnostics, "Run %s: log truncated; resuming at byte %d (skipped %d bytes)\n", id, body.Offset, body.Offset-*offset)
				}
				*offset = body.Offset
				output := &runOutput{Writer: out}
				received, streamErr = io.Copy(output, body)
				*offset += received
				_ = body.Close()
				outputErr = output.err
				if streamErr == nil && body.Trailers.Get("X-Log-Error") != "" {
					streamErr = fmt.Errorf("%s: %w", body.Trailers.Get("X-Log-Error"), io.ErrUnexpectedEOF)
				}
			}
			rotated := errors.Is(context.Cause(streamCtx), context.DeadlineExceeded)
			timer.Stop()
			cancel(nil)
			if outputErr != nil {
				return fmt.Errorf("writing command output: %v", outputErr)
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if streamErr != nil && !rotated && !transientRunError(streamErr) {
				return streamErr
			}
			requestCtx, cancelRequest := context.WithTimeout(ctx, 40*time.Second)
			defer cancelRequest()
			if err := api(func(client *buildapiclient.Client) (err error) {
				run, err = client.GetWorkspaceRun(requestCtx, name, id)
				return err
			}); err != nil {
				return err
			}
			if run.Terminal() && *offset >= run.LogBytes {
				return nil
			}
			// A moving tail is a normal resume, using the next response's offset
			// header. Never silently splice bytes across a truncation gap.
			if run.LogStartOffset > *offset {
				return nil
			}
			if streamErr != nil && !rotated {
				return streamErr
			}
			if received == 0 && time.Since(started) < expectedDuration {
				return io.ErrUnexpectedEOF
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
		if run.Terminal() && *offset >= run.LogBytes {
			if run.ExitCode == nil {
				return 0, fmt.Errorf("%s: %s (exit code unavailable)", run.Status, run.Message)
			}
			if run.LogsEvicted {
				_, _ = fmt.Fprintln(diagnostics, "Retained output was evicted by the workspace log budget; the command result is still available.")
			}
			if run.Message != "" {
				_, _ = fmt.Fprintln(diagnostics, run.Message)
			}
			if run.Status == "Cancelled" && *run.ExitCode == 0 {
				return 130, nil
			}
			return *run.ExitCode, nil
		}
	}
}
