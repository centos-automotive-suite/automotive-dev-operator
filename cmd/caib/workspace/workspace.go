// Package workspace implements CLI commands for developer workspace management.
package workspace

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	caibcommon "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
)

var (
	serverURL       string
	authToken       string
	insecureSkipTLS bool

	// create flags
	fromBuild        string
	leaseID          string
	architecture     string
	toolchainImage   string
	clientConfigFile string

	// resource flags
	cpuRequest    string
	memoryRequest string
	tmpfsBuildDir bool

	// wait flag (shared by create and start)
	waitForRunningFlag bool

	// deploy flags
	artifactMappings []string
)

// NewWorkspaceCmd creates the workspace command with subcommands.
func NewWorkspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workspace",
		Short: "Manage developer workspaces for application building",
		Long: `Create and manage persistent developer workspaces with cross-compilation
toolchains for building C/C++/Rust applications targeting automotive boards.

Workspaces run as pods on the cluster with a persistent volume for your source
code and build artifacts. Use sync to upload source, exec to compile, and
deploy to push binaries to a board via Jumpstarter.

Examples:
  # Create a workspace with a Jumpstarter lease from a previous build
  caib workspace create my-app --from-build my-os-build

  # Sync source, build, and deploy
  caib workspace sync my-app ./src
  caib workspace exec my-app -- make -j4
  caib workspace deploy my-app --artifact /workspace/src/build/app --dest /usr/local/bin/app`,
	}

	cmd.PersistentFlags().StringVar(&serverURL, "server", config.DefaultServer(), "REST API server base URL")
	cmd.PersistentFlags().StringVar(&authToken, "token", os.Getenv("CAIB_TOKEN"), "Bearer token for authentication")
	cmd.PersistentFlags().BoolVar(&insecureSkipTLS, "insecure-skip-tls-verify", false, "skip TLS certificate verification")

	cmd.AddCommand(
		newCreateCmd(),
		newListCmd(),
		newShowCmd(),
		newDeleteCmd(),
		newStartCmd(),
		newStopCmd(),
		newSyncCmd(),
		newExecCmd(),
		newShellCmd(),
		newDeployCmd(),
	)

	return cmd
}

func newCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new developer workspace",
		Long: `Create a persistent workspace pod with a cross-compilation toolchain.

The workspace includes gcc, g++, cargo, cmake, meson, and the Jumpstarter CLI,
all from the AutoSD-10 nightly repos to match the target board's libraries.

Examples:
  # Basic workspace
  caib workspace create my-app

  # Workspace linked to a flashed board
  caib workspace create my-app --from-build my-os-build --client ~/.config/jumpstarter/clients/myboard.yaml

  # Workspace with explicit lease and architecture
  caib workspace create my-app --lease lease-abc123 --arch amd64 --client ~/.config/jumpstarter/clients/myboard.yaml`,
		Args: cobra.ExactArgs(1),
		Run:  runCreate,
	}

	cmd.Flags().StringVar(&fromBuild, "from-build", "", "ImageBuild name to extract Jumpstarter lease from")
	cmd.Flags().StringVar(&leaseID, "lease", "", "direct Jumpstarter lease ID")
	cmd.Flags().StringVarP(&architecture, "arch", "a", "", "target architecture (default: from OperatorConfig)")
	cmd.Flags().StringVar(&toolchainImage, "image", "", "toolchain container image (default: from OperatorConfig)")
	cmd.Flags().StringVar(&clientConfigFile, "client", "", "path to Jumpstarter client config file")
	cmd.Flags().StringVar(&cpuRequest, "cpu", "", "CPU request/limit (e.g., \"1\", \"500m\")")
	cmd.Flags().StringVar(&memoryRequest, "memory", "", "memory request/limit (e.g., \"2Gi\", \"512Mi\")")
	cmd.Flags().BoolVar(&tmpfsBuildDir, "tmpfs", false, "mount a tmpfs volume at /tmp/build for faster compilation (uses RAM)")
	cmd.Flags().BoolVarP(&waitForRunningFlag, "wait", "w", true, "wait for workspace to be running")

	return cmd
}

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all workspaces",
		Run:   runList,
	}
}

func newShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show workspace details",
		Args:  cobra.ExactArgs(1),
		Run:   runShow,
	}
}

func newDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a workspace and its storage",
		Args:  cobra.ExactArgs(1),
		Run:   runDelete,
	}
}

func newStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start <name>",
		Short: "Start a stopped workspace",
		Long: `Start a previously stopped workspace by recreating its pod.
The workspace's persistent storage (source code, build cache, SSH keys) is preserved.

Examples:
  caib workspace start my-app`,
		Args: cobra.ExactArgs(1),
		Run:  runStart,
	}
	cmd.Flags().BoolVarP(&waitForRunningFlag, "wait", "w", true, "wait for workspace to be running")
	return cmd
}

func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop <name>",
		Short: "Stop a workspace without deleting its storage",
		Long: `Stop a running workspace by removing its pod while preserving the PVC.
This frees cluster CPU/memory resources while keeping all workspace data intact.
Use 'caib workspace start' to resume the workspace later.

Examples:
  caib workspace stop my-app`,
		Args: cobra.ExactArgs(1),
		Run:  runStop,
	}
}

func newSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync <name> [directory]",
		Short: "Upload local source directory to a workspace",
		Long: `Sync uploads a local directory to the workspace's /workspace/src/ path.
If no directory is specified, the current directory is used.

Examples:
  caib workspace sync my-app ./src
  caib workspace sync my-app`,
		Args: cobra.RangeArgs(1, 2),
		Run:  runSync,
	}
}

func newExecCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exec <name> -- <command...>",
		Short: "Execute a command in a workspace",
		Long: `Execute a command in the workspace pod and stream the output.

Everything after -- is passed as the command to execute inside the workspace.

Examples:
  caib workspace exec my-app -- make -j4
  caib workspace exec my-app -- cargo build --release
  caib workspace exec my-app -- ls -la /workspace/src`,
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: false,
		Run:                runExec,
	}
}

func newShellCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shell <name>",
		Short: "Open an interactive shell in a workspace",
		Long: `Open an interactive shell session in the workspace pod.

Your terminal is connected directly to the workspace container,
giving you a full shell with the cross-compilation toolchain.

Examples:
  caib workspace shell my-app`,
		Args: cobra.ExactArgs(1),
		Run:  runShell,
	}
}

func newDeployCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deploy <name>",
		Short: "Deploy artifacts from a workspace to a board via Jumpstarter",
		Long: `Deploy copies built artifacts from the workspace to the target board
using the Jumpstarter lease associated with the workspace.

Each --artifact flag takes a src:dest mapping. Both files and directories
are supported (uses rsync under the hood).

Examples:
  # Single file
  caib workspace deploy my-app --artifact /workspace/src/build/app:/usr/local/bin/app

  # Multiple files
  caib workspace deploy my-app \
    --artifact /workspace/src/engine-service:/usr/local/bin/engine-service \
    --artifact /workspace/src/radio-service:/usr/local/bin/radio-service

  # Directory (trailing slash = copy contents)
  caib workspace deploy my-app --artifact /workspace/src/build/:/usr/local/bin/`,
		Args: cobra.ExactArgs(1),
		Run:  runDeploy,
	}

	cmd.Flags().StringArrayVar(&artifactMappings, "artifact", nil, "artifact mapping src:dest (repeatable, required)")
	_ = cmd.MarkFlagRequired("artifact")

	return cmd
}

func runCreate(_ *cobra.Command, args []string) {
	requireServer()
	name := args[0]

	var clientConfigB64 string
	clientInfo, err := caibcommon.ResolveJumpstarterClient(strings.TrimSpace(clientConfigFile))
	if err == nil {
		fmt.Printf("Using Jumpstarter client %q (endpoint: %s)\n", clientInfo.Name, clientInfo.Endpoint)
		clientConfigB64 = base64.StdEncoding.EncodeToString(clientInfo.Data)
	}

	req := buildapitypes.WorkspaceRequest{
		Name:          name,
		FromBuild:     fromBuild,
		Lease:         leaseID,
		Arch:          architecture,
		Image:         toolchainImage,
		ClientConfig:  clientConfigB64,
		CPU:           cpuRequest,
		Memory:        memoryRequest,
		TmpfsBuildDir: tmpfsBuildDir,
	}

	var resp *buildapitypes.WorkspaceResponse
	err = caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, func(client *buildapiclient.Client) error {
		r, cerr := client.CreateWorkspace(context.Background(), req)
		if cerr != nil {
			return cerr
		}
		resp = r
		return nil
	})
	if err != nil {
		handleError(fmt.Errorf("failed to create workspace: %w", err))
	}

	fmt.Printf("Workspace %q created\n", resp.Name)
	fmt.Printf("  Architecture: %s\n", resp.Arch)
	if resp.Lease != "" {
		fmt.Printf("  Lease:        %s\n", resp.Lease)
	}

	if waitForRunningFlag {
		waitForRunning(resp.Name)
	} else {
		fmt.Printf("  Phase:        %s\n", resp.Phase)
	}
}

func runList(_ *cobra.Command, _ []string) {
	requireServer()

	var workspaces []buildapitypes.WorkspaceResponse
	err := caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, func(client *buildapiclient.Client) error {
		ws, cerr := client.ListWorkspaces(context.Background())
		if cerr != nil {
			return cerr
		}
		workspaces = ws
		return nil
	})
	if err != nil {
		handleError(fmt.Errorf("failed to list workspaces: %w", err))
	}

	if len(workspaces) == 0 {
		fmt.Println("No workspaces found")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tARCH\tPHASE\tLEASE\tAGE")
	for _, ws := range workspaces {
		lease := ws.Lease
		if lease == "" {
			lease = "-"
		}
		age := ws.Age
		if age == "" {
			age = "-"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", ws.Name, ws.Arch, ws.Phase, lease, age)
	}
	_ = w.Flush()
}

func runShow(_ *cobra.Command, args []string) {
	requireServer()
	name := args[0]

	var ws *buildapitypes.WorkspaceResponse
	err := caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, func(client *buildapiclient.Client) error {
		r, cerr := client.GetWorkspace(context.Background(), name)
		if cerr != nil {
			return cerr
		}
		ws = r
		return nil
	})
	if err != nil {
		handleError(fmt.Errorf("failed to get workspace: %w", err))
	}

	fmt.Printf("Name:         %s\n", ws.Name)
	fmt.Printf("Architecture: %s\n", ws.Arch)
	fmt.Printf("Phase:        %s\n", ws.Phase)
	fmt.Printf("Pod:          %s\n", ws.PodName)
	if ws.Lease != "" {
		fmt.Printf("Lease:        %s\n", ws.Lease)
	}
	if ws.Age != "" {
		fmt.Printf("Age:          %s\n", ws.Age)
	}
}

func runDelete(_ *cobra.Command, args []string) {
	requireServer()
	name := args[0]

	err := caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, func(client *buildapiclient.Client) error {
		return client.DeleteWorkspace(context.Background(), name)
	})
	if err != nil {
		handleError(fmt.Errorf("failed to delete workspace: %w", err))
	}

	fmt.Printf("Workspace %q deleted\n", name)
}

func runStart(_ *cobra.Command, args []string) {
	requireServer()
	name := args[0]

	var resp *buildapitypes.WorkspaceResponse
	err := caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, func(client *buildapiclient.Client) error {
		r, cerr := client.StartWorkspace(context.Background(), name)
		if cerr != nil {
			return cerr
		}
		resp = r
		return nil
	})
	if err != nil {
		handleError(fmt.Errorf("failed to start workspace: %w", err))
	}

	if waitForRunningFlag {
		fmt.Printf("Workspace %q starting...\n", resp.Name)
		waitForRunning(resp.Name)
	} else {
		fmt.Printf("Workspace %q starting (phase: %s)\n", resp.Name, resp.Phase)
	}
}

func runStop(_ *cobra.Command, args []string) {
	requireServer()
	name := args[0]

	var resp *buildapitypes.WorkspaceResponse
	err := caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, func(client *buildapiclient.Client) error {
		r, cerr := client.StopWorkspace(context.Background(), name)
		if cerr != nil {
			return cerr
		}
		resp = r
		return nil
	})
	if err != nil {
		handleError(fmt.Errorf("failed to stop workspace: %w", err))
	}

	fmt.Printf("Workspace %q stopped (storage preserved)\n", resp.Name)
}

func runSync(_ *cobra.Command, args []string) {
	requireServer()
	name := args[0]

	srcDir := "."
	if len(args) > 1 {
		srcDir = args[1]
	}

	absDir, err := filepath.Abs(srcDir)
	if err != nil {
		handleError(fmt.Errorf("invalid directory: %w", err))
	}
	info, err := os.Stat(absDir)
	if err != nil || !info.IsDir() {
		handleError(fmt.Errorf("source directory does not exist or is not a directory: %s", absDir))
	}

	files, err := gitTrackedFiles(absDir)
	if err != nil {
		handleError(fmt.Errorf("failed to list git-tracked files: %w", err))
	}
	if len(files) == 0 {
		handleError(fmt.Errorf("no git-tracked files found in %s", absDir))
	}

	manifest := computeManifest(absDir, files)
	planReq := buildapitypes.SyncPlanRequest{Files: manifest}

	var plan *buildapitypes.SyncPlanResponse
	err = caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, func(client *buildapiclient.Client) error {
		p, cerr := client.SyncPlan(context.Background(), name, planReq)
		if cerr != nil {
			return cerr
		}
		plan = p
		return nil
	})
	if err != nil {
		// Fall back to full sync — warn so users know why delta didn't work
		fmt.Fprintf(os.Stderr, "Warning: sync plan unavailable (%v), uploading all files\n", err)
		fmt.Printf("Syncing %d tracked files to workspace %q...\n", len(files), name)
		uploadFiles(name, absDir, files)
		return
	}

	if len(plan.Changed) == 0 {
		fmt.Printf("Workspace %q is up to date (%d files)\n", name, plan.Unchanged)
		return
	}

	fmt.Printf("Syncing %d changed files to workspace %q (%d unchanged)...\n",
		len(plan.Changed), name, plan.Unchanged)
	uploadFiles(name, absDir, plan.Changed)
}

func uploadFiles(name, absDir string, files []string) {
	var buf bytes.Buffer
	if err := tarTrackedFiles(absDir, files, &buf); err != nil {
		handleError(fmt.Errorf("failed to create tar archive: %w", err))
	}

	totalBytes := int64(buf.Len())
	pr := newProgressReader(&buf, totalBytes)

	err := caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, func(client *buildapiclient.Client) error {
		return client.SyncWorkspace(context.Background(), name, pr)
	})
	pr.finish()
	if err != nil {
		handleError(fmt.Errorf("failed to sync workspace: %w", err))
	}
	fmt.Println("Files synced")
}

func computeManifest(baseDir string, files []string) map[string]string {
	manifest := make(map[string]string, len(files))
	for _, relPath := range files {
		absPath := filepath.Join(baseDir, relPath)
		f, err := os.Open(absPath)
		if err != nil {
			continue // file may have been deleted since ls-files
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			continue
		}
		manifest[relPath] = hex.EncodeToString(h.Sum(nil))
	}
	return manifest
}

// gitTrackedFiles returns the list of git-tracked files relative to dir.
func gitTrackedFiles(dir string) ([]string, error) {
	cmd := exec.Command("git", "ls-files", "--cached", "--exclude-standard")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files failed (is this a git repo?): %w", err)
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

// tarTrackedFiles writes a tar archive of the given files (relative to baseDir) to w.
func tarTrackedFiles(baseDir string, files []string, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer func() { _ = tw.Close() }()

	for _, relPath := range files {
		absPath := filepath.Join(baseDir, relPath)
		fi, err := os.Lstat(absPath)
		if err != nil {
			continue // file may have been deleted since ls-files
		}

		var linkTarget string
		if fi.Mode()&os.ModeSymlink != 0 {
			linkTarget, err = os.Readlink(absPath)
			if err != nil {
				return fmt.Errorf("reading symlink %s: %w", relPath, err)
			}
		} else if !fi.Mode().IsRegular() {
			continue
		}

		hdr, err := tar.FileInfoHeader(fi, linkTarget)
		if err != nil {
			return fmt.Errorf("creating tar header for %s: %w", relPath, err)
		}
		hdr.Name = relPath

		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("writing tar header for %s: %w", relPath, err)
		}

		if fi.Mode().IsRegular() {
			f, err := os.Open(absPath)
			if err != nil {
				return fmt.Errorf("opening %s: %w", relPath, err)
			}
			_, err = io.Copy(tw, f)
			_ = f.Close()
			if err != nil {
				return fmt.Errorf("writing %s to tar: %w", relPath, err)
			}
		}
	}

	return nil
}

func runExec(_ *cobra.Command, args []string) {
	requireServer()
	name := args[0]

	// Everything after the workspace name (or after --) is the command
	cmdParts := args[1:]
	if len(cmdParts) == 0 {
		handleError(fmt.Errorf("no command specified; use: caib workspace exec <name> -- <command>"))
	}
	command := strings.Join(cmdParts, " ")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	req := buildapitypes.WorkspaceExecRequest{Command: command}

	var body io.ReadCloser
	err := caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, func(client *buildapiclient.Client) error {
		r, cerr := client.ExecWorkspace(ctx, name, req)
		if cerr != nil {
			return cerr
		}
		body = r
		return nil
	})
	if err != nil {
		handleError(fmt.Errorf("exec failed: %w", err))
	}
	defer func() { _ = body.Close() }()

	streamToStdout(body)
}

func runShell(_ *cobra.Command, args []string) {
	requireServer()
	name := args[0]

	// Set terminal to raw mode
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		handleError(fmt.Errorf("stdin is not a terminal"))
	}
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		handleError(fmt.Errorf("failed to set raw terminal: %w", err))
	}
	defer func() { _ = term.Restore(fd, oldState) }()

	// Restore terminal on signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		_ = term.Restore(fd, oldState)
		os.Exit(0)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ws *websocket.Conn
	err = caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, func(client *buildapiclient.Client) error {
		conn, cerr := client.ShellWorkspace(ctx, name)
		if cerr != nil {
			return cerr
		}
		ws = conn
		return nil
	})
	if err != nil {
		_ = term.Restore(fd, oldState)
		handleError(fmt.Errorf("shell failed: %w", err))
	}
	defer func() { _ = ws.Close() }()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, rerr := os.Stdin.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				_ = ws.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}
		}
	}()

	for {
		_, msg, rerr := ws.ReadMessage()
		if rerr != nil {
			if closeErr, ok := rerr.(*websocket.CloseError); ok && closeErr.Code != websocket.CloseNormalClosure {
				_ = term.Restore(fd, oldState)
				fmt.Fprintf(os.Stderr, "shell error: %s\n", closeErr.Text)
			}
			return
		}
		_, _ = os.Stdout.Write(msg)
	}
}

func runDeploy(_ *cobra.Command, args []string) {
	requireServer()
	name := args[0]

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	artifacts := make([]buildapitypes.ArtifactMapping, 0, len(artifactMappings))
	for _, m := range artifactMappings {
		parts := strings.SplitN(m, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			handleError(fmt.Errorf("invalid artifact mapping %q: expected src:dest", m))
		}
		artifacts = append(artifacts, buildapitypes.ArtifactMapping{Src: parts[0], Dest: parts[1]})
	}

	req := buildapitypes.WorkspaceDeployRequest{
		Artifacts: artifacts,
	}

	if len(artifacts) == 1 {
		fmt.Printf("Deploying %s -> %s\n", artifacts[0].Src, artifacts[0].Dest)
	} else {
		fmt.Printf("Deploying %d artifacts to board...\n", len(artifacts))
	}

	var body io.ReadCloser
	err := caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, func(client *buildapiclient.Client) error {
		r, cerr := client.DeployWorkspace(ctx, name, req)
		if cerr != nil {
			return cerr
		}
		body = r
		return nil
	})
	if err != nil {
		handleError(fmt.Errorf("deploy failed: %w", err))
	}
	defer func() { _ = body.Close() }()

	streamToStdout(body)
}

func waitForRunning(name string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	timeout := time.After(5 * time.Minute)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	isTTY := term.IsTerminal(int(os.Stdout.Fd()))
	lastPhase := ""

	for {
		select {
		case <-ctx.Done():
			fmt.Println()
			return
		case <-timeout:
			fmt.Println()
			handleError(fmt.Errorf("timed out waiting for workspace %q to be running", name))
		case <-ticker.C:
			var ws *buildapitypes.WorkspaceResponse
			err := caibcommon.ExecuteWithReauth(serverURL, &authToken, insecureSkipTLS, func(client *buildapiclient.Client) error {
				r, cerr := client.GetWorkspace(ctx, name)
				if cerr != nil {
					return cerr
				}
				ws = r
				return nil
			})
			if err != nil {
				continue // transient error, retry
			}

			if ws.Phase != lastPhase {
				lastPhase = ws.Phase
				if isTTY {
					fmt.Printf("\r  Phase:        %-20s", ws.Phase)
				} else {
					fmt.Printf("  Phase: %s\n", ws.Phase)
				}
			}

			switch ws.Phase {
			case "Running":
				if isTTY {
					fmt.Println()
				}
				return
			case "Failed":
				if isTTY {
					fmt.Println()
				}
				handleError(fmt.Errorf("workspace %q failed", name))
			}
		}
	}
}

func requireServer() {
	if serverURL == "" {
		handleError(fmt.Errorf("--server is required (or set CAIB_SERVER, or run 'caib login <server-url>')"))
	}
}

func handleError(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

func streamToStdout(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "stream error: %v\n", err)
	}
}

// progressReader wraps an io.Reader and renders an upload progress bar
// using the same visual style as the build progress bar (█░).
type progressReader struct {
	r     io.Reader
	total int64
	read  int64
	last  int // last printed percentage
	isTTY bool
}

func newProgressReader(r io.Reader, total int64) *progressReader {
	return &progressReader{
		r:     r,
		total: total,
		isTTY: term.IsTerminal(int(os.Stdout.Fd())),
		last:  -1,
	}
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	if p.total > 0 {
		pct := int(p.read * 100 / p.total)
		if pct != p.last {
			p.last = pct
			p.render(pct)
		}
	}
	return n, err
}

func (p *progressReader) render(pct int) {
	barWidth := 30
	filled := barWidth * pct / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	sizeInfo := fmt.Sprintf("%s / %s", humanSize(p.read), humanSize(p.total))
	if p.isTTY {
		_, _ = fmt.Fprintf(os.Stdout, "\r  Upload   │%s│ %3d%% %s", bar, pct, sizeInfo)
	} else if pct%25 == 0 || pct == 100 {
		_, _ = fmt.Fprintf(os.Stdout, "  Upload: %d%% %s\n", pct, sizeInfo)
	}
}

func (p *progressReader) finish() {
	if p.total > 0 && p.isTTY {
		_, _ = fmt.Fprintln(os.Stdout)
	}
}

func humanSize(b int64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
