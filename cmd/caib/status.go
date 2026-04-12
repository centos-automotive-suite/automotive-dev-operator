package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	statusReachable     = "reachable"
	statusNotConfigured = "not configured"
	sourceCAIBEnv       = "CAIB_SERVER env"
)

var statusOutputFormat string

func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show which Build API server builds will run on",
		Long: `Display which Build API server caib is configured to use.

Shows the resolved server URL (from CAIB_SERVER env, saved config, or Jumpstarter
derivation) and whether the server is reachable.

Examples:
  caib status
  caib status -o json
  caib status -o yaml`,
		Run: runStatus,
	}
	cmd.Flags().StringVarP(&statusOutputFormat, "output", "o", "table", "output format: table, json, yaml")
	return cmd
}

type statusInfo struct {
	Server serverInfo `json:"server" yaml:"server"`
}

type serverInfo struct {
	URL    string `json:"url" yaml:"url"`
	Source string `json:"source" yaml:"source"`
	Status string `json:"status" yaml:"status"`
}

func runStatus(_ *cobra.Command, _ []string) {
	info := gatherStatus()

	switch strings.ToLower(statusOutputFormat) {
	case "json":
		out, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			handleError(fmt.Errorf("error rendering JSON: %w", err))
			return
		}
		fmt.Println(string(out))
	case "yaml", "yml":
		out, err := yaml.Marshal(info)
		if err != nil {
			handleError(fmt.Errorf("error rendering YAML: %w", err))
			return
		}
		fmt.Print(string(out))
	case "table":
		printStatusTable(info)
	default:
		handleError(fmt.Errorf("invalid output format %q (supported: table, json, yaml)", statusOutputFormat))
	}
}

func gatherStatus() statusInfo {
	var info statusInfo

	info.Server.URL, info.Server.Source = resolveServerWithSource()

	if info.Server.URL != "" {
		info.Server.Status = checkServerHealth(info.Server.URL)
	} else {
		info.Server.Status = statusNotConfigured
	}

	return info
}

// resolveServerWithSource returns the effective server URL and a human-readable source label.
func resolveServerWithSource() (string, string) {
	if s := strings.TrimSpace(os.Getenv("CAIB_SERVER")); s != "" {
		return s, sourceCAIBEnv
	}

	cfg, err := config.Read()
	if err == nil && cfg != nil {
		if s := strings.TrimSpace(cfg.ServerURL); s != "" {
			return s, "saved config (~/.config/caib/cli.json)"
		}
	}

	if s := config.DeriveServerFromJumpstarter(); s != "" {
		return s, "derived from Jumpstarter"
	}

	return "", ""
}

func checkServerHealth(serverURL string) string {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipTLS, MinVersion: tls.VersionTLS12}, //nolint:gosec
		},
	}

	resp, err := client.Get(serverURL + "/v1/healthz")
	if err != nil {
		return fmt.Sprintf("unreachable (%v)", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		return statusReachable
	}
	return fmt.Sprintf("unhealthy (HTTP %d)", resp.StatusCode)
}

func printStatusTable(info statusInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() {
		if err := w.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to flush output: %v\n", err)
		}
	}()

	writeRows(w, [][2]string{
		{"Server", valueOrNone(info.Server.URL)},
		{"Source", valueOrNone(info.Server.Source)},
	})
	printServerStatus(w, info.Server.Status)
}

func writeRows(w *tabwriter.Writer, rows [][2]string) {
	for _, r := range rows {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", r[0], r[1]); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to write output: %v\n", err)
			return
		}
	}
}

func printServerStatus(w *tabwriter.Writer, status string) {
	var colored string
	switch {
	case status == statusReachable:
		colored = color.GreenString(status)
	case strings.HasPrefix(status, "unreachable"):
		colored = color.RedString(status)
	default:
		colored = color.YellowString(status)
	}
	if _, err := fmt.Fprintf(w, "Status\t%s\n", colored); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write output: %v\n", err)
	}
}

func valueOrNone(v string) string {
	if strings.TrimSpace(v) == "" {
		return color.YellowString("not configured")
	}
	return v
}
