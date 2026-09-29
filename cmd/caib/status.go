package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	caibcommon "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	statusReachable     = "reachable"
	statusNotConfigured = "not configured"
	sourceCAIBEnv       = "CAIB_SERVER env"
)

func newStatusCmd(insecure *bool) *cobra.Command {
	format := "table"
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
		Run: func(_ *cobra.Command, _ []string) { runStatus(format, *insecure) },
	}
	cmd.Flags().StringVarP(&format, "output", "o", "table", "output format: table, json, yaml")
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

func runStatus(outputFormat string, insecure bool) {
	format, err := caibcommon.ResolveOutputFormat(&outputFormat)
	if err != nil {
		handleError(err)
		return
	}

	info := gatherStatus(insecure)
	caibcommon.RenderFormatted(format, info, func() error {
		printStatusTable(info)
		return nil
	}, handleError)
}

func gatherStatus(insecure bool) statusInfo {
	var info statusInfo

	info.Server.URL, info.Server.Source = resolveServerWithSource()

	if info.Server.URL != "" {
		info.Server.Status = checkServerHealth(info.Server.URL, insecure)
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
			if !config.IsDerivedAndStale(cfg) {
				return s, "saved config (~/.config/caib/cli.json)"
			}
		}
	}

	if s := config.DeriveServerFromJumpstarter(); s != "" {
		return s, "derived from Jumpstarter"
	}

	return "", ""
}

func checkServerHealth(serverURL string, insecure bool) string {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}, //nolint:gosec
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
