/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package catalog

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	listArchitecture  string
	listDistro        string
	listTarget        string
	listPhase         string
	listTags          string
	listSort          string
	listLatest        bool
	listLimit         int
	listAllNamespaces bool
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List images in the catalog",
		Long: `List images in the catalog with optional filtering by architecture, distribution,
target, and phase. Use --latest to show only the newest image per schedule
(or per distro/arch/target group for non-scheduled images).`,
		RunE: runList,
	}

	addCommonFlags(cmd)
	cmd.Flags().StringVar(&listArchitecture, "architecture", "", "Filter by architecture (amd64, arm64)")
	cmd.Flags().StringVar(&listDistro, "distro", "", "Filter by distribution (cs9, autosd10-sig)")
	cmd.Flags().StringVar(&listTarget, "target", "", "Filter by hardware target (qemu, raspberry-pi)")
	cmd.Flags().StringVar(&listPhase, "phase", "", "Filter by phase (Available, Unavailable, etc)")
	cmd.Flags().StringVar(&listTags, "tags", "", "Filter by tags (comma-separated)")
	cmd.Flags().StringVar(&listSort, "sort", "created", "Sort order: created (newest first), name")
	cmd.Flags().BoolVar(&listLatest, "latest", false, "Show only the latest image per schedule or distro/arch/target group")
	cmd.Flags().IntVar(&listLimit, "limit", 20, "Maximum results to show")
	cmd.Flags().BoolVar(&listAllNamespaces, "all-namespaces", false, "List images across all namespaces")

	return cmd
}

// CatalogImageListResponse mirrors the API response
//
//nolint:revive // Name intentionally includes package name for clarity in CLI context
type CatalogImageListResponse struct {
	Items    []CatalogImageResponse `json:"items"`
	Total    int                    `json:"total"`
	Continue string                 `json:"continue,omitempty"`
}

// CatalogImageResponse mirrors the API response
//
//nolint:revive // Name intentionally includes package name for clarity in CLI context
type CatalogImageResponse struct {
	Name             string            `json:"name"`
	Namespace        string            `json:"namespace"`
	RegistryURL      string            `json:"registryUrl"`
	Phase            string            `json:"phase"`
	Architecture     string            `json:"architecture,omitempty"`
	Distro           string            `json:"distro,omitempty"`
	Targets          []Target          `json:"targets,omitempty"`
	Tags             []string          `json:"tags,omitempty"`
	SourceType       string            `json:"sourceType,omitempty"`
	SourceImageBuild string            `json:"sourceImageBuild,omitempty"`
	ScheduleName     string            `json:"scheduleName,omitempty"`
	BuildMode        string            `json:"buildMode,omitempty"`
	ExportFormat     string            `json:"exportFormat,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	SizeBytes        int64             `json:"sizeBytes,omitempty"`
	DownloadURL      string            `json:"downloadUrl,omitempty"`
	CreatedAt        string            `json:"createdAt"`
	StatusReason     string            `json:"statusReason,omitempty"`
	StatusMessage    string            `json:"statusMessage,omitempty"`
}

// Target mirrors target info from API
type Target struct {
	Name string `json:"name"`
}

func runList(cmd *cobra.Command, _ []string) error {
	// Get server URL
	server := serverURL
	if server == "" {
		server = config.DefaultServerWithDerive()
	}
	if server == "" {
		return fmt.Errorf("server URL required (use --server, CAIB_SERVER, run 'caib login <server-url>' or 'jmp login <endpoint>')")
	}

	// Get auth token
	token := authToken
	if token == "" {
		token = os.Getenv("CAIB_TOKEN")
	}

	// Build query parameters
	params := url.Values{}
	if namespace != "" && !listAllNamespaces {
		params.Set("namespace", namespace)
	}
	if listArchitecture != "" {
		params.Set("architecture", listArchitecture)
	}
	if listDistro != "" {
		params.Set("distro", listDistro)
	}
	if listTarget != "" {
		params.Set("target", listTarget)
	}
	if listPhase != "" {
		params.Set("phase", listPhase)
	}
	if listTags != "" {
		params.Set("tags", listTags)
	}
	if listSort != "" {
		if listSort != "created" && listSort != "name" {
			return fmt.Errorf("invalid --sort value %q (supported: created, name)", listSort)
		}
		params.Set("sort", listSort)
	}
	if listLatest {
		params.Set("latest", "true")
	}
	if listLimit > 0 {
		params.Set("limit", fmt.Sprintf("%d", listLimit))
	}

	// Make request
	reqURL := fmt.Sprintf("%s/v1/catalog/images", server)
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := newHTTPClient(getInsecureSkipTLS(cmd))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var result CatalogImageListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Output in requested format
	format := strings.ToLower(strings.TrimSpace(getOutputFormat(cmd)))
	switch format {
	case "json":
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	case "yaml", "yml":
		output, _ := yaml.Marshal(result)
		fmt.Println(string(output))
	case outputFormatTable:
		printTable(result.Items, listTags != "")
	default:
		return fmt.Errorf("invalid output format %q (supported: table, json, yaml)", format)
	}

	return nil
}

func printTable(items []CatalogImageResponse, tagsFiltered bool) {
	if len(items) == 0 {
		fmt.Println("No catalog images found")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() {
		if err := w.Flush(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to flush output: %v\n", err)
		}
	}()

	header := "NAME\tSCHEDULE\tARCH\tDISTRO\tTARGET\tFORMAT\tPHASE\tAGE\tIMAGE"
	if !tagsFiltered {
		header = "NAME\tSCHEDULE\tARCH\tDISTRO\tTARGET\tFORMAT\tTAGS\tPHASE\tAGE\tIMAGE"
	}

	if _, err := fmt.Fprintln(w, header); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write header: %v\n", err)
		return
	}

	for _, img := range items {
		target := ""
		if len(img.Targets) > 0 {
			target = img.Targets[0].Name
		}

		age := formatAge(img.CreatedAt)

		if tagsFiltered {
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				img.Name,
				img.ScheduleName,
				img.Architecture,
				img.Distro,
				target,
				img.ExportFormat,
				img.Phase,
				age,
				img.RegistryURL,
			); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to write row: %v\n", err)
			}
		} else {
			tags := strings.Join(img.Tags, ",")
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				img.Name,
				img.ScheduleName,
				img.Architecture,
				img.Distro,
				target,
				img.ExportFormat,
				tags,
				img.Phase,
				age,
				img.RegistryURL,
			); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to write row: %v\n", err)
			}
		}
	}

	_, _ = fmt.Fprintf(w, "\n")
	_, _ = fmt.Fprintf(os.Stderr, "%d image(s)\n", len(items))
}

// formatAge converts an RFC3339 timestamp to a human-readable relative duration.
func formatAge(timestamp string) string {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return timestamp
	}

	d := time.Since(t)
	if d < 0 {
		return "future"
	}

	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%dd", int(math.Floor(d.Hours()/24)))
	default:
		months := int(math.Floor(d.Hours() / (24 * 30)))
		if months < 12 {
			return fmt.Sprintf("%dmo", months)
		}
		return fmt.Sprintf("%dy", int(math.Floor(d.Hours()/(24*365))))
	}
}
