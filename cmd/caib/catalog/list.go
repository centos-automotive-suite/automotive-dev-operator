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
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	caibcommon "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/spf13/cobra"
)

const (
	listSortCreated = "created"
	listSortName    = "name"
)

var (
	listArchitecture string
	listDistro       string
	listTarget       string
	listPhase        string
	listTags         string
	listSort         string
	listLatest       bool
	listAll          bool
	listLimit        int
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List images in the catalog",
		Long: `List images in the catalog with optional filtering by architecture, distribution,
target, and phase. By default the API returns Available heads (newest per schedule,
or per distro/arch/target for unscheduled images). Use --all to list every catalog
image regardless of phase.`,
		RunE: runList,
	}

	addCommonFlags(cmd)
	cmd.Flags().StringVar(&listArchitecture, "architecture", "", "Filter by architecture (amd64, arm64)")
	cmd.Flags().StringVar(&listDistro, "distro", "", "Filter by distribution (cs9, autosd10-sig)")
	cmd.Flags().StringVar(&listTarget, "target", "", "Filter by hardware target (qemu, raspberry-pi)")
	cmd.Flags().StringVar(&listPhase, "phase", "", "Filter by phase (Available, Unavailable, Failed, all)")
	cmd.Flags().StringVar(&listTags, "tags", "", "Filter by tags (comma-separated)")
	cmd.Flags().StringVar(&listSort, "sort", listSortCreated, "Sort order: created (newest first), name")
	cmd.Flags().BoolVar(&listLatest, "latest", false, "Show only the latest image per schedule or distro/arch/target group (API default)")
	cmd.Flags().BoolVar(&listAll, "all", false, "List all catalog images (all phases, not only latest heads)")
	cmd.Flags().IntVar(&listLimit, "limit", 20, "Maximum results to show")

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
	RegistryURL      string            `json:"registryUrl"`
	Phase            string            `json:"phase"`
	Architecture     string            `json:"architecture,omitempty"`
	Distro           string            `json:"distro,omitempty"`
	Targets          []Target          `json:"targets,omitempty"`
	Digest           string            `json:"digest,omitempty"`
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
	PublishedAt      string            `json:"publishedAt,omitempty"`
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

	params, err := listQueryParams(cmd)
	if err != nil {
		return err
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

	rawFormat := getOutputFormat(cmd)
	format, fmtErr := caibcommon.ResolveOutputFormat(&rawFormat)
	if fmtErr != nil {
		return fmtErr
	}

	var renderErr error
	caibcommon.RenderFormatted(format, result, func() error {
		printTable(result.Items, listTags != "")
		return nil
	}, func(err error) { renderErr = err })
	return renderErr
}

// listQueryParams builds GET /v1/catalog/images query values from parsed flags.
// The API treats a missing `latest` as true; only send the param when --latest
// was set explicitly (or --all, which always disables latest-head filtering).
func listQueryParams(cmd *cobra.Command) (url.Values, error) {
	params := url.Values{}
	if listArchitecture != "" {
		params.Set("architecture", listArchitecture)
	}
	if listDistro != "" {
		params.Set("distro", listDistro)
	}
	if listTarget != "" {
		params.Set("target", listTarget)
	}
	if listAll {
		if listPhase != "" {
			return nil, fmt.Errorf("--all and --phase are mutually exclusive")
		}
		params.Set("phase", "all")
		params.Set("latest", "false")
	} else {
		if listPhase != "" {
			params.Set("phase", listPhase)
		}
		if cmd.Flags().Changed("latest") {
			params.Set("latest", strconv.FormatBool(listLatest))
		}
	}
	if listTags != "" {
		params.Set("tags", listTags)
	}
	if listSort != "" {
		if listSort != listSortCreated && listSort != listSortName {
			return nil, fmt.Errorf("invalid --sort value %q (supported: created, name)", listSort)
		}
		params.Set("sort", listSort)
	}
	if listLimit > 0 {
		params.Set("limit", fmt.Sprintf("%d", listLimit))
	}
	return params, nil
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

		age := caibcommon.FormatAge(catalogAgeTimestamp(img.CreatedAt, img.PublishedAt))

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

func catalogAgeTimestamp(createdAt, publishedAt string) string {
	if publishedAt != "" {
		return publishedAt
	}
	return createdAt
}
