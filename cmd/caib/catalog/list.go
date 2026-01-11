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
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	listArchitecture  string
	listDistro        string
	listTarget        string
	listPhase         string
	listTags          string
	listLimit         int
	listAllNamespaces bool
)

func newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List images in the catalog",
		Long:  `List images in the catalog with optional filtering by architecture, distribution, target, and phase.`,
		RunE:  runList,
	}

	addCommonFlags(cmd)
	cmd.Flags().StringVar(&listArchitecture, "architecture", "", "Filter by architecture (amd64, arm64)")
	cmd.Flags().StringVar(&listDistro, "distro", "", "Filter by distribution (autosd, autosd10-sig)")
	cmd.Flags().StringVar(&listTarget, "target", "", "Filter by hardware target (qemu, raspberry-pi)")
	cmd.Flags().StringVar(&listPhase, "phase", "", "Filter by phase (Available, Unavailable, etc)")
	cmd.Flags().StringVar(&listTags, "tags", "", "Filter by tags (comma-separated)")
	cmd.Flags().IntVar(&listLimit, "limit", 20, "Maximum results to show")
	cmd.Flags().BoolVar(&listAllNamespaces, "all-namespaces", false, "List images across all namespaces")

	return cmd
}

// CatalogImageListResponse mirrors the API response
type CatalogImageListResponse struct {
	Items    []CatalogImageResponse `json:"items"`
	Total    int                    `json:"total"`
	Continue string                 `json:"continue,omitempty"`
}

// CatalogImageResponse mirrors the API response
type CatalogImageResponse struct {
	Name         string   `json:"name"`
	Namespace    string   `json:"namespace"`
	RegistryURL  string   `json:"registryUrl"`
	Phase        string   `json:"phase"`
	Architecture string   `json:"architecture,omitempty"`
	Distro       string   `json:"distro,omitempty"`
	Targets      []Target `json:"targets,omitempty"`
	SizeBytes    int64    `json:"sizeBytes,omitempty"`
	CreatedAt    string   `json:"createdAt"`
}

// Target mirrors target info from API
type Target struct {
	Name string `json:"name"`
}

func runList(cmd *cobra.Command, args []string) error {
	// Get server URL
	server := serverURL
	if server == "" {
		server = os.Getenv("CAIB_SERVER")
	}
	if server == "" {
		return fmt.Errorf("server URL required (use --server or CAIB_SERVER env var)")
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

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

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
	switch outputFormat {
	case "json":
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	case "yaml":
		output, _ := yaml.Marshal(result)
		fmt.Println(string(output))
	default:
		printTable(result.Items)
	}

	return nil
}

func printTable(items []CatalogImageResponse) {
	if len(items) == 0 {
		fmt.Println("No catalog images found")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tREGISTRY\tARCHITECTURE\tDISTRO\tTARGET\tPHASE\tAGE")

	for _, img := range items {
		target := ""
		if len(img.Targets) > 0 {
			target = img.Targets[0].Name
		}

		// Truncate registry URL for display
		registryDisplay := img.RegistryURL
		if len(registryDisplay) > 50 {
			registryDisplay = registryDisplay[:47] + "..."
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			img.Name,
			registryDisplay,
			img.Architecture,
			img.Distro,
			target,
			img.Phase,
			img.CreatedAt,
		)
	}
	w.Flush()
}
