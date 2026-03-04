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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/spf13/cobra"
)

var (
	publishCatalogName string
	publishTags        []string
	publishWait        bool
)

func newPublishCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "publish <imagebuild-name>",
		Short: "Publish a completed ImageBuild to the catalog",
		Long:  `Promote a completed ImageBuild to the catalog, making it discoverable for deployment.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runPublish,
	}

	addCommonFlags(cmd)
	cmd.Flags().StringVar(&publishCatalogName, "catalog-name", "", "Name for catalog image (default: ImageBuild name)")
	cmd.Flags().StringArrayVar(&publishTags, "tags", nil, "Tags to apply (can be used multiple times)")
	cmd.Flags().BoolVar(&publishWait, "wait", true, "Wait for publishing to complete")

	return cmd
}

type publishRequest struct {
	ImageBuildName      string   `json:"imageBuildName"`
	ImageBuildNamespace string   `json:"imageBuildNamespace"`
	CatalogImageName    string   `json:"catalogImageName,omitempty"`
	Tags                []string `json:"tags,omitempty"`
}

func runPublish(cmd *cobra.Command, args []string) error {
	imageBuildName := args[0]

	server := serverURL
	if server == "" {
		server = config.DefaultServerWithDerive()
	}
	if server == "" {
		return fmt.Errorf("server URL required (use --server, CAIB_SERVER, run 'caib login <server-url>' or 'jmp login <endpoint>')")
	}

	token := authToken
	if token == "" {
		token = os.Getenv("CAIB_TOKEN")
	}

	ns := namespace
	if ns == "" {
		ns = defaultNamespace
	}

	fmt.Printf("Publishing ImageBuild %q to catalog...\n", imageBuildName)

	reqBody := publishRequest{
		ImageBuildName:      imageBuildName,
		ImageBuildNamespace: ns,
		CatalogImageName:    publishCatalogName,
		Tags:                publishTags,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	reqURL := fmt.Sprintf("%s/v1/catalog/publish", server)
	req, err := http.NewRequest(http.MethodPost, reqURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
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

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("ImageBuild %q not found in namespace %q", imageBuildName, ns)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result CatalogImageResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Println("✓ Published successfully")
	fmt.Println()
	fmt.Printf("Catalog Image: %s\n", result.Name)
	fmt.Printf("Registry URL:  %s\n", result.RegistryURL)
	fmt.Printf("Architecture:  %s\n", result.Architecture)
	fmt.Printf("Distro:        %s\n", result.Distro)
	if len(result.Targets) > 0 {
		fmt.Printf("Target:        %s\n", result.Targets[0].Name)
	}
	fmt.Printf("Status:        %s\n", result.Phase)

	return nil
}
