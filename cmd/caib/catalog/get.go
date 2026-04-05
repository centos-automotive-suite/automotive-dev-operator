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
	"os"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Get detailed information about a catalog image",
		Long:  `Retrieve detailed information about a specific catalog image including metadata and status.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runGet,
	}

	addCommonFlags(cmd)
	return cmd
}

func runGet(cmd *cobra.Command, args []string) error {
	name := args[0]

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

	reqURL := fmt.Sprintf("%s/v1/catalog/images/%s?namespace=%s", server, name, ns)

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
			fmt.Printf("Warning: failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("catalog image %q not found in namespace %q", name, ns)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse JSON response: %w", err)
	}

	switch getOutputFormat(cmd) {
	case "json":
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	case "yaml", "yml", "table":
		output, _ := yaml.Marshal(result)
		fmt.Println(string(output))
	default:
		return fmt.Errorf("invalid output format %q (supported: table, json, yaml)", getOutputFormat(cmd))
	}

	return nil
}
