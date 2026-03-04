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
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/spf13/cobra"
)

var (
	removeForce bool
)

func newRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an image from the catalog",
		Long:  `Remove an image from the catalog. This does not delete the image from the registry.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runRemove,
	}

	addCommonFlags(cmd)
	cmd.Flags().BoolVar(&removeForce, "force", false, "Skip confirmation prompt")

	return cmd
}

func runRemove(cmd *cobra.Command, args []string) error {
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

	// Confirm deletion
	if !removeForce {
		fmt.Printf("Removing catalog image %q...\n", name)
		fmt.Print("Are you sure you want to remove this image from the catalog? (y/N): ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Cancelled")
			return nil
		}
	}

	reqURL := fmt.Sprintf("%s/v1/catalog/images/%s?namespace=%s", server, name, ns)
	req, err := http.NewRequest(http.MethodDelete, reqURL, nil)
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

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("catalog image %q not found in namespace %q", name, ns)
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Println("✓ Removed successfully")
	return nil
}
