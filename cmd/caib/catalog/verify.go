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
)

var (
	verifyWait bool
)

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <name>",
		Short: "Manually trigger verification of a catalog image",
		Long:  `Trigger verification of a catalog image to check registry accessibility and update metadata.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runVerify,
	}

	addCommonFlags(cmd)
	cmd.Flags().BoolVar(&verifyWait, "wait", true, "Wait for verification to complete")

	return cmd
}

type verifyResponse struct {
	Message   string `json:"message"`
	Triggered bool   `json:"triggered"`
}

func runVerify(cmd *cobra.Command, args []string) error {
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

	fmt.Printf("Verifying catalog image %q...\n", name)

	reqURL := fmt.Sprintf("%s/v1/catalog/images/%s/verify?namespace=%s", server, name, ns)
	req, err := http.NewRequest(http.MethodPost, reqURL, nil)
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

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result verifyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Triggered {
		fmt.Println("✓ Verification triggered successfully")
	} else {
		fmt.Printf("Note: %s\n", result.Message)
	}

	// Optionally get updated status
	if verifyWait {
		getURL := fmt.Sprintf("%s/v1/catalog/images/%s?namespace=%s", server, name, ns)
		getReq, _ := http.NewRequest(http.MethodGet, getURL, nil)
		if token != "" {
			getReq.Header.Set("Authorization", "Bearer "+token)
		}
		getResp, err := client.Do(getReq)
		if err == nil {
			defer func() {
				if err := getResp.Body.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
				}
			}()
			if getResp.StatusCode == http.StatusOK {
				getBody, _ := io.ReadAll(getResp.Body)
				var img CatalogImageResponse
				if json.Unmarshal(getBody, &img) == nil {
					fmt.Println()
					fmt.Printf("Registry URL:  %s\n", img.RegistryURL)
					fmt.Printf("Status:        %s\n", img.Phase)
					if img.SizeBytes > 0 {
						sizeMB := float64(img.SizeBytes) / (1024 * 1024)
						sizeGB := float64(img.SizeBytes) / (1024 * 1024 * 1024)
						if sizeGB >= 1 {
							fmt.Printf("Size:          %.1f GB\n", sizeGB)
						} else {
							fmt.Printf("Size:          %.1f MB\n", sizeMB)
						}
					}
				}
			}
		}
	}

	return nil
}
