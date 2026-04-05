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
	"crypto/tls"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

const (
	defaultNamespace  = "default"
	outputFormatTable = "table"
)

var (
	serverURL string
	authToken string
	namespace string
)

// NewCatalogCmd creates the catalog command with subcommands
func NewCatalogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Manage the automotive OS image catalog",
		Long:  `Commands for browsing, publishing, and managing images in the catalog.`,
	}

	// Add subcommands
	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newGetCmd())
	cmd.AddCommand(newPublishCmd())
	cmd.AddCommand(newAddCmd())
	cmd.AddCommand(newRemoveCmd())
	cmd.AddCommand(newVerifyCmd())

	return cmd
}

// addCommonFlags adds common flags to catalog subcommands
func addCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&serverURL, "server", "", "REST API server base URL (env: CAIB_SERVER)")
	cmd.Flags().StringVar(&authToken, "token", "", "Bearer token for authentication (env: CAIB_TOKEN)")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Kubernetes namespace")
}

// getOutputFormat returns the output format from the root command's --output-format flag.
func getOutputFormat(cmd *cobra.Command) string {
	if cmd.Root() != nil {
		if flag := cmd.Root().PersistentFlags().Lookup("output-format"); flag != nil {
			return flag.Value.String()
		}
	}
	return outputFormatTable
}

// getInsecureSkipTLS returns whether to skip TLS verification
// Checks the --insecure flag from the root command or CAIB_INSECURE env var
func getInsecureSkipTLS(cmd *cobra.Command) bool {
	// Try to get from root command's persistent flag
	if cmd.Root() != nil {
		if flag := cmd.Root().PersistentFlags().Lookup("insecure"); flag != nil {
			if val, err := strconv.ParseBool(flag.Value.String()); err == nil {
				return val
			}
		}
	}
	// Fall back to env var
	return envBool("CAIB_INSECURE")
}

// envBool parses a boolean from environment variable
func envBool(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

// newHTTPClient creates an HTTP client with optional insecure TLS
func newHTTPClient(insecureSkipTLS bool) *http.Client {
	if insecureSkipTLS {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	return &http.Client{}
}
