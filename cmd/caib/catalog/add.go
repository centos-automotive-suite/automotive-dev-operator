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

// Package catalog provides commands for managing the automotive OS image catalog.
// It includes operations for adding, listing, retrieving, publishing, removing, and verifying catalog images.
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
	addArchitecture  string
	addDistro        string
	addDistroVersion string
	addTargets       []string
	addTags          []string
	addDigest        string
	addAuthSecret    string
	addBootc         bool
)

func newAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <name> <registry-url>",
		Short: "Add an external image to the catalog",
		Long:  `Add an external image from a container registry to the catalog.`,
		Args:  cobra.ExactArgs(2),
		RunE:  runAdd,
	}

	addCommonFlags(cmd)
	cmd.Flags().StringVar(&addArchitecture, "architecture", "", "Image architecture (amd64, arm64)")
	cmd.Flags().StringVar(&addDistro, "distro", "", "Distribution identifier")
	cmd.Flags().StringVar(&addDistroVersion, "distro-version", "", "Distribution version")
	cmd.Flags().StringArrayVar(&addTargets, "target", nil, "Hardware targets (can be used multiple times)")
	cmd.Flags().StringArrayVar(&addTags, "tags", nil, "Tags to apply (can be used multiple times)")
	cmd.Flags().StringVar(&addDigest, "digest", "", "Specific digest to reference")
	cmd.Flags().StringVar(&addAuthSecret, "auth-secret", "", "Secret containing registry credentials")
	cmd.Flags().BoolVar(&addBootc, "bootc", false, "Mark as bootc-compatible")

	if err := cmd.MarkFlagRequired("architecture"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to mark required flag 'architecture': %v\n", err)
		os.Exit(1)
	}
	if err := cmd.MarkFlagRequired("distro"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to mark required flag 'distro': %v\n", err)
		os.Exit(1)
	}

	return cmd
}

type createRequest struct {
	Name           string       `json:"name"`
	RegistryURL    string       `json:"registryUrl"`
	Digest         string       `json:"digest,omitempty"`
	Tags           []string     `json:"tags,omitempty"`
	AuthSecretName string       `json:"authSecretName,omitempty"`
	Architecture   string       `json:"architecture,omitempty"`
	Distro         string       `json:"distro,omitempty"`
	DistroVersion  string       `json:"distroVersion,omitempty"`
	Targets        []targetInfo `json:"targets,omitempty"`
	Bootc          bool         `json:"bootc"`
}

type targetInfo struct {
	Name     string `json:"name"`
	Verified bool   `json:"verified"`
}

func runAdd(cmd *cobra.Command, args []string) error {
	name := args[0]
	registryURL := args[1]

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

	fmt.Printf("Adding image to catalog...\n")
	fmt.Printf("✓ Validating registry URL\n")

	reqBody := createRequest{
		Name:           name,
		RegistryURL:    registryURL,
		Digest:         addDigest,
		Tags:           addTags,
		AuthSecretName: addAuthSecret,
		Architecture:   addArchitecture,
		Distro:         addDistro,
		DistroVersion:  addDistroVersion,
		Bootc:          addBootc,
	}

	for _, t := range addTargets {
		reqBody.Targets = append(reqBody.Targets, targetInfo{Name: t, Verified: false})
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	reqURL := fmt.Sprintf("%s/v1/catalog/images?namespace=%s", server, ns)
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
			fmt.Printf("Warning: failed to close response body: %v\n", err)
		}
	}()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("image with this registry URL already exists in catalog")
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result CatalogImageResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("✓ Creating catalog image %q\n", name)
	fmt.Println("✓ Added successfully")
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
