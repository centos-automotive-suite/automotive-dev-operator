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

package container

import (
	"strconv"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/spf13/cobra"
)

// NewContainerCmd creates the container command with subcommands
func NewContainerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "container",
		Short: "Build container images using Shipwright",
		Long:  `Build container images using Shipwright Build and push to registries.`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(serverURL) == "" {
				serverURL = config.DefaultServerWithDerive()
			}
			if flag := cmd.Root().PersistentFlags().Lookup("insecure"); flag != nil {
				if val, err := strconv.ParseBool(flag.Value.String()); err == nil && val {
					insecureSkipTLS = true
				}
			}
			return nil
		},
	}

	cmd.AddCommand(newBuildCmd())
	cmd.AddCommand(newLogsCmd())

	return cmd
}
