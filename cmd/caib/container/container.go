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

import "github.com/spf13/cobra"

// NewContainerCmd creates the container command with subcommands
func NewContainerCmd(defaultServer string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "container",
		Short: "Build container images using Shipwright",
		Long:  `Build container images using Shipwright Build and push to registries.`,
	}

	cmd.PersistentFlags().BoolVar(&insecureSkipTLS, "insecure-skip-tls-verify", false, "skip TLS certificate verification")

	cmd.AddCommand(newBuildCmd(defaultServer))
	cmd.AddCommand(newLogsCmd(defaultServer))

	return cmd
}
