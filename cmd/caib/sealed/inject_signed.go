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

package sealed

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	"github.com/spf13/cobra"
)

var injectSignedWorkspace string

func newInjectSignedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inject-signed <input-disk> <signed-dir> <output-disk>",
		Short: "Inject signed components back into a disk image",
		Long:  `Runs 'aib inject-signed': injects externally signed components (from extract-for-signing) into the disk image. Paths are relative to --workspace.`,
		Args:  cobra.ExactArgs(3),
		RunE:  runInjectSigned,
	}
	addSealedCommonFlags(cmd)
	addSealedServerFlags(cmd)
	cmd.Flags().StringVarP(&injectSignedWorkspace, "workspace", "w", ".", "Workspace directory (input/output paths relative to this)")
	return cmd
}

func runInjectSigned(_ *cobra.Command, args []string) error {
	if strings.TrimSpace(sealedServerURL) != "" {
		if err := runSealedViaAPI(buildapitypes.SealedInjectSigned, args[0], args[2], args[1]); err != nil {
			handleSealedError(err)
		}
		return nil
	}
	workDir := injectSignedWorkspace
	if workDir == "" {
		workDir = "."
	}
	absWork, err := filepath.Abs(workDir)
	if err != nil {
		return fmt.Errorf("workspace: %w", err)
	}
	input := args[0]
	signedDir := args[1]
	output := args[2]

	inPath, err := ensurePathInWorkspace(absWork, input)
	if err != nil {
		return err
	}
	if _, err := os.Stat(inPath); err != nil {
		return fmt.Errorf("input disk: %w", err)
	}

	signedPath, err := ensurePathInWorkspace(absWork, signedDir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(signedPath); err != nil {
		return fmt.Errorf("signed dir: %w", err)
	}

	outPath, err := ensurePathInWorkspace(absWork, output)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	relIn, _ := filepath.Rel(absWork, inPath)
	relSigned, _ := filepath.Rel(absWork, signedPath)
	relOut, _ := filepath.Rel(absWork, outPath)
	return runAIB("inject-signed", absWork, toContainerPath(relIn), toContainerPath(relSigned), toContainerPath(relOut))
}
