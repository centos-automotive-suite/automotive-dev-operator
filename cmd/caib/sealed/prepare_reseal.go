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

var prepareResealWorkspace string

func newPrepareResealCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prepare-reseal <input-disk> <output-disk>",
		Short: "Prepare a disk image for resealing",
		Long:  `Runs 'aib prepare-reseal': prepares an unsealed or modified disk image for resealing. Input and output paths are relative to --workspace (default: current directory).`,
		Args:  cobra.ExactArgs(2),
		RunE:  runPrepareReseal,
	}
	addSealedCommonFlags(cmd)
	addSealedServerFlags(cmd)
	cmd.Flags().StringVarP(&prepareResealWorkspace, "workspace", "w", ".", "Workspace directory (input/output paths relative to this)")
	return cmd
}

func runPrepareReseal(_ *cobra.Command, args []string) error {
	if strings.TrimSpace(sealedServerURL) != "" {
		if err := runSealedViaAPI(buildapitypes.SealedPrepareReseal, args[0], args[1], ""); err != nil {
			handleSealedError(err)
		}
		return nil
	}
	workDir := prepareResealWorkspace
	if workDir == "" {
		workDir = "."
	}
	absWork, err := filepath.Abs(workDir)
	if err != nil {
		return fmt.Errorf("workspace: %w", err)
	}
	input := args[0]
	output := args[1]

	inPath, err := ensurePathInWorkspace(absWork, input)
	if err != nil {
		return err
	}
	if _, err := os.Stat(inPath); err != nil {
		return fmt.Errorf("input disk: %w", err)
	}

	outPath, err := ensurePathInWorkspace(absWork, output)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	relIn, _ := filepath.Rel(absWork, inPath)
	relOut, _ := filepath.Rel(absWork, outPath)
	return runAIB("prepare-reseal", absWork, toContainerPath(relIn), toContainerPath(relOut))
}
