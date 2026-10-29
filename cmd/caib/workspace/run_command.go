package workspace

import (
	"fmt"
	"os"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/spf13/cobra"
)

// workspaceRunCommand preserves exec's literal argument and strict script
// behavior while submitting a durable shell command instead of a live stream.
func workspaceRunCommand(cmd *cobra.Command, args []string) (string, error) {
	if cmd.Flags().Changed("script") {
		if len(args) != 0 {
			return "", fmt.Errorf("--script cannot be combined with command arguments")
		}
		filename, _ := cmd.Flags().GetString("script")
		script, err := os.ReadFile(filename)
		if err != nil {
			return "", fmt.Errorf("read script: %w", err)
		}
		if strings.TrimSpace(string(script)) == "" {
			return "", fmt.Errorf("script is empty")
		}
		// Runs already provide EOF on stdin; Bash can execute the literal script.
		args = []string{"/bin/bash", "-euo", "pipefail", "-c", string(script), "caib-workspace-script"}
	}
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	command := strings.Join(quoted, " ")
	if len(command) > buildcontract.MaxWorkspaceRunCommandBytes {
		if cmd.Flags().Changed("script") {
			return "", fmt.Errorf("script exceeds the %d-byte run command limit after quoting; sync the script to the workspace and run it from there", buildcontract.MaxWorkspaceRunCommandBytes)
		}
		return "", fmt.Errorf("command exceeds the %d-byte run command limit after quoting", buildcontract.MaxWorkspaceRunCommandBytes)
	}
	return command, nil
}
