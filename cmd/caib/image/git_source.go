package image

import "github.com/spf13/cobra"

func addGitSourceFlags(cmd *cobra.Command, opts Options) {
	cmd.Flags().StringVar(&opts.Build.GitURL, "git-url", "", "HTTPS repository containing the manifest and optional adjacent <manifest>.lock")
	cmd.Flags().StringVar(&opts.Build.GitRef, "git-ref", "", "Git branch, tag, or commit (default: remote HEAD)")
	cmd.Flags().StringVar(&opts.Build.GitSecret, "git-secret", "", "Namespace-local basic-auth Secret for Git checkout")
	cmd.Flags().StringVar(&opts.Build.GitLockfile, "git-lockfile", "", "Repository-relative lockfile path in the selected Git commit (default: adjacent <manifest>.lock)")
}
