package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/auth"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	completionTimeout = time.Second
	completionTargets = "targets"
)

func configureCompletions(cmd *cobra.Command) {
	for name, values := range map[string][]string{
		"arch": {"amd64", "arm64"}, "architecture": {"amd64", "arm64"},
		"format": {"qcow2", "raw", "simg"}, "compress": {"gzip", "xz"},
		"mode": {"image", "package"}, "builder-cache-policy": {"validate", "reuse"},
		"output-format": {"table", "json", "yaml"},
	} {
		registerCompletion(cmd, name, cobra.FixedCompletions(values, cobra.ShellCompDirectiveNoFileComp))
	}
	if cmd.CommandPath() == "caib status" {
		registerCompletion(cmd, "output", cobra.FixedCompletions([]string{"table", "json", "yaml"}, cobra.ShellCompDirectiveNoFileComp))
	}
	targetKind := completionTargets
	if cmd.CommandPath() == "caib image flash" {
		targetKind = "flash-targets"
	}
	registerCompletion(cmd, "target", remoteCompletion(targetKind))
	registerCompletion(cmd, "workspace", remoteCompletion("workspaces"))
	registerCompletion(cmd, "from-build", remoteCompletion("builds"))

	kind := ""
	switch cmd.CommandPath() {
	case "caib image show", "caib image logs", "caib image download", "caib image delete", "caib image cancel", "caib image token", "caib catalog publish":
		kind = "builds"
	case "caib container logs":
		kind = "containers"
	case "caib workspace show", "caib workspace delete", "caib workspace start", "caib workspace stop", "caib workspace sync", "caib workspace exec", "caib workspace shell", "caib workspace deploy":
		kind = "workspaces"
	}
	if kind != "" {
		cmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				if cmd.CommandPath() == "caib workspace sync" && len(args) == 1 {
					return nil, cobra.ShellCompDirectiveFilterDirs
				}
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return remoteCompletion(kind)(cmd, args, prefix)
		}
	}
	for _, child := range cmd.Commands() {
		configureCompletions(child)
	}
}

func registerCompletion(cmd *cobra.Command, name string, complete cobra.CompletionFunc) {
	// Register only flags owned by this command; inherited flags already have
	// their parent's completer and Cobra rejects duplicate registrations.
	if cmd.Flags().Lookup(name) == nil && cmd.PersistentFlags().Lookup(name) == nil {
		return
	}
	if err := cmd.RegisterFlagCompletionFunc(name, complete); err != nil {
		panic(err)
	}
}

func remoteCompletion(kind string) cobra.CompletionFunc {
	return func(cmd *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
		ctx, cancel := context.WithTimeout(cmd.Context(), completionTimeout)
		defer cancel()
		api, err := completionClient(cmd)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		values, err := completionValues(ctx, api, kind)
		if err != nil {
			// Tab completion is best effort. In particular, an expired login must
			// not trigger a browser, token refresh, or an error in the user's prompt.
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		values = slices.DeleteFunc(values, func(value string) bool {
			return value == "" || !strings.HasPrefix(value, prefix)
		})
		slices.Sort(values)
		return slices.Compact(values), cobra.ShellCompDirectiveNoFileComp
	}
}

func completionValues(ctx context.Context, api *buildapiclient.Client, kind string) ([]string, error) {
	var values []string
	switch kind {
	case completionTargets, "flash-targets":
		cfg, err := api.GetOperatorConfig(ctx)
		if err != nil {
			return nil, err
		}
		if kind == completionTargets {
			values = append(values, "qemu")
			for name := range cfg.TargetDefaults {
				values = append(values, name)
			}
		}
		for name := range cfg.JumpstarterTargets {
			values = append(values, name)
		}
	case "builds":
		items, err := api.ListBuilds(ctx)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			values = append(values, item.Name)
		}
	case "workspaces":
		items, err := api.ListWorkspaces(ctx)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			values = append(values, item.Name)
		}
	case "containers":
		items, err := api.ListContainerBuilds(ctx)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			values = append(values, item.Name)
		}
	}
	return values, nil
}

func completionFlag(cmd *cobra.Command, name string) string {
	if flag := cmd.Flag(name); flag != nil {
		return strings.TrimSpace(flag.Value.String())
	}
	return ""
}

func completionClient(cmd *cobra.Command) (*buildapiclient.Client, error) {
	server := completionFlag(cmd, "server")
	if server == "" {
		// Do not probe Jumpstarter or write a derived endpoint during completion.
		server = config.DefaultServer()
	}
	if server == "" {
		return nil, fmt.Errorf("no server configured")
	}
	token := completionFlag(cmd, "token")
	if token == "" {
		token = strings.TrimSpace(os.Getenv("CAIB_TOKEN"))
	}
	if token == "" {
		token = completionCachedToken(server)
	}
	opts := []buildapiclient.Option{
		buildapiclient.WithHTTPClient(&http.Client{Timeout: completionTimeout}),
		buildapiclient.WithAuthToken(token),
	}
	if completionFlag(cmd, "insecure") == "true" || completionFlag(cmd, "insecure-skip-tls-verify") == "true" {
		opts = append(opts, buildapiclient.WithInsecureTLS())
	}
	if ca := os.Getenv("SSL_CERT_FILE"); ca != "" {
		opts = append(opts, buildapiclient.WithCACertificate(ca))
	} else if ca := os.Getenv("REQUESTS_CA_BUNDLE"); ca != "" {
		opts = append(opts, buildapiclient.WithCACertificate(ca))
	}
	return buildapiclient.New(server, opts...)
}

func completionCachedToken(server string) string {
	// Only reuse a saved login at its saved endpoint. Completion deliberately
	// skips OIDC discovery, so it cannot validate a different server's issuer.
	if saved, err := config.Read(); err == nil && saved != nil && strings.TrimRight(saved.ServerURL, "/") == strings.TrimRight(server, "/") {
		if cache, err := auth.LoadTokenCache(); err == nil && cache != nil && time.Now().Before(cache.ExpiresAt) && cache.Token != "" {
			return cache.Token
		}
	}
	// Read credentials already on disk, without executing kubeconfig plugins or oc.
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.WarnIfAllMissing = false
	cfg, err := rules.Load()
	if err != nil || cfg == nil {
		return ""
	}
	current := cfg.Contexts[cfg.CurrentContext]
	if current == nil {
		return ""
	}
	info := cfg.AuthInfos[current.AuthInfo]
	if info == nil {
		return ""
	}
	if info.Token != "" {
		return info.Token
	}
	if info.TokenFile != "" {
		if token, err := os.ReadFile(info.TokenFile); err == nil {
			return strings.TrimSpace(string(token))
		}
	}
	return ""
}
