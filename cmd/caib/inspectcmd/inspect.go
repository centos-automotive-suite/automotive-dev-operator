// Package inspectcmd provides the image inspect handler for build provenance.
package inspectcmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/types"
	"github.com/fatih/color"
	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"

	caibcommon "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/registryauth"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/oci"
)

var ociSpec = oci.Get()

// annotationDisplayLabels maps spec annotation keys to human-readable labels
// for provenance display. Keys not listed here (parts, multi-layer,
// default-partitions) are tooling-only metadata and intentionally omitted.
var annotationDisplayLabels = map[string]string{
	"distro":                   "Distro",
	"target":                   "Target",
	"arch":                     "Arch",
	"automotive-image-builder": "AIB Image",
	"builder-image":            "Builder Image",
	"aib-version":              "AIB Version",
	"task-bundle-ref":          "Task Bundle",
	"custom-defines":           "Custom Defines",
	"aib-extra-args":           "AIB Extra Args",
	"export-format":            "Export Format",
	"aib-command":              "AIB Command",
}

// Options wires inspect handler dependencies.
type Options struct {
	RegistryAuthFile *string
	OutputDir        *string
	OutputFormat     *string
	InsecureSkipTLS  *bool

	HandleError func(error)
}

type provenanceOutput struct {
	Reference   string            `json:"reference" yaml:"reference"`
	Digest      string            `json:"digest" yaml:"digest"`
	Annotations map[string]string `json:"annotations" yaml:"annotations"`
	Referrers   []referrerInfo    `json:"referrers" yaml:"referrers"`
	RebuildCmd  string            `json:"rebuildCommand" yaml:"rebuildCommand"`
}

// Handler implements the inspect command.
type Handler struct {
	opts Options
}

// NewHandler creates an inspect handler.
func NewHandler(opts Options) *Handler {
	return &Handler{opts: opts}
}

func (h *Handler) handleError(err error) {
	if h.opts.HandleError != nil {
		h.opts.HandleError(err)
		return
	}
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

func (h *Handler) supportsColor() bool {
	return caibcommon.SupportsColorOutput()
}

// RunInspect handles `caib image inspect <oci-ref>`.
func (h *Handler) RunInspect(_ *cobra.Command, args []string) {
	ociRef := args[0]

	sysCtx := &types.SystemContext{}
	if h.opts.InsecureSkipTLS != nil && *h.opts.InsecureSkipTLS {
		sysCtx.DockerInsecureSkipTLSVerify = types.OptionalBoolTrue
	}

	_, username, password := registryauth.ExtractRegistryCredentials(ociRef, "")
	if h.opts.RegistryAuthFile != nil && *h.opts.RegistryAuthFile != "" {
		sysCtx.AuthFilePath = *h.opts.RegistryAuthFile
	}
	if username != "" && password != "" {
		sysCtx.DockerAuthConfig = &types.DockerAuthConfig{
			Username: username,
			Password: password,
		}
	}

	annotations, digest, err := readManifestAnnotations(ociRef, sysCtx)
	if err != nil {
		h.handleError(fmt.Errorf("read manifest from %s: %w", ociRef, err))
		return
	}

	referrers, err := discoverReferrers(ociRef, digest, sysCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not discover referrers: %v\n", err)
	}

	referrerTypes := make(map[string]bool)
	for _, r := range referrers {
		referrerTypes[r.ArtifactType] = true
	}

	format := ""
	if h.opts.OutputFormat != nil {
		format = strings.ToLower(strings.TrimSpace(*h.opts.OutputFormat))
	}

	switch format {
	case "json", "yaml", "yml":
		h.printStructured(format, ociRef, digest, annotations, referrers, referrerTypes)
	default:
		h.printProvenance(ociRef, digest, annotations, referrers, referrerTypes)
	}

	if h.opts.OutputDir != nil && *h.opts.OutputDir != "" {
		authFile := ""
		if h.opts.RegistryAuthFile != nil {
			authFile = *h.opts.RegistryAuthFile
		}
		h.downloadReferrers(ociRef, digest, referrers, *h.opts.OutputDir, username, password, authFile)
	}
}

func (h *Handler) printStructured(format, ociRef, digest string, annotations map[string]string, referrers []referrerInfo, referrerTypes map[string]bool) {
	stripped := make(map[string]string)
	for k, v := range annotations {
		if strings.HasPrefix(k, ociSpec.AnnotationPrefix) {
			stripped[strings.TrimPrefix(k, ociSpec.AnnotationPrefix)] = v
		}
	}

	out := provenanceOutput{
		Reference:   ociRef,
		Digest:      digest,
		Annotations: stripped,
		Referrers:   referrers,
		RebuildCmd:  buildRebuildCommand(ociRef, digest, annotations, referrerTypes),
	}

	var data []byte
	var err error
	if format == "json" {
		data, err = json.MarshalIndent(out, "", "  ")
	} else {
		data, err = yaml.Marshal(out)
	}
	if err != nil {
		h.handleError(fmt.Errorf("marshal output: %w", err))
		return
	}
	fmt.Println(string(data))
}

func readManifestAnnotations(ociRef string, sysCtx *types.SystemContext) (map[string]string, string, error) {
	ref, err := docker.ParseReference("//" + ociRef)
	if err != nil {
		return nil, "", fmt.Errorf("parse reference: %w", err)
	}

	ctx := context.Background()
	src, err := ref.NewImageSource(ctx, sysCtx)
	if err != nil {
		return nil, "", fmt.Errorf("open image source: %w", err)
	}
	defer func() { _ = src.Close() }()

	rawManifest, _, err := src.GetManifest(ctx, nil)
	if err != nil {
		return nil, "", fmt.Errorf("get manifest: %w", err)
	}

	digest, err := manifest.Digest(rawManifest)
	if err != nil {
		return nil, "", fmt.Errorf("compute digest: %w", err)
	}

	var parsed struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(rawManifest, &parsed); err != nil {
		return nil, "", fmt.Errorf("parse manifest JSON: %w", err)
	}

	return parsed.Annotations, string(digest), nil
}

type referrerInfo struct {
	ArtifactType string `json:"artifactType" yaml:"artifactType"`
	Digest       string `json:"digest" yaml:"digest"`
}

func discoverReferrers(ociRef, digest string, sysCtx *types.SystemContext) ([]referrerInfo, error) {
	repoName := splitReference(ociRef)
	if repoName == "" {
		return nil, fmt.Errorf("could not parse repository from %s", ociRef)
	}

	repo, err := remote.NewRepository(repoName)
	if err != nil {
		return nil, fmt.Errorf("parse repository: %w", err)
	}

	authClient := &auth.Client{}
	if sysCtx.DockerAuthConfig != nil && sysCtx.DockerAuthConfig.Username != "" {
		authClient.Credential = auth.StaticCredential(repo.Reference.Host(), auth.Credential{
			Username: sysCtx.DockerAuthConfig.Username,
			Password: sysCtx.DockerAuthConfig.Password,
		})
	} else {
		authFilePath := sysCtx.AuthFilePath
		if authFilePath == "" {
			for _, candidate := range registryauth.FileCandidates() {
				if _, err := os.Stat(candidate); err == nil {
					authFilePath = candidate
					break
				}
			}
		}
		if authFilePath != "" {
			store, err := credentials.NewFileStore(authFilePath)
			if err != nil {
				return nil, fmt.Errorf("load auth file %s: %w", authFilePath, err)
			}
			authClient.Credential = credentials.Credential(store)
		}
	}
	if sysCtx.DockerInsecureSkipTLSVerify == types.OptionalBoolTrue {
		authClient.Client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // user explicitly opted in
				},
			},
		}
	}
	repo.Client = authClient

	dgst, err := godigest.Parse(digest)
	if err != nil {
		return nil, fmt.Errorf("parse digest: %w", err)
	}

	var result []referrerInfo
	err = repo.Referrers(context.Background(), ocispec.Descriptor{Digest: dgst}, "", func(referrers []ocispec.Descriptor) error {
		for _, r := range referrers {
			result = append(result, referrerInfo{
				ArtifactType: r.ArtifactType,
				Digest:       string(r.Digest),
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list referrers: %w", err)
	}

	return result, nil
}

func splitReference(ref string) string {
	if idx := strings.LastIndex(ref, "@"); idx >= 0 {
		return ref[:idx]
	}
	if idx := strings.LastIndex(ref, ":"); idx >= 0 {
		slashIdx := strings.LastIndex(ref, "/")
		if idx > slashIdx {
			return ref[:idx]
		}
	}
	return ref
}

func (h *Handler) printProvenance(ociRef, digest string, annotations map[string]string, _ []referrerInfo, referrerTypes map[string]bool) {
	bold := func(a ...any) string { return fmt.Sprint(a...) }
	green := func(a ...any) string { return fmt.Sprint(a...) }
	yellow := func(a ...any) string { return fmt.Sprint(a...) }
	cyan := func(a ...any) string { return fmt.Sprint(a...) }
	if h.supportsColor() {
		bold = color.New(color.FgHiWhite, color.Bold).SprintFunc()
		green = color.New(color.FgHiGreen).SprintFunc()
		yellow = color.New(color.FgHiYellow).SprintFunc()
		cyan = color.New(color.FgHiCyan).SprintFunc()
	}

	fmt.Println()
	fmt.Println(bold("Build Provenance"))
	fmt.Println(bold(strings.Repeat("═", 50)))
	fmt.Printf("  %-16s %s\n", bold("Reference:"), cyan(ociRef))
	fmt.Printf("  %-16s %s\n", bold("Digest:"), digest)
	fmt.Println()

	hasAnnotations := false
	for _, ak := range ociSpec.AllManifestAnnotationKeys() {
		label := annotationDisplayLabels[ak.Key]
		if label == "" {
			continue
		}
		val := annotations[ociSpec.AnnotationKey(ak.Key)]
		if val != "" {
			hasAnnotations = true
			fmt.Printf("  %-16s %s\n", bold(label+":"), green(val))
		}
	}
	if !hasAnnotations {
		fmt.Println("  No automotive build annotations found")
	}

	fmt.Println()
	fmt.Println(bold("Saved Artifacts"))
	fmt.Println(bold(strings.Repeat("═", 50)))

	for _, rt := range ociSpec.ReferrerTypes {
		if referrerTypes[rt.ArtifactType] {
			fmt.Printf("  %s %s  (%s)\n", green("✓"), bold(rt.Label), rt.ArtifactType)
		} else {
			fmt.Printf("  %s %s\n", yellow("✗"), rt.Label)
		}
	}

	fmt.Println()
	fmt.Println(bold("Rebuild Command"))
	fmt.Println(bold(strings.Repeat("═", 50)))

	cmd := buildRebuildCommand(ociRef, digest, annotations, referrerTypes)
	fmt.Println(cyan(cmd))
	fmt.Println()
}

func buildRebuildCommand(ociRef, digest string, annotations map[string]string, referrerTypes map[string]bool) string {
	get := func(key string) string { return annotations[ociSpec.AnnotationKey(key)] }

	aibCmd := get("aib-command")
	isDevBuild := strings.HasPrefix(aibCmd, "aib-dev")

	var parts []string
	if isDevBuild {
		parts = append(parts, "caib image build-dev")
	} else {
		parts = append(parts, "caib image build")
	}

	hasManifest := referrerTypes[ociSpec.ReferrerArtifactTypeByLabel("AIB Manifest")]
	if hasManifest {
		parts = append(parts, "manifest.aib.yml")
	} else {
		parts = append(parts, "<manifest.aib.yml>")
	}

	if v := get("distro"); v != "" {
		parts = append(parts, fmt.Sprintf("  --distro %s", v))
	}
	if v := get("target"); v != "" {
		parts = append(parts, fmt.Sprintf("  --target %s", v))
	}
	if v := get("arch"); v != "" {
		parts = append(parts, fmt.Sprintf("  --arch %s", v))
	}
	if v := get("automotive-image-builder"); v != "" {
		parts = append(parts, fmt.Sprintf("  --aib-image %s", v))
	}
	if v := get("builder-image"); v != "" {
		parts = append(parts, fmt.Sprintf("  --builder-image %s", v))
	}
	if v := get("export-format"); v != "" {
		parts = append(parts, fmt.Sprintf("  --format %s", v))
	}
	if v := get("custom-defines"); v != "" {
		for _, def := range strings.Split(v, "\n") {
			def = strings.TrimSpace(def)
			if def != "" {
				parts = append(parts, fmt.Sprintf("  --define %s", def))
			}
		}
	}
	if v := get("aib-extra-args"); v != "" {
		for _, arg := range strings.Split(v, "\n") {
			arg = strings.TrimSpace(arg)
			if arg != "" {
				parts = append(parts, fmt.Sprintf("  --extra-args %s", arg))
			}
		}
	}
	hasSources := referrerTypes[ociSpec.ReferrerArtifactTypeByLabel("Build Sources")]
	taskBundleRef := get("task-bundle-ref")
	if taskBundleRef != "" {
		parts = append(parts, fmt.Sprintf("  --task-bundle-ref %s", taskBundleRef))
	}
	if taskBundleRef != "" || hasManifest || hasSources {
		parts = append(parts, "  --secure")
		parts = append(parts, "  --reproducible")
	}
	if hasSources {
		parts = append(parts, fmt.Sprintf("  --restore-sources %s@%s", splitReference(ociRef), digest))
	}
	if isDevBuild {
		parts = append(parts, "  --push <registry>")
	} else {
		parts = append(parts, "  --push <registry>")
		parts = append(parts, "  --push-disk <registry>")
	}

	return strings.Join(parts, " \\\n")
}

func (h *Handler) downloadReferrers(ociRef, _ string, referrers []referrerInfo, outputDir, username, password, authFile string) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output dir: %v\n", err)
		return
	}

	repo := splitReference(ociRef)
	insecure := h.opts.InsecureSkipTLS != nil && *h.opts.InsecureSkipTLS

	fileMap := ociSpec.ReferrerFileMap()

	for _, ref := range referrers {
		filename, known := fileMap[ref.ArtifactType]
		if !known {
			continue
		}

		destPath := filepath.Join(outputDir, filename)
		pullRef := repo + "@" + ref.Digest
		fmt.Printf("Downloading %s → %s\n", ref.ArtifactType, destPath)
		if err := caibcommon.PullOCIArtifact(pullRef, destPath, username, password, insecure, authFile); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to download %s: %v\n", filename, err)
		}
	}
}
