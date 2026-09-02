package buildcmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	"github.com/spf13/cobra"
)

const (
	testS3Bucket     = "my-bucket"
	testS3FlagBucket = "flag-bucket"
	testS3AccessKey  = "AKID"
)

func newS3TestHandler(opts Options) *Handler {
	if opts.HandleError == nil {
		opts.HandleError = func(_ error) {}
	}
	s3DefaultsFn = func() (*config.S3Config, error) { return nil, nil }
	return NewHandler(opts)
}

func withS3Defaults(cfg *config.S3Config, fn func()) {
	orig := s3DefaultsFn
	s3DefaultsFn = func() (*config.S3Config, error) { return cfg, nil }
	defer func() { s3DefaultsFn = orig }()
	fn()
}

func TestApplyS3Options_NoBucket(t *testing.T) {
	opts := newTestDiskOpts()
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	if err := h.applyS3Options(nil, &req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.S3Bucket != "" {
		t.Error("expected empty S3Bucket")
	}
	if req.S3Credentials != nil {
		t.Error("expected nil S3Credentials")
	}
}

func TestApplyS3Options_InlineCredentials(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	*opts.S3Prefix = "builds/test"
	*opts.S3Region = "eu-west-1"
	*opts.S3Endpoint = "https://minio.local"
	*opts.S3AccessKeyID = testS3AccessKey
	*opts.S3SecretAccessKey = "SECRET"
	*opts.S3Insecure = true
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	if err := h.applyS3Options(nil, &req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.S3Bucket != testS3Bucket {
		t.Errorf("S3Bucket = %q, want %q", req.S3Bucket, testS3Bucket)
	}
	if req.S3Prefix != "builds/test" {
		t.Errorf("S3Prefix = %q, want %q", req.S3Prefix, "builds/test")
	}
	if req.S3Region != "eu-west-1" {
		t.Errorf("S3Region = %q, want %q", req.S3Region, "eu-west-1")
	}
	if req.S3Endpoint != "https://minio.local" {
		t.Errorf("S3Endpoint = %q, want %q", req.S3Endpoint, "https://minio.local")
	}
	if !req.S3InsecureSkipTLSVerify {
		t.Error("expected S3InsecureSkipTLSVerify=true")
	}
	if req.S3Credentials == nil {
		t.Fatal("expected S3Credentials to be set")
	}
	if req.S3Credentials.AccessKeyID != testS3AccessKey {
		t.Errorf("AccessKeyID = %q, want %q", req.S3Credentials.AccessKeyID, testS3AccessKey)
	}
	if req.S3Credentials.SecretAccessKey != "SECRET" {
		t.Errorf("SecretAccessKey = %q, want %q", req.S3Credentials.SecretAccessKey, "SECRET")
	}
	if req.S3CredentialsSecretName != "" {
		t.Errorf("expected empty S3CredentialsSecretName, got %q", req.S3CredentialsSecretName)
	}
}

func TestApplyS3Options_EnvVarFallback(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	t.Setenv("AWS_ACCESS_KEY_ID", "ENV_AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ENV_SECRET")
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	if err := h.applyS3Options(nil, &req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.S3Credentials == nil {
		t.Fatal("expected S3Credentials from env vars")
	}
	if req.S3Credentials.AccessKeyID != "ENV_AKID" {
		t.Errorf("AccessKeyID = %q, want %q", req.S3Credentials.AccessKeyID, "ENV_AKID")
	}
	if req.S3Credentials.SecretAccessKey != "ENV_SECRET" {
		t.Errorf("SecretAccessKey = %q, want %q", req.S3Credentials.SecretAccessKey, "ENV_SECRET")
	}
}

func TestApplyS3Options_ConflictingCredentialSourcesError(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	*opts.S3AccessKeyID = "FLAG_AKID"
	*opts.S3SecretAccessKey = "FLAG_SECRET"
	t.Setenv("AWS_ACCESS_KEY_ID", "ENV_AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ENV_SECRET")
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	err := h.applyS3Options(nil, &req)
	if err == nil {
		t.Fatal("expected error when both flags and env vars provide credentials")
	}
}

func TestApplyS3Options_SecretName(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	*opts.S3CredentialsSecret = "shared-s3-creds"
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	if err := h.applyS3Options(nil, &req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.S3CredentialsSecretName != "shared-s3-creds" {
		t.Errorf("S3CredentialsSecretName = %q, want %q", req.S3CredentialsSecretName, "shared-s3-creds")
	}
	if req.S3Credentials != nil {
		t.Error("expected nil S3Credentials when using secret name")
	}
}

func TestApplyS3Options_PartialCredentialsError(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	*opts.S3AccessKeyID = "AKID"
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	err := h.applyS3Options(nil, &req)
	if err == nil {
		t.Fatal("expected error for partial credentials")
	}
}

func TestValidateDevExportFlags_OutputWithS3Bucket(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.OutputDir = "/tmp/output"
	*opts.S3Bucket = "my-bucket"
	h := newS3TestHandler(opts)

	if err := h.validateDevExportFlags("manifest.aib.yml"); err != nil {
		t.Errorf("expected --output + --s3-bucket (no --push) to be accepted, got: %v", err)
	}
}

func TestValidateDevExportFlags_OutputWithoutPushOrS3(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.OutputDir = "/tmp/output"
	h := newS3TestHandler(opts)

	if err := h.validateDevExportFlags("manifest.aib.yml"); err == nil {
		t.Error("expected error for --output without --push or --s3-bucket")
	}
}

func TestValidateDevExportFlags_InternalRegistryConflictsWithPush(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.UseInternalRegistry = true
	*opts.ExportOCI = "quay.io/org/image:v1"
	h := newS3TestHandler(opts)

	if err := h.validateDevExportFlags("manifest.aib.yml"); err == nil {
		t.Error("expected error for --internal-registry with --push")
	}
}

func TestApplyS3Options_ExplicitAccessKeyOnlyError(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	*opts.S3AccessKeyID = "EXPLICIT_AKID"
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ENV_SECRET")
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	err := h.applyS3Options(nil, &req)
	if err == nil {
		t.Fatal("expected error when only --s3-access-key-id is set (should not combine with env)")
	}
}

func TestApplyS3Options_ExplicitSecretKeyOnlyError(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	*opts.S3SecretAccessKey = "EXPLICIT_SECRET"
	t.Setenv("AWS_ACCESS_KEY_ID", "ENV_AKID")
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	err := h.applyS3Options(nil, &req)
	if err == nil {
		t.Fatal("expected error when only --s3-secret-access-key is set (should not combine with env)")
	}
}

func TestApplyS3Options_AmbientAccessKeyOnlyError(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	t.Setenv("AWS_ACCESS_KEY_ID", "ENV_AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	err := h.applyS3Options(nil, &req)
	if err == nil {
		t.Fatal("expected error when only AWS_ACCESS_KEY_ID is set in env")
	}
}

func TestApplyS3Options_AmbientSecretKeyOnlyError(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ENV_SECRET")
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	err := h.applyS3Options(nil, &req)
	if err == nil {
		t.Fatal("expected error when only AWS_SECRET_ACCESS_KEY is set in env")
	}
}

func TestApplyS3Options_NoCredentialsAllowed(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	if err := h.applyS3Options(nil, &req); err != nil {
		t.Fatalf("expected no error for IAM-based auth, got: %v", err)
	}
	if req.S3Credentials != nil {
		t.Error("expected nil S3Credentials for IAM-based auth")
	}
}

func TestApplyS3Options_ConfigFileDefaults(t *testing.T) {
	opts := newTestDiskOpts()
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	h := newS3TestHandler(opts)

	cfg := &config.S3Config{
		Bucket:                "config-bucket",
		Prefix:                "config-prefix/",
		Endpoint:              "https://config-minio.local",
		Region:                "eu-central-1",
		CredentialsSecret:     "config-s3-creds",
		InsecureSkipTLSVerify: true,
	}

	withS3Defaults(cfg, func() {
		var req buildapitypes.BuildRequest
		if err := h.applyS3Options(nil, &req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.S3Bucket != "config-bucket" {
			t.Errorf("S3Bucket = %q, want %q", req.S3Bucket, "config-bucket")
		}
		if req.S3Prefix != "config-prefix/" {
			t.Errorf("S3Prefix = %q, want %q", req.S3Prefix, "config-prefix/")
		}
		if req.S3Endpoint != "https://config-minio.local" {
			t.Errorf("S3Endpoint = %q, want %q", req.S3Endpoint, "https://config-minio.local")
		}
		if req.S3Region != "eu-central-1" {
			t.Errorf("S3Region = %q, want %q", req.S3Region, "eu-central-1")
		}
		if req.S3CredentialsSecretName != "config-s3-creds" {
			t.Errorf("S3CredentialsSecretName = %q, want %q", req.S3CredentialsSecretName, "config-s3-creds")
		}
		if !req.S3InsecureSkipTLSVerify {
			t.Error("expected S3InsecureSkipTLSVerify=true from config")
		}
	})
}

func TestApplyS3Options_CLIFlagsOverrideConfig(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3FlagBucket
	*opts.S3Prefix = "flag-prefix/"
	*opts.S3Endpoint = "https://flag-minio.local"
	*opts.S3Region = "ap-southeast-1"
	*opts.S3CredentialsSecret = "flag-secret"
	*opts.S3Insecure = true
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	h := newS3TestHandler(opts)

	cfg := &config.S3Config{
		Bucket:                "config-bucket",
		Prefix:                "config-prefix/",
		Endpoint:              "https://config-minio.local",
		Region:                "eu-central-1",
		CredentialsSecret:     "config-s3-creds",
		InsecureSkipTLSVerify: false,
	}

	withS3Defaults(cfg, func() {
		var req buildapitypes.BuildRequest
		if err := h.applyS3Options(nil, &req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.S3Bucket != testS3FlagBucket {
			t.Errorf("S3Bucket = %q, want %q", req.S3Bucket, testS3FlagBucket)
		}
		if req.S3Prefix != "flag-prefix/" {
			t.Errorf("S3Prefix = %q, want %q", req.S3Prefix, "flag-prefix/")
		}
		if req.S3Endpoint != "https://flag-minio.local" {
			t.Errorf("S3Endpoint = %q, want %q", req.S3Endpoint, "https://flag-minio.local")
		}
		if req.S3Region != "ap-southeast-1" {
			t.Errorf("S3Region = %q, want %q", req.S3Region, "ap-southeast-1")
		}
		if req.S3CredentialsSecretName != "flag-secret" {
			t.Errorf("S3CredentialsSecretName = %q, want %q", req.S3CredentialsSecretName, "flag-secret")
		}
		if !req.S3InsecureSkipTLSVerify {
			t.Error("expected S3InsecureSkipTLSVerify=true from CLI flag")
		}
	})
}

func TestApplyS3Options_ExplicitInsecureFalseOverridesConfig(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = "test-bucket"
	*opts.S3Insecure = false
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	h := newS3TestHandler(opts)

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(opts.S3Insecure, "s3-insecure", false, "")
	_ = cmd.Flags().Set("s3-insecure", "false")

	cfg := &config.S3Config{
		Bucket:                "test-bucket",
		InsecureSkipTLSVerify: true,
	}

	withS3Defaults(cfg, func() {
		var req buildapitypes.BuildRequest
		if err := h.applyS3Options(cmd, &req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.S3InsecureSkipTLSVerify {
			t.Error("expected S3InsecureSkipTLSVerify=false when CLI explicitly sets --s3-insecure=false")
		}
	})
}

func TestApplyS3Options_ConfigBucketWithFlagOverrides(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Region = "us-west-2"
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	h := newS3TestHandler(opts)

	cfg := &config.S3Config{
		Bucket:            "config-bucket",
		Endpoint:          "https://config-minio.local",
		Region:            "eu-central-1",
		CredentialsSecret: "config-s3-creds",
	}

	withS3Defaults(cfg, func() {
		var req buildapitypes.BuildRequest
		if err := h.applyS3Options(nil, &req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.S3Bucket != "config-bucket" {
			t.Errorf("S3Bucket = %q, want %q (from config)", req.S3Bucket, "config-bucket")
		}
		if req.S3Endpoint != "https://config-minio.local" {
			t.Errorf("S3Endpoint = %q, want %q (from config)", req.S3Endpoint, "https://config-minio.local")
		}
		if req.S3Region != "us-west-2" {
			t.Errorf("S3Region = %q, want %q (flag should override config)", req.S3Region, "us-west-2")
		}
		if req.S3CredentialsSecretName != "config-s3-creds" {
			t.Errorf("S3CredentialsSecretName = %q, want %q (from config)", req.S3CredentialsSecretName, "config-s3-creds")
		}
	})
}

func TestApplyS3Options_EnvVarsOverrideConfigCredentials(t *testing.T) {
	opts := newTestDiskOpts()
	t.Setenv("AWS_ACCESS_KEY_ID", "ENV_AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ENV_SECRET")
	h := newS3TestHandler(opts)

	cfg := &config.S3Config{
		Bucket:            "config-bucket",
		CredentialsSecret: "config-secret-ref",
	}

	withS3Defaults(cfg, func() {
		var req buildapitypes.BuildRequest
		if err := h.applyS3Options(nil, &req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.S3Credentials == nil {
			t.Fatal("expected S3Credentials from env vars")
		}
		if req.S3Credentials.AccessKeyID != "ENV_AKID" {
			t.Errorf("AccessKeyID = %q, want %q (env should override config)", req.S3Credentials.AccessKeyID, "ENV_AKID")
		}
		if req.S3CredentialsSecretName != "" {
			t.Errorf("S3CredentialsSecretName = %q, want empty (env vars take priority over config secret)", req.S3CredentialsSecretName)
		}
	})
}

func TestApplyS3Options_ConfigReadError(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	h := newS3TestHandler(opts)

	orig := s3DefaultsFn
	s3DefaultsFn = func() (*config.S3Config, error) {
		return nil, fmt.Errorf("reading config for S3 defaults: invalid character 'i' looking for beginning of value")
	}
	defer func() { s3DefaultsFn = orig }()

	var req buildapitypes.BuildRequest
	err := h.applyS3Options(nil, &req)
	if err == nil {
		t.Fatal("expected error from malformed config")
	}
	if !strings.Contains(err.Error(), "reading config") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "reading config")
	}
}

func TestApplyS3Options_NoBucketWithConfigNil(t *testing.T) {
	opts := newTestDiskOpts()
	h := newS3TestHandler(opts)

	withS3Defaults(nil, func() {
		var req buildapitypes.BuildRequest
		if err := h.applyS3Options(nil, &req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.S3Bucket != "" {
			t.Error("expected empty S3Bucket when no flag and no config")
		}
	})
}

func TestApplyS3Options_ExplicitEmptyBucketOverridesConfig(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = ""
	h := newS3TestHandler(opts)

	cmd := &cobra.Command{}
	cmd.Flags().StringVar(opts.S3Bucket, "s3-bucket", "", "")
	_ = cmd.Flags().Set("s3-bucket", "")

	cfg := &config.S3Config{
		Bucket: "config-bucket",
		Region: "us-east-1",
	}

	withS3Defaults(cfg, func() {
		var req buildapitypes.BuildRequest
		if err := h.applyS3Options(cmd, &req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.S3Bucket != "" {
			t.Errorf("S3Bucket = %q, want empty (explicit --s3-bucket '' should override config)", req.S3Bucket)
		}
	})
}

func TestApplyS3Options_ExplicitEmptyConnectionParamsOverrideConfig(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3FlagBucket
	*opts.S3Prefix = ""
	*opts.S3Endpoint = ""
	*opts.S3Region = ""
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	h := newS3TestHandler(opts)

	cmd := &cobra.Command{}
	cmd.Flags().StringVar(opts.S3Bucket, "s3-bucket", "", "")
	cmd.Flags().StringVar(opts.S3Prefix, "s3-prefix", "", "")
	cmd.Flags().StringVar(opts.S3Endpoint, "s3-endpoint", "", "")
	cmd.Flags().StringVar(opts.S3Region, "s3-region", "", "")
	_ = cmd.Flags().Set("s3-bucket", testS3FlagBucket)
	_ = cmd.Flags().Set("s3-prefix", "")
	_ = cmd.Flags().Set("s3-endpoint", "")
	_ = cmd.Flags().Set("s3-region", "")

	cfg := &config.S3Config{
		Bucket:   "config-bucket",
		Prefix:   "config-prefix/",
		Endpoint: "https://config-minio.local",
		Region:   "eu-central-1",
	}

	withS3Defaults(cfg, func() {
		var req buildapitypes.BuildRequest
		if err := h.applyS3Options(cmd, &req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.S3Prefix != "" {
			t.Errorf("S3Prefix = %q, want empty (explicit --s3-prefix '' should override config)", req.S3Prefix)
		}
		if req.S3Endpoint != "" {
			t.Errorf("S3Endpoint = %q, want empty (explicit --s3-endpoint '' should override config)", req.S3Endpoint)
		}
		if req.S3Region != "" {
			t.Errorf("S3Region = %q, want empty (explicit --s3-region '' should override config)", req.S3Region)
		}
	})
}

func TestApplyS3Options_MalformedConfigErrorsWhenNoS3Flags(t *testing.T) {
	opts := newTestDiskOpts()
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	h := newS3TestHandler(opts)

	orig := s3DefaultsFn
	s3DefaultsFn = func() (*config.S3Config, error) {
		return nil, fmt.Errorf("reading config for S3 defaults: invalid character 'i' looking for beginning of value")
	}
	defer func() { s3DefaultsFn = orig }()

	var req buildapitypes.BuildRequest
	err := h.applyS3Options(nil, &req)
	if err == nil {
		t.Fatal("expected error from malformed config even when no S3 flags are set")
	}
	if !strings.Contains(err.Error(), "reading config") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "reading config")
	}
}

func TestApplyS3Options_MalformedConfigErrorsWhenS3FlagSet(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	h := newS3TestHandler(opts)

	orig := s3DefaultsFn
	s3DefaultsFn = func() (*config.S3Config, error) {
		return nil, fmt.Errorf("reading config for S3 defaults: invalid character 'i' looking for beginning of value")
	}
	defer func() { s3DefaultsFn = orig }()

	var req buildapitypes.BuildRequest
	err := h.applyS3Options(nil, &req)
	if err == nil {
		t.Fatal("expected error from malformed config when --s3-bucket is set")
	}
	if !strings.Contains(err.Error(), "reading config") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "reading config")
	}
}
