package buildcmd

import (
	"testing"

	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
)

const (
	testS3Bucket    = "my-bucket"
	testS3AccessKey = "AKID"
)

func newS3TestHandler(opts Options) *Handler {
	if opts.HandleError == nil {
		opts.HandleError = func(_ error) {}
	}
	return NewHandler(opts)
}

func TestApplyS3Options_NoBucket(t *testing.T) {
	opts := newTestDiskOpts()
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	if err := h.applyS3Options(&req); err != nil {
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
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	if err := h.applyS3Options(&req); err != nil {
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
	if err := h.applyS3Options(&req); err != nil {
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

func TestApplyS3Options_FlagOverridesEnvVar(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	*opts.S3AccessKeyID = "FLAG_AKID"
	*opts.S3SecretAccessKey = "FLAG_SECRET"
	t.Setenv("AWS_ACCESS_KEY_ID", "ENV_AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ENV_SECRET")
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	if err := h.applyS3Options(&req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.S3Credentials.AccessKeyID != "FLAG_AKID" {
		t.Errorf("AccessKeyID = %q, want flag value %q", req.S3Credentials.AccessKeyID, "FLAG_AKID")
	}
	if req.S3Credentials.SecretAccessKey != "FLAG_SECRET" {
		t.Errorf("SecretAccessKey = %q, want flag value %q", req.S3Credentials.SecretAccessKey, "FLAG_SECRET")
	}
}

func TestApplyS3Options_SecretName(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.S3Bucket = testS3Bucket
	*opts.S3CredentialsSecret = "shared-s3-creds"
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	if err := h.applyS3Options(&req); err != nil {
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
	h := newS3TestHandler(opts)

	var req buildapitypes.BuildRequest
	err := h.applyS3Options(&req)
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
	err := h.applyS3Options(&req)
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
	err := h.applyS3Options(&req)
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
	err := h.applyS3Options(&req)
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
	err := h.applyS3Options(&req)
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
	if err := h.applyS3Options(&req); err != nil {
		t.Fatalf("expected no error for IAM-based auth, got: %v", err)
	}
	if req.S3Credentials != nil {
		t.Error("expected nil S3Credentials for IAM-based auth")
	}
}
