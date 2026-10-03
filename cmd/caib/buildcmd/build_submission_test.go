package buildcmd

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/spf13/cobra"
)

func TestManifestBuildSubmission(t *testing.T) {
	t.Setenv("CAIB_SKIP_MANIFEST_VALIDATION", "1")
	t.Setenv("CAIB_CLIENT_WORKSPACE_UPLOAD", "0")
	t.Setenv("REGISTRY_URL", "registry.example")
	t.Setenv("REGISTRY_USERNAME", "test-user")
	t.Setenv("REGISTRY_PASSWORD", "test-password")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	originalS3Defaults := s3DefaultsFn
	s3DefaultsFn = func() (*config.S3Config, error) { return nil, nil }
	t.Cleanup(func() { s3DefaultsFn = originalS3Defaults })
	for _, development := range []bool{false, true} {
		for _, source := range []string{"local defaults", "local flags", "git defaults", "git flags"} {
			name := "bootc/" + source
			if development {
				name = "development/" + source
			}
			t.Run(name, func(t *testing.T) {
				git := strings.HasPrefix(source, "git")
				explicit := strings.HasSuffix(source, "flags")
				root := t.TempDir()
				manifestPath := filepath.Join(root, "example.aib.yml")
				manifest := "name: example\ntarget: manifest-board\ncontent:\n  add_files:\n    - path: /etc/example.conf\n      source_path: example.conf\n"
				lockfile := `{"version":1}`
				callbackSecret := strings.Repeat("s", 32)
				clientConfig := "endpoint: grpc.example:443\nmetadata:\n  name: test-client\n"
				for path, content := range map[string]string{
					manifestPath: manifest, filepath.Join(root, "example.conf"): "file content",
					filepath.Join(root, "input.lock"): lockfile, filepath.Join(root, "callback.secret"): callbackSecret,
					filepath.Join(root, "client.yaml"): clientConfig,
				} {
					writeUploadTestFile(t, path, content)
				}
				fixture := &manifestSubmissionServer{t: t, git: git}
				srv := httptest.NewServer(fixture)
				defer srv.Close()
				opts := newTestOpts()
				opts.Connection.ServerURL, opts.Connection.AuthToken = srv.URL, "test-token"
				opts.Build.Name, opts.Build.Mode = "test-build", "package"
				opts.Build.BuilderImage, opts.Build.RebuildBuilder = "builder.example/image:latest", true
				opts.Build.BuilderCachePolicy = "reuse"
				opts.Build.AIBExtraArgs, opts.Build.CustomDefs = []string{"user-arg"}, []string{"user=value"}
				opts.Build.Lockfile = filepath.Join(root, "input.lock")
				opts.Registry.ContainerPush, opts.Registry.ExportOCI = "registry.example/container:latest", "registry.example/disk:latest"
				opts.Callback.URL, opts.Callback.SecretFile, opts.Callback.ExternalID = "https://receiver.example/result", filepath.Join(root, "callback.secret"), "external-id"
				opts.Flash.AfterBuild, opts.Flash.JumpstarterClient = true, filepath.Join(root, "client.yaml")
				opts.Flash.LeaseName, opts.Flash.LeaseDuration = "existing-lease", "unused-duration"
				opts.S3.Bucket, opts.S3.CredentialsSecret = "artifacts", "s3-secret"
				if git {
					opts.Build.GitURL, opts.Build.GitRef, opts.Build.GitLockfile, opts.Build.Lockfile = "https://git.example/os.git", "main", "input.lock", ""
					manifestPath = filepath.Base(manifestPath)
				}
				cmd := &cobra.Command{}
				cmd.Flags().StringVar(&opts.Build.Target, "target", "qemu", "")
				cmd.Flags().StringVar(&opts.Build.Architecture, "arch", "amd64", "")
				format := &opts.Build.DiskFormat
				if development {
					format = &opts.Build.ExportFormat
				}
				cmd.Flags().StringVar(format, "format", "simg", "")
				if explicit {
					for flag, value := range map[string]string{"target": "explicit-board", "arch": "amd64", "format": "raw"} {
						if err := cmd.Flags().Set(flag, value); err != nil {
							t.Fatal(err)
						}
					}
				}
				var buildErr error
				opts.HandleError = func(err error) { buildErr = err }
				h := NewHandler(opts)
				if development {
					h.RunBuildDev(cmd, []string{manifestPath})
				} else {
					h.RunBuild(cmd, []string{manifestPath})
				}
				srv.Close()
				if buildErr != nil || fixture.submitted == nil {
					t.Fatalf("submitted=%v, error=%v", fixture.submitted != nil, buildErr)
				}
				req := fixture.submitted
				wantMode := buildcontract.ModeBootc
				if development {
					wantMode = buildcontract.ModePackage
				}
				if req.Mode != wantMode || req.BuildDiskImage == development || (req.ContainerPush != "") == development || (req.BuilderImage != "") == development || req.RebuildBuilder == development || (req.BuilderCachePolicy == "reuse") == development {
					t.Fatalf("mode-specific fields changed: %+v", req)
				}
				assertManifestSource(t, req, git, explicit, fixture.uploaded, lockfile)
				assertManifestExports(t, req, opts, clientConfig, callbackSecret)

			})
		}
	}
}

type manifestSubmissionServer struct {
	t         *testing.T
	git       bool
	submitted *buildcontract.BuildRequest
	uploaded  bool
}

func (f *manifestSubmissionServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var response any
	switch {
	case strings.HasSuffix(r.URL.Path, "/progress"):
		w.WriteHeader(http.StatusNotFound)
		return
	case r.URL.Path == "/v1/config":
		defaults := buildcontract.TargetDefaults{Architecture: "arm64", DefaultFormat: "qcow2", ExtraArgs: []string{"target-default"}}
		response = buildcontract.OperatorConfigResponse{
			TargetDefaults:     map[string]buildcontract.TargetDefaults{"manifest-board": defaults, "explicit-board": defaults},
			JumpstarterTargets: map[string]buildcontract.JumpstarterTarget{"manifest-board": {}, "explicit-board": {}},
		}
	case r.Method == http.MethodPost && r.URL.Path == "/v1/builds":
		f.submitted = &buildcontract.BuildRequest{}
		if err := json.NewDecoder(r.Body).Decode(f.submitted); err != nil {
			f.t.Error(err)
		}
		w.WriteHeader(http.StatusAccepted)
		response = buildcontract.BuildResponse{Name: "test-build", Phase: "Pending"}
	case r.Method == http.MethodPost && r.URL.Path == "/v1/builds/test-build/uploads":
		reader, err := r.MultipartReader()
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.t.Error(err)
				return
			}
			data, err := io.ReadAll(part)
			if err != nil {
				f.t.Error(err)
			}
			if part.FormName() == "file" {
				f.uploaded = string(data) == "file content"
			}
		}
		response = map[string]string{"message": "uploaded"}
	case r.URL.Path == "/v1/builds/test-build":
		phase := "Completed"
		if !f.git && !f.uploaded {
			phase = "Uploading"
		}
		response = buildcontract.BuildResponse{Name: "test-build", Phase: phase}
	default:
		f.t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		f.t.Error(err)
	}
}

func assertManifestSource(t *testing.T, req *buildcontract.BuildRequest, git, explicit, uploaded bool, lockfile string) {
	t.Helper()
	wantTarget, wantArch, wantFormat := "manifest-board", "arm64", "qcow2"
	wantArgs := []string{"target-default", "user-arg"}
	if explicit {
		wantTarget, wantArch, wantFormat = "explicit-board", "amd64", "raw"
	}
	if git {
		wantArgs = []string{"user-arg"}
		if !explicit {
			wantTarget, wantArch, wantFormat = "", "", ""
		}
		if req.GitSource == nil || req.Manifest != "" || req.Lockfile != "" || req.HasLocalFiles {
			t.Fatalf("Git source changed: %+v", req)
		}
	} else if req.GitSource != nil || req.Lockfile != lockfile || !req.HasLocalFiles || !uploaded {
		t.Fatalf("local source/upload changed: %+v, uploaded=%v", req, uploaded)
	}
	if string(req.Target) != wantTarget || string(req.Architecture) != wantArch || string(req.ExportFormat) != wantFormat || !reflect.DeepEqual(req.AIBExtraArgs, wantArgs) {
		t.Fatalf("precedence changed: target=%q arch=%q format=%q args=%v", req.Target, req.Architecture, req.ExportFormat, req.AIBExtraArgs)
	}
}

func assertManifestExports(t *testing.T, req *buildcontract.BuildRequest, opts Options, clientConfig, callbackSecret string) {
	t.Helper()
	if req.RegistryCredentials == nil || req.RegistryCredentials.Username != "test-user" || req.ExportOCI != opts.Registry.ExportOCI || req.S3Bucket != "artifacts" || req.S3CredentialsSecretName != "s3-secret" {
		t.Fatalf("export options changed: %+v", req)
	}
	if !req.FlashEnabled || req.FlashLeaseName != "existing-lease" || req.FlashLeaseDuration != "" || req.FlashClientConfig != base64.StdEncoding.EncodeToString([]byte(clientConfig)) || req.ExternalID != "external-id" || req.Callback == nil || req.Callback.Secret != base64.StdEncoding.EncodeToString([]byte(callbackSecret)) {
		t.Fatalf("flash/notification options changed: %+v", req)
	}
}
