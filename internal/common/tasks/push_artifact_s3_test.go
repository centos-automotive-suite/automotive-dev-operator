package tasks

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// awsStub records "aws s3 cp SRC s3://BUCKET/KEY" uploads as files under
// $S3_STUB_ROOT/BUCKET/KEY, so tests can inspect the resulting bucket layout.
const awsStub = `#!/bin/bash
case "$1 $2" in
  "s3 ls") exit 0 ;;
  "s3 cp")
    src="${@: -2:1}"
    dest="${@: -1}"
    path="$S3_STUB_ROOT/${dest#s3://}"
    mkdir -p "$(dirname "$path")"
    cp "$src" "$path"
    ;;
  *) echo "unexpected aws call: $*" >&2; exit 1 ;;
esac
`

type s3PushResult struct {
	objects map[string]string // key -> content
	url     string
	shared  []string // files left in the shared workspace
}

func runPushArtifactS3(t *testing.T, prefix, artifact string, files map[string]string) s3PushResult {
	t.Helper()
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared")
	results := filepath.Join(dir, "results")
	bin := filepath.Join(dir, "bin")
	root := filepath.Join(dir, "bucket")
	for _, d := range []string{shared, results, bin, root} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range files {
		path := filepath.Join(shared, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "aws"), []byte(awsStub), 0o755); err != nil {
		t.Fatal(err)
	}

	script := "emit_progress() { :; }\n" + strings.NewReplacer(
		"/workspace/shared", shared,
		"/workspace/s3-auth", filepath.Join(dir, "no-s3-auth"),
		"/etc/pki/ca-trust/custom", filepath.Join(dir, "no-ca"),
		"/tekton/results", results,
	).Replace(pushArtifactS3Script)
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"),
		"S3_STUB_ROOT="+root,
		"S3_BUCKET=bucket",
		"S3_PREFIX="+prefix,
		"S3_ENDPOINT=",
		"S3_REGION=us-east-1",
		"S3_INSECURE=false",
		"ARTIFACT_FILE="+artifact,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("push_artifact_s3.sh failed: %v\n%s", err, out)
	}

	res := s3PushResult{objects: map[string]string{}}
	bucket := filepath.Join(root, "bucket")
	walk := func(base string, visit func(rel string, content []byte)) {
		t.Helper()
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(base, path)
			if err != nil {
				return err
			}
			visit(filepath.ToSlash(rel), content)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	walk(bucket, func(rel string, content []byte) { res.objects[rel] = string(content) })
	walk(shared, func(rel string, _ []byte) { res.shared = append(res.shared, rel) })
	sort.Strings(res.shared)
	url, err := os.ReadFile(filepath.Join(results, "S3_URL"))
	if err != nil {
		t.Fatal(err)
	}
	res.url = string(url)
	return res
}

func sha256Line(content, name string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

func objectKeys(objects map[string]string) []string {
	keys := make([]string, 0, len(objects))
	for key := range objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Every uploaded artifact gets a sha256sum-format sidecar named after the
// object, so consumers can verify a download with "sha256sum -c".
func TestPushArtifactS3UploadsChecksumSidecars(t *testing.T) {
	t.Run("single file", func(t *testing.T) {
		res := runPushArtifactS3(t, "builds/b1/", "autosd-qemu.raw.xz", map[string]string{
			"autosd-qemu.raw.xz": "disk",
		})
		want := map[string]string{
			"builds/b1/autosd-qemu.raw.xz":        "disk",
			"builds/b1/autosd-qemu.raw.xz.sha256": sha256Line("disk", "autosd-qemu.raw.xz"),
		}
		if got := objectKeys(res.objects); strings.Join(got, ",") != strings.Join(objectKeys(want), ",") {
			t.Fatalf("objects = %v, want %v", got, objectKeys(want))
		}
		for key, content := range want {
			if res.objects[key] != content {
				t.Errorf("%s = %q, want %q", key, res.objects[key], content)
			}
		}
		if res.url != "s3://bucket/builds/b1/autosd-qemu.raw.xz" {
			t.Errorf("S3_URL = %q", res.url)
		}
		if strings.Join(res.shared, ",") != "autosd-qemu.raw.xz" {
			t.Errorf("shared workspace gained files: %v", res.shared)
		}
	})

	t.Run("separate partitions", func(t *testing.T) {
		parts := "autosd-ride4.simg.tar.xz-parts/"
		res := runPushArtifactS3(t, "ws/RideSX4/key.aboot", "autosd-ride4.simg.tar.xz", map[string]string{
			parts + "boot_a.simg.xz":        "boot",
			parts + "boot_a.simg.xz.size":   "4",
			parts + "system_a.simg.xz":      "system",
			parts + "system_a.simg.xz.size": "6",
			parts + "aib-manifest.yml":      "name: x",
		})
		want := map[string]string{
			"ws/RideSX4/key.aboot/boot_a.simg.xz":          "boot",
			"ws/RideSX4/key.aboot/boot_a.simg.xz.sha256":   sha256Line("boot", "boot_a.simg.xz"),
			"ws/RideSX4/key.aboot/system_a.simg.xz":        "system",
			"ws/RideSX4/key.aboot/system_a.simg.xz.sha256": sha256Line("system", "system_a.simg.xz"),
		}
		if got := objectKeys(res.objects); strings.Join(got, ",") != strings.Join(objectKeys(want), ",") {
			t.Fatalf("objects = %v, want %v", got, objectKeys(want))
		}
		for key, content := range want {
			if res.objects[key] != content {
				t.Errorf("%s = %q, want %q", key, res.objects[key], content)
			}
		}
		if res.url != "s3://bucket/ws/RideSX4/key.aboot/" {
			t.Errorf("S3_URL = %q", res.url)
		}
		if len(res.shared) != 5 {
			t.Errorf("shared workspace changed: %v", res.shared)
		}
	})
}
