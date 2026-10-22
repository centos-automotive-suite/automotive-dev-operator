package tasks

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func runBuildCostScript(t *testing.T, body string, env ...string) string {
	t.Helper()
	functions := shellFunctions(t, buildImageScript, "filesystem_used_bytes() {", "validate_config() {")
	cmd := exec.Command("bash", "-c", functions+"\n"+body)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build cost script failed: %v\n%s", err, out)
	}
	return string(out)
}

// The controller drops the whole result on malformed JSON, and printf %d turns
// an empty measurement into 0, so unmeasured values must be emitted as null.
func TestBuildTimingReportsUnmeasuredCostAsNull(t *testing.T) {
	out := runBuildCostScript(t, `build_timing_json 2 90 8 100 734003200 "" 0`)
	var timing map[string]any
	if err := json.Unmarshal([]byte(out), &timing); err != nil {
		t.Fatalf("build-timing is not JSON: %v: %q", err, out)
	}
	want := map[string]any{
		"setup_s": float64(2), "build_s": float64(90), "post_build_s": float64(8), "total_s": float64(100),
		"artifact_bytes": float64(734003200), "downloaded_bytes": nil, "peak_workspace_bytes": float64(0),
	}
	if !reflect.DeepEqual(timing, want) {
		t.Fatalf("build-timing = %v, want %v", timing, want)
	}
}

// The artifact is what artifact-filename names: the disk when one was built,
// otherwise the container. Part sizes exclude the uncompressed .size records.
func TestArtifactBytesReportsPublishedArtifact(t *testing.T) {
	for _, tc := range []struct{ name, finalName, want string }{
		{"container and disk", "autosd-qemu.qcow2.gz", "1000"},
		{"disk parts", "autosd-qemu.simg.tar.gz", "300"},
		{"container only", "container:quay.io/example/os:latest", "5000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			parts := filepath.Join(dir, "autosd-qemu.simg.tar.gz-parts")
			for name, size := range map[string]int{
				filepath.Join(dir, "autosd-qemu.qcow2.gz"): 1000,
				filepath.Join(parts, "boot.img.gz"):        100,
				filepath.Join(parts, "boot.img.gz.size"):   9,
				filepath.Join(parts, "system.img.gz"):      200,
			} {
				if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, make([]byte, size), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// A pull downloads the config and layers the manifest lists; the
			// manifest and the layout's directories are not part of the size.
			manifest := `{"config":{"digest":"sha256:c0","size":500},"layers":[{"digest":"sha256:l1","size":3000},{"digest":"sha256:l2","size":1500}]}`
			manifestDigest := strings.Repeat("e", 64)
			for name, content := range map[string]string{
				filepath.Join(dir, "oci", "index.json"):                      `{"manifests":[{"digest":"sha256:` + manifestDigest + `"}]}`,
				filepath.Join(dir, "oci", "blobs", "sha256", manifestDigest): manifest,
			} {
				if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out := runBuildCostScript(t, `
file_size() { wc -c < "$1" | tr -d ' '; }
GET_SIZE_CMD=file_size
WORKSPACE_PATH="$TEST_DIR"
FINAL_NAME="$TEST_FINAL_NAME"
CONTAINER_IMAGE_BYTES=$(oci_image_bytes "$TEST_DIR/oci")
artifact_bytes
`, "TEST_DIR="+dir, "TEST_FINAL_NAME="+tc.finalName)
			if out != tc.want {
				t.Fatalf("artifact bytes = %q, want %s", out, tc.want)
			}
		})
	}
}

// Scratch space is released before the build ends, so the final usage
// understates what the workspace volume had to hold.
func TestWorkspacePeakOutlivesReleasedScratch(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "usage"), []byte("100\n500\n300\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resultStart := strings.LastIndex(buildImageScript, "\nBUILD_END_TIME=")
	if resultStart < 0 {
		t.Fatal("build script has no result-writing block")
	}
	out := runBuildCostScript(t, `
df() {
  local calls value
  calls=$(( $(cat "$TEST_DIR/calls" 2>/dev/null || echo 0) + 1 ))
  echo "$calls" > "$TEST_DIR/calls"
  value=$(sed -n "${calls}p" "$TEST_DIR/usage")
  [ -n "$value" ] || value=$(tail -n 1 "$TEST_DIR/usage")
  printf '     Used\n%s\n' "$value"
}
sleep() { command sleep 0.01; }
WORKSPACE_PATH="$TEST_DIR"
WORKSPACE_PEAK_FILE="$TEST_DIR/peak"
trap 'kill "$WORKSPACE_SAMPLER_PID" 2>/dev/null || true; wait "$WORKSPACE_SAMPLER_PID" 2>/dev/null || true' EXIT
start_workspace_sampler
for ((i=0; i<200; i++)); do
  [ "$(cat "$TEST_DIR/calls" 2>/dev/null)" -ge 4 ] 2>/dev/null && break
  command sleep 0.01
done
[ "$i" -lt 200 ] || { echo 'workspace sampler did not advance'; exit 1; }
log_elapsed() { :; }
network_rx_bytes() { :; }
write_result() { printf '%s' "$2" > "$TEST_DIR/result.json"; }
`+buildImageScript[resultStart:]+`
[ -z "$WORKSPACE_SAMPLER_PID" ] || { echo 'workspace sampler PID was not cleared in the parent'; exit 1; }
`, "TEST_DIR="+dir)
	if strings.Contains(out, "Terminated") {
		t.Fatalf("sampler termination leaked into the build log: %s", out)
	}
	result, err := os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var timing struct {
		Peak int64 `json:"peak_workspace_bytes"`
	}
	if err := json.Unmarshal(result, &timing); err != nil {
		t.Fatal(err)
	}
	if timing.Peak != 500 {
		t.Fatalf("peak = %d, want 500", timing.Peak)
	}
}

// /proc/net follows the pod network namespace. Only the default-route
// interface carries downloads; bridges and loopback would double count.
func TestNetworkRxBytesUsesDefaultRouteInterface(t *testing.T) {
	dev := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999999    1000    0    0    0     0          0         0  9999999    1000    0    0    0     0       0          0
  eth0: 734003200  500000    0    0    0     0          0         0 12345678   90000    0    0    0     0       0          0
podman0: 734003200  500000    0    0    0     0          0         0 734003200  500000    0    0    0     0       0          0
`
	for _, tc := range []struct{ name, route, ipv6Route, want string }{
		{
			name:  "ipv4 default route",
			route: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\npodman0\t0000580A\t00000000\t0001\t0\t0\t0\t00FFFFFF\neth0\t00000000\t0100800A\t0003\t0\t0\t0\t00000000\n",
			want:  "734003200",
		},
		{
			name:      "ipv6 only",
			route:     "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n",
			ipv6Route: "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd000000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n",
			want:      "734003200",
		},
		{
			name:  "no default route",
			route: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n",
			want:  "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range map[string]string{"dev": dev, "route": tc.route, "ipv6_route": tc.ipv6Route} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out := runBuildCostScript(t, `network_rx_bytes "$TEST_DIR"`, "TEST_DIR="+dir)
			if strings.TrimSpace(out) != tc.want {
				t.Fatalf("rx bytes = %q, want %q", out, tc.want)
			}
		})
	}
}
