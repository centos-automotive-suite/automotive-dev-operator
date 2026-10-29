package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceRunStreamDurationHeader(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"", 40 * time.Second},
		{"60", time.Minute},
		{"0.01", 10 * time.Millisecond},
		{"0.000000001", time.Nanosecond},
		{"9223372036", 9223372036 * time.Second},
		{"0.0000000001", 0}, {"9223372036.854776", 0},
		{"0", 0}, {"-1", 0}, {"invalid", 0}, {"NaN", 0}, {"+Inf", 0}, {"1e300", 0},
	} {
		t.Run(tc.header, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Log-Stream-Seconds", tc.header)
				_, _ = io.WriteString(w, "raw log\x00")
			}))
			defer server.Close()
			api, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := api.WorkspaceRunLogs(context.Background(), "dev", "run", true, 0)
			if tc.want == 0 {
				if err == nil || !strings.Contains(err.Error(), "invalid workspace log stream duration") {
					t.Fatalf("invalid cap accepted: stream=%+v err=%v", stream, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stream.Close() }()
			data, err := io.ReadAll(stream)
			if err != nil || stream.StreamDuration != tc.want || string(data) != "raw log\x00" {
				t.Fatalf("stream cap: %s, data=%q err=%v", stream.StreamDuration, data, err)
			}
		})
	}
}
