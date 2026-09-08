package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
)

type contractTransport func(*http.Request) (*http.Response, error)

func (f contractTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNotificationClientRoundTrip(t *testing.T) {
	callback := &buildapi.BuildCallback{URL: "https://receiver.example.com/hook", Secret: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))}
	build := buildapi.BuildRequest{Name: "build", Manifest: "name: image", ExternalID: "job-42", Callback: callback}
	flash := buildapi.FlashRequest{Name: "flash-job", ExternalID: "job-43", Callback: callback, ImageRef: "quay.io/example/os:latest", ClientConfig: "client-config"}
	c, err := New("https://api.example.com", WithHTTPClient(&http.Client{Transport: contractTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s", r.Method)
		}
		switch r.URL.Path {
		case "/v1/builds":
			var decoded buildapi.BuildRequest
			if err := json.NewDecoder(r.Body).Decode(&decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, build) {
				t.Fatal("build request fields changed in transport")
			}
		case "/v1/flash":
			var decoded buildapi.FlashRequest
			if err := json.NewDecoder(r.Body).Decode(&decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, flash) {
				t.Fatal("flash request fields changed in transport")
			}
		default:
			t.Fatalf("unexpected route: %s", r.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"name":"accepted","phase":"Pending","externalId":"caller-id","notification":{"state":"Pending","attempts":0}}`))}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.CreateBuild(context.Background(), build)
	if err != nil {
		t.Fatal(err)
	}
	if b.Phase != "Pending" || b.ExternalID != "caller-id" || b.Notification.State != "Pending" {
		t.Fatalf("build response fields missing: %+v", b)
	}
	f, err := c.CreateFlash(context.Background(), flash)
	if err != nil {
		t.Fatal(err)
	}
	if f.Phase != "Pending" || f.ExternalID != "caller-id" || f.Notification.State != "Pending" {
		t.Fatalf("flash response fields missing: %+v", f)
	}
}
