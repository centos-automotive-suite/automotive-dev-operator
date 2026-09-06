package webhookdelivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addresses := r[host]
	if len(addresses) == 0 {
		return nil, errors.New("host not found")
	}
	return addresses, nil
}

type countingResolver struct {
	mu        sync.Mutex
	addresses map[string][]netip.Addr
	lookups   int
}

func (r *countingResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups++
	addresses := r.addresses[host]
	if len(addresses) == 0 {
		return nil, errors.New("host not found")
	}
	return addresses, nil
}

func transportRequest(endpoint string) deliveryRequest {
	return deliveryRequest{
		URL:       endpoint,
		Key:       []byte("01234567890123456789012345678901"),
		Timestamp: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC),
		Snapshot: &automotivev1alpha1.WebhookEventSnapshot{
			ID: "event-42", Type: "build.terminal", Time: metav1.NewTime(time.Date(2026, 9, 6, 11, 59, 0, 0, time.UTC)),
			Body: []byte(`{"id":"event-42","type":"build.terminal"}`),
		},
		Config: automotivev1alpha1.WebhookNotificationsConfig{
			AllowHTTP: true, TimeoutSeconds: 2,
			OutboundPolicy: &automotivev1alpha1.OutboundPolicyConfig{AllowedCIDRs: []string{"127.0.0.0/8"}},
		},
	}
}

func TestHTTPSenderSignsAndPreservesBodyAcrossRedirect(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/first" {
			http.Redirect(response, request, "/final", http.StatusTemporaryRedirect)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		if request.Header.Get("Content-Type") != "application/json" ||
			request.Header.Get(headerEvent) != "build.terminal" ||
			request.Header.Get(headerEventID) != "event-42" ||
			request.Header.Get(headerTimestamp) != "1788696000" {
			t.Errorf("unexpected delivery headers: %v", request.Header)
		}
		digest := hmac.New(sha256.New, []byte("01234567890123456789012345678901"))
		_, _ = digest.Write([]byte("1788696000."))
		_, _ = digest.Write(body)
		wantSignature := "v1=" + hex.EncodeToString(digest.Sum(nil))
		if request.Header.Get(headerSignature) != wantSignature {
			t.Errorf("signature = %q, want %q", request.Header.Get(headerSignature), wantSignature)
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &countingResolver{addresses: map[string][]netip.Addr{
		"receiver.test": {netip.MustParseAddr("127.0.0.1")},
	}}
	request := transportRequest("http://receiver.test:" + parsed.Port() + "/first")
	request.Config.OutboundPolicy = &automotivev1alpha1.OutboundPolicyConfig{AllowedHostnames: []string{"receiver.test"}}
	result := (&httpSender{resolver: resolver}).Send(context.Background(), request)
	if result.errorText != "" || result.statusCode != http.StatusNoContent {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(bodies) != 1 || !bytes.Equal(bodies[0], request.Snapshot.Body) {
		t.Fatalf("body changed across redirect: %q", bodies)
	}
	if resolver.lookups != 2 {
		t.Fatalf("DNS lookups = %d, want one per dial", resolver.lookups)
	}
}

func TestHTTPSenderRejectsUnsafeDestinationsAndRedirects(t *testing.T) {
	tests := []string{
		"http://127.0.0.1/hook",
		"https://[::1]/hook",
		"https://service.test.svc.cluster.local/hook",
		"https://user:password@example.com/hook",
		"https://example.com/hook#fragment",
	}
	for _, endpoint := range tests {
		t.Run(endpoint, func(t *testing.T) {
			request := transportRequest(endpoint)
			request.Config.OutboundPolicy = nil
			result := (&httpSender{}).Send(context.Background(), request)
			if result.errorText != "destination rejected by outbound policy" || result.retryable {
				t.Fatalf("unsafe endpoint result: %+v", result)
			}
		})
	}
	httpRequest := transportRequest("http://receiver.example/hook")
	httpRequest.Config.AllowHTTP = false
	if result := (&httpSender{}).Send(context.Background(), httpRequest); result.errorText != "destination rejected by outbound policy" {
		t.Fatalf("plain HTTP result: %+v", result)
	}

	redirectHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		redirectHits++
		response.Header().Set("Location", "http://127.0.0.1:1/private")
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port := parsed.Port()
	request := transportRequest("http://receiver.test:" + port + "/hook")
	request.Config.OutboundPolicy = &automotivev1alpha1.OutboundPolicyConfig{AllowedHostnames: []string{"receiver.test"}}
	sender := &httpSender{resolver: staticResolver{"receiver.test": {netip.MustParseAddr("127.0.0.1")}}}
	result := sender.Send(context.Background(), request)
	if result.errorText != "destination rejected by outbound policy" || result.retryable || redirectHits != 1 {
		t.Fatalf("unsafe redirect result: %+v, hits=%d", result, redirectHits)
	}
}

func TestHTTPSenderTimeoutIsRetryableAndSanitized(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	t.Cleanup(server.Close)
	request := transportRequest(server.URL)
	request.Config.TimeoutSeconds = 1
	result := (&httpSender{}).Send(context.Background(), request)
	close(release)
	if !result.retryable || result.errorText != "request timed out" || strings.Contains(result.errorText, request.URL) {
		t.Fatalf("timeout result: %+v", result)
	}
}

func TestPolicyDialRejectsDNSRebinding(t *testing.T) {
	policy, err := newDestinationPolicy(automotivev1alpha1.WebhookNotificationsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	resolver := staticResolver{"receiver.test": {
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("127.0.0.1"),
	}}
	_, err = policyDialContext(resolver, nilDialer(), policy)(context.Background(), "tcp", "receiver.test:443")
	var rejected policyError
	if !errors.As(err, &rejected) {
		t.Fatalf("mixed public/private DNS result was not rejected: %v", err)
	}
}

func nilDialer() *net.Dialer {
	return &net.Dialer{Timeout: time.Millisecond}
}

func TestHTTPSenderUsesCustomTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	certificate := server.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	request := transportRequest(server.URL)
	request.Config.AllowHTTP = false
	request.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	result := (&httpSender{}).Send(context.Background(), request)
	if result.errorText != "" || result.statusCode != http.StatusAccepted {
		t.Fatalf("custom trust result: %+v", result)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if len(pemBytes) == 0 {
		t.Fatal("failed to encode test certificate")
	}
}

func TestRetryClassificationAndResponseBound(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	for status, retryable := range map[int]bool{
		http.StatusNoContent: false, http.StatusBadRequest: false, http.StatusGone: false,
		http.StatusRequestTimeout: true, http.StatusTooEarly: true,
		http.StatusTooManyRequests: true, http.StatusServiceUnavailable: true,
	} {
		result := classifyResponse(status, "", now)
		if result.retryable != retryable {
			t.Errorf("status %d retryable = %t, want %t", status, result.retryable, retryable)
		}
	}
	if result := classifyResponse(600, "", now); result.statusCode != 0 || result.retryable ||
		result.errorText != "receiver returned an invalid HTTP status" {
		t.Fatalf("invalid status result: %+v", result)
	}
	if got := parseRetryAfter("7200", now); got != maxRetryAfter {
		t.Errorf("bounded Retry-After = %v, want %v", got, maxRetryAfter)
	}
	if got := parseRetryAfter("9999999999", now); got != maxRetryAfter {
		t.Errorf("large Retry-After = %v, want %v", got, maxRetryAfter)
	}
	if got := parseRetryAfter(now.Add(30*time.Second).Format(http.TimeFormat), now); got != 30*time.Second {
		t.Errorf("date Retry-After = %v, want 30s", got)
	}

	reader := &countingReader{remaining: maxResponseBodyBytes * 4}
	discardResponseBody(reader)
	if reader.read != maxResponseBodyBytes+1 {
		t.Fatalf("response bytes read = %d, want %d", reader.read, maxResponseBodyBytes+1)
	}
}

type countingReader struct {
	remaining int64
	read      int64
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	count := min(int64(len(buffer)), r.remaining)
	for i := range int(count) {
		buffer[i] = '0' + byte(i%10)
	}
	r.remaining -= count
	r.read += count
	return int(count), nil
}

func TestSignatureUsesExactSecretBytes(t *testing.T) {
	first := signature([]byte("secret\n"), "123", []byte("{}"))
	second := signature([]byte("secret"), "123", []byte("{}"))
	if first == second || !strings.HasPrefix(first, "v1=") {
		t.Fatalf("signature did not preserve exact key bytes: %q %q", first, second)
	}
}
