package webhookdelivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

const (
	headerEvent     = "X-CAIB-Event"
	headerEventID   = "X-CAIB-Event-ID"
	headerTimestamp = "X-CAIB-Timestamp"
	headerSignature = "X-CAIB-Signature"

	maxRedirects         = 5
	maxResponseBodyBytes = 64 * 1024
	maxRetryAfter        = time.Hour
)

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type attemptResult struct {
	statusCode int32
	retryable  bool
	retryAfter time.Duration
	errorText  string
}

type deliveryRequest struct {
	URL       string
	Key       []byte
	Snapshot  *automotivev1alpha1.WebhookEventSnapshot
	Timestamp time.Time
	Config    automotivev1alpha1.WebhookNotificationsConfig
	TLSConfig *tls.Config
}

type sender interface {
	Send(context.Context, deliveryRequest) attemptResult
}

type httpSender struct {
	resolver resolver
	dialer   *net.Dialer
}

type destinationPolicy struct {
	allowHTTP       bool
	allowedHosts    map[string]struct{}
	allowedPrefixes []netip.Prefix
}

type policyError struct{}

func (policyError) Error() string { return "destination rejected by outbound policy" }

func newDestinationPolicy(config automotivev1alpha1.WebhookNotificationsConfig) (destinationPolicy, error) {
	policy := destinationPolicy{allowHTTP: config.AllowHTTP, allowedHosts: map[string]struct{}{}}
	if config.OutboundPolicy == nil {
		return policy, nil
	}
	for _, host := range config.OutboundPolicy.AllowedHostnames {
		host = normalizeHostname(host)
		if host == "" || strings.ContainsAny(host, "/:@[]") {
			return destinationPolicy{}, errors.New("outbound policy contains an invalid hostname")
		}
		policy.allowedHosts[host] = struct{}{}
	}
	for _, raw := range config.OutboundPolicy.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return destinationPolicy{}, errors.New("outbound policy contains an invalid CIDR")
		}
		policy.allowedPrefixes = append(policy.allowedPrefixes, prefix.Masked())
	}
	return policy, nil
}

func normalizeHostname(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func (p destinationPolicy) validateURL(endpoint *url.URL) error {
	if endpoint == nil || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return policyError{}
	}
	switch endpoint.Scheme {
	case "https":
	case "http":
		if !p.allowHTTP {
			return policyError{}
		}
	default:
		return policyError{}
	}
	host := normalizeHostname(endpoint.Hostname())
	if host == "" {
		return policyError{}
	}
	if p.hostAllowed(host) {
		return nil
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		host == "cluster.local" || strings.HasSuffix(host, ".cluster.local") ||
		host == "svc" || strings.HasSuffix(host, ".svc") {
		return policyError{}
	}
	if address, err := netip.ParseAddr(host); err == nil && !p.addressAllowed(address) {
		return policyError{}
	}
	return nil
}

func (p destinationPolicy) hostAllowed(host string) bool {
	_, ok := p.allowedHosts[normalizeHostname(host)]
	return ok
}

func (p destinationPolicy) addressAllowed(address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range p.allowedPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return address.IsGlobalUnicast() && !address.IsUnspecified() && !address.IsLoopback() && !address.IsPrivate() &&
		!address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast() && !address.IsMulticast() &&
		!isSharedAddress(address)
}

func isSharedAddress(address netip.Addr) bool {
	shared := netip.MustParsePrefix("100.64.0.0/10")
	return shared.Contains(address)
}

func (s *httpSender) Send(ctx context.Context, request deliveryRequest) attemptResult {
	policy, err := newDestinationPolicy(request.Config)
	if err != nil {
		return attemptResult{errorText: err.Error()}
	}
	endpoint, err := url.Parse(request.URL)
	if err != nil || policy.validateURL(endpoint) != nil {
		return attemptResult{errorText: policyError{}.Error()}
	}
	resolver := s.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := s.dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: time.Duration(request.Config.TimeoutSeconds) * time.Second}
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           policyDialContext(resolver, dialer, policy),
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       request.TLSConfig,
		TLSHandshakeTimeout:   time.Duration(request.Config.TimeoutSeconds) * time.Second,
		ResponseHeaderTimeout: time.Duration(request.Config.TimeoutSeconds) * time.Second,
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()

	timestamp := strconv.FormatInt(request.Timestamp.Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(request.Snapshot.Body))
	if err != nil {
		return attemptResult{errorText: policyError{}.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerEvent, request.Snapshot.Type)
	req.Header.Set(headerEventID, request.Snapshot.ID)
	req.Header.Set(headerTimestamp, timestamp)
	req.Header.Set(headerSignature, signature(request.Key, timestamp, request.Snapshot.Body))

	redirects := 0
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(request.Config.TimeoutSeconds) * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			redirects++
			if redirects > maxRedirects || policy.validateURL(req.URL) != nil {
				return policyError{}
			}
			if req.Response == nil || (req.Response.StatusCode != http.StatusTemporaryRedirect && req.Response.StatusCode != http.StatusPermanentRedirect) {
				return policyError{}
			}
			return nil
		},
	}
	response, err := client.Do(req)
	if err != nil {
		return classifyRequestError(err)
	}
	defer func() { _ = response.Body.Close() }()
	discardResponseBody(response.Body)
	return classifyResponse(response.StatusCode, response.Header.Get("Retry-After"), time.Now().UTC())
}

func discardResponseBody(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxResponseBodyBytes+1))
}

func policyDialContext(resolver resolver, dialer *net.Dialer, policy destinationPolicy) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, policyError{}
		}
		normalizedHost := normalizeHostname(host)
		addresses, err := resolver.LookupNetIP(ctx, "ip", normalizedHost)
		if err != nil || len(addresses) == 0 {
			return nil, errors.New("destination lookup failed")
		}
		if !policy.hostAllowed(normalizedHost) {
			for _, resolved := range addresses {
				if !policy.addressAllowed(resolved) {
					return nil, policyError{}
				}
			}
		}
		var dialErr error
		for _, resolved := range addresses {
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.String(), port))
			if err == nil {
				return connection, nil
			}
			dialErr = err
		}
		return nil, fmt.Errorf("destination connection failed: %w", dialErr)
	}
}

func signature(key []byte, timestamp string, body []byte) string {
	digest := hmac.New(sha256.New, key)
	_, _ = io.WriteString(digest, timestamp)
	_, _ = digest.Write([]byte{'.'})
	_, _ = digest.Write(body)
	return "v1=" + hex.EncodeToString(digest.Sum(nil))
}

func classifyRequestError(err error) attemptResult {
	var rejected policyError
	if errors.As(err, &rejected) {
		return attemptResult{errorText: rejected.Error()}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return attemptResult{retryable: true, errorText: "request timed out"}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return attemptResult{retryable: true, errorText: "request timed out"}
	}
	return attemptResult{retryable: true, errorText: "request failed"}
}

func classifyResponse(status int, retryAfter string, now time.Time) attemptResult {
	if status < 100 || status > 599 {
		return attemptResult{errorText: "receiver returned an invalid HTTP status"}
	}
	result := attemptResult{statusCode: int32(status)}
	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		return result
	}
	result.retryable = status == http.StatusRequestTimeout || status == http.StatusTooEarly ||
		status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
	result.errorText = fmt.Sprintf("receiver returned HTTP %d", status)
	if result.retryable {
		result.retryAfter = parseRetryAfter(retryAfter, now)
	}
	return result
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		if seconds >= int64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		return min(time.Duration(seconds)*time.Second, maxRetryAfter)
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return min(when.Sub(now), maxRetryAfter)
}
