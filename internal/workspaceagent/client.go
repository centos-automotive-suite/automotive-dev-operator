package workspaceagent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Client calls a workspace agent's API. A failure the agent reports is an
// *Error with its HTTP status; any other error means the agent could not be
// reached or answered badly.
type Client struct {
	base   string
	token  string
	http   *http.Client
	dialer *websocket.Dialer
}

// NewClient returns a client for the agent at baseURL that sends token. roots
// verifies the agent's certificate; nil uses the system pool.
func NewClient(baseURL, token string, roots *x509.CertPool) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	// Callers build a client per request, so an idle connection would never
	// be reused, only left open.
	transport.DisableKeepAlives = true
	return &Client{
		base:   strings.TrimRight(baseURL, "/"),
		token:  token,
		http:   &http.Client{Transport: transport},
		dialer: &websocket.Dialer{Proxy: transport.Proxy, TLSClientConfig: transport.TLSClientConfig, HandshakeTimeout: 30 * time.Second},
	}
}

// request sends body as JSON, or as it is when it is already an io.Reader.
func (c *Client) request(ctx context.Context, method, path string, body any) (*http.Response, error) {
	reader, raw := body.(io.Reader)
	if body != nil && !raw {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil && !raw {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer func() { _ = resp.Body.Close() }()
		return nil, responseError(resp)
	}
	return resp, nil
}

// responseError is the failure an agent response reports.
func responseError(resp *http.Response) error {
	var failure struct {
		Error string `json:"error"`
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if json.Unmarshal(data, &failure) != nil || failure.Error == "" {
		return fmt.Errorf("workspace agent returned HTTP %d", resp.StatusCode)
	}
	return &Error{Code: resp.StatusCode, Message: failure.Error}
}

// Shell opens an interactive shell in the workspace; see handleShell.
func (c *Client) Shell(ctx context.Context) (*websocket.Conn, error) {
	conn, resp, err := c.dialer.DialContext(ctx, "ws"+strings.TrimPrefix(c.base, "http")+"/shell",
		http.Header{"Authorization": {"Bearer " + c.token}})
	if err != nil && resp != nil {
		defer func() { _ = resp.Body.Close() }()
		return nil, responseError(resp)
	}
	return conn, err
}

func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	resp, err := c.request(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("invalid workspace agent response: %w", err)
	}
	return nil
}

func runPath(id string) string { return "/runs/" + url.PathEscape(id) }

// PlanSync sends manifest, a JSON SyncPlanRequest, and returns the response
// whose body is the JSON SyncPlanResponse, for the caller to relay and close.
func (c *Client) PlanSync(ctx context.Context, manifest io.Reader) (*http.Response, error) {
	return c.request(ctx, http.MethodPost, "/sync/plan", manifest)
}

// SyncUpload sends body, a JSON SyncUploadRequest followed by a tar stream
// for the agent to unpack, and returns the response whose body is the JSON
// SyncUploadResponse, for the caller to relay and close.
func (c *Client) SyncUpload(ctx context.Context, body io.Reader) (*http.Response, error) {
	return c.request(ctx, http.MethodPost, "/sync/upload", body)
}

// Version returns the agent's protocol version.
func (c *Client) Version(ctx context.Context) (int, error) {
	var version VersionResponse
	err := c.call(ctx, http.MethodGet, "/version", nil, &version)
	return version.Protocol, err
}

// Create starts a run, or returns the existing run with the same ID.
func (c *Client) Create(ctx context.Context, req CreateRequest) (Run, error) {
	var run Run
	err := c.call(ctx, http.MethodPost, "/runs", req, &run)
	return run, err
}

// Get returns a run.
func (c *Client) Get(ctx context.Context, id string) (Run, error) {
	var run Run
	err := c.call(ctx, http.MethodGet, runPath(id), nil, &run)
	return run, err
}

// List returns runs newest first.
func (c *Client) List(ctx context.Context, offset, limit int) ([]Run, error) {
	var runs []Run
	query := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(limit)}}
	err := c.call(ctx, http.MethodGet, "/runs?"+query.Encode(), nil, &runs)
	return runs, err
}

// Cancel asks a live run to stop.
func (c *Client) Cancel(ctx context.Context, id string) (Run, error) {
	var run Run
	err := c.call(ctx, http.MethodPost, runPath(id)+"/cancel", nil, &run)
	return run, err
}

// Delete removes a finished run.
func (c *Client) Delete(ctx context.Context, id string) error {
	return c.call(ctx, http.MethodDelete, runPath(id), nil, nil)
}

// Logs opens a run's output at offset. The response carries X-Log-Offset and,
// after the body, trailers with the run's state; the caller closes it.
func (c *Client) Logs(ctx context.Context, id string, offset int64, follow bool) (*http.Response, error) {
	query := url.Values{"offset": {strconv.FormatInt(offset, 10)}, "follow": {strconv.FormatBool(follow)}}
	return c.request(ctx, http.MethodGet, runPath(id)+"/logs?"+query.Encode(), nil)
}

// Activity reports whether anything keeps the workspace from auto-pausing.
func (c *Client) Activity(ctx context.Context) (ActivityResponse, error) {
	var activity ActivityResponse
	err := c.call(ctx, http.MethodGet, "/activity", nil, &activity)
	return activity, err
}

// Grant mints a token that opens the export directory for ttl.
func (c *Client) Grant(ctx context.Context, ttl time.Duration) (GrantResponse, error) {
	var grant GrantResponse
	err := c.call(ctx, http.MethodPost, "/file-grants", GrantRequest{TTLSeconds: int64(ttl.Seconds())}, &grant)
	return grant, err
}
