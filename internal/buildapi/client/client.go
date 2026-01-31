// Package client provides a Go client library for the automotive build API server.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
)

// Client provides access to the build API server.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	authToken  string
}

// New creates a new build API client with the given base URL and options.
func New(base string, opts ...Option) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("base URL must include scheme and host (e.g., https://api.example.com)")
	}
	c := &Client{
		baseURL:    u,
		httpClient: &http.Client{}, // No global timeout to avoid aborting large uploads
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Option is a function that configures a Client.
type Option func(*Client)

// WithHTTPClient sets a custom HTTP client for the build API client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpClient = h } }

// WithAuthToken sets an authentication token for API requests.
func WithAuthToken(t string) Option { return func(c *Client) { c.authToken = t } }

// WithInsecureTLS skips TLS certificate verification (use only for testing)
func WithInsecureTLS() Option {
	return func(c *Client) {
		if c.httpClient.Transport == nil {
			// Clone default transport to preserve proxy, HTTP/2, connection pooling, and timeout settings
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			c.httpClient.Transport = transport
		} else if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{}
			}
			transport.TLSClientConfig.InsecureSkipVerify = true
		}
	}
}

// WithCACertificate configures TLS to use a custom CA certificate
func WithCACertificate(caCertPath string) Option {
	return func(c *Client) {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			// If file doesn't exist, skip (will use system CAs)
			return
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			// If parsing fails, skip (will use system CAs)
			return
		}
		if c.httpClient.Transport == nil {
			// Clone default transport to preserve proxy, HTTP/2, connection pooling, and timeout settings
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.TLSClientConfig = &tls.Config{
				RootCAs: caCertPool,
			}
			c.httpClient.Transport = transport
		} else if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{}
			}
			transport.TLSClientConfig.RootCAs = caCertPool
		}
	}
}

// CreateBuild submits a new build request to the API server.
//
//nolint:dupl // Build and Flash methods are intentionally similar but work with different types
func (c *Client) CreateBuild(ctx context.Context, req buildapi.BuildRequest) (*buildapi.BuildResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	endpoint := c.resolve("/v1/builds")
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("create build failed: %s: %s", resp.Status, string(b))
	}
	var out buildapi.BuildResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetBuild retrieves the status and details of a specific build by name.
func (c *Client) GetBuild(ctx context.Context, name string) (*buildapi.BuildResponse, error) {
	endpoint := c.resolve(path.Join("/v1/builds", url.PathEscape(name)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("get build failed: %s: %s", resp.Status, string(b))
	}
	var out buildapi.BuildResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListBuilds retrieves a list of all builds from the API server.
func (c *Client) ListBuilds(ctx context.Context) ([]buildapi.BuildListItem, error) {
	endpoint := c.resolve("/v1/builds")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("list builds failed: %s: %s", resp.Status, string(b))
	}
	var out []buildapi.BuildListItem
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) resolve(p string) string {
	u := *c.baseURL
	basePath := u.Path
	if !strings.HasSuffix(basePath, "/") && basePath != "" {
		basePath += "/"
	}
	p = strings.TrimPrefix(p, "/")
	u.Path = path.Join(basePath, p)
	return u.String()
}

// CreateFlash submits a new flash request to the API server.
//
//nolint:dupl // Build and Flash methods are intentionally similar but work with different types
func (c *Client) CreateFlash(ctx context.Context, req buildapi.FlashRequest) (*buildapi.FlashResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	endpoint := c.resolve("/v1/flash")
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("create flash failed: %s: %s", resp.Status, string(b))
	}
	var out buildapi.FlashResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetFlash retrieves the status of a specific flash job by name.
func (c *Client) GetFlash(ctx context.Context, name string) (*buildapi.FlashResponse, error) {
	endpoint := c.resolve(path.Join("/v1/flash", url.PathEscape(name)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("get flash failed: %s: %s", resp.Status, string(b))
	}
	var out buildapi.FlashResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListFlash retrieves a list of all flash jobs from the API server.
func (c *Client) ListFlash(ctx context.Context) ([]buildapi.FlashListItem, error) {
	endpoint := c.resolve("/v1/flash")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("list flash failed: %s: %s", resp.Status, string(b))
	}
	var out []buildapi.FlashListItem
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// Upload represents a file to upload to the build API.
type Upload struct {
	SourcePath string
	DestPath   string
}

// UploadFiles uploads multiple files to a specific build on the API server.
func (c *Client) UploadFiles(ctx context.Context, name string, files []Upload) error {
	endpoint := c.resolve(path.Join("/v1/builds", url.PathEscape(name), "uploads"))
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	go func() {
		defer func() {
			if err := pw.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to close pipe writer: %v\n", err)
			}
		}()
		defer func() {
			if err := mw.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to close multipart writer: %v\n", err)
			}
		}()

		done := make(chan struct{})
		go func() {
			defer close(done)
			for _, f := range files {
				file, err := os.Open(f.SourcePath)
				if err != nil {
					_ = pw.CloseWithError(err)
					return
				}
				part, err := mw.CreateFormFile("file", f.DestPath)
				if err != nil {
					_ = file.Close()
					_ = pw.CloseWithError(err)
					return
				}
				if _, err := io.Copy(part, file); err != nil {
					_ = file.Close()
					_ = pw.CloseWithError(err)
					return
				}
				if err := file.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to close file: %v\n", err)
				}
			}
		}()

		select {
		case <-done:
		case <-ctx.Done():
			pw.CloseWithError(ctx.Err())
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("upload failed: %s: %s", resp.Status, string(b))
	}
	return nil
}
