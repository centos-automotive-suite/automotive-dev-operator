package client

import (
	"bytes"
	"context"
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

type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	authToken  string
}

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

type Option func(*Client)

func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpClient = h } }
func WithAuthToken(t string) Option        { return func(c *Client) { c.authToken = t } }

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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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

func (c *Client) GetReseal(ctx context.Context, name string) (*buildapi.BuildResponse, error) {
	endpoint := c.resolve(path.Join("/v1/reseals", url.PathEscape(name)))
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("get reseal failed: %s: %s", resp.Status, string(b))
	}
	var out buildapi.BuildResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

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
	defer resp.Body.Close()
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

type Upload struct {
	SourcePath string
	DestPath   string
}

func (c *Client) UploadFiles(ctx context.Context, name string, files []Upload) error {
	endpoint := c.resolve(path.Join("/v1/builds", url.PathEscape(name), "uploads"))
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	go func() {
		defer pw.Close()
		defer mw.Close()

		done := make(chan struct{})
		go func() {
			defer close(done)
			for _, f := range files {
				file, err := os.Open(f.SourcePath)
				if err != nil {
					pw.CloseWithError(err)
					return
				}
				part, err := mw.CreateFormFile("file", f.DestPath)
				if err != nil {
					file.Close()
					pw.CloseWithError(err)
					return
				}
				if _, err := io.Copy(part, file); err != nil {
					file.Close()
					pw.CloseWithError(err)
					return
				}
				file.Close()
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("upload failed: %s: %s", resp.Status, string(b))
	}
	return nil
}
