package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func (c *Client) workspaceRunRequest(ctx context.Context, method, name, id, action string, body io.Reader) (*http.Request, error) {
	endpoint := c.resolve(path.Join("/v1/workspaces", url.PathEscape(name), "runs", url.PathEscape(id), action))
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	return req, nil
}

func (c *Client) workspaceRunResult(req *http.Request) (*buildcontract.WorkspaceRun, error) {
	resp, err := c.doRequest(req, "workspace run", statusIn(http.StatusOK, http.StatusAccepted))
	if err != nil {
		return nil, err
	}
	defer closeBody(resp)
	var run buildcontract.WorkspaceRun
	if err := json.NewDecoder(resp.Body).Decode(&run); err != nil {
		return nil, err
	}
	return &run, nil
}

// CreateWorkspaceRun starts a command independently of this request's context.
// Supply an ID to safely retry creation after a lost response.
func (c *Client) CreateWorkspaceRun(ctx context.Context, name string, run buildcontract.WorkspaceRunRequest) (*buildcontract.WorkspaceRun, error) {
	body, err := json.Marshal(run)
	if err != nil {
		return nil, err
	}
	req, err := c.workspaceRunRequest(ctx, http.MethodPost, name, "", "", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return c.workspaceRunResult(req)
}

// GetWorkspaceRun retrieves the retained status, exit code and log byte count.
func (c *Client) GetWorkspaceRun(ctx context.Context, name, id string) (*buildcontract.WorkspaceRun, error) {
	req, err := c.workspaceRunRequest(ctx, http.MethodGet, name, id, "", nil)
	if err != nil {
		return nil, err
	}
	return c.workspaceRunResult(req)
}

// CancelWorkspaceRun requests process-group cancellation; repeated calls are safe.
func (c *Client) CancelWorkspaceRun(ctx context.Context, name, id string) (*buildcontract.WorkspaceRun, error) {
	req, err := c.workspaceRunRequest(ctx, http.MethodPost, name, id, "cancel", nil)
	if err != nil {
		return nil, err
	}
	return c.workspaceRunResult(req)
}

// WorkspaceRunLogStream reports the actual absolute start offset, which may
// advance past the requested offset when the retained tail has been truncated.
// Trailers are populated when Read reaches EOF.
type WorkspaceRunLogStream struct {
	io.ReadCloser
	Offset         int64
	Trailers       http.Header
	StreamDuration time.Duration
}

// DefaultWorkspaceRunStreamDuration is used only with servers that do not
// announce their stream cap. New servers own the timing via the response header.
const DefaultWorkspaceRunStreamDuration = 40 * time.Second

// WorkspaceRunLogs reads unmodified log bytes. Resume from stream.Offset plus
// the number of bytes consumed, including partial reads before an error.
func (c *Client) WorkspaceRunLogs(ctx context.Context, name, id string, follow bool, offset int64) (*WorkspaceRunLogStream, error) {
	req, err := c.workspaceRunRequest(ctx, http.MethodGet, name, id, "logs", nil)
	if err != nil {
		return nil, err
	}
	query := req.URL.Query()
	query.Set("follow", strconv.FormatBool(follow))
	query.Set("offset", strconv.FormatInt(offset, 10))
	req.URL.RawQuery = query.Encode()
	resp, err := c.doRequest(req, "workspace run logs", statusIn(http.StatusOK))
	if err != nil {
		return nil, err
	}
	if value := resp.Header.Get("X-Log-Offset"); value != "" {
		actual, err := strconv.ParseInt(value, 10, 64)
		if err != nil || actual < offset {
			closeBody(resp)
			return nil, fmt.Errorf("invalid workspace log offset %q", value)
		}
		offset = actual
	}
	duration := DefaultWorkspaceRunStreamDuration
	if value := resp.Header.Get("X-Log-Stream-Seconds"); value != "" {
		seconds, parseErr := strconv.ParseFloat(value, 64)
		nanoseconds := seconds * float64(time.Second)
		if parseErr != nil || !(nanoseconds >= 1 && nanoseconds < float64(math.MaxInt64)) {
			closeBody(resp)
			return nil, fmt.Errorf("invalid workspace log stream duration %q", value)
		}
		duration = time.Duration(nanoseconds)
	}
	return &WorkspaceRunLogStream{ReadCloser: resp.Body, Offset: offset, Trailers: resp.Trailer, StreamDuration: duration}, nil
}

// ListWorkspaceRuns returns retained runs, newest first, with bounded pagination.
func (c *Client) ListWorkspaceRuns(ctx context.Context, name string, offset, limit int) ([]buildcontract.WorkspaceRun, error) {
	req, err := c.workspaceRunRequest(ctx, http.MethodGet, name, "", "", nil)
	if err != nil {
		return nil, err
	}
	query := req.URL.Query()
	query.Set("offset", strconv.Itoa(offset))
	query.Set("limit", strconv.Itoa(limit))
	req.URL.RawQuery = query.Encode()
	resp, err := c.doRequest(req, "list workspace runs", statusIn(http.StatusOK))
	if err != nil {
		return nil, err
	}
	defer closeBody(resp)
	var runs []buildcontract.WorkspaceRun
	if err := json.NewDecoder(resp.Body).Decode(&runs); err != nil {
		return nil, err
	}
	return runs, nil
}

// DeleteWorkspaceRun removes a terminal or unreadable run's command, result and log.
func (c *Client) DeleteWorkspaceRun(ctx context.Context, name, id string) error {
	req, err := c.workspaceRunRequest(ctx, http.MethodDelete, name, id, "", nil)
	if err != nil {
		return err
	}
	resp, err := c.doRequest(req, "delete workspace run", statusIn(http.StatusNoContent))
	if err != nil {
		return err
	}
	closeBody(resp)
	return nil
}
