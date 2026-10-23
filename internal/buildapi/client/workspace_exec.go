package client

import (
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

// WorkspaceExecError reports the remote command's nonzero exit status.
type WorkspaceExecError struct {
	Code int
}

func (e *WorkspaceExecError) Error() string {
	return fmt.Sprintf("workspace command exited with status %d", e.Code)
}

// ExitCode returns the remote command's exit status.
func (e *WorkspaceExecError) ExitCode() int { return e.Code }

type workspaceExecStream struct {
	io.ReadCloser
	response *http.Response
}

func (s *workspaceExecStream) Read(p []byte) (int, error) {
	n, err := s.ReadCloser.Read(p)
	if err != io.EOF {
		return n, err
	}
	status := s.response.Trailer.Get(buildcontract.WorkspaceExecExitCodeTrailer)
	code, parseErr := strconv.Atoi(status)
	if parseErr != nil || code < 0 || code > 255 {
		return n, fmt.Errorf("workspace exec stream ended without a valid exit status (server upgrade may be required)")
	}
	if code != 0 {
		return n, &WorkspaceExecError{Code: code}
	}
	return n, io.EOF
}
