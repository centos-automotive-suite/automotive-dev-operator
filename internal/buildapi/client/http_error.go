package client

import (
	"errors"
	"fmt"
)

// HTTPError is implemented by errors returned from build API HTTP calls
// that carry a response status code.
type HTTPError interface {
	error
	HTTPStatusCode() int
}

type responseError struct {
	code         int
	message      string
	missingRoute bool
}

func (e *responseError) Error() string {
	return e.message
}

func (e *responseError) HTTPStatusCode() int {
	return e.code
}

func newHTTPError(code int, format string, args ...any) *responseError {
	return &responseError{code: code, message: fmt.Sprintf(format, args...)}
}

// IsRouteNotFound distinguishes Gin's plain-text missing-route response from
// the API's JSON 404 for a missing or unowned resource.
func IsRouteNotFound(err error) bool {
	var response *responseError
	return errors.As(err, &response) && response.missingRoute
}
