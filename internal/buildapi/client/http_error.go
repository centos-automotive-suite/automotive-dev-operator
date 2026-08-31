package client

import "fmt"

// HTTPError is implemented by errors returned from build API HTTP calls
// that carry a response status code.
type HTTPError interface {
	error
	HTTPStatusCode() int
}

type responseError struct {
	code    int
	message string
}

func (e *responseError) Error() string {
	return e.message
}

func (e *responseError) HTTPStatusCode() int {
	return e.code
}

func newHTTPError(code int, format string, args ...any) error {
	return &responseError{code: code, message: fmt.Sprintf(format, args...)}
}
