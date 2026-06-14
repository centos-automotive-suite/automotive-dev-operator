package caibcommon

import (
	"errors"
	"fmt"
	"strings"
)

const maxFixes = 3

// ActionableError wraps an error with copy-pasteable fix commands.
// At most maxFixes commands are rendered; additional fixes are ignored.
type ActionableError struct {
	Err   error
	Fixes []string
}

// NewActionableError wraps err with one or more fix commands.
func NewActionableError(err error, fixes ...string) *ActionableError {
	return &ActionableError{Err: err, Fixes: fixes}
}

// ServerURLRequiredError returns the standard "server URL required" error
// with fix suggestions. cmdExample is the command-specific --server usage,
// e.g. "caib image build --server <server-url>".
func ServerURLRequiredError(cmdExample string) *ActionableError {
	return NewActionableError(
		fmt.Errorf("server URL required"),
		"caib login <server-url>",
		cmdExample,
		"export CAIB_SERVER=<server-url>",
	)
}

func (e *ActionableError) Error() string {
	return e.Err.Error()
}

func (e *ActionableError) Unwrap() error {
	return e.Err
}

// FormatWithFixes renders the error with fix commands.
// Only the outermost ActionableError's fixes are rendered;
// if the wrapped error is also an ActionableError, its fixes are ignored.
func (e *ActionableError) FormatWithFixes() string {
	var b strings.Builder
	b.WriteString("Error: ")
	b.WriteString(e.Err.Error())

	for i, fix := range e.Fixes {
		if i >= maxFixes {
			break
		}
		b.WriteByte('\n')
		if i == 0 {
			b.WriteString("Fix:   ")
		} else {
			b.WriteString("  or:  ")
		}
		b.WriteString(fix)
	}

	return b.String()
}

// FormatError renders err as an actionable error if it is one,
// otherwise renders it in the standard "Error: ..." format.
func FormatError(err error) string {
	var ae *ActionableError
	if errors.As(err, &ae) {
		return ae.FormatWithFixes()
	}
	return fmt.Sprintf("Error: %v", err)
}
