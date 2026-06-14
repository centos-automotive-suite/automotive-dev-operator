package caibcommon

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestActionableError_OneFix(t *testing.T) {
	ae := NewActionableError(fmt.Errorf("server URL required"), "caib login https://example.com")
	got := ae.FormatWithFixes()
	want := "Error: server URL required\nFix:   caib login https://example.com"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestActionableError_ThreeFixes(t *testing.T) {
	ae := NewActionableError(
		fmt.Errorf("server URL required"),
		"caib login https://example.com",
		"caib image build --server https://example.com",
		"export CAIB_SERVER=https://example.com",
	)
	got := ae.FormatWithFixes()
	want := "Error: server URL required\n" +
		"Fix:   caib login https://example.com\n" +
		"  or:  caib image build --server https://example.com\n" +
		"  or:  export CAIB_SERVER=https://example.com"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestActionableError_ZeroFixes(t *testing.T) {
	ae := NewActionableError(fmt.Errorf("something broke"))
	got := ae.FormatWithFixes()
	want := "Error: something broke"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestActionableError_MoreThanThreeFixes_CappedAtThree(t *testing.T) {
	ae := NewActionableError(
		fmt.Errorf("err"),
		"fix1", "fix2", "fix3", "fix4",
	)
	got := ae.FormatWithFixes()
	if count := len(strings.Split(got, "\n")) - 1; count != 3 {
		t.Errorf("expected 3 fix lines, got %d:\n%s", count, got)
	}
	if strings.Contains(got, "fix4") {
		t.Errorf("fix4 should not appear in output:\n%s", got)
	}
}

func TestActionableError_WrappedActionableError_InnerFixesIgnored(t *testing.T) {
	inner := NewActionableError(fmt.Errorf("inner"), "inner-fix")
	outer := NewActionableError(fmt.Errorf("outer: %w", inner), "outer-fix")

	got := outer.FormatWithFixes()
	want := "Error: outer: inner\nFix:   outer-fix"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestActionableError_ErrorsAs(t *testing.T) {
	ae := NewActionableError(fmt.Errorf("test"), "fix")
	wrapped := fmt.Errorf("wrap: %w", ae)

	var target *ActionableError
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As should find ActionableError in wrapped chain")
	}
	if target.Fixes[0] != "fix" {
		t.Errorf("expected fix 'fix', got %q", target.Fixes[0])
	}
}

func TestActionableError_ErrorsIs(t *testing.T) {
	sentinel := fmt.Errorf("sentinel")
	ae := NewActionableError(sentinel, "fix")

	if !errors.Is(ae, sentinel) {
		t.Fatal("errors.Is should find sentinel through ActionableError")
	}
}

func TestServerURLRequiredError(t *testing.T) {
	ae := ServerURLRequiredError("caib image build --server <server-url>")
	if ae.Error() != "server URL required" {
		t.Errorf("unexpected error: %s", ae.Error())
	}
	if len(ae.Fixes) != 3 {
		t.Fatalf("expected 3 fixes, got %d: %v", len(ae.Fixes), ae.Fixes)
	}
	if ae.Fixes[0] != "caib login <server-url>" {
		t.Errorf("unexpected first fix: %s", ae.Fixes[0])
	}
}

func TestFormatError_ActionableError(t *testing.T) {
	ae := NewActionableError(fmt.Errorf("bad flag"), "caib image build --arch arm64")
	got := FormatError(ae)
	want := "Error: bad flag\nFix:   caib image build --arch arm64"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestFormatError_RegularError(t *testing.T) {
	err := fmt.Errorf("plain error")
	got := FormatError(err)
	want := "Error: plain error"
	if got != want {
		t.Errorf("got: %q, want: %q", got, want)
	}
}
