package v1alpha1

import (
	"regexp"
	"testing"
)

// cronPattern mirrors the Pattern marker on ScheduledImageBuildSpec.Schedule.
var cronPattern = regexp.MustCompile(`^([-0-9*/,]+\s+){4}[-0-9*/,]+$`)

func TestScheduleCronPattern(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		isValid bool
	}{
		// valid expressions
		{name: "daily at 2am", input: "0 2 * * *", isValid: true},
		{name: "every 6 hours", input: "0 */6 * * *", isValid: true},
		{name: "weekdays at midnight", input: "0 0 * * 1-5", isValid: true},
		{name: "every 15 minutes", input: "*/15 * * * *", isValid: true},
		{name: "specific day and time", input: "30 4 1,15 * *", isValid: true},
		{name: "complex range", input: "0 0-6/2 * * 0,6", isValid: true},
		{name: "all wildcards", input: "* * * * *", isValid: true},
		// invalid expressions
		{name: "text input", input: "every tuesday", isValid: false},
		{name: "only 3 fields", input: "* * *", isValid: false},
		{name: "only 4 fields", input: "0 2 * *", isValid: false},
		{name: "6 fields", input: "0 2 * * * *", isValid: false},
		{name: "empty string", input: "", isValid: false},
		{name: "letters mixed", input: "0 2 * jan *", isValid: false},
		{name: "at-syntax", input: "@daily", isValid: false},
		{name: "natural language", input: "run at 2am", isValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cronPattern.MatchString(tt.input)
			if got != tt.isValid {
				t.Errorf("cronPattern.MatchString(%q) = %v, want %v", tt.input, got, tt.isValid)
			}
		})
	}
}
