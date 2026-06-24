package caibcommon

import (
	"strings"
	"testing"
)

func TestValidateLeaseTags(t *testing.T) {
	tests := []struct {
		name    string
		tags    []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid single tag",
			tags:    []string{"env=staging"},
			wantErr: false,
		},
		{
			name:    "valid multiple tags",
			tags:    []string{"env=staging", "team=platform"},
			wantErr: false,
		},
		{
			name:    "empty value is valid",
			tags:    []string{"key="},
			wantErr: false,
		},
		{
			name:    "value with equals sign is valid",
			tags:    []string{"key=val=ue"},
			wantErr: false,
		},
		{
			name:    "empty slice is valid",
			tags:    []string{},
			wantErr: false,
		},
		{
			name:    "missing equals sign",
			tags:    []string{"invalid"},
			wantErr: true,
			errMsg:  "must be in key=value format",
		},
		{
			name:    "contains comma",
			tags:    []string{"key=val,ue"},
			wantErr: true,
			errMsg:  "must not contain commas",
		},
		{
			name:    "empty key",
			tags:    []string{"=value"},
			wantErr: true,
			errMsg:  "has empty key",
		},
		{
			name:    "second tag invalid",
			tags:    []string{"good=tag", "bad"},
			wantErr: true,
			errMsg:  "must be in key=value format",
		},
		{
			name:    "whitespace-only key",
			tags:    []string{" =value"},
			wantErr: true,
			errMsg:  "has empty key",
		},
		{
			name:    "tab-only key",
			tags:    []string{"\t=value"},
			wantErr: true,
			errMsg:  "has empty key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLeaseTags(tt.tags)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateAndJoinLeaseTags(t *testing.T) {
	tests := []struct {
		name    string
		tags    *[]string
		want    string
		wantErr bool
	}{
		{
			name: "nil pointer",
			tags: nil,
			want: "",
		},
		{
			name: "empty slice",
			tags: &[]string{},
			want: "",
		},
		{
			name: "single tag",
			tags: &[]string{"env=staging"},
			want: "env=staging",
		},
		{
			name: "multiple tags joined",
			tags: &[]string{"env=staging", "team=platform"},
			want: "env=staging,team=platform",
		},
		{
			name:    "invalid tag propagates error",
			tags:    &[]string{"bad"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateAndJoinLeaseTags(tt.tags)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
