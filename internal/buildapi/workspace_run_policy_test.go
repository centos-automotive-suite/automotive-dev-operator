package buildapi

import (
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

func TestWorkspaceRunPolicyLimits(t *testing.T) {
	for _, tc := range []struct {
		name                                string
		settings                            *automotivev1alpha1.WorkspacesConfig
		requested, capacity                 int64
		timeout, logSize, retention, budget int64
		records                             int64
		invalid                             bool
	}{
		{name: "defaults", capacity: 10 << 30, timeout: 7200, logSize: 100 << 20, retention: 7 * 86400, budget: 1 << 30},
		{name: "small volume", capacity: 1 << 30, timeout: 7200, logSize: 100 << 20, retention: 7 * 86400, budget: (1 << 30) / 10},
		{name: "tiny volume clamps log cap", capacity: 512 << 20, timeout: 7200, logSize: (512 << 20) / 10, retention: 7 * 86400, budget: (512 << 20) / 10},
		{name: "configured budget clamps log cap", settings: &automotivev1alpha1.WorkspacesConfig{RunCompletedLogBudgetMiB: 1}, capacity: 10 << 30, timeout: 7200, logSize: 1 << 20, retention: 7 * 86400, budget: 1 << 20},
		{name: "large volume", capacity: 100 << 30, timeout: 7200, logSize: 100 << 20, retention: 7 * 86400, budget: 1 << 30},
		{name: "request", requested: 86400, capacity: 10 << 30, timeout: 86400, logSize: 100 << 20, retention: 7 * 86400, budget: 1 << 30},
		{name: "too long", requested: 86401, capacity: 10 << 30, invalid: true},
		{name: "negative", requested: -1, capacity: 10 << 30, invalid: true},
		{name: "operator limits", settings: &automotivev1alpha1.WorkspacesConfig{RunDefaultTimeoutMinutes: 30, RunMaxTimeoutMinutes: 60, RunMaxLogSizeMiB: 20, RunRetentionDays: 2, RunMaxRecords: 25, RunCompletedLogBudgetMiB: 250}, capacity: 10 << 30, timeout: 1800, logSize: 20 << 20, retention: 2 * 86400, budget: 250 << 20, records: 25},
		{name: "upper retention and record bounds", settings: &automotivev1alpha1.WorkspacesConfig{RunRetentionDays: 31, RunMaxRecords: 1001}, capacity: 10 << 30, timeout: 7200, logSize: 100 << 20, retention: 30 * 86400, budget: 1 << 30},
		{name: "lower cap clamps default", settings: &automotivev1alpha1.WorkspacesConfig{RunMaxTimeoutMinutes: 60}, capacity: 10 << 30, timeout: 3600, logSize: 100 << 20, retention: 7 * 86400, budget: 1 << 30},
		{name: "request above operator cap", settings: &automotivev1alpha1.WorkspacesConfig{RunMaxTimeoutMinutes: 60}, requested: 3601, capacity: 10 << 30, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options, err := resolveWorkspaceRunOptions(tc.settings, tc.requested, tc.capacity)
			if tc.invalid {
				if err == nil {
					t.Fatalf("invalid policy/request accepted: %+v", options)
				}
				return
			}
			if err != nil || options.TimeoutSeconds != tc.timeout || options.MaxLogBytes != tc.logSize || options.RetentionSeconds != tc.retention || options.CompletedLogBudgetBytes != tc.budget || options.RequestedTimeoutSeconds != tc.requested {
				t.Fatalf("policy: %+v, %v", options, err)
			}
			wantRecords := int64(1000)
			if tc.records != 0 {
				wantRecords = tc.records
			}
			if options.MaxRecords != wantRecords {
				t.Fatalf("record cap: got %d, want %d", options.MaxRecords, wantRecords)
			}
		})
	}
}
