package aisec

import (
	"testing"
)

func TestToolFirewall(t *testing.T) {
	tf := NewToolFirewall()

	tf.AddRule(FirewallRule{
		AllowedRoles:      []string{"investigator"},
		AllowedTools:      []string{"graph_query", "rag_search"},
		RequiresDualAuth:  false,
		BlockedParameters: []string{"drop table", "1=1", "exec("},
	})

	tf.AddRule(FirewallRule{
		AllowedRoles:      []string{"response"},
		AllowedTools:      []string{"quarantine_endpoint", "dispatch_command"},
		RequiresDualAuth:  true,
		BlockedParameters: []string{"rm -rf", "sudo"},
	})

	tests := []struct {
		name          string
		call          ToolCall
		expectedAllow bool
	}{
		{
			name: "Investigator calling read-only tool passes",
			call: ToolCall{
				AgentRole:  "investigator",
				ToolName:   "graph_query",
				TenantID:   "tenant-1",
				Parameters: map[string]interface{}{"query": "find connections"},
			},
			expectedAllow: true,
		},
		{
			name: "Investigator attempting to call destructive response tool blocked",
			call: ToolCall{
				AgentRole:  "investigator",
				ToolName:   "quarantine_endpoint",
				TenantID:   "tenant-1",
				Parameters: map[string]interface{}{"endpoint_id": "ep-123"},
			},
			expectedAllow: false,
		},
		{
			// Dual-auth gerektiren tool tek çağrıyla yetkilenemez → fail-closed reddi.
			name: "Dual-auth tool denied pending second approval (fail-closed)",
			call: ToolCall{
				AgentRole:  "response",
				ToolName:   "quarantine_endpoint",
				TenantID:   "tenant-1",
				Parameters: map[string]interface{}{"endpoint_id": "ep-123"},
			},
			expectedAllow: false,
		},
		{
			name: "Dangerous parameter injection blocked",
			call: ToolCall{
				AgentRole:  "investigator",
				ToolName:   "graph_query",
				TenantID:   "tenant-1",
				Parameters: map[string]interface{}{"query": "DROP TABLE users;"},
			},
			expectedAllow: false,
		},
		{
			name: "Cross-tenant / missing tenant call blocked",
			call: ToolCall{
				AgentRole:  "investigator",
				ToolName:   "graph_query",
				TenantID:   "",
				Parameters: map[string]interface{}{"query": "test query"},
			},
			expectedAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := tf.AuthorizeToolCall(tt.call)
			if allowed != tt.expectedAllow {
				t.Errorf("expected allowed=%v, got %v (reason: %s)", tt.expectedAllow, allowed, reason)
			}
		})
	}
}
