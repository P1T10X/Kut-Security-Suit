package aisec

import (
	"fmt"
	"strings"
	"sync"
)

type ToolCall struct {
	AgentRole  string
	ToolName   string
	TenantID   string
	Parameters map[string]interface{}
}

type FirewallRule struct {
	AllowedRoles      []string
	AllowedTools      []string
	RequiresDualAuth  bool
	BlockedParameters []string
}

type ToolFirewall struct {
	mu    sync.RWMutex
	rules []FirewallRule
}

func NewToolFirewall() *ToolFirewall {
	return &ToolFirewall{
		rules: make([]FirewallRule, 0),
	}
}

func (tf *ToolFirewall) AddRule(rule FirewallRule) {
	tf.mu.Lock()
	defer tf.mu.Unlock()
	tf.rules = append(tf.rules, rule)
}

func (tf *ToolFirewall) AuthorizeToolCall(call ToolCall) (bool, string) {
	if call.TenantID == "" {
		return false, "Blocked: Missing TenantID - cross-tenant or unauthenticated request"
	}
	if call.AgentRole == "" {
		return false, "Blocked: Missing AgentRole"
	}
	if call.ToolName == "" {
		return false, "Blocked: Missing ToolName"
	}

	tf.mu.RLock()
	defer tf.mu.RUnlock()

	var matchedRule *FirewallRule

	// Enforce role-based least privilege
	for _, rule := range tf.rules {
		roleAllowed := false
		for _, role := range rule.AllowedRoles {
			if role == call.AgentRole {
				roleAllowed = true
				break
			}
		}

		toolAllowed := false
		for _, tool := range rule.AllowedTools {
			if tool == call.ToolName {
				toolAllowed = true
				break
			}
		}

		if roleAllowed && toolAllowed {
			matchedRule = &rule
			break
		}
	}

	if matchedRule == nil {
		return false, fmt.Sprintf("Blocked: Role '%s' is not authorized to use tool '%s'", call.AgentRole, call.ToolName)
	}

	// Validate parameters against dangerous tokens/injections
	if len(matchedRule.BlockedParameters) > 0 {
		for _, paramVal := range call.Parameters {
			valStr := fmt.Sprintf("%v", paramVal)
			lowerValStr := strings.ToLower(valStr)
			for _, blocked := range matchedRule.BlockedParameters {
				if strings.Contains(lowerValStr, strings.ToLower(blocked)) {
					return false, fmt.Sprintf("Blocked: Parameter contains dangerous pattern: %s", blocked)
				}
			}
		}
	}

	if matchedRule.RequiresDualAuth {
		// FAIL-CLOSED: dual-auth gerektiren bir tool, bu TEK çağrıyla
		// yetkilendirilemez. İkinci-onay ayrı bir katmanda sağlanana dek REDDEDİLİR.
		// Önceki sürüm bool=true ("pending") döndürüyordu → yalnız bool'a bakan
		// çağıran ikinci-onay olmadan devam ediyordu (fail-open).
		return false, "Blocked: tool requires dual-authorization (second approval not satisfied)"
	}

	return true, "Authorized"
}
