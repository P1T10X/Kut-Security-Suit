package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestDecisionEngine_Evaluate_DestructiveHighRisk(t *testing.T) {
	engine := NewDecisionEngine()
	ctx := SecurityContext{
		TenantID:     "tenant-1",
		ActorID:      "actor-1",
		ActionImpact: "destructive",
		RiskScore:    0.8,
	}

	decision := engine.Evaluate("dec-1", ctx)

	if decision.Outcome != OutcomeChallenge {
		t.Errorf("expected OutcomeChallenge, got %s", decision.Outcome)
	}
	if !decision.RequiresDualAuth {
		t.Error("expected RequiresDualAuth to be true")
	}
	if decision.AttestationHash == "" {
		t.Error("expected non-empty AttestationHash")
	}
}

func TestDecisionEngine_Evaluate_InvalidTenant(t *testing.T) {
	engine := NewDecisionEngine()
	ctx := SecurityContext{
		TenantID:     "",
		ActorID:      "actor-1",
		ActionImpact: "read",
		RiskScore:    0.1,
	}

	decision := engine.Evaluate("dec-2", ctx)

	if decision.Outcome != OutcomeDeny {
		t.Errorf("expected OutcomeDeny, got %s", decision.Outcome)
	}
	if decision.PolicyReason != "Invalid tenant ID" {
		t.Errorf("expected Invalid tenant ID policy reason, got %s", decision.PolicyReason)
	}
}

func TestDecisionEngine_Evaluate_LowRisk(t *testing.T) {
	engine := NewDecisionEngine()
	ctx := SecurityContext{
		TenantID:     "tenant-1",
		ActionImpact: "read",
		RiskScore:    0.2,
	}

	decision := engine.Evaluate("dec-3", ctx)

	if decision.Outcome != OutcomePermit {
		t.Errorf("expected OutcomePermit, got %s", decision.Outcome)
	}
}

func TestDecisionEngine_Evaluate_OutOfScopeImpact(t *testing.T) {
	engine := NewDecisionEngine()
	ctx := SecurityContext{
		TenantID:     "tenant-1",
		ActionImpact: "unknown-impact",
		RiskScore:    0.5,
	}

	decision := engine.Evaluate("dec-4", ctx)

	if decision.Outcome != OutcomeDeny {
		t.Errorf("expected OutcomeDeny, got %s", decision.Outcome)
	}
	if !strings.Contains(decision.PolicyReason, "Out-of-scope") {
		t.Errorf("expected Out-of-scope policy reason, got %s", decision.PolicyReason)
	}
}

// TestDecisionEngine_Evaluate_MislabeledDestructive, yıkıcı bir eylemin (ör. "wipe")
// ActionImpact="read"+RiskScore=0 ile etiketlenerek OutcomePermit almasının artık
// MÜMKÜN OLMADIĞINI doğrular — impact eylem adından sunucu-tarafı türetilir.
func TestDecisionEngine_Evaluate_MislabeledDestructive(t *testing.T) {
	engine := NewDecisionEngine()
	ctx := SecurityContext{
		TenantID:     "tenant-1",
		ActorID:      "actor-1",
		ActionName:   "wipe", // yıkıcı eylem
		ActionImpact: "read", // çağıranın yanlış/düşürülmüş beyanı
		RiskScore:    0.0,    // sıfır risk beyanı
	}

	decision := engine.Evaluate("dec-mislabel", ctx)

	if decision.Outcome == OutcomePermit {
		t.Fatal("yıkıcı eylem 'read' etiketlense bile Permit ALMAMALI (bypass)")
	}
	if decision.Context.ActionImpact != "destructive" {
		t.Errorf("etki sunucu-tarafı 'destructive'e türetilmeli, alınan %s", decision.Context.ActionImpact)
	}
}

func TestDecisionEngine_AttestationHash(t *testing.T) {
	engine := NewDecisionEngine()
	ctx := SecurityContext{
		TenantID:     "tenant-1",
		ActionImpact: "read",
		RiskScore:    0.2,
	}

	decision := engine.Evaluate("dec-1", ctx)

	// Re-compute hash manually to verify logic
	expectedCanonical := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s|%s|%.4f|%.4f|%s|%s|%t",
		decision.ID, decision.EvaluatedAt.UnixNano(),
		decision.Context.TenantID, decision.Context.ActorID, decision.Context.SourceDeviceID,
		decision.Context.TargetDeviceID, decision.Context.ActionName, decision.Context.ActionImpact,
		decision.Context.RiskScore, decision.Context.Confidence,
		decision.Outcome, decision.PolicyReason, decision.RequiresDualAuth)

	hash := sha256.Sum256([]byte(expectedCanonical))
	expectedHash := hex.EncodeToString(hash[:])

	if decision.AttestationHash != expectedHash {
		t.Errorf("hash mismatch: expected %s, got %s", expectedHash, decision.AttestationHash)
	}
}
