package aiprovider

import (
	"context"
	"errors"
	"testing"

	"kut.corp/suite/server/internal/entitygraph"
)

// mockActionAuthorizer, kanonik yetki kapısının test ikamesidir.
type mockActionAuthorizer struct {
	denyErr error // nil => izin ver; non-nil => reddet
}

func (m *mockActionAuthorizer) AuthorizeResponse(ctx context.Context, action ResponseAction, approver string) error {
	return m.denyErr
}

func TestProposePlan(t *testing.T) {
	agent := NewResponseAgent(nil, nil, nil) // öneri üretimi yetki kapısı gerektirmez
	ctx := context.Background()

	tenantID := "tenant-1"
	incidentID := "inc-100"
	severity := "Critical"

	node := entitygraph.Node{ID: "node-1", Kind: "Process"}
	findings := []HuntFinding{
		{HypothesisID: "hyp-1", TargetNode: node},
		{HypothesisID: "hyp-2", TargetNode: node},
	}

	plan, err := agent.ProposePlan(ctx, tenantID, incidentID, findings, severity)
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if plan.IncidentID != incidentID || plan.TenantID != tenantID {
		t.Fatalf("plan kimlikleri hatalı: %+v", plan)
	}
	if len(plan.Actions) != 2 {
		t.Fatalf("beklenen aksiyon sayısı 2, alınan %d", len(plan.Actions))
	}
	for _, action := range plan.Actions {
		if action.TenantID != tenantID {
			t.Errorf("aksiyonda beklenen tenantID %s, alınan %s", tenantID, action.TenantID)
		}
		// TÜM yanıt aksiyonları onay gerektirmeli (BlockHash/RevokeSession dahil).
		if !action.RequiresApproval {
			t.Errorf("tüm yanıt aksiyonları onay gerektirmeli, %s gerektirmiyor", action.Type)
		}
		if action.ProposedBy != autonomousProposer {
			t.Errorf("aksiyon ProposedBy=%q olmalı, alınan %q", autonomousProposer, action.ProposedBy)
		}
	}
}

func TestProposePlan_Validation(t *testing.T) {
	agent := NewResponseAgent(nil, nil, nil)
	ctx := context.Background()

	if _, err := agent.ProposePlan(ctx, "", "inc-1", nil, "Low"); err == nil {
		t.Error("boş tenantID ile hata bekleniyordu")
	}
	if _, err := agent.ProposePlan(ctx, "tenant-1", "", nil, "Low"); err == nil {
		t.Error("boş incidentID ile hata bekleniyordu")
	}
}

func newAction() *ResponseAction {
	return &ResponseAction{
		ID:               "act-1",
		Type:             ActionIsolateEndpoint,
		TenantID:         "tenant-1",
		RequiresApproval: true,
		ProposedBy:       autonomousProposer,
	}
}

// TestExecuteAction_RequiresApprover: boş onaylayan => fail-closed.
func TestExecuteAction_RequiresApprover(t *testing.T) {
	agent := NewResponseAgent(nil, nil, &mockActionAuthorizer{})
	if err := agent.ExecuteAction(context.Background(), newAction(), ""); err == nil {
		t.Fatal("boş onaylayan ile yürütme reddedilmeliydi")
	}
}

// TestExecuteAction_FailClosedWithoutGate: kanonik yetki kapısı enjekte edilmemişse
// (nil authz) yüksek-etkili aksiyon, geçerli bir onaylayan verilse bile yürütülemez.
func TestExecuteAction_FailClosedWithoutGate(t *testing.T) {
	agent := NewResponseAgent(nil, nil, nil) // authz yok
	if err := agent.ExecuteAction(context.Background(), newAction(), "admin-user"); err == nil {
		t.Fatal("yetki kapısı yokken yürütme fail-closed reddedilmeliydi")
	}
}

// TestExecuteAction_DualControl: onaylayan, öneren ajanla aynıysa reddedilir.
func TestExecuteAction_DualControl(t *testing.T) {
	agent := NewResponseAgent(nil, nil, &mockActionAuthorizer{})
	if err := agent.ExecuteAction(context.Background(), newAction(), autonomousProposer); err == nil {
		t.Fatal("onaylayan=öneren (dual-control ihlali) reddedilmeliydi")
	}
}

// TestExecuteAction_GateDenies: yetki kapısı reddederse aksiyon yürütülmez.
func TestExecuteAction_GateDenies(t *testing.T) {
	agent := NewResponseAgent(nil, nil, &mockActionAuthorizer{denyErr: errors.New("rol yetersiz")})
	action := newAction()
	if err := agent.ExecuteAction(context.Background(), action, "admin-user"); err == nil {
		t.Fatal("yetki kapısı reddedince yürütme başarısız olmalı")
	}
	if !action.ExecutedAt.IsZero() {
		t.Fatal("reddedilen aksiyon yürütülmüş işaretlenmemeli")
	}
}

// TestExecuteAction_TenantRequired: boş tenant => fail-closed.
func TestExecuteAction_TenantRequired(t *testing.T) {
	agent := NewResponseAgent(nil, nil, &mockActionAuthorizer{})
	action := newAction()
	action.TenantID = ""
	if err := agent.ExecuteAction(context.Background(), action, "admin-user"); err == nil {
		t.Fatal("boş tenant ile yürütme reddedilmeliydi")
	}
}

// TestExecuteAction_Allowed: tüm koşullar sağlanınca yürütülür ve denetim alanları dolar.
func TestExecuteAction_Allowed(t *testing.T) {
	agent := NewResponseAgent(nil, nil, &mockActionAuthorizer{})
	action := newAction()
	if err := agent.ExecuteAction(context.Background(), action, "admin-user"); err != nil {
		t.Fatalf("geçerli onaylı aksiyon yürütülmeliydi: %v", err)
	}
	if !action.Approved || action.ApprovedBy != "admin-user" || action.ExecutedAt.IsZero() {
		t.Fatalf("yürütme sonrası denetim alanları dolmalı: %+v", action)
	}
}
