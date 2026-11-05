package aiprovider

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ResponseActionType e.g. "IsolateEndpoint", "BlockHash", "RevokeSession", "QuarantineFile", "KillProcess"
type ResponseActionType string

const (
	ActionIsolateEndpoint ResponseActionType = "IsolateEndpoint"
	ActionBlockHash       ResponseActionType = "BlockHash"
	ActionRevokeSession   ResponseActionType = "RevokeSession"
	ActionQuarantineFile  ResponseActionType = "QuarantineFile"
	ActionKillProcess     ResponseActionType = "KillProcess"
)

// ResponseAction represents a specific remediation action to be taken.
type ResponseAction struct {
	ID               string             `json:"id"`
	Type             ResponseActionType `json:"type"`
	Target           string             `json:"target"`
	TenantID         string             `json:"tenant_id"`
	RequiresApproval bool               `json:"requires_approval"`
	Reason           string             `json:"reason"`
	Approved         bool               `json:"approved"`
	ProposedBy       string             `json:"proposed_by"`           // öneren kimlik (dual-control için)
	ApprovedBy       string             `json:"approved_by,omitempty"` // onaylayan kimlik (denetim)
	ExecutedAt       time.Time          `json:"executed_at,omitempty"`
}

// autonomousProposer, ProposePlan tarafından üretilen aksiyonların öneren kimliğidir.
// ExecuteAction, onaylayanın bundan FARKLI olmasını zorunlu kılar (dual-control):
// otonom ajanın önerdiği bir aksiyonu yine kendisi "onaylayıp" yürütemez.
const autonomousProposer = "autonomous-response-agent"

// ActionAuthorizer, bir yanıt aksiyonunun yürütülmesini KANONİK yetki zincirinden
// (authz / secgateway / privman / GuardedExecutor) doğrular: onaylayan kimliği+rolü,
// tenant eşleşmesi, blast-radius. PRODUCTION wiring'de bu adaptör ENJEKTE EDİLMELİDİR;
// nil ise ExecuteAction fail-closed reddeder (yüksek-etkili aksiyon boş-olmayan tek
// string ile YÜRÜTÜLEMEZ).
type ActionAuthorizer interface {
	AuthorizeResponse(ctx context.Context, action ResponseAction, approver string) error
}

// ResponsePlan groups multiple actions into a single coordinated response plan.
type ResponsePlan struct {
	IncidentID  string           `json:"incident_id"`
	TenantID    string           `json:"tenant_id"`
	Actions     []ResponseAction `json:"actions"`
	GeneratedAt time.Time        `json:"generated_at"`
}

// ResponseAgent is responsible for evaluating findings and executing remediation actions.
type ResponseAgent struct {
	ModelRouter *ModelRouter
	RAGStore    *RAGStore
	authz       ActionAuthorizer // kanonik yetki kapısı (nil => yürütme fail-closed reddedilir)
}

// NewResponseAgent creates a new autonomous response agent. authz, aksiyon
// yürütmesi için KANONİK yetki kapısıdır; nil enjekte edilirse ExecuteAction
// fail-closed reddeder (ajan öneri üretebilir ama yürütemez).
func NewResponseAgent(router *ModelRouter, ragStore *RAGStore, authz ActionAuthorizer) *ResponseAgent {
	return &ResponseAgent{
		ModelRouter: router,
		RAGStore:    ragStore,
		authz:       authz,
	}
}

// ProposePlan evaluates severity and findings.
// Generates structured remediation plan. If severity is Critical, flags immediate containment actions.
// If action is destructive, sets RequiresApproval = true.
func (a *ResponseAgent) ProposePlan(ctx context.Context, tenantID string, incidentID string, findings []HuntFinding, severity string) (*ResponsePlan, error) {
	if tenantID == "" || incidentID == "" {
		return nil, errors.New("tenantID and incidentID are required")
	}

	plan := &ResponsePlan{
		IncidentID:  incidentID,
		TenantID:    tenantID,
		GeneratedAt: time.Now().UTC(),
		Actions:     make([]ResponseAction, 0),
	}

	for i, f := range findings {
		actionType := ActionBlockHash

		// Eğer severity Critical ise, immediate containment action'ları belirle.
		if severity == "Critical" {
			if i%2 == 0 {
				actionType = ActionIsolateEndpoint
			} else {
				actionType = ActionKillProcess
			}
		} else if severity == "High" {
			actionType = ActionQuarantineFile
		}

		// Target olarak bulgunun özetini veya varsa ilgili ID'yi alıyoruz.
		target := fmt.Sprintf("%v", f.TargetNode)

		actionID := fmt.Sprintf("action-%s-%d", incidentID, i)
		plan.Actions = append(plan.Actions, ResponseAction{
			ID:       actionID,
			Type:     actionType,
			Target:   target,
			TenantID: tenantID,
			// TÜM yanıt aksiyonları yüksek-etkilidir (Isolate/Kill/Quarantine/
			// BlockHash/RevokeSession) → istisnasız insan onayı + kanonik yetki
			// gerektirir. BlockHash/RevokeSession'ın onaysız auto-yürütülmesi burada
			// kapatıldı.
			RequiresApproval: true,
			Reason:           fmt.Sprintf("Auto-generated mitigation for finding (Hypothesis: %s)", f.HypothesisID),
			Approved:         false,
			ProposedBy:       autonomousProposer,
		})
	}

	return plan, nil
}

// ExecuteAction executes a specific response action — FAIL-CLOSED.
// Yüksek-etkili bir yanıt aksiyonu YALNIZ şu koşullar hep birlikte sağlanırsa
// yürütülür: (1) tenant kimliği boş değil; (2) boş-olmayan bir onaylayan var;
// (3) onaylayan, aksiyonu öneren kimlikten FARKLI (dual-control / dört-göz);
// (4) KANONİK yetki kapısı (authz/secgateway/privman) enjekte edilmiş VE aksiyonu
// onaylıyor (onaylayan rolü + tenant eşleşmesi + blast-radius orada doğrulanır).
// Herhangi biri eksikse aksiyon yürütülmez. Eski "boş-olmayan herhangi string onay
// sayılır" davranışı kaldırıldı.
func (a *ResponseAgent) ExecuteAction(ctx context.Context, action *ResponseAction, approver string) error {
	if action == nil {
		return errors.New("action is nil")
	}
	if action.TenantID == "" {
		return errors.New("tenant required (fail-closed)")
	}
	if approver == "" {
		return errors.New("action requires an approver (fail-closed)")
	}
	if approver == action.ProposedBy {
		return errors.New("dual-control: approver must differ from the proposing agent")
	}
	// Kanonik yetki kapısı ZORUNLU — simülasyon/string-onay yeterli değil.
	if a.authz == nil {
		return errors.New("authorization gate not configured (fail-closed)")
	}
	if err := a.authz.AuthorizeResponse(ctx, *action, approver); err != nil {
		return fmt.Errorf("authorization denied: %w", err)
	}

	action.Approved = true
	action.ApprovedBy = approver
	action.ExecutedAt = time.Now().UTC()
	return nil
}
