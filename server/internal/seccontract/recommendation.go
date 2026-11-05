package seccontract

import "time"

// AIRecommendation, değişmez bir AI önerisidir (CONTRACTS §12). Yetki DEĞİLDİR;
// yalnız Output Validator + Tool/Capability Firewall'dan geçip ACCEPTED olduktan
// sonra ActionRequest'e dönüşür. Authorization terminolojisi (APPROVED) KULLANILMAZ.
type AIRecommendation struct {
	RecommendationID string
	IncidentID       string
	PrincipalID      string
	ModelID          string
	PromptVersion    string
	ContextHash      string
	ResponseHash     string
	Action           string // öneri aksiyonu (allowlist enum; §4.5)
	Targets          []string
	EvidenceIDs      []string
	State            RecommendationState
	IssuedAt         time.Time
	ExpiresAt        time.Time
}

// Capability, bir principal'ın sahip olabileceği yetkidir (CONTRACTS §11).
type Capability string

const (
	CapIncidentRead     Capability = "incident.read"
	CapEvidenceMetaRead Capability = "evidence.metadata.read"
	CapHuntRead         Capability = "hunt.read"
	CapRecommendAction  Capability = "recommend.action"
	// Yasak (AI için asla):
	CapExecutorDirect  Capability = "executor.direct"
	CapWipe            Capability = "wipe"
	CapErase           Capability = "erase"
	CapShellExecute    Capability = "shell.execute"
	CapSQLExecute      Capability = "sql.execute"
	CapPolicyWrite     Capability = "policy.write"
	CapAuditDisable    Capability = "audit.disable"
	CapGuardrailWrite  Capability = "guardrail.write"
	CapIdentityAdmin   Capability = "identity.admin"
	CapCredentialAdmin Capability = "credential.admin"
)

// aiAllowedCaps, AI principal'ın v1'de sahip olabileceği YEGANE yeteneklerdir.
var aiAllowedCaps = map[Capability]bool{
	CapIncidentRead: true, CapEvidenceMetaRead: true, CapHuntRead: true, CapRecommendAction: true,
}

// CapabilityAllowed, verilen principal'ın bir capability'ye sahip olabilip
// olamayacağını döner. AI principal yalnız aiAllowedCaps'tekilere sahip olabilir;
// yasak capability için ASLA (INV-AI-001/035). İnsan/otomasyon için bu fonksiyon
// AI-kısıtını uygular; tam RBAC ayrı katmandır.
func CapabilityAllowed(p Principal, c Capability) bool {
	if p.Type == PrincipalAI {
		return aiAllowedCaps[c]
	}
	return true // AI-dışı principal'lar için AI-firewall kısıtı uygulanmaz (RBAC ayrı)
}

// ForbiddenForAI, bir capability'nin AI için KALICI yasak olup olmadığını döner.
func ForbiddenForAI(c Capability) bool { return !aiAllowedCaps[c] }
