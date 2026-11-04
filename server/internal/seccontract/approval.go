package seccontract

import (
	"sync"
	"time"

	"kut.corp/suite/server/internal/scope"
)

// ApprovalState, dual-control onay yaşam döngüsüdür (CONTRACTS §4). REJECTED/
// EXPIRED terminaldir; CONSUMED yalnız APPROVED'dan gelir. Karar = State;
// ayrı mutable Decision alanı yoktur.
type ApprovalState string

const (
	ApprovalRequested ApprovalState = "REQUESTED"
	ApprovalApproved  ApprovalState = "APPROVED"
	ApprovalConsumed  ApprovalState = "CONSUMED"
	ApprovalRejected  ApprovalState = "REJECTED"
	ApprovalExpired   ApprovalState = "EXPIRED"
)

var approvalTransitions = map[ApprovalState]map[ApprovalState]bool{
	ApprovalRequested: {ApprovalApproved: true, ApprovalRejected: true, ApprovalExpired: true},
	ApprovalApproved:  {ApprovalConsumed: true, ApprovalExpired: true},
}

func (s ApprovalState) CanGoTo(to ApprovalState) bool { return approvalTransitions[s][to] }

// Approval, ikinci-principal dual-control onayıdır (CONTRACTS §4). Grant DEĞİLDİR ve
// grant-mint yetkisi DEĞİLDİR; yalnız FinalizeAuthorization'da yeniden-doğrulama +
// atomik consume sonrası grant üretilir.
type Approval struct {
	ApprovalID         string
	TenantID           string
	RequestID          string
	RequestHash        string
	Action             scope.Action
	TargetsHash        string
	PolicyHash         string
	PolicyVersion      string
	RequesterPrincipal Principal
	ApproverPrincipal  Principal
	DecidedBy          string
	DecidedAt          time.Time
	IssuedAt           time.Time
	ExpiresAt          time.Time
	State              ApprovalState
}

// ApprovalStore, onayın grant-mint için TEK KEZ tüketilmesini sağlar. Bir kez
// grant mint edildikten sonra aynı onay yeniden grant üretemez.
type ApprovalStore interface {
	// Consume, onayı atomik olarak "grant için tüketildi" işaretler; ikinci çağrı hata.
	Consume(approvalID string) error
}

// MemApprovalStore, ApprovalStore'un bellek-içi atomik gerçekleştirimidir.
type MemApprovalStore struct {
	mu       sync.Mutex
	consumed map[string]bool
}

// NewMemApprovalStore oluşturur.
func NewMemApprovalStore() *MemApprovalStore { return &MemApprovalStore{consumed: map[string]bool{}} }

// Consume, onayı atomik tüketir (concurrent'ta yalnız biri başarılı).
func (s *MemApprovalStore) Consume(approvalID string) error {
	if approvalID == "" {
		return ErrApprovalInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed[approvalID] {
		return ErrApprovalInvalid
	}
	s.consumed[approvalID] = true
	return nil
}

// FinalizeAuthorization, NEED_APPROVAL sonrası onaylı bir isteği SONLANDIRIR:
// (1) onay APPROVED & süresi geçmemiş, (2) policy/tenant/target/binding YENİDEN
// doğrulanır, (3) RequesterPrincipal != ApproverPrincipal, (4) onay atomik tüketilir
// ve TEK grant mint edilir. Herhangi biri başarısızsa DENY (spesifik reason-code).
// Approval doğrudan grant-mint etmez (INV-040).
func FinalizeAuthorization(req ActionRequest, ap Approval, store ApprovalStore, effectivePolicyHash string, now time.Time, mint func() (grantID, nonce string), ttl time.Duration) AuthorizationDecision {
	if ap.State != ApprovalApproved {
		return Deny(ReasonApprovalAlreadyConsumed)
	}
	if !now.Before(ap.ExpiresAt) {
		return Deny(ReasonApprovalExpired)
	}
	if ap.RequesterPrincipal == ap.ApproverPrincipal {
		return Deny(ReasonDualControlRequired) // requester==approver → INV-010
	}
	// Binding YENİDEN doğrulama (onay sırasında değişmiş olabilir).
	if ap.RequestHash != req.RequestHash() {
		return Deny(ReasonApprovalBindingMismatch)
	}
	if ap.Action != req.Action {
		return Deny(ReasonTargetChanged) // action/target içeriği RequestHash'e girer; ek açıklık
	}
	if ap.TargetsHash != TargetsHash(req.Targets) {
		return Deny(ReasonTargetChanged)
	}
	if ap.PolicyHash != effectivePolicyHash {
		return Deny(ReasonPolicyChanged)
	}
	if trimLowerSpace(ap.TenantID) != trimLowerSpace(req.TenantID) {
		return Deny(ReasonTenantMismatch)
	}
	// Atomik consume: aynı onaya iki concurrent finalize → yalnız biri grant üretir.
	if err := store.Consume(ap.ApprovalID); err != nil {
		return Deny(ReasonApprovalAlreadyConsumed)
	}
	gid, nonce := mint()
	g := NewGrant(gid, nonce, req, effectivePolicyHash, ap.PolicyVersion, now, now.Add(ttl))
	return Allow(&g)
}
