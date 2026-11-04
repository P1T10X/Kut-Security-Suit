package seccontract

import (
	"sync"
	"time"

	"kut.corp/suite/server/internal/scope"
)

// GrantState, bir grant'in yaşam döngüsüdür (CONTRACTS §3).
type GrantState string

const (
	GrantIssued   GrantState = "ISSUED"
	GrantConsumed GrantState = "CONSUMED"
	GrantExpired  GrantState = "EXPIRED"
)

// AuthorizationGrant, ALLOW kararından sonra executor'a sunulan SUNUCU-İÇİ yetki
// capability'sidir (CONTRACTS §3). Cihaza GİTMEZ (§5.1). Tek-kullanımlıktır;
// request/policy/tenant/principal/action/target-bound.
type AuthorizationGrant struct {
	GrantID       string
	RequestHash   string
	PolicyHash    string
	PolicyVersion string
	TenantID      string
	Principal     Principal
	Action        scope.Action
	Targets       []string
	TargetsHash   string
	Nonce         string
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

// NewGrant, bir ActionRequest + etkin politikadan grant üretir (mint). RequestHash/
// TargetsHash/tenant/principal/action bağları burada kurulur.
func NewGrant(grantID, nonce string, req ActionRequest, policyHash, policyVersion string, issuedAt, expiresAt time.Time) AuthorizationGrant {
	return AuthorizationGrant{
		GrantID: grantID, RequestHash: req.RequestHash(),
		PolicyHash: policyHash, PolicyVersion: policyVersion,
		TenantID: req.TenantID, Principal: req.Principal, Action: req.Action,
		Targets: append([]string(nil), req.Targets...), TargetsHash: TargetsHash(req.Targets),
		Nonce: nonce, IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}
}

// checkBinding, CAS predicate'inin salt-okunur (mutasyonsuz) kısmıdır (INV-047):
// state hariç tüm bağların istek+etkin politikayla eşleşmesi. Uymazsa spesifik hata.
func (g AuthorizationGrant) checkBinding(req ActionRequest, effectivePolicyHash string, now time.Time) error {
	if !now.Before(g.ExpiresAt) {
		return ErrGrantExpired
	}
	if trimLowerSpace(g.TenantID) != trimLowerSpace(req.TenantID) {
		return ErrGrantMismatch
	}
	if g.RequestHash != req.RequestHash() {
		return ErrGrantMismatch
	}
	if g.PolicyHash != effectivePolicyHash {
		return ErrGrantMismatch
	}
	if g.Action != req.Action {
		return ErrGrantMismatch
	}
	if g.TargetsHash != TargetsHash(req.Targets) {
		return ErrGrantMismatch
	}
	return nil
}

// ReasonFor, bir consume hatasını ReasonCode'a eşler (SOC/audit için).
func ReasonFor(err error) ReasonCode {
	switch err {
	case ErrGrantExpired:
		return ReasonGrantExpired
	case ErrGrantReplayed:
		return ReasonGrantReplayed
	case ErrGrantMissing:
		return ReasonGrantMissing
	default:
		return ReasonGrantMismatch
	}
}

// ReplayStore, grant'in TEK-KULLANIM tüketimini yönetir (CONTRACTS §3, INV-003).
type ReplayStore interface {
	// Consume, grant'i ISSUED→CONSUMED'e ATOMİK compare-and-swap ile geçirir; YALNIZ
	// checkBinding predicate'i sağlanırsa (INV-047, tek commit-point). Aynı grant'e
	// iki concurrent çağrıda EN FAZLA biri başarılı olur; diğeri ErrGrantReplayed.
	Consume(g AuthorizationGrant, req ActionRequest, effectivePolicyHash string, now time.Time) error
}

// MemReplayStore, ReplayStore'un bellek-içi gerçekleştirimidir (test/demo). Doğrulama
// + tüketim TEK kilit altında yapılır — validate ile CAS arasında TOCTOU penceresi yok.
type MemReplayStore struct {
	mu       sync.Mutex
	consumed map[string]bool
}

// NewMemReplayStore oluşturur.
func NewMemReplayStore() *MemReplayStore { return &MemReplayStore{consumed: map[string]bool{}} }

// Consume, ReplayStore'u gerçekler (atomik: validate+CAS tek kilit).
func (s *MemReplayStore) Consume(g AuthorizationGrant, req ActionRequest, effectivePolicyHash string, now time.Time) error {
	if g.GrantID == "" {
		return ErrGrantMissing
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed[g.GrantID] {
		return ErrGrantReplayed
	}
	if err := g.checkBinding(req, effectivePolicyHash, now); err != nil {
		return err // tüketilmedi; bağ uyumsuz/expired
	}
	s.consumed[g.GrantID] = true // atomik CAS: ISSUED→CONSUMED
	return nil
}
