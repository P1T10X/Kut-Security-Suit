package seccontract

import (
	"sync"
	"time"

	"kut.corp/suite/server/internal/scope"
)

// guardedexecutor.go — CONTRACTS §13. Durum-değiştiren tek merkezi sınır.
// GuardedExecutor, ATOMİK security transition'ın SAHİBİDİR: capability kontrolü +
// CommandID üretimi + (grant consume + ExecutionIntent) atomik işlemi + envelope mint.
// Storage impl'leri authorization'ı yeniden uygulamaz; alt işlemler (consume/create)
// dışarıya ayrı ayrı sunulmaz — yalnız SecurityStore'un atomik metodu üzerinden.

// SecurityStore, grant tüketimi ile ExecutionIntent yaratımını TEK ATOMİK işlemde
// yapar (INV-041; aynı persistence boundary). İkisi birlikte başarılı olur ya da
// hiçbiri; validate+CAS tek commit-point'tir (INV-047).
type SecurityStore interface {
	ConsumeGrantAndCreateIntent(g AuthorizationGrant, req ActionRequest, effectivePolicyHash string, intent ExecutionIntent, now time.Time) error
}

// PolicyProvider, bir istek için etkin politika özetini döner (CAS binding'i için).
type PolicyProvider interface {
	EffectivePolicyHash(req ActionRequest) string
}

// PolicyFunc, PolicyProvider'ın fonksiyon adaptörüdür.
type PolicyFunc func(req ActionRequest) string

func (f PolicyFunc) EffectivePolicyHash(req ActionRequest) string { return f(req) }

// GuardedExecutor, yüksek-etkili eylemlerin TEK giriş sınırıdır.
type GuardedExecutor struct {
	store  SecurityStore
	policy PolicyProvider
	now    func() time.Time
	genID  func() string
	ttl    time.Duration
}

// NewGuardedExecutor oluşturur. now/genID/ttl için makul varsayılanlar uygulanır.
func NewGuardedExecutor(store SecurityStore, policy PolicyProvider, now func() time.Time, genID func() string) *GuardedExecutor {
	if now == nil {
		now = time.Now
	}
	return &GuardedExecutor{store: store, policy: policy, now: now, genID: genID, ttl: 5 * time.Minute}
}

// Execute, bir ActionRequest'i geçerli bir grant ile yürütür ve cihaza gidecek
// CommandEnvelope'u mint eder. Sıra (CONTRACTS §0): capability firewall → CommandID
// üret → atomik(consume grant + ExecutionIntent) → envelope mint. Herhangi bir
// doğrulama başarısızsa DENY; grant tüketilmez.
func (e *GuardedExecutor) Execute(req ActionRequest, grant AuthorizationGrant) (CommandEnvelope, error) {
	// Capability firewall: yürütme executor.direct gerektirir. AI principal buna ASLA
	// sahip olamaz → AI hiçbir zaman doğrudan executor'a ulaşamaz (INV-AI-001).
	if !CapabilityAllowed(req.Principal, CapExecutorDirect) {
		return CommandEnvelope{}, ErrForbiddenCapability
	}
	now := e.now()
	commandID := e.genID() // ExecutionIntent'ten ÖNCE (INV-046)
	intent := ExecutionIntent{
		IntentID: e.genID(), CommandID: commandID, GrantID: grant.GrantID,
		TenantID: req.TenantID, Action: req.Action, Targets: append([]string(nil), req.Targets...),
		Destructive: req.EffectiveImpact() >= scope.Destructive, State: IntentCreated, CreatedAt: now,
	}
	// Atomik: grant consume (CAS + binding) + ExecutionIntent — birlikte ya da hiç.
	if err := e.store.ConsumeGrantAndCreateIntent(grant, req, e.policy.EffectivePolicyHash(req), intent, now); err != nil {
		return CommandEnvelope{}, err
	}
	return CommandEnvelope{
		CommandID:                  commandID,
		AuthorizationCorrelationID: CorrelationID(grant.GrantID), // opak; GrantID değil
		RequestID:                  req.RequestID,
		TenantID:                   req.TenantID,
		DeviceID:                   firstTarget(req.Targets),
		Action:                     req.Action,
		IssuedAt:                   now,
		ExpiresAt:                  now.Add(e.ttl),
	}, nil
}

func firstTarget(targets []string) string {
	if len(targets) > 0 {
		return targets[0]
	}
	return ""
}

// MemSecurityStore, SecurityStore'un bellek-içi ATOMİK gerçekleştirimidir: consume +
// intent TEK kilit altında (aynı boundary → INV-041). ikisi birlikte ya da hiç.
type MemSecurityStore struct {
	mu       sync.Mutex
	consumed map[string]bool
	intents  map[string]ExecutionIntent
}

// NewMemSecurityStore oluşturur.
func NewMemSecurityStore() *MemSecurityStore {
	return &MemSecurityStore{consumed: map[string]bool{}, intents: map[string]ExecutionIntent{}}
}

// ConsumeGrantAndCreateIntent, SecurityStore'u gerçekler (atomik).
func (s *MemSecurityStore) ConsumeGrantAndCreateIntent(g AuthorizationGrant, req ActionRequest, effectivePolicyHash string, intent ExecutionIntent, now time.Time) error {
	if g.GrantID == "" {
		return ErrGrantMissing
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed[g.GrantID] {
		return ErrGrantReplayed
	}
	if err := g.checkBinding(req, effectivePolicyHash, now); err != nil {
		return err // ne consume ne intent (atomik: hiçbiri)
	}
	s.consumed[g.GrantID] = true
	s.intents[intent.IntentID] = intent
	return nil
}

// IntentCount, kaç ExecutionIntent kurulduğunu döner (test görünürlüğü).
func (s *MemSecurityStore) IntentCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.intents)
}
