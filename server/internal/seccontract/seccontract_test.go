package seccontract

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kut.corp/suite/server/internal/scope"
)

func sampleRequest() ActionRequest {
	return ActionRequest{
		RequestID: "req-1", TenantID: "t1",
		Principal: Principal{Type: PrincipalHuman, ID: "admin1"},
		Action:    scope.ActionWipe, Targets: []string{"dev-b", "dev-a"},
		RequestedImpact: scope.Passive, // caller düşük beyan etti (tuzak)
		CreatedAt:       time.Unix(1_700_000_000, 0),
	}
}

// INV-006: EffectiveImpact caller'ın RequestedImpact'ine göre değil, Action'dan
// server-side türetilir; WIPE düşürülemez.
func TestEffectiveImpactServerDerived(t *testing.T) {
	r := sampleRequest()
	if r.RequestedImpact != scope.Passive {
		t.Fatal("test kurulumu")
	}
	if r.EffectiveImpact() != scope.Destructive {
		t.Fatalf("WIPE EffectiveImpact Destructive olmalı, aldım: %v", r.EffectiveImpact())
	}
	if r.EffectiveImpact() < scope.HighImpact {
		t.Fatal("destructive aksiyon caller tarafından düşürülememeli")
	}
}

// INV-044: boş tenant → DENY (implicit default'a düşme yok).
func TestNormTenantMissingDeny(t *testing.T) {
	if _, err := NormTenant("   "); err != ErrTenantMissing {
		t.Fatalf("boş tenant ErrTenantMissing dönmeli: %v", err)
	}
	got, err := NormTenant("  T1 ")
	if err != nil || got != "t1" {
		t.Fatalf("tenant normalize: %q %v", got, err)
	}
}

// INV-008..011: ALLOW⇔Grant!=nil; DENY/NEED_APPROVAL⇔Grant==nil.
func TestDecisionValid(t *testing.T) {
	if Allow(nil).Valid() {
		t.Fatal("ALLOW + nil grant geçersiz olmalı")
	}
	if !Allow(&AuthorizationGrant{GrantID: "g"}).Valid() {
		t.Fatal("ALLOW + grant geçerli olmalı")
	}
	if !Deny(ReasonRBACDeny).Valid() {
		t.Fatal("DENY (grant nil) geçerli olmalı")
	}
	if !NeedApproval().Valid() {
		t.Fatal("NEED_APPROVAL (grant nil) geçerli olmalı")
	}
	if (AuthorizationDecision{Result: ResultAllow}).Valid() {
		t.Fatal("ALLOW ama grant nil → geçersiz")
	}
}

func newIssuedGrant(req ActionRequest, now time.Time) AuthorizationGrant {
	return NewGrant("g-1", "nonce-1", req, "P1", "policy-v1", now, now.Add(5*time.Minute))
}

// INV-003: grant tek-kullanım; ikinci consume → ErrGrantReplayed.
func TestGrantConsumeSingleUse(t *testing.T) {
	req := sampleRequest()
	now := req.CreatedAt
	g := newIssuedGrant(req, now)
	s := NewMemReplayStore()
	if err := s.Consume(g, req, "P1", now); err != nil {
		t.Fatalf("ilk consume başarılı olmalı: %v", err)
	}
	if err := s.Consume(g, req, "P1", now); err != ErrGrantReplayed {
		t.Fatalf("ikinci consume ErrGrantReplayed olmalı: %v", err)
	}
}

// INV-047: CAS predicate — expired / tenant / requestHash / policyHash / action /
// targets uyumsuz → DENY; ve grant TÜKETİLMEZ.
func TestGrantConsumeBindingPredicate(t *testing.T) {
	req := sampleRequest()
	now := req.CreatedAt
	g := newIssuedGrant(req, now)

	// expired
	if err := NewMemReplayStore().Consume(g, req, "P1", g.ExpiresAt.Add(time.Second)); err != ErrGrantExpired {
		t.Fatalf("expired → ErrGrantExpired: %v", err)
	}
	// policy değişti
	if err := NewMemReplayStore().Consume(g, req, "P2-changed", now); err != ErrGrantMismatch {
		t.Fatalf("policy mismatch → ErrGrantMismatch: %v", err)
	}
	// tenant uyumsuz
	badTenant := req
	badTenant.TenantID = "t2"
	if err := NewMemReplayStore().Consume(g, badTenant, "P1", now); err != ErrGrantMismatch {
		t.Fatalf("tenant mismatch → ErrGrantMismatch: %v", err)
	}
	// action uyumsuz (RequestHash da değişir; yine mismatch)
	badAction := req
	badAction.Action = scope.ActionQuarantine
	if err := NewMemReplayStore().Consume(g, badAction, "P1", now); err != ErrGrantMismatch {
		t.Fatalf("action mismatch → ErrGrantMismatch: %v", err)
	}
	// hedef uyumsuz
	badTargets := req
	badTargets.Targets = []string{"dev-x"}
	if err := NewMemReplayStore().Consume(g, badTargets, "P1", now); err != ErrGrantMismatch {
		t.Fatalf("targets mismatch → ErrGrantMismatch: %v", err)
	}
	// başarısız consume grant'i TÜKETMEMELİ: uyumsuz istekle deneme → hata, ardından
	// doğru istekle hâlâ geçmeli.
	s := NewMemReplayStore()
	if err := s.Consume(g, badTargets, "P1", now); err != ErrGrantMismatch {
		t.Fatalf("uyumsuz istek ErrGrantMismatch dönmeli: %v", err)
	}
	if err := s.Consume(g, req, "P1", now); err != nil {
		t.Fatalf("önceki başarısız denemeler grant'i tüketmemeli: %v", err)
	}
}

// INV-003 atomiklik: aynı grant'e N concurrent consume → tam olarak 1 başarı.
func TestGrantConsumeConcurrentAtomic(t *testing.T) {
	req := sampleRequest()
	now := req.CreatedAt
	g := newIssuedGrant(req, now)
	s := NewMemReplayStore()
	var success int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Consume(g, req, "P1", now) == nil {
				atomic.AddInt64(&success, 1)
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("concurrent consume'da tam 1 başarı olmalı, oldu: %d", success)
	}
}

// RequestHash içerik-bağı: hedef sırası fark etmez; içerik değişince hash değişir.
func TestRequestAndTargetsHashDeterministic(t *testing.T) {
	a := sampleRequest()
	b := sampleRequest()
	b.Targets = []string{"dev-a", "dev-b"} // farklı sıra, aynı küme
	if a.RequestHash() != b.RequestHash() {
		t.Fatal("hedef sırası RequestHash'i değiştirmemeli")
	}
	if TargetsHash(a.Targets) != TargetsHash(b.Targets) {
		t.Fatal("TargetsHash sırasız olmalı")
	}
	c := sampleRequest()
	c.Action = scope.ActionQuarantine
	if a.RequestHash() == c.RequestHash() {
		t.Fatal("farklı action farklı RequestHash üretmeli")
	}
}
