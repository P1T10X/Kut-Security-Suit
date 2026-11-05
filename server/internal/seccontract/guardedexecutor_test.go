package seccontract

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kut.corp/suite/server/internal/scope"
)

func counterGen() func() string {
	var n int64
	return func() string { return fmt.Sprintf("id-%d", atomic.AddInt64(&n, 1)) }
}

func newExecutor(store SecurityStore, now time.Time) *GuardedExecutor {
	return NewGuardedExecutor(store, PolicyFunc(func(ActionRequest) string { return "P1" }),
		func() time.Time { return now }, counterGen())
}

// INV-046/041: geçerli grant → envelope mint (CommandID set), tek intent; ikinci
// Execute aynı grant → ErrGrantReplayed (INV-003).
func TestGuardedExecuteHappyPath(t *testing.T) {
	req := sampleRequest()
	now := req.CreatedAt
	g := NewGrant("g-1", "n-1", req, "P1", "v1", now, now.Add(5*time.Minute))
	store := NewMemSecurityStore()
	ex := newExecutor(store, now)

	env, err := ex.Execute(req, g)
	if err != nil {
		t.Fatalf("geçerli execute başarılı olmalı: %v", err)
	}
	if env.CommandID == "" {
		t.Fatal("CommandID üretilmeli (INV-046)")
	}
	if store.IntentCount() != 1 {
		t.Fatalf("tam 1 ExecutionIntent beklenirdi: %d", store.IntentCount())
	}
	if _, err := ex.Execute(req, g); err != ErrGrantReplayed {
		t.Fatalf("ikinci execute ErrGrantReplayed olmalı: %v", err)
	}
}

// envelope GERÇEK GrantID taşımaz; opak, deterministik korelasyon.
func TestEnvelopeCarriesNoGrantID(t *testing.T) {
	req := sampleRequest()
	now := req.CreatedAt
	g := NewGrant("g-secret-42", "n-1", req, "P1", "v1", now, now.Add(5*time.Minute))
	env, err := newExecutor(NewMemSecurityStore(), now).Execute(req, g)
	if err != nil {
		t.Fatal(err)
	}
	if env.AuthorizationCorrelationID == g.GrantID {
		t.Fatal("envelope GrantID taşımamalı")
	}
	if env.AuthorizationCorrelationID != CorrelationID(g.GrantID) {
		t.Fatal("korelasyon kimliği deterministik olmalı")
	}
}

// INV-AI-001: AI principal executor.direct alamaz → ErrForbiddenCapability; grant
// tüketilmez (intent yok).
func TestGuardedExecuteAIForbidden(t *testing.T) {
	req := sampleRequest()
	req.Principal = Principal{Type: PrincipalAI, ID: "local-ai"}
	now := req.CreatedAt
	g := NewGrant("g-1", "n-1", req, "P1", "v1", now, now.Add(5*time.Minute))
	store := NewMemSecurityStore()
	if _, err := newExecutor(store, now).Execute(req, g); err != ErrForbiddenCapability {
		t.Fatalf("AI execute ErrForbiddenCapability olmalı: %v", err)
	}
	if store.IntentCount() != 0 {
		t.Fatal("AI reddi öncesinde grant tüketilmemeli / intent yaratılmamalı")
	}
}

// INV-041/003 atomiklik: aynı grant'e N concurrent Execute → tam 1 envelope + tam 1 intent.
func TestGuardedExecuteConcurrentAtomic(t *testing.T) {
	req := sampleRequest()
	now := req.CreatedAt
	g := NewGrant("g-1", "n-1", req, "P1", "v1", now, now.Add(5*time.Minute))
	store := NewMemSecurityStore()
	ex := newExecutor(store, now)
	var ok int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ex.Execute(req, g); err == nil {
				atomic.AddInt64(&ok, 1)
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("concurrent execute'da tam 1 başarı: %d", ok)
	}
	if store.IntentCount() != 1 {
		t.Fatalf("tam 1 intent olmalı (atomik): %d", store.IntentCount())
	}
}

// Grant binding uyumsuz (hedef değişti) → ErrGrantMismatch, envelope yok.
func TestGuardedExecuteMismatchDenied(t *testing.T) {
	req := sampleRequest()
	now := req.CreatedAt
	g := NewGrant("g-1", "n-1", req, "P1", "v1", now, now.Add(5*time.Minute))
	tampered := req
	tampered.Targets = []string{"dev-evil"}
	if _, err := newExecutor(NewMemSecurityStore(), now).Execute(tampered, g); err != ErrGrantMismatch {
		t.Fatalf("uyumsuz grant ErrGrantMismatch olmalı: %v", err)
	}
}

// Capability firewall: AI yasak capability'ye asla sahip olamaz (INV-AI-001/035).
func TestCapabilityFirewall(t *testing.T) {
	ai := Principal{Type: PrincipalAI, ID: "local-ai"}
	human := Principal{Type: PrincipalHuman, ID: "admin1"}
	if CapabilityAllowed(ai, CapWipe) || CapabilityAllowed(ai, CapExecutorDirect) || CapabilityAllowed(ai, CapShellExecute) {
		t.Fatal("AI yasak capability'lere sahip olamaz")
	}
	if !CapabilityAllowed(ai, CapRecommendAction) || !CapabilityAllowed(ai, CapIncidentRead) {
		t.Fatal("AI izinli capability'lere sahip olmalı")
	}
	if !CapabilityAllowed(human, CapExecutorDirect) {
		t.Fatal("insan principal executor.direct'e (AI-firewall dışında) sahip olabilir")
	}
	_ = scope.ActionWipe
}
