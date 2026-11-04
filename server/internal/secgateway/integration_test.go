package secgateway_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kut.corp/suite/server/internal/authz"
	"kut.corp/suite/server/internal/scope"
	"kut.corp/suite/server/internal/seccontract"
	"kut.corp/suite/server/internal/secgateway"
)

// harness, köprü (secgateway) + yürütme sınırını (GuardedExecutor) AYNI politika/saat/
// id-üreteciyle birlikte kurar — böylece grant binding'i (RequestHash/PolicyHash/tenant/
// target) iki uçta da eşleşir. Bu, migration'ın hedeflediği uçtan-uca zinciri test eder:
// ActionRequest → Authorize → Grant → Execute → CommandEnvelope.
func harness() (*secgateway.Gateway, *seccontract.GuardedExecutor, *seccontract.MemSecurityStore) {
	fixed := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return fixed }
	var ctr int64
	genID := func() string { return fmt.Sprintf("id-%d", atomic.AddInt64(&ctr, 1)) } // concurrency-safe
	policy := seccontract.PolicyFunc(func(seccontract.ActionRequest) string { return "policy-v1" })

	gw := secgateway.New(authz.NewGateway(authz.DefaultPolicy()), policy, now, genID, time.Minute)
	store := seccontract.NewMemSecurityStore()
	exec := seccontract.NewGuardedExecutor(store, policy, now, genID)
	return gw, exec, store
}

func actionReq(pt seccontract.PrincipalType, act scope.Action) seccontract.ActionRequest {
	return seccontract.ActionRequest{
		RequestID: "req-1", TenantID: "t1",
		Principal: seccontract.Principal{Type: pt, ID: "p-1"},
		Action:    act, Targets: []string{"dev-1"},
	}
}

// TestGatewayToExecutor_HappyPath, tam zinciri doğrular ve envelope invariant'larını
// kontrol eder: CommandID dolu; envelope GrantID TAŞIMAZ (opak correlation);
// ExecutionIntent oluşur (INV-046).
func TestGatewayToExecutor_HappyPath(t *testing.T) {
	gw, exec, store := harness()
	req := actionReq(seccontract.PrincipalHuman, scope.ActionQuarantine)

	dec := gw.Authorize(req)
	if dec.Result != seccontract.ResultAllow || dec.Grant == nil {
		t.Fatalf("ALLOW+grant bekleniyordu: %+v", dec)
	}
	env, err := exec.Execute(req, *dec.Grant)
	if err != nil {
		t.Fatalf("Execute başarısız: %v", err)
	}
	if env.CommandID == "" {
		t.Fatal("CommandID dolu olmalı")
	}
	if env.AuthorizationCorrelationID == dec.Grant.GrantID || env.AuthorizationCorrelationID == "" {
		t.Fatalf("envelope opak correlation taşımalı, GrantID DEĞİL: corr=%q grant=%q", env.AuthorizationCorrelationID, dec.Grant.GrantID)
	}
	if env.DeviceID != "dev-1" || env.RequestID != "req-1" || env.TenantID != "t1" {
		t.Fatalf("envelope alanları hatalı: %+v", env)
	}
	if store.IntentCount() != 1 {
		t.Fatalf("tam 1 ExecutionIntent bekleniyordu: %d", store.IntentCount())
	}
}

// TestGatewayToExecutor_ReplayDenied, grant'in TEK-KULLANIMLIK olduğunu doğrular
// (INV-003): aynı grant ikinci kez tüketilemez, ikinci intent oluşmaz.
func TestGatewayToExecutor_ReplayDenied(t *testing.T) {
	gw, exec, store := harness()
	req := actionReq(seccontract.PrincipalHuman, scope.ActionQuarantine)
	dec := gw.Authorize(req)
	if _, err := exec.Execute(req, *dec.Grant); err != nil {
		t.Fatalf("ilk Execute geçmeli: %v", err)
	}
	if _, err := exec.Execute(req, *dec.Grant); err != seccontract.ErrGrantReplayed {
		t.Fatalf("ikinci Execute ErrGrantReplayed dönmeli: %v", err)
	}
	if store.IntentCount() != 1 {
		t.Fatalf("replay sonrası hâlâ tam 1 intent olmalı: %d", store.IntentCount())
	}
}

// TestGatewayToExecutor_ConcurrentSingleWinner, aynı grant'e N eşzamanlı Execute'ta
// yalnız BİRİNİN başarılı olduğunu doğrular (INV-003; -race altında atomiklik kanıtı).
func TestGatewayToExecutor_ConcurrentSingleWinner(t *testing.T) {
	gw, exec, store := harness()
	req := actionReq(seccontract.PrincipalHuman, scope.ActionQuarantine)
	dec := gw.Authorize(req)
	grant := *dec.Grant

	const N = 32
	var ok int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := exec.Execute(req, grant); err == nil {
				atomic.AddInt64(&ok, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok != 1 {
		t.Fatalf("tam 1 başarılı Execute bekleniyordu, %d oldu", ok)
	}
	if store.IntentCount() != 1 {
		t.Fatalf("tam 1 intent bekleniyordu: %d", store.IntentCount())
	}
}

// TestGateway_AICapabilityFirewall, AI principal grant alsa bile GuardedExecutor'a
// ASLA ulaşamayacağını doğrular (INV-AI-001): executor.direct AI'da yasaktır.
func TestGateway_AICapabilityFirewall(t *testing.T) {
	gw, exec, store := harness()
	req := actionReq(seccontract.PrincipalAI, scope.ActionActiveScan) // düşük etki → gateway ALLOW
	dec := gw.Authorize(req)
	if dec.Result != seccontract.ResultAllow || dec.Grant == nil {
		t.Fatalf("AI düşük-etki için ALLOW+grant bekleniyordu: %+v", dec)
	}
	if _, err := exec.Execute(req, *dec.Grant); err != seccontract.ErrForbiddenCapability {
		t.Fatalf("AI Execute ErrForbiddenCapability dönmeli (INV-AI-001): %v", err)
	}
	if store.IntentCount() != 0 {
		t.Fatalf("AI firewall'da hiç intent oluşmamalı: %d", store.IntentCount())
	}
}

// TestGateway_MissingTenantNoGrant, boş tenant'ın DENY döndürdüğünü ve yürütme yolu
// (grant) bırakmadığını doğrular (INV-044 + ALLOW⇔Grant!=nil).
func TestGateway_MissingTenantNoGrant(t *testing.T) {
	gw, _, _ := harness()
	req := actionReq(seccontract.PrincipalHuman, scope.ActionQuarantine)
	req.TenantID = ""
	dec := gw.Authorize(req)
	if dec.Result != seccontract.ResultDeny || dec.Grant != nil || !dec.Valid() {
		t.Fatalf("boş tenant DENY (grant nil) dönmeli: %+v", dec)
	}
}
