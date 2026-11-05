package seccontract

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func approvedApproval(req ActionRequest, approver Principal, now time.Time) Approval {
	return Approval{
		ApprovalID: "ap-1", TenantID: req.TenantID, RequestID: req.RequestID,
		RequestHash: req.RequestHash(), Action: req.Action, TargetsHash: TargetsHash(req.Targets),
		PolicyHash: "P1", PolicyVersion: "v1",
		RequesterPrincipal: req.Principal, ApproverPrincipal: approver,
		DecidedBy: approver.ID, DecidedAt: now, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		State: ApprovalApproved,
	}
}

func mintFn() func() (string, string) {
	var n int64
	return func() (string, string) {
		i := atomic.AddInt64(&n, 1)
		return fmt.Sprintf("g-%d", i), fmt.Sprintf("n-%d", i)
	}
}

// INV-040: onaylı + eşleşen istek → ALLOW + grant; grant isteğe bağlanır.
func TestFinalizeAuthorizationHappy(t *testing.T) {
	req := sampleRequest()
	now := req.CreatedAt
	ap := approvedApproval(req, Principal{Type: PrincipalHuman, ID: "admin2"}, now)
	dec := FinalizeAuthorization(req, ap, NewMemApprovalStore(), "P1", now, mintFn(), 5*time.Minute)
	if dec.Result != ResultAllow || dec.Grant == nil || !dec.Valid() {
		t.Fatalf("onaylı finalize ALLOW+grant olmalı: %+v", dec)
	}
	// Üretilen grant, isteği tüketebilmeli.
	if err := NewMemReplayStore().Consume(*dec.Grant, req, "P1", now); err != nil {
		t.Fatalf("finalize grant'i isteği tüketebilmeli: %v", err)
	}
}

// INV-010: requester == approver → DENY (dual-control).
func TestFinalizeRequesterEqualsApprover(t *testing.T) {
	req := sampleRequest()
	now := req.CreatedAt
	ap := approvedApproval(req, req.Principal, now) // approver == requester
	dec := FinalizeAuthorization(req, ap, NewMemApprovalStore(), "P1", now, mintFn(), 5*time.Minute)
	if dec.Result != ResultDeny {
		t.Fatalf("requester==approver → DENY: %+v", dec)
	}
}

// APPROVAL_EXPIRED / POLICY_CHANGED / TARGET_CHANGED → DENY.
func TestFinalizeBindingChecks(t *testing.T) {
	req := sampleRequest()
	now := req.CreatedAt
	appr := Principal{Type: PrincipalHuman, ID: "admin2"}

	expired := approvedApproval(req, appr, now)
	if dec := FinalizeAuthorization(req, expired, NewMemApprovalStore(), "P1", expired.ExpiresAt.Add(time.Second), mintFn(), 5*time.Minute); dec.Result != ResultDeny {
		t.Fatal("expired approval → DENY")
	}
	if dec := FinalizeAuthorization(req, approvedApproval(req, appr, now), NewMemApprovalStore(), "P2-changed", now, mintFn(), 5*time.Minute); dec.Result != ResultDeny {
		t.Fatal("policy changed → DENY")
	}
	tampered := req
	tampered.Targets = []string{"dev-x"}
	if dec := FinalizeAuthorization(tampered, approvedApproval(req, appr, now), NewMemApprovalStore(), "P1", now, mintFn(), 5*time.Minute); dec.Result != ResultDeny {
		t.Fatal("target changed → DENY")
	}
}

// Atomiklik: aynı onaya N concurrent finalize → tam 1 ALLOW (tek grant).
func TestFinalizeAtomicSingleGrant(t *testing.T) {
	req := sampleRequest()
	now := req.CreatedAt
	ap := approvedApproval(req, Principal{Type: PrincipalHuman, ID: "admin2"}, now)
	store := NewMemApprovalStore()
	mint := mintFn()
	var allows int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if FinalizeAuthorization(req, ap, store, "P1", now, mint, 5*time.Minute).Result == ResultAllow {
				atomic.AddInt64(&allows, 1)
			}
		}()
	}
	wg.Wait()
	if allows != 1 {
		t.Fatalf("aynı onaydan tam 1 grant üretilmeli: %d", allows)
	}
}
