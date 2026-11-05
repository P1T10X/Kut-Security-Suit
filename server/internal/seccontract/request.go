package seccontract

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"kut.corp/suite/server/internal/scope"
)

// ActionRequest, bir principal'ın NE yapmak istediğidir (CONTRACTS §1). Yetki
// KANITI DEĞİLDİR. `RequestedImpact` yalnız HINT'tir; enforcement `EffectiveImpact`
// ile server-side belirlenir (INV-006).
type ActionRequest struct {
	RequestID       string
	TenantID        string
	Principal       Principal
	Action          scope.Action
	Targets         []string
	RequestedImpact scope.Impact // yalnız bilgilendirici; enforcement DEĞİL
	Confirmed       bool
	CreatedAt       time.Time
}

// EffectiveImpact, etkiyi SERVER-SIDE, Action'dan deterministik türetir. Caller
// düşüremez; bilinmeyen aksiyon en katı sınıfa (Destructive) düşer (scope.ImpactOf).
func (r ActionRequest) EffectiveImpact() scope.Impact { return scope.ImpactOf(r.Action) }

// canonicalTargets, hedefleri kırpıp tekilleştirip sıralar (deterministik hash için).
func canonicalTargets(targets []string) []string {
	seen := make(map[string]bool, len(targets))
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// TargetsHash, hedef kümesinin kanonik (sırasız) özetidir (CONTRACTS §4/§5 TargetsHash).
func TargetsHash(targets []string) string {
	h := sha256.New()
	for _, t := range canonicalTargets(targets) {
		h.Write([]byte(t))
		h.Write([]byte{0x1e})
	}
	return "th_" + hex.EncodeToString(h.Sum(nil))[:32]
}

// RequestHash, isteğin GÜVENLİK-İLGİLİ içeriğinin kanonik özetidir: tenant,
// principal, action, kanonik-targets. RequestID (kimlik) ve zaman DAHİL DEĞİLDİR —
// Grant/Approval bu içerik-bağına kilitlenir. Alan sırası ve ayraçlar sabittir;
// üretici ve doğrulayıcı aynı formu üretir.
func (r ActionRequest) RequestHash() string {
	h := sha256.New()
	write := func(s string) { h.Write([]byte(s)); h.Write([]byte{0x1f}) }
	write(trimLowerSpace(r.TenantID))
	write(string(r.Principal.Type))
	write(r.Principal.ID)
	write(string(r.Action))
	for _, t := range canonicalTargets(r.Targets) {
		h.Write([]byte(t))
		h.Write([]byte{0x1e})
	}
	return "rh_" + hex.EncodeToString(h.Sum(nil))[:32]
}
