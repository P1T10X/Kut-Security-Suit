package aisec

import "testing"

// TestEvaluateExfiltration, INV-AG-004'ü doğrular: credential.read + external.write
// birlikteliği tainted'te DENY, untrusted'ta REQUIRE_HUMAN, trusted'ta ALLOW; tek başına
// bir yetenek veya güvenilir context serbest.
func TestEvaluateExfiltration(t *testing.T) {
	both := CapSet{CapCredentialRead: true, CapExternalWrite: true}
	onlyRead := CapSet{CapCredentialRead: true}
	onlyWrite := CapSet{CapExternalWrite: true}

	cases := []struct {
		name  string
		trust TrustLevel
		eff   CapSet
		want  AGDecision
	}{
		{"tainted+both→DENY", Tainted, both, AGDeny},
		{"untrusted+both→REQUIRE_HUMAN", Untrusted, both, AGRequireHuman},
		{"trusted+both→ALLOW", Trusted, both, AGAllow},
		{"tainted+onlyRead→ALLOW", Tainted, onlyRead, AGAllow},
		{"tainted+onlyWrite→ALLOW", Tainted, onlyWrite, AGAllow},
		{"tainted+none→ALLOW", Tainted, CapSet{}, AGAllow},
	}
	for _, c := range cases {
		if got := EvaluateExfiltration(c.trust, c.eff); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

// TestToolOutputIsData, INV-AG-005'i doğrular: tool/MCP çıktısı en fazla Untrusted'tır
// ve bir agent onu okuyunca güveni yükselmez (yalnız düşer/korunur).
func TestToolOutputIsData(t *testing.T) {
	if ToolOutputTrust() != Untrusted {
		t.Fatalf("tool çıktısı en fazla Untrusted olmalı: %s", ToolOutputTrust())
	}
	// Güvenilir agent tool okur → en fazla Untrusted'a düşer (talimat yetkisi kazanmaz).
	if got := AbsorbToolOutput(Trusted); got != Untrusted {
		t.Fatalf("trusted agent tool okuyunca Untrusted olmalı: %s", got)
	}
	// Zaten tainted agent tool okur → tainted kalır (yükselme yok).
	if got := AbsorbToolOutput(Tainted); got != Tainted {
		t.Fatalf("tainted agent tool okuyunca tainted kalmalı: %s", got)
	}
}

// TestExfiltrationChainScenario, uçtan-uca senaryo: güvenilir agent untrusted web +
// tool çıktısı okur (zincir tainted olur) ve credential+external yeteneğiyle exfil
// dener → DENY.
func TestExfiltrationChainScenario(t *testing.T) {
	// Zincir: iç agent (Trusted) → untrusted web (Untrusted) → tainted araç sonucu.
	trust := ChainTrust(Trusted, Untrusted, Tainted)
	eff := EffectiveCapabilities(
		CapSet{CapCredentialRead: true, CapExternalWrite: true}, // human
		CapSet{CapCredentialRead: true, CapExternalWrite: true}, // agent
	)
	if got := EvaluateExfiltration(trust, eff); got != AGDeny {
		t.Fatalf("tainted zincir + credential + external → DENY bekleniyordu: %s", got)
	}
}

type mockSanitizer struct {
	ok  bool
	out string
}

func (m *mockSanitizer) Sanitize(input string) (string, bool) {
	return m.out, m.ok
}

// TestSanitizeContext, Tainted bağlam yalnızca CapSanitize ve
// başarılı doğrulayıcı ile Untrusted'a yükseltilebilir. Asla doğrudan Trusted olamaz.
func TestSanitizeContext(t *testing.T) {
	sanitizer := &mockSanitizer{ok: true, out: "cleaned input"}
	failingSanitizer := &mockSanitizer{ok: false, out: ""}
	capWithSanitize := CapSet{CapSanitize: true}
	capWithoutSanitize := CapSet{}

	// 1. CapSanitize olmadan temizleme başarısız olmalı (Tainted kalır)
	newTrust, _, ok := SanitizeContext(Tainted, capWithoutSanitize, sanitizer, "dirty")
	if ok || newTrust != Tainted {
		t.Fatalf("CapSanitize olmadan yükseltme engellenmeli: ok=%v, trust=%v", ok, newTrust)
	}

	// 2. Başarısız sanitizer ile temizleme başarısız olmalı
	newTrust, _, ok = SanitizeContext(Tainted, capWithSanitize, failingSanitizer, "dirty")
	if ok || newTrust != Tainted {
		t.Fatalf("başarısız doğrulayıcı ile yükseltme engellenmeli: ok=%v, trust=%v", ok, newTrust)
	}

	// 3. Başarılı sanitizer ve CapSanitize ile Tainted -> Untrusted olmalı
	newTrust, clean, ok := SanitizeContext(Tainted, capWithSanitize, sanitizer, "dirty")
	if !ok || newTrust != Untrusted || clean != "cleaned input" {
		t.Fatalf("başarılı sanitization Untrusted dönmeli: ok=%v, trust=%v, clean=%s", ok, newTrust, clean)
	}

	// 4. Untrusted veya Trusted bağlam zaten kirli olmadığından korunmalı
	newTrust, _, ok = SanitizeContext(Untrusted, capWithSanitize, sanitizer, "input")
	if !ok || newTrust != Untrusted {
		t.Fatalf("Untrusted bağlam korunmalı: %v", newTrust)
	}
}
