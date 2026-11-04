package aisec

// dataflow.go — agent veri-akışı güvenliği (KUT-AI-SEC-007) + taint→exfiltration
// guard (INV-AG-004) ve tool/MCP çıktısı = DATA (INV-AG-005). Deterministik enforcement.

// AGDecision, agentic bir kontrolün deterministik kararıdır.
type AGDecision string

const (
	AGAllow        AGDecision = "ALLOW"
	AGDeny         AGDecision = "DENY"
	AGRequireHuman AGDecision = "REQUIRE_HUMAN"
)

// Sık kullanılan agent yetenekleri (execution §11'den AYRI; agent-davranış düzlemi).
const (
	CapCredentialRead Cap = "credential.read"  // hassas sır/kimlik-bilgisi okuma
	CapExternalWrite  Cap = "external.write"   // dış kanal (HTTP/exfil) yazma
	CapSanitize       Cap = "context.sanitize" // kirli (tainted) bağlamı doğrulayıp temizleme yetkisi
)

// EvaluateExfiltration, INV-AG-004'ü uygular: tainted/untrusted bir context'te
// credential.read + external.write yeteneklerinin BİRLİKTELİĞİ sessizce geçemez —
// klasik indirect prompt-injection → credential access → exfiltration zinciri. Karar
// güven düzeyine göre kademeli: Tainted → DENY; Untrusted → REQUIRE_HUMAN; Trusted →
// ALLOW. `eff` delegation+tenant kesişiminden gelen ETKİN yetenek kümesidir (INV-AG-003).
func EvaluateExfiltration(trust TrustLevel, eff CapSet) AGDecision {
	if eff.Allows(CapCredentialRead) && eff.Allows(CapExternalWrite) {
		switch trust {
		case Tainted:
			return AGDeny
		case Untrusted:
			return AGRequireHuman
		}
	}
	return AGAllow
}

// ToolOutputTrust, bir tool/MCP çıktısının güven düzeyini döner: DAİMA en fazla
// Untrusted (INV-AG-005). Tool/MCP çıktısı DATA'dır — komut/talimat yetkisi TAŞIMAZ;
// bilinen-güvenilir bir tool bile çıktısını "güvenilir talimat"a yükseltemez.
func ToolOutputTrust() TrustLevel { return Untrusted }

// AbsorbToolOutput, bir agent'ın tool/MCP çıktısı okuduktan sonraki ETKİN güven düzeyini
// döner: çıktı DATA olduğundan agent'ın güveni en fazla çıktı düzeyine DÜŞER (INV-AG-001/
// 005). Yükseltme yok.
func AbsorbToolOutput(agentTrust TrustLevel) TrustLevel {
	return PropagateTrust(agentTrust, ToolOutputTrust())
}

// Sanitizer, kirli (tainted) içeriği onaylı doğrulama/filtreleme kurallarından geçiren arayüzdür.
type Sanitizer interface {
	Sanitize(input string) (cleaned string, ok bool)
}

// SanitizeContext, Tainted bir bağlamı kontrollü şekilde Untrusted düzeyine
// yükseltir. Asla doğrudan Trusted'a yükseltmez (INV-AG-001 ihlal edilemez).
// Yalnızca etkin yetenek kümesinde CapSanitize bulunan agent'lar ve başarılı doğrulama ile çalışır.
func SanitizeContext(current TrustLevel, eff CapSet, sanitizer Sanitizer, input string) (TrustLevel, string, bool) {
	if current != Tainted {
		return current, input, true
	}
	if !eff.Allows(CapSanitize) {
		return Tainted, input, false
	}
	if sanitizer == nil {
		return Tainted, input, false
	}
	cleaned, ok := sanitizer.Sanitize(input)
	if !ok {
		return Tainted, input, false
	}
	// Tainted -> Untrusted'a kontrollü geçiş (asla Trusted değil)
	return Untrusted, cleaned, true
}
