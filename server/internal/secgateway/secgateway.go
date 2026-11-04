// Package secgateway, frozen seccontract sözleşmesini (docs/CONTRACTS.md v3.2.1)
// canlı authz.Gateway'e bağlayan KÖPRÜDÜR. Amaç: yüksek-etkili
// isteklerin tek yetki-karar noktasını `seccontract.ActionRequest → AuthorizationDecision`
// tipleriyle ifade etmek; blast-radius/rate-limit kontrollerini mevcut authz.Gateway'e
// devretmek. Bu paket ADDITIVE ve DAVRANIŞ-KORUYANDIR: henüz hiçbir canlı executor yolu
// buradan geçmez (paralel yol). Sonraki değişiklikler canlı yolları buraya taşır.
//
// İki fail-closed kapı (CONTRACTS): boş tenant → DENY (INV-044); tanınmayan/boş
// principal type → DENY (insan sanılıp yumuşak-tavana düşme YASAK).
package secgateway

import (
	"time"

	"kut.corp/suite/server/internal/authz"
	"kut.corp/suite/server/internal/scope"
	"kut.corp/suite/server/internal/seccontract"
)

// Gateway, seccontract tiplerini authz.Gateway'e köprüler. Grant mint için politika
// sağlayıcı + kimlik/nonce üreteci + TTL tutar. Eşzamanlı kullanım authz.Gateway kadar
// güvenlidir (rate-limit durumu orada kilitlidir).
type Gateway struct {
	gw     *authz.Gateway
	policy seccontract.PolicyProvider
	now    func() time.Time
	genID  func() string
	ttl    time.Duration
}

// New, bir köprü Gateway oluşturur. now nil ise time.Now; ttl<=0 ise 5dk (grant kısa
// ömürlü olmalı — CONTRACTS §3). genID grant/nonce üretir; nil olmamalı.
func New(gw *authz.Gateway, policy seccontract.PolicyProvider, now func() time.Time, genID func() string, ttl time.Duration) *Gateway {
	if now == nil {
		now = time.Now
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Gateway{gw: gw, policy: policy, now: now, genID: genID, ttl: ttl}
}

// Authorize, bir ActionRequest'i frozen sözleşmeye göre yetkilendirir ve
// AuthorizationDecision döner. Sıra: tenant fail-closed → principal fail-closed →
// canlı authz (blast-radius → rate-limit) → ALLOW'da grant mint. Dönen karar daima
// Valid()'tir (ALLOW ⇔ Grant!=nil).
func (b *Gateway) Authorize(req seccontract.ActionRequest) seccontract.AuthorizationDecision {
	// 1) Tenant fail-closed (INV-044): boş kiracı güvenlik nesnesinde implicit
	// "default"a düşemez → DENY.
	if _, err := seccontract.NormTenant(req.TenantID); err != nil {
		return seccontract.Deny(seccontract.ReasonTenantMismatch)
	}
	// 2) Principal fail-closed: tanınmayan/boş type insan sanılıp yumuşak yola
	// düşmemeli. authz boş Requester'ı Human sayar; o tuzağı burada kapatırız.
	r, ok := mapRequester(req.Principal.Type)
	if !ok {
		return seccontract.Deny(seccontract.ReasonRBACDeny)
	}

	// 2.5) Boş yüksek-etki Target → DENY (CONTRACTS §1). authz TargetCount<1'i 1'e
	// yükselttiğinden blast-radius kapısını atlar; burada fail-closed kapatırız (yoksa
	// hedefsiz yıkıcı/yüksek-etki istek için DeviceID="" bir grant mint edilirdi).
	// NOT: AI'ın yüksek-etki grant ALMASI frozen sözleşmede (sert-otonom-yarıçap içinde)
	// KASITLI olarak izinlidir; yürütme yine GuardedExecutor'da bloklanır — bu yüzden
	// grant-mint'te ayrı bir capability kapısı EKLENMEZ (§1-13 semantiği değiştirilmez).
	if len(req.Targets) == 0 && req.EffectiveImpact() >= scope.HighImpact {
		return seccontract.Deny(seccontract.ReasonScopeDeny)
	}

	// 3) Canlı gateway: etki Action'dan server-side türetilir; TargetCount
	// blast-radius içindir. Confirmed yalnız insan yumuşak-tavanını etkiler.
	d := b.gw.Authorize(authz.Request{
		Requester:   r,
		Principal:   req.Principal.ID,
		Action:      req.Action,
		TargetCount: len(req.Targets),
		Confirmed:   req.Confirmed,
	})

	switch {
	case d.Allow:
		// ALLOW → grant mint (ALLOW ⇔ Grant!=nil; INV-008). Grant SUNUCU-İÇİdir,
		// tek-kullanımlık ve request/policy/tenant/target-bound (NewGrant kurar).
		now := b.now()
		g := seccontract.NewGrant(
			b.genID(), b.genID(), req,
			b.policy.EffectivePolicyHash(req), "",
			now, now.Add(b.ttl),
		)
		return seccontract.Allow(&g)
	case d.NeedApproval:
		return seccontract.NeedApproval(translate(d.Code))
	default:
		return seccontract.Deny(translate(d.Code))
	}
}

// mapRequester, seccontract.PrincipalType'ı authz.Requester'a eşler. İnsan-dışı her
// tip OTONOM sayılır (authz sert tavanı uygular). Boş/tanınmayan tip → (false):
// çağıran DENY etmeli (fail-closed; asla Human'a düşme).
func mapRequester(t seccontract.PrincipalType) (authz.Requester, bool) {
	switch t {
	case seccontract.PrincipalHuman:
		return authz.Human, true
	case seccontract.PrincipalAI:
		return authz.AI, true
	case seccontract.PrincipalSOAR, seccontract.PrincipalAutoResponder:
		return authz.SOAR, true // otomatik yanıt sınıfı
	case seccontract.PrincipalRule, seccontract.PrincipalScheduled:
		return authz.Rule, true // deterministik/zamanlanmış otomasyon
	default:
		return "", false // boş/bilinmeyen → fail-closed DENY
	}
}

// translate, authz makine-okunur Code'unu seccontract ReasonCode'una çevirir.
func translate(c authz.Code) seccontract.ReasonCode {
	switch c {
	case authz.CodeBlastRadius:
		return seccontract.ReasonBlastRadiusExceeded
	case authz.CodeRateLimit:
		return seccontract.ReasonRateLimited
	default:
		return seccontract.ReasonScopeDeny // gerekçesiz beklenmedik red → en genel deny
	}
}
