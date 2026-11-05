// Package scope, MERKEZİ ve BYPASS-EDİLEMEZ Scope / Rules-of-Engagement (ROE)
// guardrail motorudur. Yüksek-etkili her operasyon — WIPE, LOCK,
// RESTART, QUARANTINE, uzak komut, policy-enforcement, aktif tarama — hedefe
// uygulanmadan ÖNCE bu motordan geçmelidir. Böylece scope kontrolü yalnız API
// katmanında değil, komut/worker/agent/SOAR yollarının hepsinde tek noktada
// uygulanır.
//
// Tasarım ilkeleri:
//   - FAIL-CLOSED: eşleşen bir izin (allow) kuralı yoksa yüksek-etkili aksiyon
//     REDDEDİLİR. Yanlış yapılandırma "her şeye izin ver" anlamına gelmez.
//   - EXCLUDED ÖNCELİKLİDİR: hariç-tutulan bir hedef, allow eşleşse bile reddedilir
//     (ör. "production.example.com" asla taranmaz/wipe edilmez).
//   - ACTION-GATED ROE: destructive/exploitation gibi sınıflar ayrıca açıkça
//     etkinleştirilmeden çalışmaz (varsayılan kapalı).
//   - SAF ve TESTLİ: dış bağımlılık yok; net.IP/CIDR dışında yalnız stdlib.
package scope

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Action, korunması gereken bir operasyon türüdür.
type Action string

const (
	ActionPassiveScan   Action = "passive_scan"
	ActionActiveScan    Action = "active_scan"
	ActionExploitation  Action = "exploitation"
	ActionRemoteCommand Action = "remote_command"
	ActionPolicyEnforce Action = "policy_enforce"
	ActionQuarantine    Action = "quarantine"
	ActionRestart       Action = "restart"
	ActionLock          Action = "lock"
	ActionWipe          Action = "wipe"
)

// Impact, bir aksiyonun etki sınıfıdır (ROE seviyeleri).
type Impact int

const (
	Passive     Impact = iota // salt gözlem
	Active                    // hedefe dokunan tarama
	Remote                    // uzak komut yürütme
	HighImpact                // kilitleme/yeniden başlatma/karantina/policy
	Destructive               // geri döndürülemez (WIPE, exploitation)
)

func (i Impact) String() string {
	switch i {
	case Passive:
		return "PASSIVE"
	case Active:
		return "ACTIVE"
	case Remote:
		return "REMOTE_ACTION"
	case HighImpact:
		return "HIGH_IMPACT"
	case Destructive:
		return "DESTRUCTIVE"
	default:
		return "UNKNOWN"
	}
}

// impactOf, her aksiyonu bir etki sınıfına eşler.
var impactOf = map[Action]Impact{
	ActionPassiveScan:   Passive,
	ActionActiveScan:    Active,
	ActionExploitation:  Destructive,
	ActionRemoteCommand: Remote,
	ActionPolicyEnforce: HighImpact,
	ActionQuarantine:    HighImpact,
	ActionRestart:       HighImpact,
	ActionLock:          HighImpact,
	ActionWipe:          Destructive,
}

// ImpactOf, aksiyonun etki sınıfını döndürür (bilinmeyen aksiyon = Destructive,
// yani en katı sınıf — fail-closed).
func ImpactOf(a Action) Impact {
	if imp, ok := impactOf[a]; ok {
		return imp
	}
	return Destructive
}

// Known, aksiyonun etki tablosunda KAYITLI olup olmadığını bildirir. ImpactOf kayıtsız
// aksiyonu Destructive saydığından, çağıranlar "gerçekten Destructive" ile "tanınmayan"ı
// ayırt etmek için (ör. komut tablosu tutarlılık testleri) bunu kullanır.
func Known(a Action) bool {
	_, ok := impactOf[a]
	return ok
}

// Target, üzerinde işlem yapılacak varlıktır. Alanlar bilindiği kadarıyla doldurulur;
// boş alanlar ilgili seçici tarafından yok sayılır.
type Target struct {
	Tenant      string
	Environment string // "production" | "staging" | ...
	DeviceID    string
	Host        string
	Domain      string
	Service     string
	IP          net.IP
	Port        int
}

// Selector, bir hedef kümesini tanımlar. Boş bir alan "bu boyutta kısıt yok" demektir.
type Selector struct {
	Domains      []string // "*.example.com" (soneki eşleşme) veya tam alan adı
	Networks     []string // CIDR: "10.0.0.0/16", "2001:db8::/32"
	Hosts        []string // tam host adı (küçük harfe duyarsız)
	Devices      []string // cihaz kimliği (tam)
	Tenants      []string // kiracı kimliği (tam)
	Environments []string // ortam adı (tam, küçük harfe duyarsız)
	Ports        []int
}

// Policy, tek bir kiracı (ya da global) için scope + ROE kurallarıdır.
type Policy struct {
	Allowed  Selector
	Excluded Selector
	// Actions, aksiyon-bazlı ROE anahtarlarıdır. Bir aksiyon burada YOKSA:
	// Passive/Active/Remote/HighImpact için "allow eşleşmesine bak"; Destructive
	// için VARSAYILAN KAPALI (açıkça true olmalı).
	Actions map[Action]bool
	// RateLimitRPS, bu scope için önerilen saniyedeki istek limitidir (0 = sınırsız);
	// motor bunu taşır, uygulaması çağırana (ratelimit paketi) bırakılır.
	RateLimitRPS float64
}

// Decision, bir yetkilendirme sonucudur.
type Decision struct {
	Allowed bool
	Impact  Impact
	Reason  string
}

// rateLimiter basit bir token-bucket algoritması gerçeklemesidir.
type rateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	rate       float64 // son görülen RPS (eviction uygunluk kontrolü için)
	lastUpdate time.Time
}

func (r *rateLimiter) allow(rate float64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.rate = rate
	now := time.Now()
	if r.lastUpdate.IsZero() {
		r.lastUpdate = now
		r.tokens = rate
	} else {
		elapsed := now.Sub(r.lastUpdate).Seconds()
		r.tokens += elapsed * rate
		if r.tokens > rate {
			r.tokens = rate
		}
		r.lastUpdate = now
	}

	if r.tokens >= 1 {
		r.tokens -= 1
		return true
	}
	return false
}

// evictable, bu limiter'ın güvenle silinebileceğini bildirir: hiç kullanılmamış,
// ya da TTL'den uzun süredir atıl VE atıl süre boyunca kovanın TAMAMEN dolacağı
// durumda. İkinci koşulda silip yeniden-oluşturmak, girdiyi korumakla birebir aynı
// davranışı verir (yeni rateLimiter de dolu başlar); böylece hâlâ kısıtlanan
// (yarı-dolu) bir kova asla erken sıfırlanmaz, ama boşaltılıp terk edilmiş bir kova
// yeniden dolacağı anda geri kazanılır.
func (r *rateLimiter) evictable(now time.Time, ttl time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lastUpdate.IsZero() {
		// Henüz kullanılmamış (oluşturma ile ilk allow arasındaki geçici pencere):
		// hemen ardından kullanılacak, sızıntı adayı değildir.
		return false
	}
	if now.Sub(r.lastUpdate) <= ttl {
		return false
	}
	refilled := r.tokens + now.Sub(r.lastUpdate).Seconds()*r.rate
	return refilled >= r.rate
}

// Engine, kiracı-bazlı Policy'leri tutar ve yetkilendirme kararı verir.
// Eşzamanlı erişime güvenlidir.
type Engine struct {
	mu        sync.RWMutex
	global    *Policy
	perTenant map[string]*Policy

	rlMu         sync.Mutex
	rateLimiters map[string]*rateLimiter
	lastSweep    time.Time
}

const (
	// limiterIdleTTL, bir rate-limiter girdisinin eviction için atıl sayılma eşiği.
	limiterIdleTTL = 15 * time.Minute
	// limiterSweepEvery, ardışık taramalar arası asgari süre (amortize maliyet).
	limiterSweepEvery = 1 * time.Minute
)

// maybeSweepLocked, atıl/dolu rate-limiter girdilerini temizler. Çağıran e.rlMu'yu
// tutmalıdır. Taramalar limiterSweepEvery ile sınırlıdır; böylece map, saldırganın
// kiracı/aksiyon uzayını sondalayarak sınırsız büyütmesine karşı sınırlanır.
func (e *Engine) maybeSweepLocked(now time.Time) {
	if !e.lastSweep.IsZero() && now.Sub(e.lastSweep) < limiterSweepEvery {
		return
	}
	e.lastSweep = now
	for k, rl := range e.rateLimiters {
		if rl.evictable(now, limiterIdleTTL) {
			delete(e.rateLimiters, k)
		}
	}
}

// New, isteğe bağlı bir global (tüm kiracılara uygulanan taban) policy ile motor kurar.
func New(global *Policy) *Engine {
	return &Engine{
		global:       global,
		perTenant:    map[string]*Policy{},
		rateLimiters: map[string]*rateLimiter{},
	}
}

// SetTenantPolicy, bir kiracıya özel policy atar (nil = kaldır).
func (e *Engine) SetTenantPolicy(tenant string, p *Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p == nil {
		delete(e.perTenant, tenant)
		return
	}
	e.perTenant[tenant] = p
}

// policyFor, kiracının policy'sini (yoksa global'i) döndürür.
func (e *Engine) policyFor(tenant string) *Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if p, ok := e.perTenant[tenant]; ok {
		return p
	}
	return e.global
}

// Authorize, hedef+aksiyon için kararı döndürür. FAIL-CLOSED: policy yoksa yalnız
// Passive'e izin verilir; yüksek-etkili aksiyonlar reddedilir.
func (e *Engine) Authorize(t Target, a Action) Decision {
	imp := ImpactOf(a)
	p := e.policyFor(t.Tenant)

	if p == nil {
		if imp == Passive {
			return Decision{Allowed: true, Impact: imp, Reason: "policy yok; yalnız pasif izinli"}
		}
		return Decision{Allowed: false, Impact: imp,
			Reason: fmt.Sprintf("scope policy tanımsız — %s reddedildi (fail-closed)", imp)}
	}

	// 1) Excluded önceliklidir.
	if field, ok := matchSelector(p.Excluded, t); ok {
		return Decision{Allowed: false, Impact: imp,
			Reason: fmt.Sprintf("hedef hariç-tutma listesinde (%s)", field)}
	}

	// 2) Allowed eşleşmesi gereklidir (Passive dışında da fail-closed).
	if !allowedEmpty(p.Allowed) {
		if _, ok := matchSelector(p.Allowed, t); !ok {
			return Decision{Allowed: false, Impact: imp, Reason: "hedef izin verilen scope dışında"}
		}
	} else if imp > Passive {
		// Allowed hiç tanımlı değilse yüksek-etkili aksiyon reddedilir.
		return Decision{Allowed: false, Impact: imp,
			Reason: fmt.Sprintf("allow-scope boş — %s reddedildi (fail-closed)", imp)}
	}

	// 3) Action-gated ROE.
	if allow, set := p.Actions[a]; set {
		if !allow {
			return Decision{Allowed: false, Impact: imp,
				Reason: fmt.Sprintf("ROE: %q aksiyonu devre dışı", a)}
		}
	} else if imp == Destructive {
		return Decision{Allowed: false, Impact: imp,
			Reason: fmt.Sprintf("ROE: yıkıcı aksiyon %q açıkça etkinleştirilmemiş", a)}
	}

	// 4) Rate limit kontrolü
	if p.RateLimitRPS > 0 {
		key := fmt.Sprintf("%s:%s", t.Tenant, a)
		e.rlMu.Lock()
		rl, ok := e.rateLimiters[key]
		if !ok {
			rl = &rateLimiter{}
			e.rateLimiters[key] = rl
			// Yeni anahtar eklendi: map büyümesini sınırlamak için fırsatçı tarama.
			e.maybeSweepLocked(time.Now())
		}
		e.rlMu.Unlock()

		if !rl.allow(p.RateLimitRPS) {
			return Decision{Allowed: false, Impact: imp, Reason: "rate limit aşıldı"}
		}
	}

	return Decision{Allowed: true, Impact: imp, Reason: "scope+ROE onayladı"}
}

// allowedEmpty, allow seçicisinin hiçbir kısıt taşımadığını bildirir.
func allowedEmpty(s Selector) bool {
	return len(s.Domains) == 0 && len(s.Networks) == 0 && len(s.Hosts) == 0 &&
		len(s.Devices) == 0 && len(s.Tenants) == 0 && len(s.Environments) == 0 &&
		len(s.Ports) == 0
}

// matchSelector, hedefin seçiciyle eşleşip eşleşmediğini ve eşleşen boyutu döndürür.
// Herhangi bir boyutta eşleşme yeterlidir (OR semantiği).
func matchSelector(s Selector, t Target) (string, bool) {
	if t.Domain != "" {
		for _, d := range s.Domains {
			if domainMatch(d, t.Domain) {
				return "domain", true
			}
		}
	}
	if t.IP != nil {
		for _, c := range s.Networks {
			if cidrMatch(c, t.IP) {
				return "network", true
			}
		}
	}
	if t.Host != "" && containsFold(s.Hosts, t.Host) {
		return "host", true
	}
	if t.DeviceID != "" && contains(s.Devices, t.DeviceID) {
		return "device", true
	}
	if t.Tenant != "" && contains(s.Tenants, t.Tenant) {
		return "tenant", true
	}
	if t.Environment != "" && containsFold(s.Environments, t.Environment) {
		return "environment", true
	}
	if t.Port != 0 {
		for _, p := range s.Ports {
			if p == t.Port {
				return "port", true
			}
		}
	}
	return "", false
}

// domainMatch, "*.example.com" joker (soneki) eşleşmesini ve tam eşleşmeyi destekler.
// "*.example.com" hem "a.example.com" hem "example.com" ile eşleşir.
func domainMatch(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return false
}

// cidrMatch, IP'nin CIDR bloğunda olup olmadığını döndürür (geçersiz CIDR = eşleşmez).
func cidrMatch(cidr string, ip net.IP) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return n.Contains(ip)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
