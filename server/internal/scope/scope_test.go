package scope

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func dec(t *testing.T, e *Engine, tg Target, a Action) Decision {
	t.Helper()
	return e.Authorize(tg, a)
}

func TestFailClosedNoPolicy(t *testing.T) {
	e := New(nil)
	if d := dec(t, e, Target{DeviceID: "d1"}, ActionPassiveScan); !d.Allowed {
		t.Errorf("policy yokken pasif izinli olmalı: %+v", d)
	}
	for _, a := range []Action{ActionWipe, ActionQuarantine, ActionActiveScan, ActionRemoteCommand} {
		if d := dec(t, e, Target{DeviceID: "d1"}, a); d.Allowed {
			t.Errorf("policy yokken %q reddedilmeli (fail-closed): %+v", a, d)
		}
	}
}

func TestExcludedWins(t *testing.T) {
	e := New(&Policy{
		Allowed:  Selector{Domains: []string{"*.example.com"}},
		Excluded: Selector{Hosts: []string{"production.example.com"}},
		Actions:  map[Action]bool{ActionWipe: true},
	})
	// izin verilen scope içinde ama hariç tutulan host → reddedilmeli
	d := dec(t, e, Target{Domain: "production.example.com", Host: "production.example.com"}, ActionWipe)
	if d.Allowed {
		t.Errorf("hariç-tutulan host reddedilmeli: %+v", d)
	}
	// scope içinde, hariç değil → izinli (wipe açıkça etkin)
	d = dec(t, e, Target{Domain: "app.example.com"}, ActionWipe)
	if !d.Allowed {
		t.Errorf("scope içi wipe izinli olmalı: %+v", d)
	}
}

func TestOutOfScopeDenied(t *testing.T) {
	e := New(&Policy{Allowed: Selector{Networks: []string{"10.10.0.0/16"}}})
	in := net.ParseIP("10.10.5.5")
	out := net.ParseIP("192.168.1.1")
	if d := dec(t, e, Target{IP: in}, ActionActiveScan); !d.Allowed {
		t.Errorf("scope içi IP aktif tarama izinli olmalı: %+v", d)
	}
	if d := dec(t, e, Target{IP: out}, ActionActiveScan); d.Allowed {
		t.Errorf("scope dışı IP reddedilmeli: %+v", d)
	}
}

func TestDestructiveNeedsExplicitEnable(t *testing.T) {
	// wipe Actions'ta yok → yıkıcı, reddedilmeli
	e := New(&Policy{Allowed: Selector{Devices: []string{"d1"}}})
	if d := dec(t, e, Target{DeviceID: "d1"}, ActionWipe); d.Allowed {
		t.Errorf("açıkça etkinleştirilmemiş wipe reddedilmeli: %+v", d)
	}
	// aynı hedef için HIGH_IMPACT (quarantine) allow eşleşmesiyle izinli
	if d := dec(t, e, Target{DeviceID: "d1"}, ActionQuarantine); !d.Allowed {
		t.Errorf("scope içi quarantine izinli olmalı: %+v", d)
	}
}

func TestActionDisabled(t *testing.T) {
	e := New(&Policy{
		Allowed: Selector{Devices: []string{"d1"}},
		Actions: map[Action]bool{ActionQuarantine: false, ActionWipe: true},
	})
	if d := dec(t, e, Target{DeviceID: "d1"}, ActionQuarantine); d.Allowed {
		t.Errorf("devre dışı quarantine reddedilmeli: %+v", d)
	}
	if d := dec(t, e, Target{DeviceID: "d1"}, ActionWipe); !d.Allowed {
		t.Errorf("etkin wipe izinli olmalı: %+v", d)
	}
}

func TestDomainMatch(t *testing.T) {
	cases := []struct {
		pat, host string
		want      bool
	}{
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", true},
		{"*.example.com", "evil.com", false},
		{"example.com", "example.com", true},
		{"example.com", "a.example.com", false},
		{"*.Example.com", "A.EXAMPLE.COM", true}, // küçük harfe duyarsız
	}
	for _, c := range cases {
		if got := domainMatch(c.pat, c.host); got != c.want {
			t.Errorf("domainMatch(%q,%q)=%v, beklenen %v", c.pat, c.host, got, c.want)
		}
	}
}

func TestCIDRv6(t *testing.T) {
	e := New(&Policy{Allowed: Selector{Networks: []string{"2001:db8::/32"}}})
	in := net.ParseIP("2001:db8::1")
	out := net.ParseIP("2001:dead::1")
	if d := dec(t, e, Target{IP: in}, ActionActiveScan); !d.Allowed {
		t.Errorf("v6 scope içi izinli olmalı: %+v", d)
	}
	if d := dec(t, e, Target{IP: out}, ActionActiveScan); d.Allowed {
		t.Errorf("v6 scope dışı reddedilmeli: %+v", d)
	}
}

func TestEmptyAllowFailClosedForHighImpact(t *testing.T) {
	// Allowed boş (kısıt yok) → pasif izinli, yüksek-etkili reddedilmeli
	e := New(&Policy{Actions: map[Action]bool{ActionWipe: true}})
	if d := dec(t, e, Target{DeviceID: "d1"}, ActionPassiveScan); !d.Allowed {
		t.Errorf("boş allow'da pasif izinli olmalı: %+v", d)
	}
	if d := dec(t, e, Target{DeviceID: "d1"}, ActionWipe); d.Allowed {
		t.Errorf("boş allow'da wipe reddedilmeli (fail-closed): %+v", d)
	}
}

func TestPerTenantPolicy(t *testing.T) {
	e := New(nil)
	e.SetTenantPolicy("t1", &Policy{
		Allowed: Selector{Tenants: []string{"t1"}},
		Actions: map[Action]bool{ActionWipe: true},
	})
	// t1 kendi policy'siyle izinli
	if d := dec(t, e, Target{Tenant: "t1"}, ActionWipe); !d.Allowed {
		t.Errorf("t1 wipe izinli olmalı: %+v", d)
	}
	// t2 policy'siz → fail-closed
	if d := dec(t, e, Target{Tenant: "t2"}, ActionWipe); d.Allowed {
		t.Errorf("t2 (policy yok) wipe reddedilmeli: %+v", d)
	}
	// kaldır → t1 de fail-closed olur
	e.SetTenantPolicy("t1", nil)
	if d := dec(t, e, Target{Tenant: "t1"}, ActionWipe); d.Allowed {
		t.Errorf("policy kaldırınca t1 wipe reddedilmeli: %+v", d)
	}
}

func TestImpactOfUnknownIsDestructive(t *testing.T) {
	if ImpactOf(Action("hayali_aksiyon")) != Destructive {
		t.Error("bilinmeyen aksiyon en katı (Destructive) sınıflanmalı")
	}
	if ImpactOf(ActionPassiveScan) != Passive {
		t.Error("passive_scan Passive olmalı")
	}
}

func FuzzAuthorize(f *testing.F) {
	f.Add("t1", "app.example.com", "10.0.0.5", "wipe")
	f.Add("", "", "", "")
	f.Add("t1", "*.x", "::1", "passive_scan")
	e := New(&Policy{
		Allowed:  Selector{Domains: []string{"*.example.com"}, Networks: []string{"10.0.0.0/8"}},
		Excluded: Selector{Hosts: []string{"prod"}},
		Actions:  map[Action]bool{ActionWipe: true},
	})
	f.Fuzz(func(t *testing.T, tenant, domain, ip, action string) {
		// panik olmamalı; herhangi bir girdi için karar dönmeli
		_ = e.Authorize(Target{
			Tenant: tenant, Domain: domain, Host: domain, IP: net.ParseIP(ip),
		}, Action(action))
	})
}

func TestRateLimitEnforcement(t *testing.T) {
	e := New(&Policy{
		Allowed:      Selector{Tenants: []string{"t1"}},
		Actions:      map[Action]bool{ActionWipe: true},
		RateLimitRPS: 2, // 2 requests per second
	})

	// First two should pass
	d1 := dec(t, e, Target{Tenant: "t1"}, ActionWipe)
	if !d1.Allowed {
		t.Errorf("İlk istek izinli olmalı: %+v", d1)
	}

	d2 := dec(t, e, Target{Tenant: "t1"}, ActionWipe)
	if !d2.Allowed {
		t.Errorf("İkinci istek izinli olmalı: %+v", d2)
	}

	// Third should fail due to rate limit
	d3 := dec(t, e, Target{Tenant: "t1"}, ActionWipe)
	if d3.Allowed || d3.Reason != "rate limit aşıldı" {
		t.Errorf("Üçüncü istek rate limit'e takılmalı: %+v", d3)
	}
}

func TestNoRateLimit(t *testing.T) {
	e := New(&Policy{
		Allowed:      Selector{Tenants: []string{"t1"}},
		Actions:      map[Action]bool{ActionWipe: true},
		RateLimitRPS: 0, // Sınırsız
	})

	for i := 0; i < 5; i++ {
		d := dec(t, e, Target{Tenant: "t1"}, ActionWipe)
		if !d.Allowed {
			t.Errorf("Sınırsız rate limit izin vermeli (iterasyon %d): %+v", i, d)
		}
	}
}

func TestRateLimitPerTenantIsolation(t *testing.T) {
	e := New(nil)
	e.SetTenantPolicy("t1", &Policy{
		Allowed:      Selector{Tenants: []string{"t1"}},
		RateLimitRPS: 1,
	})
	e.SetTenantPolicy("t2", &Policy{
		Allowed:      Selector{Tenants: []string{"t2"}},
		RateLimitRPS: 1,
	})

	// t1 uses its 1 token
	if d := dec(t, e, Target{Tenant: "t1"}, ActionPassiveScan); !d.Allowed {
		t.Errorf("t1 ilk istek izinli olmalı")
	}
	// t1 second request fails
	if d := dec(t, e, Target{Tenant: "t1"}, ActionPassiveScan); d.Allowed {
		t.Errorf("t1 ikinci istek reddedilmeli")
	}

	// t2 should still have its token (isolation)
	if d := dec(t, e, Target{Tenant: "t2"}, ActionPassiveScan); !d.Allowed {
		t.Errorf("t2 ilk istek izolasyon sayesinde izinli olmalı")
	}
}

// TestRateLimiterEviction, atıl ve yeniden-dolacak limiter girdilerinin temizlenerek
// map'in sınırsız büyümesinin önlendiğini doğrular (bellek tüketimi DoS'u).
func TestRateLimiterEviction(t *testing.T) {
	e := New(&Policy{RateLimitRPS: 5}) // boş allow + pasif aksiyon her kiracıda geçer

	for i := 0; i < 50; i++ {
		dec(t, e, Target{Tenant: fmt.Sprintf("t%d", i)}, ActionPassiveScan)
	}

	e.rlMu.Lock()
	before := len(e.rateLimiters)
	stale := time.Now().Add(-2 * limiterIdleTTL)
	for _, rl := range e.rateLimiters {
		rl.mu.Lock()
		rl.lastUpdate = stale
		rl.mu.Unlock()
	}
	e.lastSweep = time.Time{} // anlık taramaya izin ver
	e.maybeSweepLocked(time.Now())
	after := len(e.rateLimiters)
	e.rlMu.Unlock()

	if before == 0 {
		t.Fatalf("beklenen limiter girdileri oluşmadı")
	}
	if after != 0 {
		t.Errorf("atıl+yeniden-dolacak limiter'lar temizlenmeli: before=%d after=%d", before, after)
	}
}

// TestRateLimiterRecentlyActiveNotEvicted, TTL içindeki (yakın zamanda aktif)
// girdilerin taramada korunduğunu doğrular.
func TestRateLimiterRecentlyActiveNotEvicted(t *testing.T) {
	e := New(&Policy{RateLimitRPS: 5})
	dec(t, e, Target{Tenant: "t1"}, ActionPassiveScan) // lastUpdate = now

	e.rlMu.Lock()
	e.lastSweep = time.Time{}
	e.maybeSweepLocked(time.Now())
	n := len(e.rateLimiters)
	e.rlMu.Unlock()

	if n != 1 {
		t.Errorf("yakın zamanda aktif limiter evict edilmemeli, kalan=%d", n)
	}
}
