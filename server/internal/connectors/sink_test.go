package connectors

import (
	"context"
	"errors"
	"testing"
	"time"

	"kut.corp/suite/server/internal/logingest"
	"kut.corp/suite/server/internal/model"
)

type recSave struct {
	saved map[string][]model.Event
	fail  bool
}

func (r *recSave) save(_ context.Context, dev string, evs []model.Event) (uint64, error) {
	if r.fail {
		return 0, errors.New("db down")
	}
	if r.saved == nil {
		r.saved = map[string][]model.Event{}
	}
	r.saved[dev] = append(r.saved[dev], evs...)
	return 0, nil
}

func mkEv(src string) model.Event {
	return model.Event{
		Category: "SECURITY", Severity: "HIGH", Message: "m", OccurredAt: time.Unix(1700000000, 0),
		DeviceID: logingest.SourceUUID(src),
		// Kaynak verisi kiracı SEÇMEYE çalışır: ezilmelidir.
		TenantID: "attacker-chosen",
	}
}

// her bağlayıcı yapılandırılmış kiracısıyla damgalanır (kaynak verisindeki değer ezilir)
// ve iki kiracının aynı kaynak adı ayrı cihaz kimliğine düşer.
func TestConnectorSinkStampsConfiguredTenant(t *testing.T) {
	var a, b recSave
	sinkA := NewTenantSink(context.Background(), "acme", "acme", nil, a.save, nil)
	sinkB := NewTenantSink(context.Background(), "globex", "globex", nil, b.save, nil)
	sinkA([]model.Event{mkEv("fw1")})
	sinkB([]model.Event{mkEv("fw1")})

	for dev, evs := range a.saved {
		for _, e := range evs {
			if e.TenantID != "acme" || e.DeviceID != dev {
				t.Fatalf("acme olayı acme damgalı olmalı: %+v (cihaz %s)", e, dev)
			}
		}
	}
	for dev, evs := range b.saved {
		for _, e := range evs {
			if e.TenantID != "globex" || e.DeviceID != dev {
				t.Fatalf("globex olayı globex damgalı olmalı: %+v", e)
			}
		}
	}
	var da, db string
	for d := range a.saved {
		da = d
	}
	for d := range b.saved {
		db = d
	}
	if da == "" || db == "" || da == db {
		t.Fatalf("aynı kaynak adı iki kiracıda AYRI cihaz olmalı: %q %q", da, db)
	}
}

// Varsayılan kiracı: cihaz kimliği değişmez (süreklilik), olay "default" damgalı (boş değil).
func TestConnectorSinkDefaultTenantKeepsDeviceID(t *testing.T) {
	var r recSave
	NewTenantSink(context.Background(), "default", "", nil, r.save, nil)([]model.Event{mkEv("fw1")})
	want := logingest.SourceUUID("fw1")
	evs := r.saved[want]
	if len(evs) != 1 || evs[0].TenantID != "default" {
		t.Fatalf("varsayılan kiracı kimliği korumalı ve damgalamalı: %+v", r.saved)
	}
}

// Yineleme tespiti kiracı damgasından SONRA çalışır; yazma hatası onErr'e bildirilir ve
// panik/kayıp sessiz olmaz.
func TestConnectorSinkDedupAndErrors(t *testing.T) {
	var r recSave
	seen := map[string]bool{}
	isDup := func(e *model.Event) bool {
		id := e.EnsureID()
		if seen[id] {
			return true
		}
		seen[id] = true
		return false
	}
	sink := NewTenantSink(context.Background(), "acme", "acme", isDup, r.save, nil)
	sink([]model.Event{mkEv("fw1")})
	sink([]model.Event{mkEv("fw1")}) // aynı olay → düşer
	total := 0
	for _, evs := range r.saved {
		total += len(evs)
	}
	if total != 1 {
		t.Fatalf("tekrar düşürülmeliydi, kaydedilen=%d", total)
	}

	var gotErr error
	bad := recSave{fail: true}
	NewTenantSink(context.Background(), "acme", "acme", nil, bad.save, func(_ string, err error) { gotErr = err })([]model.Event{mkEv("fw2")})
	if gotErr == nil {
		t.Fatal("yazma hatası onErr'e bildirilmeli")
	}
}

// SourceConfig kiracısı: boş → dağıtım varsayılanı; geçersiz biçim fail-closed (BuildAll hata).
func TestSourceConfigResolveTenant(t *testing.T) {
	c := SourceConfig{Name: "x"}
	if got, err := c.ResolveTenant("Deploy-1"); err != nil || got != "deploy-1" {
		t.Fatalf("boş kiracı dağıtım varsayılanına düşmeli: %q %v", got, err)
	}
	if got, err := c.ResolveTenant(""); err != nil || got != "default" {
		t.Fatalf("her ikisi boşsa default: %q %v", got, err)
	}
	c.Tenant = " ACME "
	if got, err := c.ResolveTenant("deploy"); err != nil || got != "acme" {
		t.Fatalf("yapılandırılmış kiracı normalize edilmeli: %q %v", got, err)
	}
	c.Tenant = "bad tenant!"
	if _, err := c.ResolveTenant("deploy"); err == nil {
		t.Fatal("geçersiz kiracı hata vermeli")
	}
	if _, err := BuildAll([]SourceConfig{{Name: "x", Format: "syslog", Source: "/nonexistent", Tenant: "bad tenant!"}}); err == nil {
		t.Fatal("BuildAll geçersiz kiracıyı fail-fast reddetmeli")
	}
}

// kiracısız bağlayıcı (dağıtım kiracısı acme) acme ile damgalanır ama cihaz kimliği
// kiracı damgalama öncesiyle aynı kalır; açık farklı kiracıya bağlı bağlayıcı ad-alanlanır.
func TestConnectorBindingKeepsLegacyDeviceID(t *testing.T) {
	legacy, err := SourceConfig{Name: "fw"}.ResolveBinding("acme", false)
	if err != nil || legacy.Tenant != "acme" || legacy.IDTenant != "" {
		t.Fatalf("kiracısız bağlayıcı: %+v %v", legacy, err)
	}
	var r recSave
	NewTenantSink(context.Background(), legacy.Tenant, legacy.IDTenant, nil, r.save, nil)([]model.Event{mkEv("fw1")})
	want := logingest.SourceUUID("fw1")
	if evs := r.saved[want]; len(evs) != 1 || evs[0].TenantID != "acme" || evs[0].DeviceID != want {
		t.Fatalf("legacy bağlayıcı eski kimliği korumalı, acme damgalamalı: %+v", r.saved)
	}

	bound, err := SourceConfig{Name: "fw", Tenant: "beta"}.ResolveBinding("acme", false)
	if err != nil || bound.Tenant != "beta" || bound.IDTenant != "beta" {
		t.Fatalf("bağlı bağlayıcı: %+v %v", bound, err)
	}
	var b recSave
	NewTenantSink(context.Background(), bound.Tenant, bound.IDTenant, nil, b.save, nil)([]model.Event{mkEv("fw1")})
	if _, same := b.saved[want]; same || len(b.saved) != 1 {
		t.Fatalf("bağlı bağlayıcı ad-alanlı kimlik almalı: %+v", b.saved)
	}
}

// INV-044: KUT_TENANT_ENFORCE=1 iken kiracısız bağlayıcı REDDEDİLİR (HTTP ingest'in
// kiracısız token'ı 403'lemesiyle aynı fail-closed); kapalıyken dağıtım kiracısına düşer.
func TestConnectorBindingEnforceRequiresTenant(t *testing.T) {
	if _, err := (SourceConfig{Name: "fw"}).ResolveBinding("acme", true); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("enforce açıkken kiracısız bağlayıcı ErrTenantRequired olmalı: %v", err)
	}
	if _, err := (SourceConfig{Name: "fw", Tenant: "  "}).ResolveBinding("acme", true); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("boşluk-kiracı da reddedilmeli: %v", err)
	}
	if bd, err := (SourceConfig{Name: "fw", Tenant: "beta"}).ResolveBinding("acme", true); err != nil || bd.Tenant != "beta" {
		t.Fatalf("açık kiracılı bağlayıcı enforce'ta geçmeli: %+v %v", bd, err)
	}
	// Geçersiz biçim enforce'ta da hata.
	if _, err := (SourceConfig{Name: "fw", Tenant: "bad tenant!"}).ResolveBinding("acme", true); err == nil {
		t.Fatal("geçersiz kiracı reddedilmeli")
	}
	// Enforce kapalı: mevcut davranış (dağıtım kiracısı).
	if bd, err := (SourceConfig{Name: "fw"}).ResolveBinding("acme", false); err != nil || bd.Tenant != "acme" {
		t.Fatalf("enforce kapalıyken dağıtım kiracısına düşmeli: %+v %v", bd, err)
	}
	if bd, err := (SourceConfig{Name: "fw"}).ResolveBinding("", false); err != nil || bd.Tenant != "default" {
		t.Fatalf("her ikisi boşsa default: %+v %v", bd, err)
	}
}
