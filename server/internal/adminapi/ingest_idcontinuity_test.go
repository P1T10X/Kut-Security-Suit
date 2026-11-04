package adminapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/authtoken"
	"kut.corp/suite/server/internal/logingest"
)

const fw1JSON = `[{"source":"fw1","category":"SECURITY","severity":"HIGH","message":"deny"}]`

// KUT_TENANT_ID=acme dağıtımında legacy (kiracısız) statik token olayları dağıtım
// kiracısıyla DAMGALAR ama cihaz kimliği kiracı damgalama öncesiyle AYNI kalır (geçmiş bölünmez);
// kiracıya bağlı token'lar ad-alanlanır ve aynı kaynak adını kullanan iki kiracı ayrı kalır.
func TestIngestDeviceIDContinuity(t *testing.T) {
	srv, store := newServer(t)
	srv.SetTenantID("acme")
	srv.SetTokenStore(authtoken.NewMemStore(nil))
	sink := newTenantIngest()
	srv.SetIngest(sink, "legacy-tok")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	plat := wallAdmin(t, ts, store, "plat-adm", admin.RoleAdmin, "")
	legacyID := logingest.SourceUUID("fw1")

	// 1) Legacy token + dağıtım kiracısı acme: eski kimlik korunur, kiracı damgası acme.
	if c := ingestPost(t, ts.URL+"/api/ingest", "legacy-tok", "application/json", fw1JSON, nil); c != http.StatusOK {
		t.Fatalf("legacy ingest: %d", c)
	}
	if len(sink.saved) != 1 {
		t.Fatalf("1 cihaz beklenir: %d", len(sink.saved))
	}
	evs, ok := sink.saved[legacyID]
	if !ok || len(evs) != 1 || evs[0].DeviceID != legacyID || evs[0].TenantID != "acme" {
		t.Fatalf("legacy token eski kimliği korumalı ve acme damgalamalı: %+v", sink.saved)
	}

	// 2) Dağıtım kiracısından FARKLI açık bağlı token → ad-alanlı kimlik.
	betaTok := mintIngest(t, ts, plat, "beta")
	gammaTok := mintIngest(t, ts, plat, "gamma")
	for _, tok := range []string{betaTok, gammaTok} {
		if c := ingestPost(t, ts.URL+"/api/ingest", tok, "application/json", fw1JSON, nil); c != http.StatusOK {
			t.Fatalf("bağlı token ingest: %d", c)
		}
	}
	betaID := logingest.TenantDeviceID("beta", legacyID)
	gammaID := logingest.TenantDeviceID("gamma", legacyID)
	if betaID == legacyID || gammaID == legacyID || betaID == gammaID {
		t.Fatal("test ön-koşulu: üç kimlik birbirinden farklı olmalı")
	}
	if len(sink.saved) != 3 || len(sink.saved[betaID]) != 1 || len(sink.saved[gammaID]) != 1 {
		t.Fatalf("beta ve gamma AYRI ad-alanlı cihazlara düşmeli: %v", keysOf(sink.saved))
	}
	if sink.saved[betaID][0].TenantID != "beta" || sink.saved[gammaID][0].TenantID != "gamma" {
		t.Fatal("kiracı damgaları yanlış")
	}

	// 3) Dağıtım kiracısına (acme) açıkça bağlı token da eski kimliği paylaşır (süreklilik).
	acmeTok := mintIngest(t, ts, plat, "acme")
	if c := ingestPost(t, ts.URL+"/api/ingest", acmeTok, "application/json", fw1JSON, nil); c != http.StatusOK {
		t.Fatalf("acme ingest: %d", c)
	}
	if len(sink.saved[legacyID]) != 2 {
		t.Fatalf("dağıtım kiracısına bağlı token eski kimliğe yazmalı: %v", keysOf(sink.saved))
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
