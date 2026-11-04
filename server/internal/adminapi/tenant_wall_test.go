package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/aisec"
	"kut.corp/suite/server/internal/authtoken"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/msp"
	"kut.corp/suite/server/internal/security"
)

// wallServer: dağıtım varsayılan kiracısı "deploy-default" olan bir sunucu + httptest.
func wallServer(t *testing.T) (*httptest.Server, *memStore) {
	t.Helper()
	srv, store := newServer(t)
	srv.SetTenantID("deploy-default")
	srv.SetDetector(detect.NewEngine([]detect.Rule{{
		ID: "R1", Name: "x", Category: "SECURITY", Contains: []string{"x"}, Severity: "HIGH",
	}}))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, store
}

// wallAdmin, bir yönetici ekler (tenant "" → platform) ve oturum token'ını döner.
func wallAdmin(t *testing.T, ts *httptest.Server, store *memStore, id string, role admin.Role, tenantID string) string {
	t.Helper()
	addAdmin(t, store, id, id+"@x", "secret", role)
	store.adminTen[id] = tenantID
	_, b := post(t, ts.URL+"/api/login", "", map[string]string{"email": id + "@x", "password": "secret"})
	if b["token"] == "" {
		t.Fatalf("%s için oturum alınamadı", id)
	}
	return b["token"]
}

func hasAuditRow(store *memStore, action string) bool {
	for _, a := range store.auditRows {
		if a.Action == action || strings.HasPrefix(a.Action, action+":") {
			return true
		}
	}
	return false
}

func doReq(t *testing.T, method, url, token string, body string) int {
	t.Helper()
	var rdr *bytes.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, url, rdr)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// --- enrollment token kiracısı ---

func TestIssueTokenTenantBoundCallerCannotChooseTenant(t *testing.T) {
	ts, store := wallServer(t)
	acme := wallAdmin(t, ts, store, "acme-op", admin.RoleOperator, "acme")

	// NEGATIF: yabancı kiracı → 403 ve token KAYDEDİLMEZ.
	before := store.tokenSeq
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens", acme, map[string]string{"tenant_id": "globex"}); code != http.StatusForbidden {
		t.Fatalf("yabancı kiracı için token 403 olmalı: %d", code)
	}
	if store.tokenSeq != before {
		t.Fatal("reddedilen istek token üretmemeli")
	}
	// NEGATIF: geçersiz biçimli kiracı da (kendi kiracısına eşit değil) 403.
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens", acme, map[string]string{"tenant_id": "Bad_Tenant!"}); code != http.StatusForbidden {
		t.Fatalf("geçersiz kiracı 403 olmalı: %d", code)
	}

	// POZITIF: boş gövde {} → kendi kiracısı (ASLA dağıtım varsayılanı değil).
	if code, b := post(t, ts.URL+"/api/enrollment-tokens", acme, map[string]string{}); code != http.StatusOK || b["enrollment_token"] == "" {
		t.Fatalf("boş gövde meşru olmalı: %d %v", code, b)
	}
	if got := store.tokenTen["etok-"+strconv.Itoa(store.tokenSeq)]; got != "acme" {
		t.Fatalf("boş gövde çağıranın kiracısına sabitlenmeli, dönen: %q", got)
	}
	// POZITIF: tamamen gövdesiz istek de kendi kiracısı.
	if code := doReq(t, "POST", ts.URL+"/api/enrollment-tokens", acme, ""); code != http.StatusOK {
		t.Fatalf("gövdesiz istek meşru olmalı: %d", code)
	}
	if got := store.tokenTen["etok-"+strconv.Itoa(store.tokenSeq)]; got != "acme" {
		t.Fatalf("gövdesiz istek kendi kiracısı olmalı: %q", got)
	}
	// POZITIF: kendi kiracısını (büyük harfle) açıkça vermek de geçer, normalize edilir.
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens", acme, map[string]string{"tenant_id": "ACME"}); code != http.StatusOK {
		t.Fatalf("kendi kiracısı (normalize) kabul edilmeli: %d", code)
	}
}

func TestIssueTokenPlatformAdminChoosesValidatedTenant(t *testing.T) {
	ts, store := wallServer(t)
	plat := wallAdmin(t, ts, store, "plat-op", admin.RoleOperator, "")

	if code, _ := post(t, ts.URL+"/api/enrollment-tokens", plat, map[string]string{"tenant_id": "Globex"}); code != http.StatusOK {
		t.Fatalf("platform admini kiracı seçebilmeli: %d", code)
	}
	if got := store.tokenTen["etok-"+strconv.Itoa(store.tokenSeq)]; got != "globex" {
		t.Fatalf("seçilen kiracı tenant.Normalize ile normalize edilmeli: %q", got)
	}
	// NEGATIF: geçersiz biçim → 400 ve kayıt yok.
	before := store.tokenSeq
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens", plat, map[string]string{"tenant_id": "bad_tenant!"}); code != http.StatusBadRequest {
		t.Fatalf("geçersiz kiracı 400 olmalı: %d", code)
	}
	if store.tokenSeq != before {
		t.Fatal("geçersiz kiracı ile token üretilmemeli")
	}
	// POZITIF: boş gövde → dağıtım varsayılanı (yalnız platform için).
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens", plat, map[string]string{}); code != http.StatusOK {
		t.Fatalf("platform boş gövde: %d", code)
	}
	if got := store.tokenTen["etok-"+strconv.Itoa(store.tokenSeq)]; got != "deploy-default" {
		t.Fatalf("platform boş gövde dağıtım varsayılanı olmalı: %q", got)
	}
}

// --- token iptali kiracı kapısı ---

func TestRevokeTokenTenantGateHTTP(t *testing.T) {
	ts, store := wallServer(t)
	plat := wallAdmin(t, ts, store, "plat-op", admin.RoleOperator, "")
	acme := wallAdmin(t, ts, store, "acme-op", admin.RoleOperator, "acme")

	post(t, ts.URL+"/api/enrollment-tokens", plat, map[string]string{"tenant_id": "globex"})
	globexTok := "etok-" + strconv.Itoa(store.tokenSeq)
	post(t, ts.URL+"/api/enrollment-tokens", acme, map[string]string{})
	acmeTok := "etok-" + strconv.Itoa(store.tokenSeq)

	isUsed := func(id string) bool {
		for _, r := range store.tokenRows {
			if r.ID == id {
				return r.Used
			}
		}
		return false
	}
	// NEGATIF: acme, globex token'ını iptal edemez.
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens/"+globexTok+"/revoke", acme, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("yabancı token iptali 403 olmalı: %d", code)
	}
	if isUsed(globexTok) {
		t.Fatal("yabancı token iptal EDİLMEMELİYDİ")
	}
	// POZITIF: kendi token'ı.
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens/"+acmeTok+"/revoke", acme, map[string]string{}); code != http.StatusOK {
		t.Fatalf("kendi token iptali geçmeli: %d", code)
	}
	if !isUsed(acmeTok) {
		t.Fatal("kendi token iptal edilmeliydi")
	}
	// POZITIF: platform admini her token'ı iptal eder.
	if code, _ := post(t, ts.URL+"/api/enrollment-tokens/"+globexTok+"/revoke", plat, map[string]string{}); code != http.StatusOK {
		t.Fatalf("platform admini iptal edebilmeli: %d", code)
	}
}

// --- yönetici-yönetimi HTTP ---

func TestAdminManagementTenantScopeHTTP(t *testing.T) {
	ts, store := wallServer(t)
	plat := wallAdmin(t, ts, store, "plat-adm", admin.RoleAdmin, "")
	acme := wallAdmin(t, ts, store, "acme-adm", admin.RoleAdmin, "acme")
	_ = wallAdmin(t, ts, store, "globex-adm", admin.RoleAdmin, "globex")
	_ = plat

	// NEGATIF: acme, globex yöneticisinin rolünü / durumunu değiştiremez; platform adminine dokunamaz.
	for _, target := range []string{"globex-adm", "plat-adm"} {
		if code, _ := post(t, ts.URL+"/api/admins/"+target+"/role", acme, map[string]string{"role": "VIEWER"}); code != http.StatusForbidden {
			t.Fatalf("%s rol değişimi 403 olmalı: %d", target, code)
		}
		if code, _ := post(t, ts.URL+"/api/admins/"+target+"/deactivate", acme, map[string]string{}); code != http.StatusForbidden {
			t.Fatalf("%s pasifleştirme 403 olmalı: %d", target, code)
		}
		if !store.adminInfos[target].Active || store.adminInfos[target].Role != admin.RoleAdmin {
			t.Fatalf("%s DEĞİŞMEMELİYDİ: %+v", target, store.adminInfos[target])
		}
	}
	// NEGATIF: liste yalnız kendi kiracısı.
	resp, err := authedGET(t, ts.URL+"/api/admins", acme)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	body := buf.String()
	if strings.Contains(body, "globex-adm@x") || strings.Contains(body, "plat-adm@x") {
		t.Fatalf("liste başka kiracı/platform yöneticilerini SIZDIRMAMALI: %s", body)
	}
	if !strings.Contains(body, "acme-adm@x") {
		t.Fatalf("kendi kiracısı listede olmalı: %s", body)
	}

	// POZITIF: platform admini kısıtsız.
	if code, _ := post(t, ts.URL+"/api/admins/globex-adm/role", plat, map[string]string{"role": "VIEWER"}); code != http.StatusOK {
		t.Fatalf("platform admini rol değiştirebilmeli: %d", code)
	}
	if store.adminInfos["globex-adm"].Role != admin.RoleViewer {
		t.Fatal("rol güncellenmeliydi")
	}
	// POZITIF: kiracı admini kendi kiracısında (yeni yönetici oluşturup) değiştirebilir.
	code, nb := post(t, ts.URL+"/api/admins", acme, map[string]string{"email": "n@acme", "password": "parola12", "role": "VIEWER"})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("kendi kiracısında admin oluşturma: %d %v", code, nb)
	}
	newID := nb["admin_id"]
	if code, _ := post(t, ts.URL+"/api/admins/"+newID+"/role", acme, map[string]string{"role": "OPERATOR"}); code != http.StatusOK {
		t.Fatalf("kendi kiracısında rol değişimi geçmeli: %d", code)
	}
}

// --- yönetilen API token'ları yalnız platform admini ---

func TestManagedAPITokensPlatformAdminOnly(t *testing.T) {
	srv, store := newServer(t)
	srv.SetTokenStore(authtoken.NewMemStore(nil))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	plat := wallAdmin(t, ts, store, "plat-adm", admin.RoleAdmin, "")
	acme := wallAdmin(t, ts, store, "acme-adm", admin.RoleAdmin, "acme")

	// Platform admini bir token üretir (pozitif) + audit.
	code, cb := post(t, ts.URL+"/api/tokens", plat, map[string]any{"scope": "metrics"})
	if code != http.StatusCreated || cb["id"] == "" {
		t.Fatalf("platform admini token üretebilmeli: %d %v", code, cb)
	}
	if !hasAuditRow(store, "API_TOKEN_CREATE") {
		t.Fatal("API_TOKEN_CREATE audit satırı yazılmalıydı")
	}

	// NEGATIF: kiracılı ADMIN üretemez / listeleyemez / iptal edemez.
	if code, _ := post(t, ts.URL+"/api/tokens", acme, map[string]any{"scope": "ingest"}); code != http.StatusForbidden {
		t.Fatalf("kiracılı admin token üretememeli: %d", code)
	}
	if code := doReq(t, "GET", ts.URL+"/api/tokens", acme, ""); code != http.StatusForbidden {
		t.Fatalf("kiracılı admin token listeleyememeli: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/tokens/"+cb["id"]+"/revoke", acme, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("kiracılı admin token iptal edememeli: %d", code)
	}
	if hasAuditRow(store, "API_TOKEN_REVOKE") {
		t.Fatal("reddedilen iptal audit'te başarılı görünmemeli")
	}

	// POZITIF: platform admini listeler ve iptal eder (+ audit).
	if code := doReq(t, "GET", ts.URL+"/api/tokens", plat, ""); code != http.StatusOK {
		t.Fatalf("platform admini listeleyebilmeli: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/tokens/"+cb["id"]+"/revoke", plat, map[string]string{}); code != http.StatusOK {
		t.Fatalf("platform admini iptal edebilmeli: %d", code)
	}
	if !hasAuditRow(store, "API_TOKEN_REVOKE") {
		t.Fatal("API_TOKEN_REVOKE audit satırı yazılmalıydı")
	}
}

// --- cihaz etiketleri ---

func TestDeviceTagsCrossTenantDeniedHTTP(t *testing.T) {
	ts, store := wallServer(t)
	store.deviceTenant = map[string]string{"d-acme": "acme", "d-globex": "globex"}
	acme := wallAdmin(t, ts, store, "acme-op", admin.RoleOperator, "acme")

	if code, _ := post(t, ts.URL+"/api/devices/d-globex/tags", acme, map[string]any{"tags": []string{"x"}}); code != http.StatusForbidden {
		t.Fatalf("yabancı cihaz etiketleme 403 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/devices/d-acme/tags", acme, map[string]any{"tags": []string{"x"}}); code != http.StatusOK {
		t.Fatalf("kendi cihazını etiketleyebilmeli: %d", code)
	}
}

// --- Z4a (rol eşikleri): custody / artifact download / replay ---

func TestForensicsRoutesRequireOperator(t *testing.T) {
	ts, store := wallServer(t)
	viewer := wallAdmin(t, ts, store, "vw", admin.RoleViewer, "")
	op := wallAdmin(t, ts, store, "op", admin.RoleOperator, "")
	aid, _ := store.SaveArtifact(context.Background(), "dev-1", "cmd-1", "C:/logs/app.log", "abcd", []byte("icerik"))

	// NEGATIF: VIEWER 403.
	if code, _ := post(t, ts.URL+"/api/devices/dev-1/evidence/"+aid+"/custody", viewer, map[string]string{"action": "ACCESSED"}); code != http.StatusForbidden {
		t.Fatalf("VIEWER custody 403 olmalı: %d", code)
	}
	if code := doReq(t, "GET", ts.URL+"/api/artifacts/"+aid+"/download", viewer, ""); code != http.StatusForbidden {
		t.Fatalf("VIEWER artifact download 403 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/detections/replay", viewer, map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("VIEWER replay 403 olmalı: %d", code)
	}

	// POZITIF: OPERATOR geçer (403 değil; indirme 200, replay 200).
	if code := doReq(t, "GET", ts.URL+"/api/artifacts/"+aid+"/download", op, ""); code != http.StatusOK {
		t.Fatalf("OPERATOR artifact download 200 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/detections/replay", op, map[string]any{}); code != http.StatusOK {
		t.Fatalf("OPERATOR replay 200 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/devices/dev-1/evidence/"+aid+"/custody", op, map[string]string{"action": "ACCESSED"}); code == http.StatusForbidden {
		t.Fatalf("OPERATOR custody 403 almamalı: %d", code)
	}
}

// --- MFA yeniden kayıt HTTP ---

func TestMFAReenrollNeedsCodeHTTP(t *testing.T) {
	ts, store := wallServer(t)
	tok := wallAdmin(t, ts, store, "op1", admin.RoleOperator, "")

	// İlk kayıt: {} ile kodsuz çalışır.
	code, eb := post(t, ts.URL+"/api/mfa/enroll", tok, map[string]string{})
	if code != http.StatusOK || eb["secret"] == "" {
		t.Fatalf("ilk kayıt kodsuz çalışmalı: %d %v", code, eb)
	}
	secret := eb["secret"]
	otp, _ := security.TOTPAt(secret, time.Now())
	if c, _ := post(t, ts.URL+"/api/mfa/activate", tok, map[string]string{"code": otp}); c != http.StatusOK {
		t.Fatalf("activate: %d", c)
	}

	// NEGATIF: etkinken kodsuz yeniden kayıt 403 → MFA kapatılmaz, sır değişmez.
	if c, _ := post(t, ts.URL+"/api/mfa/enroll", tok, map[string]string{}); c != http.StatusForbidden {
		t.Fatalf("kodsuz yeniden kayıt 403 olmalı: %d", c)
	}
	if c, _ := post(t, ts.URL+"/api/mfa/enroll", tok, map[string]string{"code": "000000"}); c != http.StatusForbidden {
		t.Fatalf("yanlış kodlu yeniden kayıt 403 olmalı: %d", c)
	}
	if m := store.mfa["op1"]; m == nil || !m.enrolled || m.secret != secret {
		t.Fatalf("reddedilen yeniden kayıt MFA'yı değiştirmemeli: %+v", m)
	}
	if !hasAuditRow(store, "MFA_REENROLL_DENIED") {
		t.Fatal("MFA_REENROLL_DENIED audit satırı yazılmalıydı")
	}

	// POZITIF: geçerli (sonraki adım) kod ile yeniden kayıt.
	// Not: sunucu saati gerçek zaman olduğundan ±1 adım penceresi içindeki kod aranır; aktivasyonda
	// kullanılan adım tüketildiği için ONDAN BÜYÜK bir adım (sonraki pencere) kullanılır.
	next, _ := security.TOTPAt(secret, time.Now().Add(30*time.Second))
	if c, b := post(t, ts.URL+"/api/mfa/enroll", tok, map[string]string{"code": next}); c != http.StatusOK || b["secret"] == "" || b["secret"] == secret {
		t.Fatalf("geçerli kodla yeniden kayıt geçmeli: %d %v", c, b)
	}
	if !hasAuditRow(store, "MFA_REENROLL_BEGIN") {
		t.Fatal("MFA_REENROLL_BEGIN audit satırı yazılmalıydı")
	}
}

// (HTTP): kiracının SON etkin ADMIN'i kendini düşüremez/pasifleştiremez (403); ikinci bir
// ADMIN varsa düşürebilir. Platform admini ve diğer kiracıların ADMIN'leri sayılmaz.
func TestLastTenantAdminSelfDemotionDeniedHTTP(t *testing.T) {
	ts, store := wallServer(t)
	_ = wallAdmin(t, ts, store, "plat-adm", admin.RoleAdmin, "")
	acme := wallAdmin(t, ts, store, "acme-adm", admin.RoleAdmin, "acme")
	_ = wallAdmin(t, ts, store, "globex-adm", admin.RoleAdmin, "globex")

	if code, _ := post(t, ts.URL+"/api/admins/acme-adm/role", acme, map[string]string{"role": "VIEWER"}); code != http.StatusForbidden {
		t.Fatalf("son ADMIN kendini düşüremez (403): %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/admins/acme-adm/deactivate", acme, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("son ADMIN kendini pasifleştiremez (403): %d", code)
	}
	if info := store.adminInfos["acme-adm"]; !info.Active || info.Role != admin.RoleAdmin {
		t.Fatalf("reddedilen çağrılar DEĞİŞTİRMEMELİ: %+v", info)
	}

	// İkinci bir kiracı ADMIN'i eklenince kendini düşürebilir.
	code, nb := post(t, ts.URL+"/api/admins", acme, map[string]string{"email": "b@acme", "password": "parola12", "role": "ADMIN"})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("ikinci ADMIN oluşturma: %d %v", code, nb)
	}
	if code, _ := post(t, ts.URL+"/api/admins/acme-adm/role", acme, map[string]string{"role": "VIEWER"}); code != http.StatusOK {
		t.Fatalf("ikinci ADMIN varken düşürmek geçmeli: %d", code)
	}
}

// --- politika sahipliği HTTP ---

func TestPolicyTenantWallHTTP(t *testing.T) {
	ts, store := wallServer(t)
	store.deviceTenant = map[string]string{"d-acme": "acme", "d-globex": "globex"}
	acme := wallAdmin(t, ts, store, "acme-adm", admin.RoleAdmin, "acme")
	plat := wallAdmin(t, ts, store, "plat-adm", admin.RoleAdmin, "")

	// Platform: globex'e özel politika + paylaşımlı politika oluşturur.
	_, gb := post(t, ts.URL+"/api/policies", plat, map[string]string{"name": "G", "version": "v1", "tenant_id": "globex"})
	_, sb := post(t, ts.URL+"/api/policies", plat, map[string]string{"name": "S", "version": "v1"})
	globexPol, sharedPol := gb["policy_id"], sb["policy_id"]
	if globexPol == "" || sharedPol == "" {
		t.Fatalf("platform politikaları oluşturabilmeli: %v %v", gb, sb)
	}
	// acme kendi politikasını oluşturur (gövdedeki tenant boş = kendi kiracısı).
	code, ab := post(t, ts.URL+"/api/policies", acme, map[string]string{"name": "A", "version": "v1"})
	acmePol := ab["policy_id"]
	if code != http.StatusOK || acmePol == "" {
		t.Fatalf("acme kendi politikasını oluşturabilmeli: %d %v", code, ab)
	}
	// NEGATIF: acme başka kiracı adına politika oluşturamaz.
	if code, _ := post(t, ts.URL+"/api/policies", acme, map[string]string{"name": "X", "version": "v1", "tenant_id": "globex"}); code != http.StatusForbidden {
		t.Fatalf("başka kiracı adına oluşturma 403 olmalı: %d", code)
	}
	// NEGATIF: platform geçersiz kiracı kimliğiyle 400 alır.
	if code, _ := post(t, ts.URL+"/api/policies", plat, map[string]string{"name": "X", "version": "v1", "tenant_id": "Bad Tenant!"}); code != http.StatusBadRequest {
		t.Fatalf("geçersiz kiracı kimliği 400 olmalı: %d", code)
	}

	rule := map[string]any{"type": "APP_BLOCK_ALWAYS", "target": "evil.exe"}
	// NEGATIF: acme, globex ve paylaşımlı politikaya kural ekleyemez / globex kurallarını okuyamaz.
	if code, _ := post(t, ts.URL+"/api/policies/"+globexPol+"/rules", acme, rule); code != http.StatusForbidden {
		t.Fatalf("yabancı politikaya kural 403 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/policies/"+sharedPol+"/rules", acme, rule); code != http.StatusForbidden {
		t.Fatalf("paylaşımlı politikaya kural (kiracılı admin) 403 olmalı: %d", code)
	}
	if code := doReq(t, "GET", ts.URL+"/api/policies/"+globexPol+"/rules", acme, ""); code != http.StatusForbidden {
		t.Fatalf("yabancı politika kural listesi 403 olmalı: %d", code)
	}
	if len(store.rules[globexPol]) != 0 || len(store.rules[sharedPol]) != 0 {
		t.Fatal("reddedilen çağrılar kural yazmamalı")
	}
	// NEGATIF: yabancı politika atama.
	if code, _ := post(t, ts.URL+"/api/policies/assign", acme, map[string]string{"device_id": "d-acme", "policy_id": globexPol}); code != http.StatusForbidden {
		t.Fatalf("yabancı politika atama 403 olmalı: %d", code)
	}
	// NEGATIF: platform bile acme politikasını globex cihazına atayamaz.
	if code, _ := post(t, ts.URL+"/api/policies/assign", plat, map[string]string{"device_id": "d-globex", "policy_id": acmePol}); code != http.StatusForbidden {
		t.Fatalf("kiracılar arası atama (platform dahil) 403 olmalı: %d", code)
	}
	if len(store.assigned) != 0 {
		t.Fatalf("reddedilen atamalar yazılmamalı: %v", store.assigned)
	}

	// POZITIF: kendi politikasına kural + okuma + atama; paylaşımlı atama; platform kural.
	if code, _ := post(t, ts.URL+"/api/policies/"+acmePol+"/rules", acme, rule); code != http.StatusOK {
		t.Fatalf("kendi politikasına kural 200 olmalı: %d", code)
	}
	if code := doReq(t, "GET", ts.URL+"/api/policies/"+acmePol+"/rules", acme, ""); code != http.StatusOK {
		t.Fatalf("kendi kuralları 200 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/policies/assign", acme, map[string]string{"device_id": "d-acme", "policy_id": acmePol}); code != http.StatusOK {
		t.Fatalf("kendi politikası atama 200 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/policies/assign", acme, map[string]string{"device_id": "d-acme", "policy_id": sharedPol}); code != http.StatusOK {
		t.Fatalf("paylaşımlı politika atama 200 olmalı: %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/policies/"+globexPol+"/rules", plat, rule); code != http.StatusOK {
		t.Fatalf("platform her politikaya kural ekleyebilmeli: %d", code)
	}

	// Liste: acme yalnız kendi + paylaşımlı; platform hepsi.
	listIDs := func(token string) map[string]bool {
		resp, err := authedGET(t, ts.URL+"/api/policies", token)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("politika listesi 200 olmalı: %v %v", resp, err)
		}
		defer resp.Body.Close()
		var out struct {
			Policies []struct {
				ID     string `json:"id"`
				Shared bool   `json:"shared"`
			} `json:"policies"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		ids := map[string]bool{}
		for _, p := range out.Policies {
			ids[p.ID] = p.Shared
		}
		return ids
	}
	got := listIDs(acme)
	if _, leaked := got[globexPol]; leaked || len(got) != 2 {
		t.Fatalf("acme yalnız kendi + paylaşımlı politikaları görmeli: %v", got)
	}
	if shared, ok := got[sharedPol]; !ok || !shared {
		t.Fatalf("paylaşımlı politika shared=true ile listelenmeli: %v", got)
	}
	if all := listIDs(plat); len(all) != 3 {
		t.Fatalf("platform admini 3 politikayı görmeli: %v", all)
	}
}

// Kiracı izolasyonu: artefakt/delil LİSTELEME uçları (dosya yolları + gözetim-zinciri aktörleri) de
// adli eşikte (OPERATOR+) olmalı; gözetim-zinciri yazımı yönetici denetim izine de düşmeli.
func TestForensicsListingsRequireOperatorAndCustodyIsAudited(t *testing.T) {
	ts, store := wallServer(t)
	viewer := wallAdmin(t, ts, store, "vw", admin.RoleViewer, "")
	op := wallAdmin(t, ts, store, "op", admin.RoleOperator, "")
	aid, _ := store.SaveArtifact(context.Background(), "dev-1", "cmd-1", "C:/Users/bob/notes.txt", "abcd", []byte("icerik"))

	// NEGATIF: VIEWER artefakt / delil listesini göremez.
	if code := doReq(t, "GET", ts.URL+"/api/devices/dev-1/artifacts", viewer, ""); code != http.StatusForbidden {
		t.Fatalf("VIEWER artefakt listesi 403 olmalı: %d", code)
	}
	if code := doReq(t, "GET", ts.URL+"/api/devices/dev-1/evidence", viewer, ""); code != http.StatusForbidden {
		t.Fatalf("VIEWER delil listesi 403 olmalı: %d", code)
	}
	// POZITIF: OPERATOR görür.
	if code := doReq(t, "GET", ts.URL+"/api/devices/dev-1/artifacts", op, ""); code != http.StatusOK {
		t.Fatalf("OPERATOR artefakt listesi 200 olmalı: %d", code)
	}
	if code := doReq(t, "GET", ts.URL+"/api/devices/dev-1/evidence", op, ""); code != http.StatusOK {
		t.Fatalf("OPERATOR delil listesi 200 olmalı: %d", code)
	}

	// NEGATIF: reddedilen (VIEWER) ve geçersiz eylemli (OPERATOR) gözetim yazımı denetim satırı BIRAKMAZ.
	custodyURL := ts.URL + "/api/devices/dev-1/evidence/" + aid + "/custody"
	if code, _ := post(t, custodyURL, viewer, map[string]string{"action": "ACCESSED"}); code != http.StatusForbidden {
		t.Fatalf("VIEWER custody 403 olmalı: %d", code)
	}
	if code, _ := post(t, custodyURL, op, map[string]string{"action": "BOGUS"}); code != http.StatusBadRequest {
		t.Fatalf("geçersiz eylem 400 olmalı: %d", code)
	}
	for _, a := range store.auditRows {
		if strings.HasPrefix(a.Action, "CUSTODY_") {
			t.Fatalf("başarısız gözetim yazımı denetim satırı bırakmamalı: %+v", a)
		}
	}
	// POZITIF: başarılı yazım hem delil zincirine hem yönetici denetim izine düşer.
	if code, _ := post(t, custodyURL, op, map[string]string{"action": "ACCESSED"}); code != http.StatusOK {
		t.Fatalf("OPERATOR custody 200 olmalı: %d", code)
	}
	found := false
	for _, a := range store.auditRows {
		if a.Action == "CUSTODY_ACCESSED" && a.TargetType == "artifact" && a.TargetID == aid {
			found = true
		}
	}
	if !found {
		t.Fatalf("CUSTODY_ACCESSED denetim satırı yazılmalıydı: %+v", store.auditRows)
	}
}

// recMSP, MSPAddCustomer'a geçen kiracıyı kaydeden MSP deposudur.
type recMSP struct {
	fakeMSPStore
	tenants []string
}

func (r *recMSP) MSPAddCustomer(name, tenantID string) (msp.Customer, error) {
	r.tenants = append(r.tenants, tenantID)
	return msp.Customer{Name: name, TenantID: tenantID}, nil
}

// istekten gelen kiracı değerleri sınırda doğrulanır/normalleştirilir (MSP müşterisi,
// yönetici oluşturma, ajan-güvenlik ?tenant= filtresi). Boş kiracı yönetici oluşturmada
// "platform" olarak KALIR ('default'a dönüşmez).
func TestTenantInputValidatedAtBoundaries(t *testing.T) {
	srv, store := newServer(t)
	srv.SetTenantID("deploy-default")
	rec := &recMSP{}
	srv.SetMSPStore(rec)
	srv.SetAgentSec(aisec.NewService())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	plat := wallAdmin(t, ts, store, "plat", admin.RoleAdmin, "")
	acme := wallAdmin(t, ts, store, "acme-adm", admin.RoleAdmin, "acme")

	// --- MSP müşterisi ---
	if code, _ := post(t, ts.URL+"/api/msp/customers", plat, map[string]string{"name": "n", "tenant_id": "  ACME-Corp "}); code != http.StatusCreated {
		t.Fatalf("geçerli (büyük harfli) kiracı kabul edilmeli: %d", code)
	}
	if len(rec.tenants) != 1 || rec.tenants[0] != "acme-corp" {
		t.Fatalf("MSP kiracısı normalleştirilmeli: %v", rec.tenants)
	}
	for _, bad := range []string{"Bad Tenant!", "-lead", strings.Repeat("a", 64)} {
		if code, _ := post(t, ts.URL+"/api/msp/customers", plat, map[string]string{"name": "n", "tenant_id": bad}); code != http.StatusBadRequest {
			t.Fatalf("geçersiz MSP kiracısı (%q) 400 olmalı: %d", bad, code)
		}
	}
	if len(rec.tenants) != 1 {
		t.Fatalf("geçersiz kiracılar depoya ulaşmamalı: %v", rec.tenants)
	}

	// --- Yönetici oluşturma ---
	mk := func(token, email, tn string) (int, string) {
		code, b := post(t, ts.URL+"/api/admins", token, map[string]string{
			"email": email, "password": "longenough1", "role": "VIEWER", "tenant_id": tn,
		})
		return code, b["admin_id"]
	}
	if code, id := mk(plat, "g1@x", "GLOBEX"); code != http.StatusOK || store.adminTen[id] != "globex" {
		t.Fatalf("platform: kiracı normalleşmeli: %d %q", code, store.adminTen[id])
	}
	if code, _ := mk(plat, "bad@x", "Bad Tenant!"); code != http.StatusBadRequest {
		t.Fatalf("platform: geçersiz kiracı 400 olmalı: %d", code)
	}
	if code, id := mk(plat, "p2@x", ""); code != http.StatusOK || store.adminTen[id] != "" {
		t.Fatalf("platform: boş kiracı platform admini KALMALI: %d %q", code, store.adminTen[id])
	}
	// Kiracıya bağlı: kendi kiracısının büyük-harf yazımı kabul (normalleşir), başkası/başkasının büyük harfi 403.
	if code, id := mk(acme, "a1@x", "ACME"); code != http.StatusOK || store.adminTen[id] != "acme" {
		t.Fatalf("kiracılı: kendi kiracısı (büyük harf) kabul + normalleşmeli: %d %q", code, store.adminTen[id])
	}
	for _, other := range []string{"globex", "GLOBEX"} {
		if code, _ := mk(acme, "x-"+other+"@x", other); code != http.StatusForbidden {
			t.Fatalf("kiracılı: başka kiracı (%s) 403 olmalı: %d", other, code)
		}
	}

	// --- Ajan-güvenlik ?tenant= (yalnız platform için anlamlı) ---
	if code := doReq(t, "GET", ts.URL+"/api/agentsec/canonical?tenant=Bad%20Tenant!", plat, ""); code != http.StatusBadRequest {
		t.Fatalf("platform: geçersiz ?tenant= 400 olmalı: %d", code)
	}
	if code := doReq(t, "GET", ts.URL+"/api/agentsec/canonical?tenant=ACME", plat, ""); code != http.StatusOK {
		t.Fatalf("platform: geçerli ?tenant= 200 olmalı: %d", code)
	}
	if code := doReq(t, "GET", ts.URL+"/api/agentsec/canonical?tenant=Bad%20Tenant!", acme, ""); code != http.StatusOK {
		t.Fatalf("kiracılı: ?tenant= zaten YOK SAYILIR (200): %d", code)
	}
}
