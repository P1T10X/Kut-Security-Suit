package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/iam"
	"kut.corp/suite/server/internal/msp"
)

// TestABACEvaluateRequiresAdmin, politika-değerlendirme ucunun (policy oracle) artık
// RoleAdmin gerektirdiğini doğrular: VIEWER 403 alır, ADMIN geçer. (Önceden
// herhangi bir Viewer ABAC yüzeyini haritalayabiliyordu.)
func TestABACEvaluateRequiresAdmin(t *testing.T) {
	srv, store := newServer(t)
	srv.SetABAC(iam.NewEngine(nil))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)
	addAdmin(t, store, "a1", "admin@x", "secret", admin.RoleAdmin)
	_, vb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	_, ab := post(t, ts.URL+"/api/login", "", map[string]string{"email": "admin@x", "password": "secret"})

	body := map[string]any{"subject": map[string]any{"id": "u1"}, "action": "read", "resource": map[string]any{"type": "case"}}
	if code, _ := post(t, ts.URL+"/api/iam/abac/evaluate", vb["token"], body); code != http.StatusForbidden {
		t.Fatalf("VIEWER ABAC evaluate 403 almalıydı, %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/iam/abac/evaluate", ab["token"], body); code != http.StatusOK {
		t.Fatalf("ADMIN ABAC evaluate 200 almalıydı, %d", code)
	}
}

// fakeProvisioner, iam.Provisioner'ı test için gerçekler (girdi kullanıcıyı geri döner).
type fakeProvisioner struct{}

func (fakeProvisioner) Create(_ string, u iam.User) (iam.User, error)     { return u, nil }
func (fakeProvisioner) Replace(_, _ string, u iam.User) (iam.User, error) { return u, nil }
func (fakeProvisioner) Deactivate(_, id string) (iam.User, error)         { return iam.User{ID: id}, nil }
func (fakeProvisioner) Get(_, id string) (iam.User, error)                { return iam.User{ID: id}, nil }

// fakeMSPStore, adminapi.MSPStore'u test için gerçekler.
type fakeMSPStore struct{}

func (fakeMSPStore) MSPAddCustomer(name, tenantID string) (msp.Customer, error) {
	return msp.Customer{Name: name, TenantID: tenantID}, nil
}
func (fakeMSPStore) MSPListCustomers() ([]msp.Customer, error) { return nil, nil }
func (fakeMSPStore) MSPGetCustomer(string) (msp.Customer, bool, error) {
	return msp.Customer{}, false, nil
}
func (fakeMSPStore) MSPDeactivateCustomer(string) (bool, error) { return true, nil }

// TestSCIMAndMSPRequireAdmin, kimlik/tenant yönetim uçlarının (SCIM + MSP) artık RoleAdmin
// gerektirdiğini doğrular: bir VIEWER 403 alır, bir ADMIN geçer. (Önceden
// bu uçlar yalnız s.authed ile korunuyordu → herhangi bir Viewer kimlik/müşteri
// oluşturabiliyordu.)
func TestSCIMAndMSPRequireAdmin(t *testing.T) {
	srv, store := newServer(t)
	srv.SetSCIMProvisioner(fakeProvisioner{})
	srv.SetMSPStore(fakeMSPStore{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)
	addAdmin(t, store, "a1", "admin@x", "secret", admin.RoleAdmin)
	_, vb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	_, ab := post(t, ts.URL+"/api/login", "", map[string]string{"email": "admin@x", "password": "secret"})
	viewerTok, adminTok := vb["token"], ab["token"]

	cases := []struct {
		name, path string
		body       any
	}{
		{"scim-create", "/scim/v2/Users", map[string]any{"userName": "u1", "active": true}},
		{"msp-create", "/api/msp/customers", map[string]string{"name": "acme", "tenant_id": "t1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, _ := post(t, ts.URL+c.path, viewerTok, c.body); code != http.StatusForbidden {
				t.Fatalf("VIEWER %s 403 almalıydı, %d", c.path, code)
			}
			if code, _ := post(t, ts.URL+c.path, adminTok, c.body); code != http.StatusCreated {
				t.Fatalf("ADMIN %s 201 almalıydı, %d", c.path, code)
			}
		})
	}
}

// TestMSPRequiresPlatformAdmin, MSP (kiracı/müşteri yönetimi = kontrol-düzlemi) uçlarının
// PLATFORM admini (kiracısız) gerektirdiğini kanıtlar: kiracıya bağlı bir RoleAdmin bile
// 403 alır (tüm kiracıları listeleyemez/yönetemez), platform admini geçer. Kontrol-düzlemi
// çapraz-kiracı sızıntısı kapalı.
func TestMSPRequiresPlatformAdmin(t *testing.T) {
	srv, store := newServer(t)
	srv.SetMSPStore(fakeMSPStore{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "plat", "plat@x", "secret", admin.RoleAdmin) // adminTen yok → platform
	addAdmin(t, store, "tadm", "tadmin@x", "secret", admin.RoleAdmin)
	store.adminTen["tadm"] = "acme" // kiracıya bağlı ADMIN
	_, pb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "plat@x", "password": "secret"})
	_, tb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "tadmin@x", "password": "secret"})

	// Kiracıya bağlı admin: MSP oluşturma + listeleme 403.
	if code, _ := post(t, ts.URL+"/api/msp/customers", tb["token"], map[string]string{"name": "x", "tenant_id": "t2"}); code != http.StatusForbidden {
		t.Fatalf("kiracı-admin MSP oluşturma 403 almalıydı, %d", code)
	}
	lr, _ := authedGET(t, ts.URL+"/api/msp/customers", tb["token"])
	if lr.StatusCode != http.StatusForbidden {
		t.Fatalf("kiracı-admin MSP listeleme 403 almalıydı, %d", lr.StatusCode)
	}
	lr.Body.Close()

	// Platform admini: geçer.
	if code, _ := post(t, ts.URL+"/api/msp/customers", pb["token"], map[string]string{"name": "x", "tenant_id": "t2"}); code != http.StatusCreated {
		t.Fatalf("platform admini MSP oluşturabilmeli, %d", code)
	}
	pr, _ := authedGET(t, ts.URL+"/api/msp/customers", pb["token"])
	if pr.StatusCode != http.StatusOK {
		t.Fatalf("platform admini MSP listeleyebilmeli, %d", pr.StatusCode)
	}
	pr.Body.Close()
}

// TestCaseTenantHeaderIgnored, X-Tenant-ID başlığının artık YOK SAYILDIĞINI kanıtlar:
// bir vaka "attacker" başlığıyla oluşturulup "victim" başlığıyla listelense bile görünür
// (ikisi de dağıtım tenant'ına düşer). Başlık onurlandırılsaydı liste boş dönerdi. Böylece
// cross-tenant IDOR kapalıdır — kiracı istemciden seçilemez.
func TestCaseTenantHeaderIgnored(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	tok := ob["token"]

	// Oluştur — sahte "attacker" tenant başlığıyla.
	create, _ := http.NewRequest("POST", ts.URL+"/api/cases", strings.NewReader(`{"title":"x","severity":"HIGH"}`))
	create.Header.Set("Authorization", "Bearer "+tok)
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("X-Tenant-ID", "attacker")
	cr, err := http.DefaultClient.Do(create)
	if err != nil {
		t.Fatal(err)
	}
	cr.Body.Close()
	if cr.StatusCode != http.StatusOK {
		t.Fatalf("vaka oluşturma 200 dönmeliydi, %d", cr.StatusCode)
	}

	// Listele — FARKLI "victim" tenant başlığıyla. Başlık yok sayıldığından vaka görünmeli.
	list, _ := http.NewRequest("GET", ts.URL+"/api/cases", nil)
	list.Header.Set("Authorization", "Bearer "+tok)
	list.Header.Set("X-Tenant-ID", "victim")
	lr, err := http.DefaultClient.Do(list)
	if err != nil {
		t.Fatal(err)
	}
	defer lr.Body.Close()
	var lst struct {
		Count int `json:"count"`
	}
	_ = json.NewDecoder(lr.Body).Decode(&lst)
	if lst.Count != 1 {
		t.Fatalf("X-Tenant-ID yok sayılmalı → farklı başlıkla da vaka görünmeli (count=1 bekleniyordu, %d)", lst.Count)
	}
}
