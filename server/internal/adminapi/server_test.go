package adminapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/adminread"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/eventbus"
	"kut.corp/suite/server/internal/evidence"
	"kut.corp/suite/server/internal/security"
)

// memStore, hem admin.Store hem adminapi.AuthStore'u karşılar.
type memStore struct {
	custody       map[string][]evidence.CustodyEntry
	roles         map[string]admin.Role
	emails        map[string]adminRec // email -> (id, hash)
	commands      []string            // "deviceID:type"
	cipher        *security.FieldCipher
	devRows       []adminread.DeviceRow
	evtRows       []adminread.EventRow
	auditRows     []adminread.AuditRow
	certRows      []adminread.CertRow
	cmdRows       []adminread.CmdRow
	tokenRows     []adminread.EnrollmentTokenRow
	tokenSeq      int
	tokenTen      map[string]string // tokenID -> mühürlü kiracı
	polID         string
	polVer        string
	polTen        map[string]string // policyID -> sahip kiracı ("" = platform/paylaşımlı)
	polSeq        int
	rules         map[string][]admin.RuleInput // policyID -> kurallar
	assigned      map[string]string            // deviceID -> policyID
	statuses      map[string]string            // deviceID -> son ayarlanan durum
	adminInfos    map[string]*admin.AdminInfo  // id -> yönetici görünümü
	adminTen      map[string]string            // id -> kiracı ("" = platform)
	deviceTenant  map[string]string            // deviceID -> kiracı (çok-tenant aksiyon kapısı)
	eventTenant   map[string]string            // eventID -> kiracı (çok-tenant triyaj kapısı)
	lastEvtF      adminread.EventFilter        // QueryEvents'e geçen son filtre (kapsam testi)
	nextAdmID     int
	mfa           map[string]*mfaRec // adminID -> MFA durumu
	eventAcks     map[string]adminread.EventAck
	artifacts     map[string]adminread.ArtifactContent
	artMeta       []adminread.ArtifactRow
	pendWipes     map[string]string   // deviceID -> requestedBy (çift-kontrol WIPE)
	softwareByDev map[string][]string // deviceID -> yüklü yazılım (vuln re-scan testi)
}

type adminRec struct{ id, hash string }

type mfaRec struct {
	secret   string
	pending  string
	enrolled bool
	lastStep int64
}

func newMemStore() *memStore {
	return &memStore{
		roles:      map[string]admin.Role{},
		emails:     map[string]adminRec{},
		rules:      map[string][]admin.RuleInput{},
		assigned:   map[string]string{},
		adminInfos: map[string]*admin.AdminInfo{},
		adminTen:   map[string]string{},
	}
}

// admin.Store
func (m *memStore) AdminRole(_ context.Context, id string) (admin.Role, error) {
	return m.roles[id], nil
}
func (m *memStore) SaveEnrollmentToken(_ context.Context, _ []byte, createdBy, tenantID string, expiresAt time.Time) error {
	m.tokenSeq++
	if m.tokenTen == nil {
		m.tokenTen = map[string]string{}
	}
	m.tokenTen["etok-"+strconv.Itoa(m.tokenSeq)] = tenantID
	// createdBy admin id'sini e-postaya çöz (db LEFT JOIN davranışını taklit et).
	var email string
	for e, r := range m.emails {
		if r.id == createdBy {
			email = e
			break
		}
	}
	m.tokenRows = append([]adminread.EnrollmentTokenRow{{
		ID: "etok-" + strconv.Itoa(m.tokenSeq), CreatedByEmail: email,
		ExpiresAt: expiresAt, Used: false, CreatedAt: time.Now(),
	}}, m.tokenRows...)
	return nil
}
func (m *memStore) EnrollmentTokenTenant(_ context.Context, tokenID string) (string, bool, error) {
	t, ok := m.tokenTen[tokenID]
	return t, ok, nil
}
func (m *memStore) RevokeEnrollmentToken(_ context.Context, tokenID, tenantID string) error {
	if tenantID != "" { // db gibi — tenantID doluysa token'ın kiracısı eşleşmeli
		if t, ok := m.tokenTen[tokenID]; !ok || t != tenantID {
			return admin.ErrForbidden
		}
	}
	for i := range m.tokenRows {
		if m.tokenRows[i].ID == tokenID && !m.tokenRows[i].Used {
			m.tokenRows[i].Used = true
			break
		}
	}
	return nil
}
func (m *memStore) ListEnrollmentTokens(_ context.Context, _ int, _ string) ([]adminread.EnrollmentTokenRow, error) {
	return m.tokenRows, nil
}

func (m *memStore) ListPolicies(_ context.Context, _ int, tenantID string) ([]adminread.PolicyRow, error) {
	counts := map[string]int{}
	for dev, pid := range m.assigned {
		if tenantID == "" || m.deviceTenant[dev] == tenantID {
			counts[pid]++
		}
	}
	ids := map[string]bool{}
	for id := range m.rules {
		ids[id] = true
	}
	for id := range m.polTen {
		ids[id] = true
	}
	var out []adminread.PolicyRow
	for id := range ids {
		owner := m.polTen[id]
		if tenantID != "" && owner != "" && owner != tenantID {
			continue // db gibi: kiracıya bağlı çağıran yalnız kendi + paylaşımlı politikaları görür
		}
		ver := ""
		if id == m.polID {
			ver = m.polVer
		}
		out = append(out, adminread.PolicyRow{
			ID: id, Name: id, Version: ver, TenantID: owner,
			RuleCount: len(m.rules[id]), DeviceCount: counts[id],
		})
	}
	return out, nil
}
func (m *memStore) EnqueueCommand(_ context.Context, deviceID, cmdType, _ string) error {
	m.commands = append(m.commands, deviceID+":"+cmdType)
	return nil
}
func (m *memStore) SetDeviceStatus(_ context.Context, deviceID, status string) error {
	if m.statuses == nil {
		m.statuses = map[string]string{}
	}
	m.statuses[deviceID] = status
	return nil
}
func (m *memStore) SetDeviceTags(_ context.Context, deviceID string, tags []string, tenantID string) error {
	if tenantID != "" && m.deviceTenant[deviceID] != tenantID {
		return admin.ErrForbidden
	}
	for i := range m.devRows {
		if m.devRows[i].ID == deviceID {
			m.devRows[i].Tags = tags
		}
	}
	return nil
}
func (m *memStore) RevokeDeviceCerts(_ context.Context, deviceID, _ string) error {
	m.commands = append(m.commands, deviceID+":REVOKE")
	return nil
}
func (m *memStore) EraseDeviceData(_ context.Context, deviceID string) (int, int, int, error) {
	m.commands = append(m.commands, deviceID+":ERASE")
	// Bu cihaza ait olayları temizle (device-scoped alan yoksa tümünü temsilen).
	n := len(m.evtRows)
	m.evtRows = nil
	return n, 0, 1, nil
}
func (m *memStore) WriteAudit(_ context.Context, adminID, action, targetType, targetID string) error {
	m.auditRows = append([]adminread.AuditRow{{
		ID: int64(len(m.auditRows) + 1), AdminEmail: adminID, Action: action,
		TargetType: targetType, TargetID: targetID, CreatedAt: time.Now(),
	}}, m.auditRows...)
	return nil
}
func (m *memStore) CreatePolicy(_ context.Context, _, _, tenantID string) (string, error) {
	if m.polTen == nil {
		m.polTen = map[string]string{}
	}
	m.polSeq++
	id := "pol-" + strconv.Itoa(m.polSeq)
	m.polTen[id] = tenantID
	return id, nil
}

// PolicyTenant: db gibi — sahibi bilinen politika (CreatePolicy ile oluşturulan ya da testte
// tohumlanan: polID / rules) bulunur; aksi found=false.
func (m *memStore) PolicyTenant(_ context.Context, policyID string) (string, bool, error) {
	if t, ok := m.polTen[policyID]; ok {
		return t, true, nil
	}
	if _, ok := m.rules[policyID]; ok || policyID == m.polID {
		return "", true, nil
	}
	return "", false, nil
}
func (m *memStore) AssignPolicy(_ context.Context, deviceID, policyID string) error {
	m.assigned[deviceID] = policyID
	return nil
}
func (m *memStore) AddPolicyRule(_ context.Context, policyID string, in admin.RuleInput) error {
	m.rules[policyID] = append(m.rules[policyID], in)
	return nil
}
func (m *memStore) BumpPolicyVersion(_ context.Context, _ string) (string, error) {
	return "v2", nil
}
func (m *memStore) DevicesForPolicy(_ context.Context, policyID string) ([]string, error) {
	var out []string
	for dev, pol := range m.assigned {
		if pol == policyID {
			out = append(out, dev)
		}
	}
	return out, nil
}
func (m *memStore) ListPolicyRules(_ context.Context, policyID string) ([]admin.RuleView, error) {
	var out []admin.RuleView
	for i, r := range m.rules[policyID] {
		out = append(out, admin.RuleView{
			ID: "r-" + string(rune('0'+i)), Type: r.Type, Target: r.Target,
			Start: r.Start, End: r.End, ActiveDays: r.ActiveDays,
		})
	}
	return out, nil
}

func (m *memStore) CreateAdmin(_ context.Context, email, passwordHash string, role admin.Role, tenantID string) (string, error) {
	m.nextAdmID++
	id := "adm-" + string(rune('0'+m.nextAdmID))
	m.roles[id] = role
	m.emails[email] = adminRec{id: id, hash: passwordHash}
	m.adminInfos[id] = &admin.AdminInfo{ID: id, Email: email, Role: role, Active: true}
	m.adminTen[id] = tenantID
	return id, nil
}
func (m *memStore) AdminTenant(_ context.Context, adminID string) (string, error) {
	// db gibi — rolü olmayan (bilinmeyen/pasif: DeactivateAdmin roles'u siler)
	// yönetici platform ("") DEĞİL, ErrUnknownAdmin.
	if _, ok := m.roles[adminID]; !ok {
		return "", admin.ErrUnknownAdmin
	}
	return m.adminTen[adminID], nil
}
func (m *memStore) TenantForDevice(_ context.Context, deviceID string) (string, error) {
	return m.deviceTenant[deviceID], nil
}
func (m *memStore) EventTenant(_ context.Context, eventID string) (string, error) {
	return m.eventTenant[eventID], nil
}
func (m *memStore) SetAdminRole(_ context.Context, id string, role admin.Role, tenantID string) error {
	if tenantID != "" && m.adminTen[id] != tenantID {
		return admin.ErrForbidden
	}
	m.roles[id] = role
	if a, ok := m.adminInfos[id]; ok {
		a.Role = role
	}
	return nil
}
func (m *memStore) DeactivateAdmin(_ context.Context, id, tenantID string) error {
	if tenantID != "" && m.adminTen[id] != tenantID {
		return admin.ErrForbidden
	}
	if a, ok := m.adminInfos[id]; ok {
		a.Active = false
	}
	// Gerçek db/memstore davranışı: pasif admin için AdminRole boş döner (WHERE
	// is_active). authed'in aktiflik teyidini test edebilmek için taklit.
	delete(m.roles, id)
	return nil
}
func (m *memStore) ListAdmins(_ context.Context, tenantID string) ([]admin.AdminInfo, error) {
	var out []admin.AdminInfo
	for id, a := range m.adminInfos {
		if tenantID != "" && m.adminTen[id] != tenantID {
			continue
		}
		out = append(out, *a)
	}
	return out, nil
}

// adminapi.AuthStore
func (m *memStore) LookupAdmin(_ context.Context, email string) (string, string, error) {
	r := m.emails[email]
	return r.id, r.hash, nil
}

// admin.Store + adminapi.MFAStore (MFA)
func (m *memStore) ensureMFA() {
	if m.mfa == nil {
		m.mfa = map[string]*mfaRec{}
	}
}
func (m *memStore) SetPendingMFASecret(_ context.Context, id, secret string) error {
	m.ensureMFA()
	r, ok := m.mfa[id]
	if !ok {
		r = &mfaRec{}
		m.mfa[id] = r
	}
	r.pending = secret // etkin sır/enrolled DEĞİŞMEZ (yeniden kayıtta MFA açık kalır)
	return nil
}
func (m *memStore) LookupMFA(_ context.Context, id string) (string, bool, error) {
	m.ensureMFA()
	if r, ok := m.mfa[id]; ok {
		return r.secret, r.enrolled, nil
	}
	return "", false, nil
}
func (m *memStore) LookupPendingMFA(_ context.Context, id string) (string, error) {
	m.ensureMFA()
	if r, ok := m.mfa[id]; ok {
		return r.pending, nil
	}
	return "", nil
}
func (m *memStore) ActivateMFA(_ context.Context, id string) error {
	m.ensureMFA()
	if r, ok := m.mfa[id]; ok && r.pending != "" {
		r.secret = r.pending
		r.pending = ""
		r.enrolled = true
	}
	return nil
}
func (m *memStore) DisableMFA(_ context.Context, id string) error {
	m.ensureMFA()
	delete(m.mfa, id)
	return nil
}
func (m *memStore) ConsumeTOTPStep(_ context.Context, id string, step int64) (bool, error) {
	m.ensureMFA()
	r, ok := m.mfa[id]
	if !ok {
		return false, nil
	}
	if step <= r.lastStep {
		return false, nil
	}
	r.lastStep = step
	return true, nil
}

// adminread.Store
func (m *memStore) ListDevices(_ context.Context, _ int, tenantID string) ([]adminread.DeviceRow, error) {
	if tenantID == "" {
		return m.devRows, nil
	}
	var out []adminread.DeviceRow
	for _, d := range m.devRows {
		if d.TenantID == tenantID {
			out = append(out, d)
		}
	}
	return out, nil
}
func (m *memStore) ListEvents(_ context.Context, deviceID, severity, category string, _ int) ([]adminread.EventRow, error) {
	var out []adminread.EventRow
	for _, e := range m.evtRows {
		if severity != "" && e.Severity != severity {
			continue
		}
		if category != "" && e.Category != category {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}
func (m *memStore) DeviceStatusCounts(_ context.Context, tenantID string) (map[string]int, error) {
	out := map[string]int{}
	for _, d := range m.devRows {
		if tenantID != "" && d.TenantID != tenantID {
			continue
		}
		out[d.Status]++
	}
	return out, nil
}
func (m *memStore) EventSeverityCounts(_ context.Context, since time.Time, _ string) (map[string]int, error) {
	out := map[string]int{}
	for _, e := range m.evtRows {
		if e.CreatedAt.Before(since) {
			continue
		}
		out[e.Severity]++
	}
	return out, nil
}
func (m *memStore) EventCategoryCounts(_ context.Context, since time.Time, _ string) (map[string]int, error) {
	out := map[string]int{}
	for _, e := range m.evtRows {
		if e.CreatedAt.Before(since) {
			continue
		}
		out[e.Category]++
	}
	return out, nil
}
func (m *memStore) LatestComplianceByDevice(_ context.Context, _ string) (map[string]adminread.ComplianceStatus, error) {
	out := map[string]adminread.ComplianceStatus{}
	for i := len(m.evtRows) - 1; i >= 0; i-- {
		e := m.evtRows[i]
		if e.DeviceID == "" || len(e.Details) == 0 {
			continue
		}
		if _, seen := out[e.DeviceID]; seen {
			continue
		}
		var d struct {
			Enc string `json:"disk_encryption"`
			Fw  string `json:"firewall"`
		}
		if err := json.Unmarshal(e.Details, &d); err != nil {
			continue
		}
		if d.Enc == "" && d.Fw == "" {
			continue
		}
		out[e.DeviceID] = adminread.ComplianceStatus{Enc: d.Enc, Fw: d.Fw}
	}
	return out, nil
}
func (m *memStore) SearchSoftware(_ context.Context, _ string, _ string) (map[string][]string, error) {
	return map[string][]string{}, nil
}
func (m *memStore) SetEventAck(_ context.Context, eventID, adminID, status string) error {
	if m.eventAcks == nil {
		m.eventAcks = map[string]adminread.EventAck{}
	}
	rec := m.eventAcks[eventID]
	rec.Status, rec.AdminEmail, rec.At = status, adminID, time.Now()
	m.eventAcks[eventID] = rec
	return nil
}
func (m *memStore) SetEventCase(_ context.Context, eventID, adminID, assignee, note string) error {
	if m.eventAcks == nil {
		m.eventAcks = map[string]adminread.EventAck{}
	}
	rec := m.eventAcks[eventID]
	rec.Assignee, rec.Note, rec.AdminEmail, rec.At = assignee, note, adminID, time.Now()
	m.eventAcks[eventID] = rec
	return nil
}
func (m *memStore) EventAcks(_ context.Context) (map[string]adminread.EventAck, error) {
	return m.eventAcks, nil
}
func (m *memStore) SavePendingWipe(_ context.Context, deviceID, requestedBy, _ string) error {
	if m.pendWipes == nil {
		m.pendWipes = map[string]string{}
	}
	m.pendWipes[deviceID] = requestedBy
	return nil
}
func (m *memStore) GetPendingWipe(_ context.Context, deviceID string) (string, bool, error) {
	rb, ok := m.pendWipes[deviceID]
	return rb, ok, nil
}
func (m *memStore) DeletePendingWipe(_ context.Context, deviceID string) error {
	delete(m.pendWipes, deviceID)
	return nil
}
func (m *memStore) ConsumePendingWipe(_ context.Context, deviceID, approverID string) (string, bool, error) {
	rb, ok := m.pendWipes[deviceID]
	if !ok {
		return "", false, nil
	}
	if rb == approverID {
		return rb, false, nil
	}
	delete(m.pendWipes, deviceID)
	return rb, true, nil
}
func (m *memStore) ListPendingWipes(_ context.Context, _ string) ([]adminread.PendingWipeRow, error) {
	var out []adminread.PendingWipeRow
	for dev, rb := range m.pendWipes {
		out = append(out, adminread.PendingWipeRow{DeviceID: dev, RequestedBy: rb})
	}
	return out, nil
}
func (m *memStore) ListIncidents(_ context.Context, _ int, _ string) ([]adminread.IncidentRow, error) {
	return nil, nil
}
func (m *memStore) SaveSearch(_ context.Context, name, filterJSON, createdBy string) (adminread.SavedSearchRow, error) {
	return adminread.SavedSearchRow{ID: "srch-1", Name: name, Filter: filterJSON, CreatedBy: createdBy}, nil
}
func (m *memStore) ListSavedSearches(_ context.Context, _ string) ([]adminread.SavedSearchRow, error) {
	return nil, nil
}
func (m *memStore) DeleteSavedSearch(_ context.Context, _, _ string) (bool, error) { return true, nil }
func (m *memStore) QueryEvents(_ context.Context, f adminread.EventFilter) ([]adminread.EventRow, error) {
	m.lastEvtF = f // kapsam testi: handler'ın çağıranın kiracısını bastığını doğrulamak için
	var out []adminread.EventRow
	for _, e := range m.evtRows {
		if f.Severity != "" && e.Severity != f.Severity {
			continue
		}
		if f.Category != "" && e.Category != f.Category {
			continue
		}
		if f.MessageContains != "" && !strings.Contains(strings.ToLower(e.Message), strings.ToLower(f.MessageContains)) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}
func (m *memStore) LatestSoftwareByDevice(_ context.Context, _ string) (map[string][]string, error) {
	return m.softwareByDev, nil
}
func (m *memStore) EnqueueCommandParams(_ context.Context, deviceID, cmdType, _ string, params map[string]string) error {
	m.commands = append(m.commands, deviceID+":"+cmdType)
	return nil
}
func (m *memStore) SaveArtifact(_ context.Context, deviceID, commandID, path, sha256 string, content []byte) (string, error) {
	if m.artifacts == nil {
		m.artifacts = map[string]adminread.ArtifactContent{}
	}
	id := "art-" + strconv.Itoa(len(m.artifacts)+1)
	m.artifacts[id] = adminread.ArtifactContent{Path: path, Content: content}
	m.artMeta = append(m.artMeta, adminread.ArtifactRow{ID: id, DeviceID: deviceID, Path: path, SHA256: sha256, Size: len(content), CollectedAt: time.Now()})
	return id, nil
}
func (m *memStore) ListArtifacts(_ context.Context, deviceID string) ([]adminread.ArtifactRow, error) {
	var out []adminread.ArtifactRow
	for _, a := range m.artMeta {
		if a.DeviceID == deviceID {
			out = append(out, a)
		}
	}
	return out, nil
}
func (m *memStore) GetArtifact(_ context.Context, id string, _ string) (adminread.ArtifactContent, bool, error) {
	c, ok := m.artifacts[id]
	return c, ok, nil
}
func (m *memStore) ListAudit(_ context.Context, _ int, _ string) ([]adminread.AuditRow, error) {
	return m.auditRows, nil
}
func (m *memStore) DeviceByID(_ context.Context, id string) (adminread.DeviceRow, bool, error) {
	for _, d := range m.devRows {
		if d.ID == id {
			return d, true, nil
		}
	}
	return adminread.DeviceRow{}, false, nil
}
func (m *memStore) CertsByDevice(_ context.Context, _ string) ([]adminread.CertRow, error) {
	return m.certRows, nil
}
func (m *memStore) CommandHistory(_ context.Context, _ string) ([]adminread.CmdRow, error) {
	return m.cmdRows, nil
}
func (m *memStore) AssignedPolicy(_ context.Context, _ string) (string, string, error) {
	return m.polID, m.polVer, nil
}

func newServer(t *testing.T) (*Server, *memStore) {
	t.Helper()
	store := newMemStore()

	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	bidx := security.NewBlindIndexer(security.DeriveKey(master, security.LabelBlindIndex))
	sessions := security.NewSessionSigner(security.DeriveKey(master, security.LabelSessionToken))
	cipher, err := security.NewFieldCipher(security.DeriveKey(master, security.LabelFieldEncryption))
	if err != nil {
		t.Fatal(err)
	}
	store.cipher = cipher
	adminSvc := admin.NewService(store, bidx, time.Hour)
	// API testleri Scope/ROE motoru bağlamaz; yüksek-etkili op'ların fail-closed
	// reddedilmemesi için geriye-uyumlu moda al (fail-closed davranışı admin
	// paketinde ayrıca doğrulanır).
	adminSvc.SetScopeAllowUnconfigured(true)
	reader := adminread.NewService(store, cipher)
	return New(adminSvc, reader, store, sessions, time.Hour), store
}

func setup(t *testing.T) (*httptest.Server, *memStore) {
	t.Helper()
	srv, store := newServer(t)
	return httptest.NewServer(srv.Handler()), store
}

func setupStream(t *testing.T) (*httptest.Server, *memStore, *eventbus.Bus) {
	t.Helper()
	srv, store := newServer(t)
	bus := eventbus.New()
	srv.SetStream(bus)
	return httptest.NewServer(srv.Handler()), store, bus
}

func addAdmin(t *testing.T, store *memStore, id, email, password string, role admin.Role) {
	t.Helper()
	hash, err := security.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	store.roles[id] = role
	store.emails[email] = adminRec{id: id, hash: hash}
	store.adminInfos[id] = &admin.AdminInfo{ID: id, Email: email, Role: role, Active: true}
}

func post(t *testing.T, url, token string, body any) (int, map[string]string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// MFA (2FA) uçtan uca: kayıt → etkinleştir → sonraki girişlerde TOTP kodu zorunlu.
func TestLoginEnforcesMFAWhenEnrolled(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	// İlk giriş (MFA yok) → token.
	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]
	if token == "" {
		t.Fatal("ilk giriş token vermeliydi")
	}
	// MFA kaydını başlat → sır döner.
	code, eb := post(t, ts.URL+"/api/mfa/enroll", token, map[string]string{})
	if code != http.StatusOK || eb["secret"] == "" {
		t.Fatalf("mfa enroll başarısız: %d %v", code, eb)
	}
	secret := eb["secret"]
	// Doğru kod ile etkinleştir.
	otp, _ := security.TOTPAt(secret, time.Now())
	if c, _ := post(t, ts.URL+"/api/mfa/activate", token, map[string]string{"code": otp}); c != http.StatusOK {
		t.Fatalf("mfa activate başarısız: %d", c)
	}
	// Artık kodsuz giriş token VERMEMELİ (mfa_required).
	_, nb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	if nb["token"] != "" {
		t.Fatal("MFA etkinken kodsuz giriş token vermemeliydi")
	}
	// Yanlış kod → 401.
	if c, _ := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret", "code": "000000"}); c != http.StatusUnauthorized {
		t.Fatalf("yanlış MFA kodu 401 dönmeliydi, %d", c)
	}
	// Doğru kod → token. (Sonraki zaman-adımından kod: aktivasyonda kullanılan adım
	// tek-kullanım kuralıyla tüketildiğinden login FARKLI/sonraki bir adım kullanmalı.)
	otp2, _ := security.TOTPAt(secret, time.Now().Add(30*time.Second))
	_, okBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret", "code": otp2})
	if okBody["token"] == "" {
		t.Fatal("doğru MFA kodu ile giriş token vermeliydi")
	}
	// Tek-kullanım: AYNI kodu tekrar oynatmak → 401 (replay reddi).
	if c, _ := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret", "code": otp2}); c != http.StatusUnauthorized {
		t.Fatalf("yeniden kullanılan MFA kodu 401 dönmeliydi, %d", c)
	}
}

func TestLoginAndQuarantine(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	// Yanlış parola → 401.
	if code, _ := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "yanlis"}); code != http.StatusUnauthorized {
		t.Fatalf("yanlış parola 401 dönmeliydi, %d", code)
	}

	// Doğru parola → token.
	code, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	if code != http.StatusOK || body["token"] == "" {
		t.Fatalf("login başarısız: code=%d body=%v", code, body)
	}
	token := body["token"]

	// Token'sız karantina → 401.
	if code, _ := post(t, ts.URL+"/api/devices/quarantine", "", map[string]string{"device_id": "dev-1"}); code != http.StatusUnauthorized {
		t.Fatalf("token'sız istek 401 dönmeliydi, %d", code)
	}

	// Token'lı karantina → 200 + komut kuyruğa eklenmeli.
	if code, _ := post(t, ts.URL+"/api/devices/quarantine", token, map[string]string{"device_id": "dev-1"}); code != http.StatusOK {
		t.Fatalf("yetkili karantina 200 dönmeliydi, %d", code)
	}
	if len(store.commands) != 1 || store.commands[0] != "dev-1:QUARANTINE" {
		t.Fatalf("QUARANTINE komutu kuyruğa eklenmeliydi: %v", store.commands)
	}
}

func TestServesConsole(t *testing.T) {
	ts, _ := setup(t)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("konsol 200 dönmeliydi, %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("konsol HTML olmalı, %q", ct)
	}
	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "KUT Komuta Merkezi") {
		t.Fatal("konsol içeriği beklenen başlığı taşımıyor")
	}
}

func TestListDevicesDecrypted(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	hostEnc, _ := store.cipher.EncryptString("WS-07")
	macEnc, _ := store.cipher.EncryptString("aa:bb:cc:dd:ee:ff")
	store.devRows = []adminread.DeviceRow{{ID: "dev-1", Status: "ACTIVE", HostnameEnc: hostEnc, MACEnc: macEnc}}

	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	token := body["token"]

	req, _ := http.NewRequest("GET", ts.URL+"/api/devices", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("200 beklenirdi, %d", resp.StatusCode)
	}
	var out struct {
		Devices []struct {
			Hostname string `json:"hostname"`
			MAC      string `json:"mac"`
			Status   string `json:"status"`
		} `json:"devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Devices) != 1 || out.Devices[0].Hostname != "WS-07" || out.Devices[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("cihaz deşifre edilip listelenmişti olmalı: %+v", out.Devices)
	}

	// Token'sız erişim reddedilmeli.
	if r2, _ := http.Get(ts.URL + "/api/devices"); r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token'sız liste 401 dönmeliydi, %d", r2.StatusCode)
	}
}

// /api/devices liste yolu çağıranın kiracısıyla daraltılmalı: kiracıya bağlı admin
// yalnız kendi cihazlarını, platform admini tümünü görür.
func TestListDevicesScopedToCallerTenant(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	store.devRows = []adminread.DeviceRow{
		{ID: "d-acme", Status: "ACTIVE", TenantID: "acme"},
		{ID: "d-globex", Status: "ACTIVE", TenantID: "globex"},
		{ID: "d-none", Status: "ACTIVE"},
	}

	count := func(email string) int {
		_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": email, "password": "secret"})
		tok := lb["token"]
		resp, err := authedGET(t, ts.URL+"/api/devices", tok)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Devices []struct {
				ID string `json:"id"`
			} `json:"devices"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return len(out.Devices)
	}

	addAdmin(t, store, "acme-op", "acme@x", "secret", admin.RoleOperator)
	store.adminTen["acme-op"] = "acme"
	if n := count("acme@x"); n != 1 {
		t.Fatalf("acme admini yalnız kendi cihazını görmeli, dönen: %d", n)
	}

	addAdmin(t, store, "plat-op", "plat@x", "secret", admin.RoleOperator)
	if n := count("plat@x"); n != 3 {
		t.Fatalf("platform admini tüm cihazları görmeli, dönen: %d", n)
	}
}

func TestRevokeRequiresOperator(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	_, vBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	if code, _ := post(t, ts.URL+"/api/devices/revoke", vBody["token"], map[string]string{"device_id": "d1"}); code != http.StatusForbidden {
		t.Fatalf("VIEWER iptal edememeli, %d", code)
	}
	_, opBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	if code, _ := post(t, ts.URL+"/api/devices/revoke", opBody["token"], map[string]string{"device_id": "d1"}); code != http.StatusOK {
		t.Fatalf("OPERATOR iptal edebilmeli, %d", code)
	}
	if !contains(store.commands, "d1:REVOKE") {
		t.Fatalf("iptal komutu store'a yansımalıydı: %v", store.commands)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestSecurityHeaders(t *testing.T) {
	ts, _ := setup(t)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff başlığı eksik")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options DENY eksik (clickjacking)")
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("konsolda CSP eksik")
	}
}

func TestViewerForbidden(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)

	_, body := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	token := body["token"]

	code, _ := post(t, ts.URL+"/api/devices/quarantine", token, map[string]string{"device_id": "dev-1"})
	if code != http.StatusForbidden {
		t.Fatalf("VIEWER karantina 403 dönmeliydi, %d", code)
	}
	if len(store.commands) != 0 {
		t.Fatal("reddedilen istek komut üretmemeli")
	}
}

func TestPolicyRuleEditorHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "ad1", "admin@x", "secret", admin.RoleAdmin)

	_, adBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "admin@x", "password": "secret"})
	token := adBody["token"]

	// Politika oluştur.
	code, body := post(t, ts.URL+"/api/policies", token, map[string]string{"name": "Mesai", "version": "v1"})
	if code != http.StatusOK || body["policy_id"] == "" {
		t.Fatalf("politika oluşturulmalı: code=%d body=%v", code, body)
	}
	policyID := body["policy_id"]

	// Kural ekle.
	code, _ = post(t, ts.URL+"/api/policies/"+policyID+"/rules", token, map[string]any{
		"type": "APP_TIME_BLOCK", "target": "oyun.exe", "start": "09:00", "end": "18:00",
		"active_days": []int{1, 2, 3, 4, 5},
	})
	if code != http.StatusOK {
		t.Fatalf("kural eklenebilmeli, code=%d", code)
	}

	// Kuralları listele.
	req, _ := http.NewRequest("GET", ts.URL+"/api/policies/"+policyID+"/rules", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("kural listesi 200 dönmeliydi, %d", resp.StatusCode)
	}
	var out struct {
		Rules []struct {
			Type       string  `json:"type"`
			Target     string  `json:"target"`
			Start      string  `json:"start"`
			End        string  `json:"end"`
			ActiveDays []int32 `json:"active_days"`
		} `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Rules) != 1 || out.Rules[0].Type != "APP_TIME_BLOCK" || out.Rules[0].Target != "oyun.exe" ||
		out.Rules[0].Start != "09:00" || out.Rules[0].End != "18:00" {
		t.Fatalf("eklenen kural listede dönmeliydi: %+v", out.Rules)
	}

	// Geçersiz kural (APP_TIME_BLOCK ama zaman aralığı yok) → 400.
	code, _ = post(t, ts.URL+"/api/policies/"+policyID+"/rules", token, map[string]any{
		"type": "APP_TIME_BLOCK", "target": "x",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("geçersiz kural 400 dönmeliydi, %d", code)
	}
}

func TestAdminUserManagementHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "ad1", "admin@x", "secret", admin.RoleAdmin)

	_, adBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "admin@x", "password": "secret"})
	token := adBody["token"]

	// Kısa parola → 400.
	if code, _ := post(t, ts.URL+"/api/admins", token, map[string]string{
		"email": "kisa@x", "password": "123", "role": "VIEWER",
	}); code != http.StatusBadRequest {
		t.Fatalf("kısa parola 400 dönmeliydi, %d", code)
	}

	// Yeni yönetici oluştur.
	code, body := post(t, ts.URL+"/api/admins", token, map[string]string{
		"email": "yeni@x", "password": "parola12", "role": "OPERATOR",
	})
	if code != http.StatusOK || body["admin_id"] == "" {
		t.Fatalf("yönetici oluşturulmalı: code=%d body=%v", code, body)
	}
	newID := body["admin_id"]

	// Listede yeni yönetici görünmeli (parola hash'i JSON'da OLMAMALI).
	resp, err := authedGET(t, ts.URL+"/api/admins", token)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("liste 200 dönmeliydi, %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if bytes.Contains(bytes.ToLower(raw), []byte("hash")) || bytes.Contains(raw, []byte("password")) {
		t.Fatalf("yönetici listesi parola hash'i sızdırmamalı: %s", raw)
	}
	var out struct {
		Admins []struct {
			ID     string `json:"id"`
			Email  string `json:"email"`
			Role   string `json:"role"`
			Active bool   `json:"active"`
		} `json:"admins"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, a := range out.Admins {
		if a.ID == newID {
			found = true
			if a.Email != "yeni@x" || a.Role != "OPERATOR" || !a.Active {
				t.Fatalf("yeni yönetici alanları hatalı: %+v", a)
			}
		}
	}
	if !found {
		t.Fatalf("yeni yönetici listede görünmeliydi: %+v", out.Admins)
	}

	// Rol değiştir → ADMIN.
	if code, _ := post(t, ts.URL+"/api/admins/"+newID+"/role", token, map[string]string{"role": "ADMIN"}); code != http.StatusOK {
		t.Fatalf("rol değiştirme 200 dönmeliydi, %d", code)
	}
	if store.roles[newID] != admin.RoleAdmin {
		t.Fatalf("rol ADMIN olmalıydı: %v", store.roles[newID])
	}

	// Pasifleştir.
	if code, _ := post(t, ts.URL+"/api/admins/"+newID+"/deactivate", token, map[string]string{}); code != http.StatusOK {
		t.Fatalf("pasifleştirme 200 dönmeliydi, %d", code)
	}
	if store.adminInfos[newID].Active {
		t.Fatal("yönetici pasifleştirilmiş olmalıydı")
	}
}

func TestListAdminsRequiresOperatorHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	// OPERATOR listeleyebilmeli.
	_, opBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	resp, err := authedGET(t, ts.URL+"/api/admins", opBody["token"])
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("OPERATOR yönetici listeleyebilmeli, %d", resp.StatusCode)
	}

	// OPERATOR yeni yönetici oluşturamamalı (ADMIN gerekir) → 403.
	if code, _ := post(t, ts.URL+"/api/admins", opBody["token"], map[string]string{
		"email": "x@x", "password": "parola12", "role": "VIEWER",
	}); code != http.StatusForbidden {
		t.Fatalf("OPERATOR admin oluşturamamalı, %d", code)
	}
}

func TestCreatePolicyRequiresAdminHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	addAdmin(t, store, "ad1", "admin@x", "secret", admin.RoleAdmin)

	_, opBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	if code, _ := post(t, ts.URL+"/api/policies", opBody["token"], map[string]string{"name": "P", "version": "v1"}); code != http.StatusForbidden {
		t.Fatalf("OPERATOR politika oluşturamamalı, %d", code)
	}

	_, adBody := post(t, ts.URL+"/api/login", "", map[string]string{"email": "admin@x", "password": "secret"})
	code, body := post(t, ts.URL+"/api/policies", adBody["token"], map[string]string{"name": "P", "version": "v1"})
	if code != http.StatusOK || body["policy_id"] == "" {
		t.Fatalf("ADMIN politika oluşturabilmeli: code=%d body=%v", code, body)
	}
}

// Tespit kuralı test aracı (dry-run): örnek olay motora verilir, eşleşen
// kurallar döner. Salt-okunur — herhangi bir kimliği doğrulanmış kullanıcı
// erişebilir; eşleşme yoksa boş liste döner.
func TestDetectionTestEndpoint(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "v1", "viewer@x", "secret", admin.RoleViewer)

	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "viewer@x", "password": "secret"})
	token := lb["token"]
	if token == "" {
		t.Fatal("login token alınamadı")
	}

	// Token'sız → 401.
	if code, _ := post(t, ts.URL+"/api/detections/test", "", map[string]string{"category": "SECURITY", "message": "kurcalama"}); code != http.StatusUnauthorized {
		t.Fatalf("token'sız istek 401 dönmeliydi, %d", code)
	}

	do := func(category, message string) (int, int, string) {
		b, _ := json.Marshal(map[string]string{"category": category, "message": message})
		req, _ := http.NewRequest("POST", ts.URL+"/api/detections/test", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Matched int `json:"matched"`
			Matches []struct {
				RuleID string `json:"rule_id"`
			} `json:"matches"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		first := ""
		if len(out.Matches) > 0 {
			first = out.Matches[0].RuleID
		}
		return resp.StatusCode, out.Matched, first
	}

	// "kurcalama" + SECURITY → KUT-0001 eşleşir.
	if code, n, first := do("SECURITY", "ajan kurcalama girişimi tespit edildi"); code != http.StatusOK || n < 1 || first != "KUT-0001" {
		t.Fatalf("kurcalama eşleşmeliydi: code=%d matched=%d first=%q", code, n, first)
	}

	// Eşleşmeyen içerik → boş.
	if code, n, _ := do("SECURITY", "sıradan bilgilendirme mesajı"); code != http.StatusOK || n != 0 {
		t.Fatalf("eşleşme olmamalıydı: code=%d matched=%d", code, n)
	}

	// Kategori kapsamı: "kurcalama" SECURITY kuralında tanımlı; kuralı olmayan
	// bir kategoride (INFO) aynı metin eşleşmemeli.
	if code, n, _ := do("INFO", "kurcalama"); code != http.StatusOK || n != 0 {
		t.Fatalf("kategori kapsamı: eşleşme olmamalıydı: code=%d matched=%d", code, n)
	}
}

// Çift-kontrol WIPE uçtan uca (HTTP): adminA talep → pending (kuyruğa girmez);
// adminA kendi talebini onaylayamaz (403); adminB onaylar → queued (kuyruğa girer).
func TestWipeDualControlHTTP(t *testing.T) {
	srv, store := newServer(t)
	srv.adminSvc.SetWipeDualControl(true)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	addAdmin(t, store, "adA", "a@x", "secret", admin.RoleAdmin)
	addAdmin(t, store, "adB", "b@x", "secret", admin.RoleAdmin)
	_, la := post(t, ts.URL+"/api/login", "", map[string]string{"email": "a@x", "password": "secret"})
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "b@x", "password": "secret"})
	tokA, tokB := la["token"], lb["token"]
	if tokA == "" || tokB == "" {
		t.Fatal("token alınamadı")
	}

	// adminA talep → pending; komut kuyruğa GİRMEMELİ.
	code, body := post(t, ts.URL+"/api/devices/dev-1/wipe", tokA, map[string]string{"reason": "kayıp cihaz"})
	if code != http.StatusOK || body["status"] != "wipe_pending_approval" {
		t.Fatalf("talep pending dönmeli: %d %v", code, body)
	}
	for _, c := range store.commands {
		if strings.Contains(c, "WIPE") {
			t.Fatalf("talep aşamasında WIPE kuyruğa GİRMEMELİ: %v", store.commands)
		}
	}
	// adminA kendi talebini onaylayamaz → 403 (dört-göz).
	if code, _ := post(t, ts.URL+"/api/devices/dev-1/wipe/approve", tokA, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("kendi onayı 403 dönmeli, %d", code)
	}
	// adminB onaylar → queued.
	if code, b := post(t, ts.URL+"/api/devices/dev-1/wipe/approve", tokB, map[string]string{}); code != http.StatusOK || b["status"] != "wipe_queued" {
		t.Fatalf("farklı ADMIN onayı queued dönmeli: %d %v", code, b)
	}
	found := false
	for _, c := range store.commands {
		if strings.Contains(c, "dev-1:WIPE") {
			found = true
		}
	}
	if !found {
		t.Fatalf("onay sonrası WIPE kuyruğa girmeli: %v", store.commands)
	}
}

// İstek gövdesi boyut sınırı: devasa JSON gövdesi 413 ile reddedilmeli (DoS
// koruması). decode() tüm JSON POST uçlarında MaxBytesReader uygular.
func TestRequestBodySizeLimit(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "ad1", "ad@x", "secret", admin.RoleAdmin)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "ad@x", "password": "secret"})
	token := lb["token"]
	if token == "" {
		t.Fatal("login token alınamadı")
	}

	// ~2 MiB'lik geçerli-JSON gövde (sınır 1 MiB) → 413.
	big := make([]byte, 2<<20)
	for i := range big {
		big[i] = 'a'
	}
	body := []byte(`{"name":"`)
	body = append(body, big...)
	body = append(body, []byte(`"}`)...)
	req, _ := http.NewRequest("POST", ts.URL+"/api/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("devasa gövde 413 dönmeliydi, %d", resp.StatusCode)
	}

	// Normal küçük gövde hâlâ çalışmalı.
	if code, b := post(t, ts.URL+"/api/policies", token, map[string]string{"name": "P", "version": "v1"}); code != http.StatusOK || b["policy_id"] == "" {
		t.Fatalf("normal gövde 200 dönmeliydi: code=%d", code)
	}
}

// Alarm yaşam-döngüsü uçtan uca (HTTP): OPERATOR olayı ack'ler → 200; sonraki
// olay listesinde ack_status görünür; VIEWER 403 alır.
func TestEventAckHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	addAdmin(t, store, "vw1", "vw@x", "secret", admin.RoleViewer)
	store.evtRows = []adminread.EventRow{
		{ID: "evt-x", Category: "SECURITY", Severity: "HIGH", Message: "şüpheli", CreatedAt: time.Now()},
	}

	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	opTok := ob["token"]
	_, vb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "vw@x", "password": "secret"})
	vwTok := vb["token"]
	if opTok == "" || vwTok == "" {
		t.Fatal("token alınamadı")
	}

	// VIEWER ack → 403.
	if code, _ := post(t, ts.URL+"/api/events/evt-x/ack", vwTok, map[string]string{}); code != http.StatusForbidden {
		t.Fatalf("VIEWER ack 403 dönmeliydi, %d", code)
	}
	// OPERATOR ack → 200.
	if code, _ := post(t, ts.URL+"/api/events/evt-x/ack", opTok, map[string]string{}); code != http.StatusOK {
		t.Fatalf("OPERATOR ack 200 dönmeliydi, %d", code)
	}

	// Olay listesinde ack_status görünmeli.
	req, _ := http.NewRequest("GET", ts.URL+"/api/events", nil)
	req.Header.Set("Authorization", "Bearer "+opTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Events []struct {
			ID        string `json:"id"`
			AckStatus string `json:"ack_status"`
		} `json:"events"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	found := false
	for _, e := range out.Events {
		if e.ID == "evt-x" {
			found = true
			if e.AckStatus != "ACKNOWLEDGED" {
				t.Fatalf("evt-x ACKNOWLEDGED olmalıydı, %q", e.AckStatus)
			}
		}
	}
	if !found {
		t.Fatal("evt-x olay listesinde bulunamadı")
	}

	// RESOLVE → 200.
	if code, _ := post(t, ts.URL+"/api/events/evt-x/resolve", opTok, map[string]string{}); code != http.StatusOK {
		t.Fatalf("OPERATOR resolve 200 dönmeliydi, %d", code)
	}

	// Vaka ata (assignee+note): VIEWER 403, OPERATOR 200; liste alanlarda görünmeli.
	if code, _ := post(t, ts.URL+"/api/events/evt-x/case", vwTok,
		map[string]string{"assignee": "soc@x", "note": "fidye"}); code != http.StatusForbidden {
		t.Fatalf("VIEWER vaka 403 dönmeliydi, %d", code)
	}
	if code, _ := post(t, ts.URL+"/api/events/evt-x/case", opTok,
		map[string]string{"assignee": "soc@x", "note": "fidye şüphesi"}); code != http.StatusOK {
		t.Fatalf("OPERATOR vaka 200 dönmeliydi, %d", code)
	}
	req2, _ := http.NewRequest("GET", ts.URL+"/api/events", nil)
	req2.Header.Set("Authorization", "Bearer "+opTok)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var out2 struct {
		Events []struct {
			ID       string `json:"id"`
			Assignee string `json:"ack_assignee"`
			Note     string `json:"ack_note"`
		} `json:"events"`
	}
	_ = json.NewDecoder(resp2.Body).Decode(&out2)
	okCase := false
	for _, e := range out2.Events {
		if e.ID == "evt-x" {
			okCase = e.Assignee == "soc@x" && e.Note == "fidye şüphesi"
		}
	}
	if !okCase {
		t.Fatalf("evt-x vaka alanları listede görünmeliydi: %+v", out2.Events)
	}
}

// Adli dosya toplama uçtan uca (HTTP): OPERATOR collect-file → queued; VIEWER
// 403; artefakt listesi + indirme içerikle döner.
func TestArtifactCollectionHTTP(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)
	addAdmin(t, store, "vw1", "vw@x", "secret", admin.RoleViewer)
	// Önceden toplanmış bir artefakt (grpc SaveArtifact yolunu taklit).
	_, _ = store.SaveArtifact(context.Background(), "dev-1", "cmd-1", "C:/logs/app.log", "abcd", []byte("gizli-log-icerigi"))

	_, ob := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	opTok := ob["token"]
	_, vb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "vw@x", "password": "secret"})
	vwTok := vb["token"]

	// VIEWER collect-file → 403.
	if code, _ := post(t, ts.URL+"/api/devices/dev-1/collect-file", vwTok, map[string]string{"path": "C:/x"}); code != http.StatusForbidden {
		t.Fatalf("VIEWER collect-file 403 dönmeliydi, %d", code)
	}
	// OPERATOR collect-file → 200 + komut kuyruğa.
	if code, _ := post(t, ts.URL+"/api/devices/dev-1/collect-file", opTok, map[string]string{"path": "C:/x/log.txt"}); code != http.StatusOK {
		t.Fatalf("OPERATOR collect-file 200 dönmeliydi, %d", code)
	}
	found := false
	for _, c := range store.commands {
		if c == "dev-1:COLLECT_FILE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("COLLECT_FILE komutu kuyruğa eklenmeliydi: %v", store.commands)
	}

	// Artefakt listesi.
	req, _ := http.NewRequest("GET", ts.URL+"/api/devices/dev-1/artifacts", nil)
	req.Header.Set("Authorization", "Bearer "+opTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var lst struct {
		Artifacts []struct {
			ID   string `json:"id"`
			Path string `json:"path"`
			Size int    `json:"size"`
		} `json:"artifacts"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&lst)
	if len(lst.Artifacts) != 1 || lst.Artifacts[0].Path != "C:/logs/app.log" {
		t.Fatalf("1 artefakt beklenirdi: %+v", lst.Artifacts)
	}
	aid := lst.Artifacts[0].ID

	// İndirme içerikle döner.
	dreq, _ := http.NewRequest("GET", ts.URL+"/api/artifacts/"+aid+"/download", nil)
	dreq.Header.Set("Authorization", "Bearer "+opTok)
	dresp, err := http.DefaultClient.Do(dreq)
	if err != nil {
		t.Fatal(err)
	}
	defer dresp.Body.Close()
	body, _ := io.ReadAll(dresp.Body)
	if string(body) != "gizli-log-icerigi" {
		t.Fatalf("indirme içeriği hatalı: %q", string(body))
	}
	if cd := dresp.Header.Get("Content-Disposition"); !strings.Contains(cd, "app.log") {
		t.Fatalf("Content-Disposition dosya adı içermeli: %q", cd)
	}
}

// Retro-hunt: "rules" modu mevcut tespit motorunu GEÇMİŞ olaylara uygular
// (yeni kuralla eski olayları tarama); "query" modu zaman/alan filtreli arama.
func TestHuntHTTP(t *testing.T) {
	srv, store := newServer(t)
	// Özel tek-kurallı motor: "mimikatz" içeren SECURITY olayı eşleşsin.
	srv.SetDetector(detect.NewEngine([]detect.Rule{{
		ID: "HUNT-1", Name: "mimikatz", Category: "SECURITY",
		Contains: []string{"mimikatz"}, Severity: "CRITICAL",
	}}))
	store.evtRows = []adminread.EventRow{
		{ID: "e1", Category: "SECURITY", Severity: "HIGH", Message: "mimikatz.exe çalıştı", CreatedAt: time.Now()},
		{ID: "e2", Category: "SYSTEM", Severity: "INFO", Message: "normal olay", CreatedAt: time.Now()},
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	addAdmin(t, store, "ad1", "a@x", "secret", admin.RoleViewer)
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "a@x", "password": "secret"})
	tok := lb["token"]
	if tok == "" {
		t.Fatal("token alınamadı")
	}

	type huntResp struct {
		Scanned int `json:"scanned"`
		Hits    []struct {
			Event struct {
				ID string `json:"id"`
			} `json:"event"`
			Matched []string `json:"matched"`
		} `json:"hits"`
	}
	hunt := func(body map[string]any) huntResp {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", ts.URL+"/api/hunt", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out huntResp
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	// rules modu: motor 2 geçmiş olaya uygulanır; yalnız e1 (mimikatz) eşleşir.
	r := hunt(map[string]any{"mode": "rules"})
	if r.Scanned != 2 {
		t.Fatalf("2 olay taranmalıydı: %d", r.Scanned)
	}
	if len(r.Hits) != 1 || r.Hits[0].Event.ID != "e1" || len(r.Hits[0].Matched) == 0 {
		t.Fatalf("rules-hunt yalnız e1'i eşleştirmeliydi: %+v", r.Hits)
	}
	// query modu: message_contains "normal" → yalnız e2.
	q := hunt(map[string]any{"mode": "query", "message_contains": "normal"})
	if len(q.Hits) != 1 || q.Hits[0].Event.ID != "e2" {
		t.Fatalf("query-hunt 'normal' → e2 eşleşmeliydi: %+v", q.Hits)
	}
}

// Okuma-yolu kiracı kapsamı: /api/hunt sorgusu çağıran yöneticinin kiracısıyla
// SUNUCU-TARAFI daraltılmalı (istekte tenant yok). Kiracıya bağlı admin → kendi
// kiracısı; platform admini (kiracısız) → boş filtre (tüm kiracılar).
func TestHuntQueryScopedToCallerTenant(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()

	huntAs := func(email string) {
		_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": email, "password": "secret"})
		tok := lb["token"]
		if tok == "" {
			t.Fatalf("%s token alınamadı", email)
		}
		b, _ := json.Marshal(map[string]any{"mode": "query", "message_contains": "x"})
		req, _ := http.NewRequest("POST", ts.URL+"/api/hunt", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s hunt beklenen 200, dönen %d", email, resp.StatusCode)
		}
	}

	// Kiracıya bağlı yönetici → filtre kendi kiracısına sabitlenir.
	addAdmin(t, store, "acme-op", "acme@x", "secret", admin.RoleViewer)
	store.adminTen["acme-op"] = "acme"
	huntAs("acme@x")
	if store.lastEvtF.TenantID != "acme" {
		t.Fatalf("kiracı-admin sorgusu 'acme' ile daraltılmalıydı, dönen: %q", store.lastEvtF.TenantID)
	}

	// Platform yöneticisi (kiracısız) → boş filtre (tüm kiracılar).
	addAdmin(t, store, "plat-op", "plat@x", "secret", admin.RoleViewer)
	huntAs("plat@x")
	if store.lastEvtF.TenantID != "" {
		t.Fatalf("platform-admin sorgusu daraltılmamalıydı, dönen: %q", store.lastEvtF.TenantID)
	}
}

// /api/events liste yolu da çağıranın kiracısıyla daraltılmalı (QueryEvents'e
// yönlendirilir). Kiracıya bağlı admin → kendi kiracısı; platform admini → boş.
func TestListEventsScopedToCallerTenant(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()

	getEventsAs := func(email string) {
		_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": email, "password": "secret"})
		tok := lb["token"]
		if tok == "" {
			t.Fatalf("%s token alınamadı", email)
		}
		resp, err := authedGET(t, ts.URL+"/api/events", tok)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s /api/events beklenen 200, dönen %d", email, resp.StatusCode)
		}
	}

	addAdmin(t, store, "acme-op", "acme@x", "secret", admin.RoleOperator)
	store.adminTen["acme-op"] = "acme"
	getEventsAs("acme@x")
	if store.lastEvtF.TenantID != "acme" {
		t.Fatalf("kiracı-admin liste yolu 'acme' ile daraltılmalıydı, dönen: %q", store.lastEvtF.TenantID)
	}

	addAdmin(t, store, "plat-op", "plat@x", "secret", admin.RoleOperator)
	getEventsAs("plat@x")
	if store.lastEvtF.TenantID != "" {
		t.Fatalf("platform-admin liste yolu daraltılmamalıydı, dönen: %q", store.lastEvtF.TenantID)
	}
}

// Toplu eylem: dry_run önizleme HİÇBİR komut kuyruğa almamalı; gerçek çağrı
// yalnız etiketli cihazlara uygulanmalı.
func TestBulkActionDryRunAndApply(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "ad1", "op@x", "secret", admin.RoleOperator)
	store.devRows = []adminread.DeviceRow{
		{ID: "d1", Tags: []string{"prod"}},
		{ID: "d2", Tags: []string{"prod"}},
		{ID: "d3", Tags: []string{"dev"}},
	}
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	tok := lb["token"]
	if tok == "" {
		t.Fatal("token alınamadı")
	}

	// dry-run: hiçbir komut kuyruğa GİRMEMELİ.
	if code, _ := post(t, ts.URL+"/api/devices/bulk", tok,
		map[string]any{"tag": "prod", "action": "quarantine", "dry_run": true}); code != http.StatusOK {
		t.Fatalf("dry-run 200 dönmeli: %d", code)
	}
	for _, c := range store.commands {
		if strings.Contains(c, "QUARANTINE") {
			t.Fatalf("dry-run komut kuyruğa GİRMEMELİ: %v", store.commands)
		}
	}
	// gerçek: yalnız prod (d1,d2) karantinaya alınmalı; d3 (dev) etkilenmemeli.
	if code, _ := post(t, ts.URL+"/api/devices/bulk", tok,
		map[string]any{"tag": "prod", "action": "quarantine"}); code != http.StatusOK {
		t.Fatalf("apply 200 dönmeli: %d", code)
	}
	q := 0
	for _, c := range store.commands {
		if strings.Contains(c, "QUARANTINE") {
			q++
		}
		if strings.HasPrefix(c, "d3:") && strings.Contains(c, "QUARANTINE") {
			t.Fatal("dev etiketli cihaz etkilenmemeliydi")
		}
	}
	if q != 2 {
		t.Fatalf("2 prod cihazı karantinaya alınmalıydı: %v", store.commands)
	}
}

func TestSafeRequestID(t *testing.T) {
	// Geçerli kimlik olduğu gibi korunur.
	if got := safeRequestID("abc-123.def_456"); got != "abc-123.def_456" {
		t.Fatalf("geçerli kimlik korunmalı, %q", got)
	}
	// Log-enjeksiyonu (newline) → temizlenir (yeni kimlik üretilir, girdi kullanılmaz).
	inj := "ok\nFAKE [access] injected"
	if got := safeRequestID(inj); got == inj || len(got) != 16 {
		t.Fatalf("enjeksiyonlu kimlik reddedilip yeni üretilmeli, %q", got)
	}
	// Boş → üretilir (16 hex).
	if got := safeRequestID(""); len(got) != 16 {
		t.Fatalf("boş kimlik → 16 hex üretilmeli, %q", got)
	}
	// Aşırı uzun → reddedilir.
	long := ""
	for i := 0; i < 100; i++ {
		long += "a"
	}
	if got := safeRequestID(long); len(got) != 16 {
		t.Fatalf("aşırı uzun kimlik reddedilmeli, %q", got)
	}
}

func (m *memStore) ListCustody(_ context.Context, evidenceID string) ([]evidence.CustodyEntry, error) {
	out := make([]evidence.CustodyEntry, len(m.custody[evidenceID]))
	copy(out, m.custody[evidenceID])
	return out, nil
}

func (m *memStore) AppendCustody(_ context.Context, evidenceID string, e evidence.CustodyEntry) error {
	if m.custody == nil {
		m.custody = map[string][]evidence.CustodyEntry{}
	}
	m.custody[evidenceID] = append(m.custody[evidenceID], e)
	return nil
}

// (HTTP): yeniden kayıt BAŞARILI olduktan sonra, yeni sır etkinleştirilene dek MFA
// zorunluluğu sürer — kodsuz giriş token vermez, keyfi kodla disable reddedilir ve MFA
// durumu (etkin sır + enrolled) değişmez.
func TestMFAReenrollPendingWindowStaysEnforced(t *testing.T) {
	ts, store := setup(t)
	defer ts.Close()
	addAdmin(t, store, "op1", "op@x", "secret", admin.RoleOperator)

	const oldSecret = "JBSWY3DPEHPK3PXP"
	store.ensureMFA()
	store.mfa["op1"] = &mfaRec{secret: oldSecret, enrolled: true}

	// Mevcut kodla giriş → oturum.
	otp, _ := security.TOTPAt(oldSecret, time.Now())
	_, lb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret", "code": otp})
	token := lb["token"]
	if token == "" {
		t.Fatal("geçerli kodla giriş token vermeliydi")
	}

	// Yeniden kayıt (sonraki adımdan geçerli mevcut kod) → 200 + yeni sır.
	otp2, _ := security.TOTPAt(oldSecret, time.Now().Add(30*time.Second))
	code, eb := post(t, ts.URL+"/api/mfa/enroll", token, map[string]string{"code": otp2})
	if code != http.StatusOK || eb["secret"] == "" || eb["secret"] == oldSecret {
		t.Fatalf("yeniden kayıt başarısız: %d %v", code, eb)
	}

	// Bekleyen pencerede MFA hâlâ açık: eski sır etkin, enrolled=true, yeni sır bekleyen.
	r := store.mfa["op1"]
	if !r.enrolled || r.secret != oldSecret || r.pending != eb["secret"] {
		t.Fatalf("bekleyen pencerede etkin MFA korunmalı: %+v", r)
	}
	// Kodsuz giriş token VERMEMELİ.
	_, nb := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret"})
	if nb["token"] != "" {
		t.Fatal("bekleyen pencerede kodsuz giriş token vermemeliydi")
	}
	// Yeni (bekleyen) sırdan gelen kodla giriş de reddedilir (henüz etkin değil).
	pend, _ := security.TOTPAt(eb["secret"], time.Now())
	if c, _ := post(t, ts.URL+"/api/login", "", map[string]string{"email": "op@x", "password": "secret", "code": pend}); c != http.StatusUnauthorized {
		t.Fatalf("bekleyen sırdan kod ile giriş 401 dönmeliydi, %d", c)
	}
	// Keyfi kodla disable reddedilir ve MFA açık kalır.
	if c, _ := post(t, ts.URL+"/api/mfa/disable", token, map[string]string{"code": "000000"}); c == http.StatusOK {
		t.Fatal("keyfi kodla disable başarılı olmamalıydı")
	}
	if !store.mfa["op1"].enrolled || store.mfa["op1"].secret != oldSecret {
		t.Fatal("reddedilen disable MFA'yı kapatmamalıydı")
	}
}
