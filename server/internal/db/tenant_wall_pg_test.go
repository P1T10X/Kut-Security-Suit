package db

// Gerçek PostgreSQL'e karşı kiracı-duvarı entegrasyon testleri. KUT_DATABASE_URL yoksa
// ATLANIR (CI'daki "DB yolu (PostgreSQL)" işi şemayı yükleyip bu testleri koşturur).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/enroll"
	"kut.corp/suite/server/internal/security"
)

func pgStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	dsn := os.Getenv("KUT_DATABASE_URL")
	if dsn == "" {
		t.Skip("KUT_DATABASE_URL yok — PostgreSQL entegrasyon testi atlandı")
	}
	ctx := context.Background()
	s, err := New(ctx, dsn)
	if err != nil {
		t.Fatalf("db bağlantısı: %v", err)
	}
	t.Cleanup(s.Close)
	return s, ctx
}

func uniq(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + hex.EncodeToString(b)
}

func devStatus(ctx context.Context, t *testing.T, s *Store, id string) string {
	t.Helper()
	var st string
	if err := s.pool.QueryRow(ctx, `SELECT status::text FROM devices WHERE id = $1::uuid`, id).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

// (PG): ON CONFLICT yolu cihazı kiracılar arası TAŞIMAZ ve karantinayı ACTIVE'e düşürmez.
func TestPGEnrollTenantWallAndStatusKept(t *testing.T) {
	s, ctx := pgStore(t)
	tA, tB := uniq(t, "ta-"), uniq(t, "tb-")
	mac := []byte(uniq(t, "mac-"))

	in := enroll.DeviceEnrollment{
		MACBlindIndex: mac, HostnameEnc: []byte("h1"), MACEnc: []byte("m"), OSInfoEnc: []byte("o"),
		OSPlatform: "linux", AgentVersion: "1", TenantID: tA,
	}
	id, err := s.UpsertEnrollingDevice(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, id) })

	// NEGATIF (re-home): aynı MAC, başka kiracının token'ı → A'nın satırına DOKUNULMAZ; B kendi
	// AYRI cihazını alır (tekillik kiracı başına, MAC-squat DoS yok).
	evil := in
	evil.TenantID, evil.HostnameEnc = tB, []byte("EVIL")
	idB, err := s.UpsertEnrollingDevice(ctx, evil)
	if err != nil || idB == id {
		t.Fatalf("çapraz-kiracı kayıt A'nın cihazını devralmamalı, B kendi satırını almalı: id=%q err=%v", idB, err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, idB) })
	if tn, _ := s.TenantForDevice(ctx, id); tn != tA {
		t.Fatalf("cihaz kiracısı değişmemeli: %q", tn)
	}
	if tn, _ := s.TenantForDevice(ctx, idB); tn != tB {
		t.Fatalf("B cihazı B kiracısında olmalı: %q", tn)
	}
	var host []byte
	if err := s.pool.QueryRow(ctx, `SELECT hostname_encrypted FROM devices WHERE id = $1::uuid`, id).Scan(&host); err != nil || string(host) != "h1" {
		t.Fatalf("diğer kiracının kaydı A'nın alanlarını değiştirmemeli: %q %v", host, err)
	}

	// NEGATIF: token'a bağlı cihaz (PreferredDeviceID) yolu da kiracı duvarına tabi.
	pref := in
	pref.PreferredDeviceID, pref.TenantID = id, tB
	if _, err := s.UpsertEnrollingDevice(ctx, pref); !errors.Is(err, enroll.ErrTenantMismatch) {
		t.Fatalf("preferred çapraz-kiracı ErrTenantMismatch olmalı: %v", err)
	}
	if tn, _ := s.TenantForDevice(ctx, id); tn != tA {
		t.Fatalf("preferred yolu kiracıyı değiştirmemeli: %q", tn)
	}

	// Karantina durumları yeniden kayıtla KORUNUR.
	for _, keep := range []string{"QUARANTINED", "QUARANTINE_PENDING", "ACTIVE"} {
		if err := s.SetDeviceStatus(ctx, id, keep); err != nil {
			t.Fatal(err)
		}
		in.HostnameEnc = []byte("h-" + keep)
		if got, err := s.UpsertEnrollingDevice(ctx, in); err != nil || got != id {
			t.Fatalf("aynı kiracıda yeniden kayıt aynı cihaz olmalı: %q %v", got, err)
		}
		if st := devStatus(ctx, t, s, id); st != keep {
			t.Fatalf("yeniden kayıt %s durumunu korumalı, dönen %s", keep, st)
		}
	}
	// POZITIF: OFFLINE / UNINSTALLED → ACTIVE.
	for _, from := range []string{"OFFLINE", "UNINSTALLED"} {
		_ = s.SetDeviceStatus(ctx, id, from)
		if _, err := s.UpsertEnrollingDevice(ctx, in); err != nil {
			t.Fatal(err)
		}
		if st := devStatus(ctx, t, s, id); st != "ACTIVE" {
			t.Fatalf("%s cihaz yeniden kayıtla ACTIVE olmalı, dönen %s", from, st)
		}
	}
	// POZITIF: preferred + aynı kiracı geçer.
	pref.TenantID = tA
	if got, err := s.UpsertEnrollingDevice(ctx, pref); err != nil || got != id {
		t.Fatalf("preferred aynı kiracı geçmeli: %q %v", got, err)
	}
	// Bilinmeyen preferred cihaz: eski "yok" hatası (ErrTenantMismatch DEĞİL).
	pref.PreferredDeviceID = "00000000-0000-0000-0000-000000000001"
	if _, err := s.UpsertEnrollingDevice(ctx, pref); err == nil || errors.Is(err, enroll.ErrTenantMismatch) {
		t.Fatalf("var olmayan cihaz için genel hata beklenirdi: %v", err)
	}
}

// (PG): token kiracı sorgusu ve kiracı süzmeli yönetici listesi.
func TestPGTokenTenantAndAdminListScoped(t *testing.T) {
	s, ctx := pgStore(t)
	tA, tB := uniq(t, "ta-"), uniq(t, "tb-")

	if err := s.SaveEnrollmentToken(ctx, []byte(uniq(t, "tok-")), "", tA, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListEnrollmentTokens(ctx, 5, tA)
	if err != nil || len(rows) == 0 {
		t.Fatalf("token listelenmeli: %v %v", rows, err)
	}
	got, found, err := s.EnrollmentTokenTenant(ctx, rows[0].ID)
	if err != nil || !found || got != tA {
		t.Fatalf("token kiracısı %q olmalı: %q found=%v err=%v", tA, got, found, err)
	}
	if _, found, err := s.EnrollmentTokenTenant(ctx, "bu-bir-uuid-degil"); err != nil || found {
		t.Fatalf("geçersiz id found=false, hata yok olmalı: found=%v err=%v", found, err)
	}

	emailA, emailB := uniq(t, "a-")+"@x", uniq(t, "b-")+"@x"
	if _, err := s.CreateAdmin(ctx, emailA, "h", admin.RoleAdmin, tA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAdmin(ctx, emailB, "h", admin.RoleAdmin, tB); err != nil {
		t.Fatal(err)
	}
	listA, err := s.ListAdmins(ctx, tA)
	if err != nil || len(listA) != 1 || listA[0].Email != emailA {
		t.Fatalf("yalnız %s kiracısının yöneticisi beklenirdi: %+v %v", tA, listA, err)
	}
}

func devTenant(ctx context.Context, t *testing.T, s *Store, id string) string {
	t.Helper()
	var tn string
	if err := s.pool.QueryRow(ctx, `SELECT tenant_id FROM devices WHERE id = $1::uuid`, id).Scan(&tn); err != nil {
		t.Fatal(err)
	}
	return tn
}

// (PG): kiracı öncesi (legacy) cihazların tenant_id'si boştur (şema varsayılanı). Örtük
// "default" token'ıyla yeniden kayıt (hem MAC/ON CONFLICT hem PreferredDeviceID yolu)
// reddedilmez ve kiracıyı default'a normalleştirir; gerçek kiracılar için taşıma engelli kalır.
func TestPGLegacyEmptyTenantDeviceReenrollsUnderDefault(t *testing.T) {
	s, ctx := pgStore(t)
	other := uniq(t, "tx-")

	// MAC yolu (ON CONFLICT).
	mac := []byte(uniq(t, "mac-legacy-"))
	in := enroll.DeviceEnrollment{
		MACBlindIndex: mac, HostnameEnc: []byte("old"), MACEnc: []byte("m"), OSInfoEnc: []byte("o"),
		OSPlatform: "linux", AgentVersion: "1", TenantID: "",
	}
	id, err := s.UpsertEnrollingDevice(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, id) })
	if tn := devTenant(ctx, t, s, id); tn != "" {
		t.Fatalf("legacy cihaz boş kiracıyla başlamalı: %q", tn)
	}

	// NEGATIF: gerçek kiracı legacy cihazı devralamaz: kendi AYRI satırını alır, legacy
	// satır değişmez.
	evil := in
	evil.TenantID, evil.HostnameEnc = other, []byte("EVIL")
	idO, err := s.UpsertEnrollingDevice(ctx, evil)
	if err != nil || idO == id {
		t.Fatalf("gerçek kiracı legacy cihazı devralamaz, kendi satırını almalı: id=%q err=%v", idO, err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, idO) })
	if tn := devTenant(ctx, t, s, id); tn != "" {
		t.Fatalf("diğer kiracının kaydı legacy kiracıyı değiştirmemeli: %q", tn)
	}

	// POZITIF: "default" token'ı aynı cihazı günceller + kiracıyı normalleştirir.
	def := in
	def.TenantID, def.HostnameEnc = "default", []byte("new")
	got, err := s.UpsertEnrollingDevice(ctx, def)
	if err != nil || got != id {
		t.Fatalf("default token'ı legacy cihazı yeniden kaydetmeli: %q %v", got, err)
	}
	if tn := devTenant(ctx, t, s, id); tn != "default" {
		t.Fatalf("kiracı default'a normalleşmeli: %q", tn)
	}
	var host []byte
	if err := s.pool.QueryRow(ctx, `SELECT hostname_encrypted FROM devices WHERE id = $1::uuid`, id).Scan(&host); err != nil || string(host) != "new" {
		t.Fatalf("alanlar güncellenmeli: %q %v", host, err)
	}
	// Normalleşmeden sonra da gerçek kiracı için duvar aynı: yine kendi satırını alır.
	if again, err := s.UpsertEnrollingDevice(ctx, evil); err != nil || again != idO {
		t.Fatalf("normalleşmiş cihaz başka kiracıya taşınamaz, other kendi satırını güncellemeli: %q %v", again, err)
	}

	// PreferredDeviceID yolu: ikinci bir legacy cihaz.
	in2 := in
	in2.MACBlindIndex = []byte(uniq(t, "mac-legacy2-"))
	id2, err := s.UpsertEnrollingDevice(ctx, in2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, id2) })
	pref := in2
	pref.PreferredDeviceID, pref.TenantID = id2, other
	if _, err := s.UpsertEnrollingDevice(ctx, pref); !errors.Is(err, enroll.ErrTenantMismatch) {
		t.Fatalf("preferred yolunda gerçek kiracı legacy cihazı devralamaz: %v", err)
	}
	pref.TenantID = "default"
	if got, err := s.UpsertEnrollingDevice(ctx, pref); err != nil || got != id2 {
		t.Fatalf("preferred yolunda default token'ı geçmeli: %q %v", got, err)
	}
	if tn := devTenant(ctx, t, s, id2); tn != "default" {
		t.Fatalf("preferred yolunda da default'a normalleşmeli: %q", tn)
	}
}

// (PG): bekleyen sır AYRI sütunda tutulur; ActivateMFA tek UPDATE ile takas yapar;
// bekleyen pencerede etkin sır + enrolled=true korunur; Disable ikisini de temizler.
func TestPGMFAPendingSecretSwap(t *testing.T) {
	s, ctx := pgStore(t)
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	cipher, err := security.NewFieldCipher(security.DeriveKey(master, security.LabelFieldEncryption))
	if err != nil {
		t.Fatal(err)
	}
	s.SetFieldCipher(cipher)

	id, err := s.CreateAdmin(ctx, uniq(t, "mfa-")+"@x", "h", admin.RoleOperator, uniq(t, "tm-"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM admins WHERE id = $1::uuid`, id) })

	look := func(wantSecret string, wantOn bool, wantPending string) {
		t.Helper()
		sec, on, err := s.LookupMFA(ctx, id)
		if err != nil || sec != wantSecret || on != wantOn {
			t.Fatalf("LookupMFA = %q/%v/%v, beklenen %q/%v", sec, on, err, wantSecret, wantOn)
		}
		p, err := s.LookupPendingMFA(ctx, id)
		if err != nil || p != wantPending {
			t.Fatalf("LookupPendingMFA = %q/%v, beklenen %q", p, err, wantPending)
		}
	}

	look("", false, "")
	// Bekleyen sır etkin görünmez.
	if err := s.SetPendingMFASecret(ctx, id, "SECRETONE"); err != nil {
		t.Fatal(err)
	}
	look("", false, "SECRETONE")
	// Bekleyen sırrı etkinleştir (ilk kayıt).
	if err := s.ActivateMFA(ctx, id); err != nil {
		t.Fatal(err)
	}
	look("SECRETONE", true, "")

	// Yeniden kayıt: yeni sır bekleyen kalırken eski sır + enrolled=true AYNEN korunur.
	if err := s.SetPendingMFASecret(ctx, id, "SECRETTWO"); err != nil {
		t.Fatal(err)
	}
	look("SECRETONE", true, "SECRETTWO")
	// Atomik takas: yeni sır etkin, bekleyen temizlenir, eski sır gider.
	if err := s.ActivateMFA(ctx, id); err != nil {
		t.Fatal(err)
	}
	look("SECRETTWO", true, "")
	// Bekleyen yokken tekrar ActivateMFA hiçbir şeyi değiştirmez.
	if err := s.ActivateMFA(ctx, id); err != nil {
		t.Fatal(err)
	}
	look("SECRETTWO", true, "")

	// Disable etkin + bekleyen sırrı temizler.
	if err := s.SetPendingMFASecret(ctx, id, "SECRETTHREE"); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableMFA(ctx, id); err != nil {
		t.Fatal(err)
	}
	look("", false, "")
}

// (PG): MAC-squat DoS. Kiracı A, B'nin MAC'ini önceden kaydetse bile B kendi cihazını
// enroll edebilir; uq_devices_tenant_mac aynı kiracıda ikinci satırı engeller (kanonik
// kiracı: legacy boş ≡ default); eski küresel kısıt artık yoktur.
func TestPGMACSquatCannotBlockOtherTenant(t *testing.T) {
	s, ctx := pgStore(t)
	evilT, victimT := uniq(t, "tevil-"), uniq(t, "tvic-")
	mac := []byte(uniq(t, "mac-squat-"))
	base := enroll.DeviceEnrollment{
		MACBlindIndex: mac, HostnameEnc: []byte("squat"), MACEnc: []byte("m"), OSInfoEnc: []byte("o"),
		OSPlatform: "linux", AgentVersion: "1", TenantID: evilT,
	}
	squat, err := s.UpsertEnrollingDevice(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, squat) })

	// NEGATIF (saldırı): squat eden kiracı kurbanın aynı MAC'iyle kurbanı engelleyemez.
	vin := base
	vin.TenantID, vin.HostnameEnc = victimT, []byte("real")
	victim, err := s.UpsertEnrollingDevice(ctx, vin)
	if err != nil {
		t.Fatalf("kurban kiracı aynı MAC ile enroll olabilmeli: %v", err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, victim) })
	if victim == squat {
		t.Fatal("kurban squat eden kiracının satırını almamalı")
	}
	if tn, _ := s.TenantForDevice(ctx, victim); tn != victimT {
		t.Fatalf("kurban cihazı kurban kiracısında olmalı: %q", tn)
	}
	if tn, _ := s.TenantForDevice(ctx, squat); tn != evilT {
		t.Fatalf("squat satırı değişmemeli: %q", tn)
	}

	// POZITIF: kurban yeniden kaydı kendi satırını günceller (ON CONFLICT yeni hedef).
	vin.HostnameEnc = []byte("real2")
	if again, err := s.UpsertEnrollingDevice(ctx, vin); err != nil || again != victim {
		t.Fatalf("kurban yeniden kaydı kendi satırını güncellemeli: %q %v", again, err)
	}

	// Şema: aynı kiracıda aynı MAC ikinci satır OLAMAZ; farklı kiracıda olabilir; eski küresel
	// tekillik kısıtı yok; yeni indeks var.
	dup := `INSERT INTO devices (hostname_encrypted, mac_address_encrypted, mac_address_bidx, tenant_id)
	        VALUES ('\x01', '\x01', $1, $2)`
	if _, err := s.pool.Exec(ctx, dup, mac, evilT); err == nil {
		t.Fatal("aynı kiracıda aynı MAC için ikinci satır unique ihlali olmalı")
	}
	var oldConstraint, newIndex int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conname = 'devices_mac_address_bidx_key'`).Scan(&oldConstraint); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname = 'uq_devices_tenant_mac'`).Scan(&newIndex); err != nil {
		t.Fatal(err)
	}
	if oldConstraint != 0 || newIndex != 1 {
		t.Fatalf("eski küresel kısıt kalkmalı (%d), yeni indeks var olmalı (%d)", oldConstraint, newIndex)
	}
}

// upgradeBlock, db/schema.sql'ten `-- BEGIN <name>` … `-- END <name>` arasındaki GERÇEK yükseltme
// bloğunu çıkarır ve ifadelere böler (yorum satırları atılır). Blokta dollar-quote yoktur.
func upgradeBlock(t *testing.T, name string) []string {
	t.Helper()
	raw, err := os.ReadFile("../../../db/schema.sql")
	if err != nil {
		t.Fatalf("db/schema.sql okunamadı: %v", err)
	}
	src := strings.ReplaceAll(string(raw), "\r\n", "\n")
	begin, end := "\n-- BEGIN "+name+"\n", "\n-- END "+name+"\n"
	i, j := strings.Index(src, begin), strings.Index(src, end)
	if i < 0 || j < 0 || j < i {
		t.Fatalf("schema.sql içinde %s bloğu bulunamadı", name)
	}
	var body strings.Builder
	for _, ln := range strings.Split(src[i+len(begin):j], "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "--") {
			continue
		}
		body.WriteString(ln + "\n")
	}
	var stmts []string
	for _, s := range strings.Split(body.String(), ";") {
		if s = strings.TrimSpace(s); s != "" {
			stmts = append(stmts, s)
		}
	}
	if len(stmts) == 0 {
		t.Fatalf("%s bloğu boş", name)
	}
	return stmts
}

// Kiracı izolasyonu yükseltmesi (PG): schema.sql'deki GERÇEK TENANT-MAC ve INGEST-TOKEN-TENANT yükseltme blokları, ESKİ (legacy) bir
// durumdan — küresel mac_address_bidx kısıtı VAR, policies.tenant_id / tokens.tenant_id YOK —
// başlayıp İKİ KEZ çalıştırılır: ilk turda eski kısıt düşer, yeni indeks ve sütunlar oluşur;
// ikinci tur hatasız no-op'tur. Her şey bir transaction + geçici şema içinde yapılır (geri alınır,
// paylaşılan test şemasına dokunulmaz). Test kopyası değil, dosyadaki blok çalıştırıldığından
// blok ile test arasında sapma olamaz.
func TestPGUpgradeBlockIdempotent(t *testing.T) {
	s, ctx := pgStore(t)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // sonda her zaman geri al
	exec := func(sql string) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatalf("%v\n%s", err, sql)
		}
	}
	scratch := uniq(t, "upg_")
	exec(`CREATE SCHEMA ` + scratch)
	exec(`SET LOCAL search_path TO ` + scratch + `, public`)
	// Legacy durum: küresel UNIQUE kısıtlı devices, tenant_id'siz policies/tokens.
	exec(`CREATE TABLE devices (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
	        tenant_id VARCHAR(63) NOT NULL DEFAULT '', mac_address_bidx BYTEA NOT NULL,
	        CONSTRAINT devices_mac_address_bidx_key UNIQUE (mac_address_bidx))`)
	exec(`CREATE TABLE policies (id UUID PRIMARY KEY DEFAULT uuid_generate_v4())`)
	exec(`CREATE TABLE tokens (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), scope TEXT NOT NULL)`)

	count := func(q string) int {
		t.Helper()
		var n int
		if err := tx.QueryRow(ctx, q).Scan(&n); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
		return n
	}
	// docs/MULTI-TENANCY.md'deki yükseltme-sonrası doğrulama sorgusuyla AYNI: mac_address_bidx
	// üzerindeki tek-sütunlu UNIQUE kısıt/indeks sayısı (adı ne olursa olsun) 0 olmalı.
	const legacyUnique = `SELECT (SELECT count(*) FROM pg_constraint c
	    JOIN pg_class t ON t.oid = c.conrelid
	    JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY (c.conkey)
	   WHERE t.relname = 'devices' AND t.relnamespace = to_regnamespace(current_schema())
	     AND c.contype = 'u' AND array_length(c.conkey, 1) = 1 AND a.attname = 'mac_address_bidx')
	  + (SELECT count(*) FROM pg_index i
	    JOIN pg_class t ON t.oid = i.indrelid
	    JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = i.indkey[0]
	   WHERE t.relname = 'devices' AND t.relnamespace = to_regnamespace(current_schema())
	     AND i.indisunique AND i.indnatts = 1 AND a.attname = 'mac_address_bidx')`
	if n := count(legacyUnique); n == 0 {
		t.Fatal("legacy durumda küresel kısıt bulunmalı (test ön koşulu)")
	}

	blocks := append(upgradeBlock(t, "TENANT-MAC-UPGRADE"), upgradeBlock(t, "INGEST-TOKEN-TENANT-UPGRADE")...)
	for round := 0; round < 2; round++ {
		for _, stmt := range blocks {
			if _, err := tx.Exec(ctx, stmt); err != nil {
				t.Fatalf("gerçek yükseltme bloğu (tur %d) çalışmalı: %v\n%s", round, err, stmt)
			}
		}
		if n := count(legacyUnique); n != 0 {
			t.Fatalf("tur %d: küresel mac_address_bidx kısıtı/indeksi kalmamalı: %d", round, n)
		}
		if n := count(`SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'uq_devices_tenant_mac'`); n != 1 {
			t.Fatalf("tur %d: uq_devices_tenant_mac var olmalı: %d", round, n)
		}
		for _, col := range []string{"policies", "tokens"} {
			if n := count(`SELECT count(*) FROM information_schema.columns
			                WHERE table_schema = current_schema() AND table_name = '` + col + `' AND column_name = 'tenant_id'`); n != 1 {
				t.Fatalf("tur %d: %s.tenant_id eklenmeli: %d", round, col, n)
			}
		}
	}
	// Yükseltme sonrası: aynı MAC iki farklı kiracıda ayrı satır olabilir, aynı kiracıda olamaz.
	exec(`INSERT INTO devices (tenant_id, mac_address_bidx) VALUES ('a', '\x01'), ('b', '\x01')`)
	if _, err := tx.Exec(ctx, `INSERT INTO devices (tenant_id, mac_address_bidx) VALUES ('a', '\x01')`); err == nil {
		t.Fatal("aynı kiracıda aynı MAC reddedilmeli")
	}
}

// (PG): bilinmeyen, geçersiz-id'li veya pasif yönetici platform ("") DEĞİL,
// ErrUnknownAdmin; etkin platform/kiracılı admin doğru kiracıyı alır.
func TestPGAdminTenantUnknownInactiveFailsClosed(t *testing.T) {
	s, ctx := pgStore(t)
	tn := uniq(t, "tn-")
	plat, err := s.CreateAdmin(ctx, uniq(t, "plat-")+"@x", "h", admin.RoleAdmin, "")
	if err != nil {
		t.Fatal(err)
	}
	tenanted, err := s.CreateAdmin(ctx, uniq(t, "ten-")+"@x", "h", admin.RoleOperator, tn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, `DELETE FROM admins WHERE id IN ($1::uuid, $2::uuid)`, plat, tenanted)
	})

	// POZITIF.
	if got, err := s.AdminTenant(ctx, plat); err != nil || got != "" {
		t.Fatalf("etkin platform admini '' + nil olmalı: %q %v", got, err)
	}
	if got, err := s.AdminTenant(ctx, tenanted); err != nil || got != tn {
		t.Fatalf("etkin kiracılı admin kendi kiracısı: %q %v", got, err)
	}
	// NEGATIF: var olmayan uuid, geçersiz id, boş id.
	for _, id := range []string{"00000000-0000-0000-0000-000000000002", "bu-bir-uuid-degil", ""} {
		if got, err := s.AdminTenant(ctx, id); !errors.Is(err, admin.ErrUnknownAdmin) || got != "" {
			t.Fatalf("id %q için ErrUnknownAdmin beklenirdi: %q %v", id, got, err)
		}
	}
	// NEGATIF: pasifleştirilmiş yönetici.
	if err := s.DeactivateAdmin(ctx, tenanted, ""); err != nil {
		t.Fatal(err)
	}
	if got, err := s.AdminTenant(ctx, tenanted); !errors.Is(err, admin.ErrUnknownAdmin) || got != "" {
		t.Fatalf("pasif yönetici ErrUnknownAdmin olmalı: %q %v", got, err)
	}
	if !errors.Is(admin.ErrUnknownAdmin, admin.ErrForbidden) {
		t.Fatal("ErrUnknownAdmin 403'e eşlenmek için ErrForbidden'ı sarmalı")
	}
}

// (PG): token iptali, yönetici rol/pasifleştirme ve cihaz etiketi SQL'i kiracı
// predicate'ini taşır — servis kapısı atlansa bile çapraz-kiracı yazma etkisizdir; boş
// kiracı (platform) süzülmez.
func TestPGWritesCarryTenantPredicate(t *testing.T) {
	s, ctx := pgStore(t)
	tA, tB := uniq(t, "ta-"), uniq(t, "tb-")

	// --- Token iptali ---
	tokB := []byte(uniq(t, "tokb-"))
	if err := s.SaveEnrollmentToken(ctx, tokB, "", tB, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rowsB, err := s.ListEnrollmentTokens(ctx, 1, tB)
	if err != nil || len(rowsB) != 1 {
		t.Fatalf("B token'ı listelenmeli: %v %v", rowsB, err)
	}
	tokID := rowsB[0].ID
	usedAt := func() bool {
		var used bool
		if err := s.pool.QueryRow(ctx, `SELECT used_at IS NOT NULL FROM enrollment_tokens WHERE id::text = $1`, tokID).Scan(&used); err != nil {
			t.Fatal(err)
		}
		return used
	}
	// NEGATIF: A kapsamı B'nin token'ını iptal edemez (hata + token kullanılmamış kalır).
	if err := s.RevokeEnrollmentToken(ctx, tokID, tA); !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("çapraz-kiracı token iptali ErrForbidden olmalı: %v", err)
	}
	if usedAt() {
		t.Fatal("yabancı kiracının token'ı iptal EDİLMEMELİ")
	}
	// NEGATIF: var olmayan / geçersiz id, kiracılı çağıran için ErrForbidden (varlık sızmaz).
	for _, id := range []string{"00000000-0000-0000-0000-000000000003", "yok"} {
		if err := s.RevokeEnrollmentToken(ctx, id, tA); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("yok token (%q) ErrForbidden olmalı: %v", id, err)
		}
	}
	// POZITIF: kendi kiracısı iptal eder; tekrar iptal sessiz no-op.
	if err := s.RevokeEnrollmentToken(ctx, tokID, tB); err != nil {
		t.Fatal(err)
	}
	if !usedAt() {
		t.Fatal("kendi token'ı iptal edilmeliydi")
	}
	if err := s.RevokeEnrollmentToken(ctx, tokID, tB); err != nil {
		t.Fatalf("zaten kullanılmış kendi token'ı sessiz no-op olmalı: %v", err)
	}
	// POZITIF: platform kapsamı (boş) herhangi bir token'ı iptal eder.
	tokP := []byte(uniq(t, "tokp-"))
	if err := s.SaveEnrollmentToken(ctx, tokP, "", tA, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rowsA, _ := s.ListEnrollmentTokens(ctx, 1, tA)
	if err := s.RevokeEnrollmentToken(ctx, rowsA[0].ID, ""); err != nil {
		t.Fatalf("platform kapsamı süzülmemeli: %v", err)
	}

	// --- Yönetici rol / pasifleştirme ---
	admA, err := s.CreateAdmin(ctx, uniq(t, "a-")+"@x", "h", admin.RoleAdmin, tA)
	if err != nil {
		t.Fatal(err)
	}
	admB, err := s.CreateAdmin(ctx, uniq(t, "b-")+"@x", "h", admin.RoleAdmin, tB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, `DELETE FROM admins WHERE id IN ($1::uuid, $2::uuid)`, admA, admB)
	})
	roleOf := func(id string) (string, bool) {
		var r string
		var act bool
		if err := s.pool.QueryRow(ctx, `SELECT role::text, is_active FROM admins WHERE id = $1::uuid`, id).Scan(&r, &act); err != nil {
			t.Fatal(err)
		}
		return r, act
	}
	// NEGATIF.
	if err := s.SetAdminRole(ctx, admB, admin.RoleViewer, tA); !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("çapraz-kiracı rol güncelleme ErrForbidden olmalı: %v", err)
	}
	if err := s.DeactivateAdmin(ctx, admB, tA); !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("çapraz-kiracı pasifleştirme ErrForbidden olmalı: %v", err)
	}
	if err := s.SetAdminRole(ctx, "bu-bir-uuid-degil", admin.RoleViewer, tA); !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("geçersiz id kiracılı çağıran için ErrForbidden olmalı: %v", err)
	}
	if r, act := roleOf(admB); r != "ADMIN" || !act {
		t.Fatalf("yabancı yönetici değişmemeli: %s active=%v", r, act)
	}
	// POZITIF: kendi kiracısı ve platform kapsamı.
	if err := s.SetAdminRole(ctx, admA, admin.RoleOperator, tA); err != nil {
		t.Fatal(err)
	}
	if r, _ := roleOf(admA); r != "OPERATOR" {
		t.Fatalf("kendi kiracısında rol güncellenmeli: %s", r)
	}
	if err := s.DeactivateAdmin(ctx, admB, ""); err != nil {
		t.Fatalf("platform kapsamı süzülmemeli: %v", err)
	}
	if _, act := roleOf(admB); act {
		t.Fatal("platform kapsamı B yöneticisini pasifleştirebilmeli")
	}

	// --- Cihaz etiketi ---
	devB, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		MACBlindIndex: []byte(uniq(t, "mac-tag-")), HostnameEnc: []byte("h"), MACEnc: []byte("m"),
		OSInfoEnc: []byte("o"), OSPlatform: "linux", AgentVersion: "1", TenantID: tB,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, devB) })
	tagsOf := func() []string {
		var tg []string
		if err := s.pool.QueryRow(ctx, `SELECT tags FROM devices WHERE id = $1::uuid`, devB).Scan(&tg); err != nil {
			t.Fatal(err)
		}
		return tg
	}
	// NEGATIF.
	if err := s.SetDeviceTags(ctx, devB, []string{"evil"}, tA); !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("çapraz-kiracı etiket yazımı ErrForbidden olmalı: %v", err)
	}
	if err := s.SetDeviceTags(ctx, "yok", []string{"x"}, tA); !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("geçersiz cihaz id kiracılı çağıran için ErrForbidden olmalı: %v", err)
	}
	if len(tagsOf()) != 0 {
		t.Fatalf("yabancı cihaz etiketlenmemeli: %v", tagsOf())
	}
	// POZITIF: kendi kiracısı ve platform.
	if err := s.SetDeviceTags(ctx, devB, []string{"ok"}, tB); err != nil {
		t.Fatal(err)
	}
	if tg := tagsOf(); len(tg) != 1 || tg[0] != "ok" {
		t.Fatalf("kendi kiracısında etiket yazılmalı: %v", tg)
	}
	if err := s.SetDeviceTags(ctx, devB, []string{"plat"}, ""); err != nil {
		t.Fatalf("platform kapsamı süzülmemeli: %v", err)
	}
	if tg := tagsOf(); len(tg) != 1 || tg[0] != "plat" {
		t.Fatalf("platform etiketi yazılmalı: %v", tg)
	}
}

func pgDevice(ctx context.Context, t *testing.T, s *Store, tenantID string) string {
	t.Helper()
	id, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{
		MACBlindIndex: []byte(uniq(t, "mac-pol-")), HostnameEnc: []byte("h"), MACEnc: []byte("m"),
		OSInfoEnc: []byte("o"), OSPlatform: "linux", AgentVersion: "1", TenantID: tenantID,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM devices WHERE id = $1::uuid`, id) })
	return id
}

func pgPolicy(ctx context.Context, t *testing.T, s *Store, name, tenantID string) string {
	t.Helper()
	id, err := s.CreatePolicy(ctx, name, "v1", tenantID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM policies WHERE id = $1::uuid`, id) })
	return id
}

// (PG): politika sahipliği — PolicyTenant, kiracı süzmeli liste (kendi +
// paylaşımlı, cihaz sayımı yalnız kendi kiracısı), atama bütünlüğü (SQL seviyesinde) ve
// CurrentPolicy'nin çapraz-kiracı atamayı ajana itmemesi.
func TestPGPolicyTenantOwnership(t *testing.T) {
	s, ctx := pgStore(t)
	tA, tB := uniq(t, "ta-"), uniq(t, "tb-")
	polA := pgPolicy(ctx, t, s, uniq(t, "pa-"), tA)
	polB := pgPolicy(ctx, t, s, uniq(t, "pb-"), tB)
	polS := pgPolicy(ctx, t, s, uniq(t, "ps-"), "")
	devA, devB := pgDevice(ctx, t, s, tA), pgDevice(ctx, t, s, tB)

	// PolicyTenant.
	if tn, ok, err := s.PolicyTenant(ctx, polA); err != nil || !ok || tn != tA {
		t.Fatalf("PolicyTenant %q olmalı: %q %v %v", tA, tn, ok, err)
	}
	if tn, ok, err := s.PolicyTenant(ctx, polS); err != nil || !ok || tn != "" {
		t.Fatalf("paylaşımlı politika '' olmalı: %q %v %v", tn, ok, err)
	}
	for _, id := range []string{"00000000-0000-0000-0000-000000000004", "uuid-degil"} {
		if _, ok, err := s.PolicyTenant(ctx, id); err != nil || ok {
			t.Fatalf("yok/geçersiz id found=false, hata yok olmalı (%q): %v %v", id, ok, err)
		}
	}

	// NEGATIF: SQL seviyesinde atama bütünlüğü — A cihazına B politikası bağlanamaz.
	if err := s.AssignPolicy(ctx, devA, polB); !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("çapraz-kiracı atama ErrForbidden olmalı: %v", err)
	}
	if err := s.AssignPolicy(ctx, "00000000-0000-0000-0000-000000000005", polA); !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("bilinmeyen cihaz ErrForbidden olmalı: %v", err)
	}
	if err := s.AssignPolicy(ctx, devA, "uuid-degil"); !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("geçersiz politika id ErrForbidden olmalı: %v", err)
	}
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM device_policies WHERE device_id = $1::uuid`, devA).Scan(&n); err != nil || n != 0 {
		t.Fatalf("reddedilen atamalar satır yazmamalı: %d %v", n, err)
	}
	// POZITIF: kendi + paylaşımlı; tekrar atama idempotent.
	for _, p := range []string{polA, polS, polA} {
		if err := s.AssignPolicy(ctx, devA, p); err != nil {
			t.Fatalf("meşru atama geçmeli: %v", err)
		}
	}
	if err := s.AssignPolicy(ctx, devB, polS); err != nil {
		t.Fatalf("paylaşımlı politika her kiracıya atanabilmeli: %v", err)
	}

	// Liste süzmesi: A yalnız kendi + paylaşımlı; B politikası görünmez; sayım yalnız A cihazları.
	rows, err := s.ListPolicies(ctx, 1000, tA)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]adminreadPolicy{}
	for _, r := range rows {
		seen[r.ID] = adminreadPolicy{r.TenantID, r.DeviceCount}
	}
	if _, leaked := seen[polB]; leaked {
		t.Fatal("A, B'nin politikasını listelememeli")
	}
	if got, ok := seen[polA]; !ok || got.tenant != tA || got.devices != 1 {
		t.Fatalf("A kendi politikasını 1 cihazla görmeli: %+v", seen[polA])
	}
	if got, ok := seen[polS]; !ok || got.tenant != "" || got.devices != 1 {
		t.Fatalf("paylaşımlıda yalnız A'nın cihazı sayılmalı (B cihazı sızmaz): %+v", seen[polS])
	}
	// POZITIF: platform (boş) hepsini ve tüm cihazları görür.
	allRows, _ := s.ListPolicies(ctx, 1000, "")
	seenAll := map[string]adminreadPolicy{}
	for _, r := range allRows {
		seenAll[r.ID] = adminreadPolicy{r.TenantID, r.DeviceCount}
	}
	if _, ok := seenAll[polB]; !ok || seenAll[polS].devices < 2 {
		t.Fatalf("platform hepsini görmeli, paylaşımlı >=2 cihaz: %+v", seenAll[polS])
	}

	// CurrentPolicy: eski/bozuk çapraz-kiracı atama (doğrudan SQL ile) ajana itilmez; meşru olan verilir.
	if _, err := s.pool.Exec(ctx, `INSERT INTO device_policies (device_id, policy_id) VALUES ($1::uuid, $2::uuid)`, devB, polA); err != nil {
		t.Fatal(err)
	}
	if err := s.AddPolicyRule(ctx, polA, admin.RuleInput{Type: "APP_BLOCK_ALWAYS", Target: "x.exe"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddPolicyRule(ctx, polS, admin.RuleInput{Type: "APP_BLOCK_ALWAYS", Target: "s.exe"}); err != nil {
		t.Fatal(err)
	}
	// devB'ye hem bozuk (polA) hem meşru (polS) bağlı: yalnız polS kuralı gelmeli.
	b, err := s.CurrentPolicy(ctx, devB)
	if err != nil || b == nil {
		t.Fatalf("meşru (paylaşımlı) politika verilmeli: %v %v", b, err)
	}
	for _, r := range b.GetRules() {
		if r.GetTargetValue() == "x.exe" {
			t.Fatal("çapraz-kiracı politikanın kuralı ajana itilmemeli")
		}
	}
	if len(b.GetRules()) != 1 || b.GetRules()[0].GetTargetValue() != "s.exe" {
		t.Fatalf("yalnız paylaşımlı kural beklenirdi: %v", b.GetRules())
	}
}

type adminreadPolicy struct {
	tenant  string
	devices int
}

// (PG): legacy boş kiracılı cihaz ≡ 'default' kiracı — 'default' politikası atanabilir,
// gerçek kiracının politikası atanamaz.
func TestPGPolicyAssignLegacyEmptyTenantDevice(t *testing.T) {
	s, ctx := pgStore(t)
	legacy := pgDevice(ctx, t, s, "") // kiracı öncesi cihaz: tenant_id = ''
	polDefault := pgPolicy(ctx, t, s, uniq(t, "pd-"), "default")
	polOther := pgPolicy(ctx, t, s, uniq(t, "po-"), uniq(t, "tx-"))
	if err := s.AssignPolicy(ctx, legacy, polOther); !errors.Is(err, admin.ErrForbidden) {
		t.Fatalf("gerçek kiracının politikası legacy cihaza atanamaz: %v", err)
	}
	if err := s.AssignPolicy(ctx, legacy, polDefault); err != nil {
		t.Fatalf("'default' politikası legacy cihaza atanabilmeli: %v", err)
	}
}

// pgEvent, test için doğrudan event_logs'a (2099 bölümü) kiracılı bir olay yazar.
func pgEvent(ctx context.Context, t *testing.T, s *Store, deviceID, tenantID string) string {
	t.Helper()
	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS event_logs_2099_01 PARTITION OF event_logs
	    FOR VALUES FROM ('2099-01-01') TO ('2099-02-01')`); err != nil {
		t.Fatal(err)
	}
	var id string
	err := s.pool.QueryRow(ctx, `INSERT INTO event_logs (device_id, tenant_id, category, severity, message, occurred_at, created_at)
	    VALUES ($1::uuid, $2, 'SYSTEM', 'INFO', 'm', '2099-01-15', '2099-01-15') RETURNING id::text`, deviceID, tenantID).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, `DELETE FROM event_ack WHERE event_id = $1`, id)
		_, _ = s.pool.Exec(ctx, `DELETE FROM event_logs WHERE id = $1::uuid`, id)
	})
	return id
}

func ackTenantOf(ctx context.Context, t *testing.T, s *Store, eventID string) string {
	t.Helper()
	var tn string
	if err := s.pool.QueryRow(ctx, `SELECT tenant_id FROM event_ack WHERE event_id = $1`, eventID).Scan(&tn); err != nil {
		t.Fatal(err)
	}
	return tn
}

// (PG): event_ack.tenant_id artık OLAYIN kiracısıyla yazılır (ack ve vaka yolları);
// eski boş kiracı 'default'a kanonikleşir; önceki hatalı ('default') satır doğru kiracıyla onarılır;
// bulunamayan/geçersiz olay 'default' alır ve mevcut satırın kiracısını bozmaz.
func TestPGEventAckWritesEventTenant(t *testing.T) {
	s, ctx := pgStore(t)
	tA := uniq(t, "ta-")
	devA, devLegacy := pgDevice(ctx, t, s, tA), pgDevice(ctx, t, s, "")
	evA, evLegacy := pgEvent(ctx, t, s, devA, tA), pgEvent(ctx, t, s, devLegacy, "")

	// POZITIF: ack olayın kiracısını yazar (artık 'default' değil).
	if err := s.SetEventAck(ctx, evA, "", "ACKNOWLEDGED"); err != nil {
		t.Fatal(err)
	}
	if got := ackTenantOf(ctx, t, s, evA); got != tA {
		t.Fatalf("event_ack.tenant_id olayın kiracısı %q olmalı: %q", tA, got)
	}
	// Vaka yolu aynı kiracıyı korur, durumu bozmaz.
	if err := s.SetEventCase(ctx, evA, "", "analist", "not"); err != nil {
		t.Fatal(err)
	}
	var st string
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(status,'') FROM event_ack WHERE event_id = $1`, evA).Scan(&st); err != nil || st != "ACKNOWLEDGED" {
		t.Fatalf("vaka güncellemesi durumu korumalı: %q %v", st, err)
	}
	if got := ackTenantOf(ctx, t, s, evA); got != tA {
		t.Fatalf("vaka sonrası kiracı korunmalı: %q", got)
	}
	// Vaka yolu ack'siz yeni olayda da kiracıyı yazar.
	evB := pgEvent(ctx, t, s, devA, tA)
	if err := s.SetEventCase(ctx, evB, "", "a", "n"); err != nil {
		t.Fatal(err)
	}
	if got := ackTenantOf(ctx, t, s, evB); got != tA {
		t.Fatalf("SetEventCase olay kiracısını yazmalı: %q", got)
	}

	// Legacy boş kiracılı olay → kanonik 'default'.
	if err := s.SetEventAck(ctx, evLegacy, "", "RESOLVED"); err != nil {
		t.Fatal(err)
	}
	if got := ackTenantOf(ctx, t, s, evLegacy); got != "default" {
		t.Fatalf("legacy olay 'default' olmalı: %q", got)
	}

	// Önceki hatayı onar: yanlış ('default') yazılmış satır, yeniden ack'te olayın kiracısına döner.
	evC := pgEvent(ctx, t, s, devA, tA)
	if _, err := s.pool.Exec(ctx, `INSERT INTO event_ack (event_id, tenant_id, status) VALUES ($1, 'default', 'ACKNOWLEDGED')`, evC); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEventAck(ctx, evC, "", "RESOLVED"); err != nil {
		t.Fatal(err)
	}
	if got := ackTenantOf(ctx, t, s, evC); got != tA {
		t.Fatalf("hatalı satır olayın kiracısıyla onarılmalı: %q", got)
	}

	// NEGATIF: bulunamayan / geçersiz olay → 'default'; mevcut satırın kiracısı bozulmaz.
	ghost := "00000000-0000-0000-0000-0000000000aa"
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM event_ack WHERE event_id IN ($1, 'not-a-uuid')`, ghost) })
	for _, id := range []string{ghost, "not-a-uuid"} {
		if err := s.SetEventAck(ctx, id, "", "ACKNOWLEDGED"); err != nil {
			t.Fatalf("bilinmeyen olay hata vermemeli (%q): %v", id, err)
		}
		if got := ackTenantOf(ctx, t, s, id); got != "default" {
			t.Fatalf("bilinmeyen olay 'default' almalı (%q): %q", id, got)
		}
	}
	if _, err := s.pool.Exec(ctx, `UPDATE event_ack SET tenant_id = $2 WHERE event_id = $1`, ghost, tA); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEventAck(ctx, ghost, "", "RESOLVED"); err != nil {
		t.Fatal(err)
	}
	if got := ackTenantOf(ctx, t, s, ghost); got != tA {
		t.Fatalf("olay bulunamayınca mevcut satırın kiracısı korunmalı: %q", got)
	}
}

// (PG): incidents.tenant_id cihazın kiracısıyla yazılır; legacy boş kiracı, cihazsız
// incident ve bilinmeyen cihaz 'default'.
func TestPGOpenIncidentWritesDeviceTenant(t *testing.T) {
	s, ctx := pgStore(t)
	tA := uniq(t, "ta-")
	devA, devLegacy := pgDevice(ctx, t, s, tA), pgDevice(ctx, t, s, "")
	tenantOf := func(id string) string {
		t.Helper()
		var tn string
		if err := s.pool.QueryRow(ctx, `SELECT tenant_id FROM incidents WHERE id = $1::uuid`, id).Scan(&tn); err != nil {
			t.Fatal(err)
		}
		return tn
	}
	open := func(dev string) string {
		t.Helper()
		id, err := s.OpenIncident(ctx, dev, uniq(t, "k-"), "R1", "T1059", "HIGH", "msg", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM incidents WHERE id = $1::uuid`, id) })
		return id
	}
	if got := tenantOf(open(devA)); got != tA {
		t.Fatalf("incident cihazın kiracısını yazmalı: %q", got)
	}
	if got := tenantOf(open(devLegacy)); got != "default" {
		t.Fatalf("legacy cihaz incident'i 'default' olmalı: %q", got)
	}
	if got := tenantOf(open("")); got != "default" {
		t.Fatalf("cihazsız incident 'default' olmalı: %q", got)
	}
	// Okuma yolu (device→tenant join) hâlâ kiracıyı doğru süzer.
	rows, err := s.ListIncidents(ctx, 100, tA)
	if err != nil || len(rows) == 0 {
		t.Fatalf("A kendi incident'ini görmeli: %v %v", rows, err)
	}
	for _, r := range rows {
		if r.DeviceID != devA {
			t.Fatalf("A başka cihazın incident'ini görmemeli: %+v", r)
		}
	}
}
