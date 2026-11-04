package db

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/adminapi"
	"kut.corp/suite/server/internal/evidence"
	"kut.corp/suite/server/internal/security"
	"kut.corp/suite/server/internal/tenant"
)

// Derleme-zamanı arayüz kontrolleri.
var (
	_ admin.Store        = (*Store)(nil)
	_ adminapi.AuthStore = (*Store)(nil)
)

// LookupAdmin, e-postadan yönetici id'si ve parola hash'ini çözer (adminapi auth).
func (s *Store) LookupAdmin(ctx context.Context, email string) (string, string, error) {
	const q = `SELECT id::text, COALESCE(password_hash, '') FROM admins WHERE email = $1 AND is_active`
	var id, hash string
	err := s.pool.QueryRow(ctx, q, email).Scan(&id, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("db: admin arama: %w", err)
	}
	return id, hash, nil
}

// AdminRole, yöneticinin rolünü döner. Bilinmeyen/pasif admin için boş rol
// (yetkisiz) döner.
func (s *Store) AdminRole(ctx context.Context, adminID string) (admin.Role, error) {
	const q = `SELECT role FROM admins WHERE id = $1 AND is_active`
	var r string
	err := s.pool.QueryRow(ctx, q, adminID).Scan(&r)
	if errors.Is(err, pgx.ErrNoRows) {
		return admin.Role(""), nil
	}
	if err != nil {
		return "", fmt.Errorf("db: admin rolü: %w", err)
	}
	return admin.Role(r), nil
}

// SaveEnrollmentToken, admin tarafından üretilen token'ın HMAC indeksini saklar.
func (s *Store) SaveEnrollmentToken(ctx context.Context, tokenIndex []byte, createdBy, tenantID string, expiresAt time.Time) error {
	const q = `
		INSERT INTO enrollment_tokens (token_hash, created_by, tenant_id, expires_at)
		VALUES ($1, NULLIF($2,'')::uuid, $3, $4)`
	_, err := s.pool.Exec(ctx, q, tokenIndex, createdBy, tenantID, expiresAt)
	if err != nil {
		return fmt.Errorf("db: enrollment token kaydı: %w", err)
	}
	return nil
}

// WriteAudit, değişmez denetim izine bir satır yazar.
// SaveArtifact, toplanan bir dosya artefaktını saklar ve id'sini döner
// (grpc.ArtifactSink; adli/IR). command_id boşsa NULL yazılır.
func (s *Store) SaveArtifact(ctx context.Context, deviceID, commandID, path, sha256 string, content []byte) (string, error) {
	const q = `
		INSERT INTO artifacts (device_id, command_id, path, sha256, size_bytes, content)
		VALUES ($1::uuid, NULLIF($2,'')::uuid, $3, $4, $5, $6)
		RETURNING id::text`
	var id string
	if err := s.pool.QueryRow(ctx, q, deviceID, commandID, path, sha256, len(content), content).Scan(&id); err != nil {
		return "", fmt.Errorf("db: artefakt kaydı: %w", err)
	}
	return id, nil
}

// AppendCustody, delil gözetim zincirine EKLE-YALNIZ bir kayıt yazar. PRIMARY
// KEY(evidence_id, seq) çatallanmayı engeller: eşzamanlı ikinci ekleme aynı seq ile
// çakışır ve hata döner (çağıran zinciri yeniden okuyup tekrar deneyebilir).
func (s *Store) AppendCustody(ctx context.Context, evidenceID string, e evidence.CustodyEntry) error {
	const q = `
		INSERT INTO evidence_custody (evidence_id, seq, actor, action, at, prev_hash, hash)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)`
	if _, err := s.pool.Exec(ctx, q, evidenceID, e.Seq, e.Actor, e.Action, e.At, e.PrevHash, e.Hash); err != nil {
		return fmt.Errorf("db: gözetim ekleme: %w", err)
	}
	return nil
}

// SetEventAck, bir olayın triyaj durumunu ayarlar (olay başına upsert). Alarm
// yaşam-döngüsü (ACKNOWLEDGED/RESOLVED).
// EventTenant, bir olayın (event_logs.id) kiracısını döner (triyaj yazma-yolu kiracı
// kapısı). Olay yoksa veya id geçerli uuid değilse boş döner (kiracıya bağlı admin için
// fail-closed → reddedilir; platform admini zaten muaf).
func (s *Store) EventTenant(ctx context.Context, eventID string) (string, error) {
	var tenant string
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(tenant_id,'') FROM event_logs WHERE id = $1::uuid`, eventID).Scan(&tenant)
	if err != nil {
		return "", nil // bulunamadı / geçersiz id → boş (fail-closed)
	}
	return tenant, nil
}

// ackTenant, olayın (event_logs.id) kiracısını KANONİK biçimde ve bulunup bulunmadığıyla
// döner: bulunamazsa ("", false). Kiracı SUNUCU-TARAFI olaydan okunur, çağıranın girdisinden
// DEĞİL. Eski (kiracı öncesi) olayların boş kiracısı tenant.Canonical ile 'default'a çevrilir
// (event_ack/incidents'in şema varsayılanıyla aynı temsil).
func (s *Store) ackTenant(ctx context.Context, eventID string) (string, bool) {
	if !validUUID(eventID) {
		return "", false
	}
	var tn string
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(tenant_id,'') FROM event_logs WHERE id = $1::uuid LIMIT 1`, eventID).Scan(&tn)
	if err != nil {
		return "", false
	}
	return tenant.Canonical(tn), true
}

// SetEventAck, olayın triyaj durumunu yazar. event_ack.tenant_id artık OLAYIN
// kiracısıyla yazılır (önceden her satır şema varsayılanı 'default' alıyordu). Olay
// bulunamazsa (ör. bölümü silinmiş) mevcut satırın kiracısı korunur, yeni satır 'default' alır.
func (s *Store) SetEventAck(ctx context.Context, eventID, adminID, status string) error {
	tn, _ := s.ackTenant(ctx, eventID) // bulunamazsa "" → aşağıda mevcut korunur / default
	const q = `
		INSERT INTO event_ack (event_id, tenant_id, status, admin_id, updated_at)
		VALUES ($1, COALESCE(NULLIF($4,''),'default'), $2, NULLIF($3,'')::uuid, now())
		ON CONFLICT (event_id) DO UPDATE
		   SET status = EXCLUDED.status, admin_id = EXCLUDED.admin_id, updated_at = now(),
		       tenant_id = COALESCE(NULLIF($4,''), event_ack.tenant_id)`
	if _, err := s.pool.Exec(ctx, q, eventID, status, adminID, tn); err != nil {
		return fmt.Errorf("db: olay triyaj durumu: %w", err)
	}
	return nil
}

// SetEventCase, olayın sorumlu+not alanlarını ayarlar (durumu korur; upsert). Kiracı
// SetEventAck ile aynı kuralla olaydan yazılır.
func (s *Store) SetEventCase(ctx context.Context, eventID, adminID, assignee, note string) error {
	tn, _ := s.ackTenant(ctx, eventID)
	const q = `
		INSERT INTO event_ack (event_id, tenant_id, assignee, note, admin_id, updated_at)
		VALUES ($1, COALESCE(NULLIF($5,''),'default'), NULLIF($2,''), NULLIF($3,''), NULLIF($4,'')::uuid, now())
		ON CONFLICT (event_id) DO UPDATE
		   SET assignee = NULLIF($2,''), note = NULLIF($3,''), admin_id = EXCLUDED.admin_id, updated_at = now(),
		       tenant_id = COALESCE(NULLIF($5,''), event_ack.tenant_id)`
	if _, err := s.pool.Exec(ctx, q, eventID, assignee, note, adminID, tn); err != nil {
		return fmt.Errorf("db: olay vaka güncelleme: %w", err)
	}
	return nil
}

// OpenIncident, yeni bir korelasyon incident'i açar (correlate.IncidentSink).
// incidents.tenant_id artık CİHAZIN kiracısıyla yazılır (sunucu-tarafı alt-sorgu; eski
// cihazın boş kiracısı, cihazsız incident ve bulunamayan cihaz 'default' — tenant.Canonical
// ile aynı temsil). Okuma yolu hâlâ device→tenant join kullanır; sütun RLS/rapor içindir.
func (s *Store) OpenIncident(ctx context.Context, deviceID, key, ruleID, technique, severity, message string, at time.Time) (string, error) {
	const q = `
		INSERT INTO incidents (device_id, tenant_id, corr_key, rule_id, technique, severity, sample_msg, first_seen, last_seen)
		VALUES (NULLIF($1,'')::uuid,
		        COALESCE(NULLIF((SELECT d.tenant_id FROM devices d WHERE d.id = NULLIF($1,'')::uuid), ''), 'default'),
		        $2, NULLIF($3,''), NULLIF($4,''), NULLIF($5,''), $6, $7, $7)
		RETURNING id::text`
	var id string
	if err := s.pool.QueryRow(ctx, q, deviceID, key, ruleID, technique, severity, message, at).Scan(&id); err != nil {
		return "", fmt.Errorf("db: incident aç: %w", err)
	}
	return id, nil
}

// BumpIncident, mevcut incident'in sayaç/son-görülme değerini günceller.
func (s *Store) BumpIncident(ctx context.Context, id string, at time.Time) error {
	if _, err := s.pool.Exec(ctx, `UPDATE incidents SET count = count + 1, last_seen = $2 WHERE id = $1::uuid`, id, at); err != nil {
		return fmt.Errorf("db: incident güncelle: %w", err)
	}
	return nil
}

// SavePendingWipe, ikinci-onay bekleyen WIPE talebini saklar (çift-kontrol; upsert).
func (s *Store) SavePendingWipe(ctx context.Context, deviceID, requestedBy, reason string) error {
	const q = `
		INSERT INTO pending_wipes (device_id, requested_by, reason, requested_at)
		VALUES ($1::uuid, $2::uuid, NULLIF($3,''), now())
		ON CONFLICT (device_id) DO UPDATE
		   SET requested_by = EXCLUDED.requested_by, reason = EXCLUDED.reason, requested_at = now()`
	if _, err := s.pool.Exec(ctx, q, deviceID, requestedBy, reason); err != nil {
		return fmt.Errorf("db: bekleyen wipe kaydı: %w", err)
	}
	return nil
}

// GetPendingWipe, cihaz için bekleyen WIPE talebini (talep eden admin id'si) döner.
func (s *Store) GetPendingWipe(ctx context.Context, deviceID string) (string, bool, error) {
	var rb string
	err := s.pool.QueryRow(ctx, `SELECT requested_by::text FROM pending_wipes WHERE device_id = $1::uuid`, deviceID).Scan(&rb)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("db: bekleyen wipe okuma: %w", err)
	}
	return rb, true, nil
}

// DeletePendingWipe, bekleyen WIPE talebini siler (onay/iptal sonrası; yoksa no-op).
func (s *Store) DeletePendingWipe(ctx context.Context, deviceID string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM pending_wipes WHERE device_id = $1::uuid`, deviceID); err != nil {
		return fmt.Errorf("db: bekleyen wipe silme: %w", err)
	}
	return nil
}

// ConsumePendingWipe, bekleyen WIPE talebini ATOMİK claim eder. Tek deyimli
// `DELETE ... WHERE requested_by <> approver RETURNING` claim'dir: iki eşzamanlı
// onaylayandan yalnız biri satırı siler/döndürür (diğeri ErrNoRows alır → çift-enqueue
// yok). Silinmezse takip SELECT'i "talep yok" ile "self-approval"ı ayırır (bu ayrım
// yarış-kritik değildir; claim zaten başarısız olmuştur).
func (s *Store) ConsumePendingWipe(ctx context.Context, deviceID, approverID string) (string, bool, error) {
	var rb string
	err := s.pool.QueryRow(ctx,
		`DELETE FROM pending_wipes WHERE device_id = $1::uuid AND requested_by <> $2::uuid RETURNING requested_by::text`,
		deviceID, approverID).Scan(&rb)
	if err == nil {
		return rb, true, nil // atomik claim başarılı
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", false, fmt.Errorf("db: bekleyen wipe consume: %w", err)
	}
	// Silinmedi: talep yok ya da requested_by == approver (self-approval). Ayırt et.
	var existing string
	e2 := s.pool.QueryRow(ctx, `SELECT requested_by::text FROM pending_wipes WHERE device_id = $1::uuid`, deviceID).Scan(&existing)
	if errors.Is(e2, pgx.ErrNoRows) {
		return "", false, nil // talep yok (ya da başka onaylayan tüketti)
	}
	if e2 != nil {
		return "", false, fmt.Errorf("db: bekleyen wipe consume kontrol: %w", e2)
	}
	return existing, false, nil // self-approval (silme yok)
}

// auditChainLockKey, denetim hash-zinciri yazımlarını serileştiren advisory-lock anahtarıdır
// (sabit, keyfi). READ COMMITTED altında iki eşzamanlı yazım aynı prev_hash'i okuyup zinciri
// ÇATALLAYABİLİR; bu kilit okuma-değiştirme-yazma'yı sıralar.
const auditChainLockKey int64 = 0x4155_4449_54 // "AUDIT"

func (s *Store) WriteAudit(ctx context.Context, adminID, action, targetType, targetID string) error {
	// Kurcalama-kanıtı hash zinciri: önceki entry_hash okunur, yeni hash
	// hesaplanır ve prev_hash+entry_hash+created_at ile eklenir — hepsi tek transaction'da.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("db: denetim tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Zincir RMW'sini serileştir (aksi halde eşzamanlı yazımlar çatallanır — yanlış
	// "tampered" alarmı). Transaction-ömürlü kilit commit/rollback'te otomatik bırakılır.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditChainLockKey); err != nil {
		return fmt.Errorf("db: denetim zinciri kilidi: %w", err)
	}

	var tenantID string
	if adminID != "" {
		_ = tx.QueryRow(ctx, `SELECT tenant_id FROM admins WHERE id = $1`, adminID).Scan(&tenantID)
	}

	var prev []byte
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("db: son denetim hash: %w", err)
	}
	now := time.Now().Truncate(time.Microsecond)
	hash := security.AuditChainHash(prev, tenantID, adminID, action, targetType, targetID, now.UnixNano())

	const q = `
		INSERT INTO audit_log (admin_id, tenant_id, action, target_type, target_id, created_at, prev_hash, entry_hash)
		VALUES (NULLIF($1,'')::uuid, $2, $3, NULLIF($4,''), NULLIF($5,'')::uuid, $6, $7, $8)`
	if _, err := tx.Exec(ctx, q, adminID, tenantID, action, targetType, targetID, now, prev, hash); err != nil {
		return fmt.Errorf("db: denetim izi: %w", err)
	}
	return tx.Commit(ctx)
}

// VerifyAuditChain, audit_log hash zincirinin bütünlüğünü doğrular.
// Kayıtları id sırasıyla okur ve her entry_hash'i yeniden hesaplayıp karşılaştırır.
func (s *Store) VerifyAuditChain(ctx context.Context) error {
	rows, err := s.pool.Query(ctx,
		`SELECT id, COALESCE(admin_id::text,''), tenant_id, action, COALESCE(target_type,''),
		        COALESCE(target_id::text,''), created_at, entry_hash
		   FROM audit_log ORDER BY id`)
	if err != nil {
		return fmt.Errorf("db: denetim zinciri okuma: %w", err)
	}
	defer rows.Close()

	var prev []byte
	for rows.Next() {
		var id int64
		var adminID, tenantID, action, targetType, targetID string
		var createdAt time.Time
		var stored []byte
		if err := rows.Scan(&id, &adminID, &tenantID, &action, &targetType, &targetID, &createdAt, &stored); err != nil {
			return fmt.Errorf("db: denetim satırı: %w", err)
		}
		want := security.AuditChainHash(prev, tenantID, adminID, action, targetType, targetID, createdAt.UnixNano())
		if !bytes.Equal(want, stored) {
			return fmt.Errorf("db: denetim izi zinciri kırık: kayıt id=%d", id)
		}
		prev = stored
	}
	return rows.Err()
}

// CreatePolicy, yeni bir politika oluşturur ve id'sini döner. tenantID politikanın sahibi
// kiracıdır ("" = platform/paylaşımlı).
func (s *Store) CreatePolicy(ctx context.Context, name, version, tenantID string) (string, error) {
	const q = `INSERT INTO policies (name, version, tenant_id) VALUES ($1, $2, $3) RETURNING id::text`
	var id string
	if err := s.pool.QueryRow(ctx, q, name, version, tenantID).Scan(&id); err != nil {
		return "", fmt.Errorf("db: politika oluşturma: %w", err)
	}
	return id, nil
}

// AssignPolicy, bir politikayı cihaza atar (idempotent). Derinlemesine savunma: atama
// SQL'i de politikanın platform/paylaşımlı ya da CİHAZIN kiracısına ait olmasını şart koşar;
// aksi halde (ya da cihaz/politika yoksa) satır eklenmez ve ErrForbidden döner — servis
// katmanı hatası bir kiracının politikasını başka kiracının cihazına bağlayamaz.
func (s *Store) AssignPolicy(ctx context.Context, deviceID, policyID string) error {
	if !validUUID(deviceID) || !validUUID(policyID) {
		return admin.ErrForbidden
	}
	const q = `
		INSERT INTO device_policies (device_id, policy_id)
		SELECT d.id, p.id
		  FROM devices d, policies p
		 WHERE d.id = $1::uuid AND p.id = $2::uuid
		   AND (p.tenant_id = '' OR p.tenant_id = COALESCE(NULLIF(d.tenant_id, ''), 'default'))
		ON CONFLICT (device_id, policy_id) DO UPDATE SET policy_id = EXCLUDED.policy_id`
	ct, err := s.pool.Exec(ctx, q, deviceID, policyID)
	if err != nil {
		return fmt.Errorf("db: politika atama: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return admin.ErrForbidden
	}
	return nil
}
