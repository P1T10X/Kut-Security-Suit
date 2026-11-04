-- +goose Up
-- =============================================================================
-- KUT Security Suite — PostgreSQL Şeması (düzeltilmiş)
-- =============================================================================
-- Sürümlü yol: db/postgres/migrations/00001_baseline.sql bu dosyanın goose notasyonlu
-- eşdeğeridir (aynı ifadeler); yeni şema değişiklikleri yalnız migrasyon olarak eklenir.
-- =============================================================================
-- İnceleme bulgularına göre orijinal taslaktan farklar:
--   #1  Eksik `policies` tablosu eklendi; kırık FK düzeltildi.
--   #1  event_logs artık ZAMAN-BAZLI PARTITIONING kullanır ve sorgulanabilir
--       kalması için mesaj/detay alanları düz metin/JSONB'dir. Gizlilik
--       AT-REST şifreleme (TDE / şifreli disk / pgcrypto ile SEÇİLİ alanlar)
--       ile sağlanır — her logu BYTEA'ya şifreleyip aranamaz hale getirmek yerine.
--   #2  Blind index'ler düz SHA-256 değil, HMAC (keyed) üretilmelidir.
--       Uygulama katmanı, sunucudaki gizli anahtarla HMAC-SHA256 hesaplar.
--   #6  enrollment_tokens, agent_certificates tabloları (PKI bootstrap).
--   #4  ota_releases: imza alanı (yalnız hash değil).
--   #10 admins (RBAC) + audit_log (yönetici aksiyon denetim izi).
--   common: device_status'a PENDING_ENROLLMENT eklendi.
--
-- NOT (gizlilik): Bu şema, gerçekten hassas serbest-metin alanlarını (hostname,
-- mac, os_info) pgcrypto ile ŞİFRELİ (BYTEA) saklar ve arama için AYRI bir HMAC
-- blind-index sütunu tutar. Yüksek hacimli event_logs ise sorgulanabilirlik için
-- şifrelenmez; onun gizliliği disk/tablespace düzeyi at-rest şifreleme ile korunur.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- ENUM TİPLERİ
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
DO $$
BEGIN
    CREATE TYPE device_status AS ENUM (
    'PENDING_ENROLLMENT', 'ACTIVE', 'OFFLINE', 'QUARANTINE_PENDING', 'QUARANTINED', 'UNINSTALLED'
);
EXCEPTION WHEN duplicate_object THEN NULL;
END
$$;
-- +goose StatementEnd
-- QUARANTINE_PENDING: karantina komutu kuyruğa alındı (DESIRED) ama cihaz henüz gerçek
-- izolasyonu ONAYLAMADI. Effective 'QUARANTINED', yalnız ajan komut SUCCESS bildirince
-- verilir (desired≠effective). Mevcut DB'ye ekleme: ALTER TYPE device_status
-- ADD VALUE IF NOT EXISTS 'QUARANTINE_PENDING' BEFORE 'QUARANTINED';

-- +goose StatementBegin
DO $$
BEGIN
    CREATE TYPE event_category AS ENUM (
    'SYSTEM', 'SECURITY', 'NETWORK_DISCOVERY', 'POLICY_VIOLATION', 'AGENT_UPDATE', 'PROCESS', 'NETWORK_CONN'
);
EXCEPTION WHEN duplicate_object THEN NULL;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
BEGIN
    CREATE TYPE severity AS ENUM (
    'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
);
EXCEPTION WHEN duplicate_object THEN NULL;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
BEGIN
    CREATE TYPE admin_role AS ENUM ('VIEWER', 'OPERATOR', 'ADMIN');
EXCEPTION WHEN duplicate_object THEN NULL;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
BEGIN
    CREATE TYPE command_type AS ENUM (
    'QUARANTINE', 'UNQUARANTINE', 'RUN_SIGNED_SCRIPT', 'UNINSTALL', 'COLLECT_DIAGNOSTICS', 'COLLECT_FILE',
    'LOCK', 'RESTART', 'WIPE'
);
EXCEPTION WHEN duplicate_object THEN NULL;
END
$$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- CİHAZLAR
--   * Hassas serbest-metin alanları pgcrypto ile şifreli (BYTEA).
--   * *_bidx sütunları HMAC(keyed) blind index'tir — düz SHA-256 DEĞİL (#2).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS devices (
    id                     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname_encrypted     BYTEA NOT NULL,
    mac_address_encrypted  BYTEA NOT NULL,
    os_info_encrypted      BYTEA,
    -- HMAC-SHA256(sunucu_gizli_anahtarı, normalize_edilmiş_mac). MAC uzayı ~48 bit
    -- olduğundan DÜZ hash offline brute-force'a açıktır; keyed HMAC şarttır.
    mac_address_bidx       BYTEA NOT NULL,            -- tekillik KİRACI BAŞINA: bkz. uq_devices_tenant_mac (Kiracı Duvarı II)
    agent_version          VARCHAR(50),
    os_platform            VARCHAR(20),               -- "windows" | "linux"
    os_version             VARCHAR(120),              -- okunabilir OS sürümü (filo envanteri)
    agent_binary_hash      CHAR(64),                  -- ajan ikilisinin SHA-256'sı (öz-tasdik, #4)
    agent_binary_version   VARCHAR(50),               -- yukarıdaki hash'in ait olduğu sürüm (kurcalama teşhisi)
    status                 device_status NOT NULL DEFAULT 'PENDING_ENROLLMENT',
    tenant_id              VARCHAR(63) NOT NULL DEFAULT '',  -- çok-tenant: cihazın kiracısı (enrollment token'dan bağlanır; boş = tek-tenant)
    current_policy_version VARCHAR(64),
    tags                   TEXT[] NOT NULL DEFAULT '{}',   -- filo gruplama/etiketleme
    last_seen              TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_devices_status    ON devices (status);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices (last_seen);

-- ---------------------------------------------------------------------------
-- PKI / ENROLLMENT (#6 bootstrap)
-- ---------------------------------------------------------------------------
-- Tek kullanımlık, süreli kayıt token'ları. token_hash = HMAC(token) saklanır,
-- ham token asla DB'de tutulmaz.
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash  BYTEA NOT NULL UNIQUE,
    created_by  UUID,                       -- admins.id (aşağıda FK)
    tenant_id   VARCHAR(63) NOT NULL DEFAULT '',  -- çok-tenant: bu token'la kaydolan cihazın kiracısı
    device_id   UUID REFERENCES devices(id) ON DELETE SET NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,                -- NULL => henüz kullanılmadı
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_enroll_tokens_expiry ON enrollment_tokens (expires_at)
    WHERE used_at IS NULL;

-- İmzalanmış istemci sertifikaları ve iptal durumu (mTLS + revocation).
CREATE TABLE IF NOT EXISTS agent_certificates (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    serial_number NUMERIC NOT NULL UNIQUE,   -- X.509 seri no
    fingerprint   BYTEA NOT NULL UNIQUE,     -- SHA-256(DER)
    not_before    TIMESTAMPTZ NOT NULL,
    not_after     TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,               -- NULL => geçerli
    revoke_reason VARCHAR(100),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_certs_device ON agent_certificates (device_id);
CREATE INDEX IF NOT EXISTS idx_agent_certs_active ON agent_certificates (device_id)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- POLİTİKALAR (#1 — eksik tablo eklendi)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policies (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(150) NOT NULL,
    description TEXT,
    version     VARCHAR(64) NOT NULL,        -- ajana itilen sürüm etiketi
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    tenant_id   VARCHAR(63) NOT NULL DEFAULT '',  -- çok-tenant: politikanın sahibi kiracı; boş = platform/paylaşımlı (kiracıya bağlı admin için salt-okunur)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id    UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    type         VARCHAR(50) NOT NULL,       -- APP_TIME_BLOCK | APP_BLOCK_ALWAYS | NETWORK_RULE
    target_value VARCHAR(255) NOT NULL,
    start_time   TIME,                       -- APP_TIME_BLOCK için gerekli
    end_time     TIME,
    active_days  INT[] NOT NULL DEFAULT '{1,2,3,4,5,6,0}',  -- 0=Pazar
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_policy_rules_policy ON policy_rules (policy_id);

-- Hangi cihaz(lar)a hangi politika atanmış (grup yerine önce doğrudan atama).
CREATE TABLE IF NOT EXISTS device_policies (
    device_id  UUID NOT NULL REFERENCES devices(id)  ON DELETE CASCADE,
    policy_id  UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    PRIMARY KEY (device_id, policy_id)
);

-- ---------------------------------------------------------------------------
-- OTA SÜRÜMLERİ (#4 — imza, yalnız hash değil)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ota_releases (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    version         VARCHAR(50) NOT NULL UNIQUE,
    os_platform     VARCHAR(20) NOT NULL,     -- "windows" | "linux"
    download_url    TEXT NOT NULL,
    sha256_hex      VARCHAR(64) NOT NULL,     -- bütünlük
    signature       BYTEA NOT NULL,           -- Ed25519/Authenticode imzası (kimlik)
    mandatory       BOOLEAN NOT NULL DEFAULT FALSE,
    rollout_percent INT NOT NULL DEFAULT 100 CHECK (rollout_percent BETWEEN 0 AND 100),
    published_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- OLAY LOGLARI (#1 — partitioned, sorgulanabilir)
--   Gizlilik at-rest şifreleme ile; içerik JSONB olarak sorgulanabilir kalır.
--   PostgreSQL 12+ native RANGE partitioning (created_at üzerinde).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event_logs (
    id          UUID NOT NULL DEFAULT uuid_generate_v4(),
    device_id   UUID NOT NULL,               -- FK partition'lı tabloda pratik
                                             -- nedenlerle uygulama katmanında doğrulanır
    tenant_id   VARCHAR(63) NOT NULL DEFAULT '',  -- çok-tenant: olayın kiracısı (server-side; cihazdan)
    category    event_category NOT NULL,
    severity    severity NOT NULL DEFAULT 'INFO',
    message     TEXT NOT NULL,
    details     JSONB,
    occurred_at TIMESTAMPTZ NOT NULL,        -- ajanın gözlemlediği an
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),  -- sunucuya ulaşma anı
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Sorgu erişim desenleri için indeksler (partition'lara miras kalır).
CREATE INDEX IF NOT EXISTS idx_event_logs_device   ON event_logs (device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_event_logs_category ON event_logs (category, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_event_logs_severity ON event_logs (severity, created_at DESC)
    WHERE severity IN ('HIGH', 'CRITICAL');
CREATE INDEX IF NOT EXISTS idx_event_logs_details  ON event_logs USING GIN (details);

-- Örnek başlangıç partition'ları. Üretimde pg_partman veya cron ile otomatik
-- oluşturulmalı ve saklama süresi (KVKK #11) ile eski partition'lar DROP edilmeli.
CREATE TABLE IF NOT EXISTS event_logs_2026_08 PARTITION OF event_logs
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS event_logs_2026_09 PARTITION OF event_logs
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

-- Olay triyaj durumu (alarm yaşam-döngüsü): yüksek-önem olayları SOC analisti
-- ACKNOWLEDGED (inceleniyor) veya RESOLVED (kapatıldı) olarak işaretler. event_id
-- olayın kimliğidir (partition'lı event_logs'a FK pratik değil — bkz. device_id
-- notu). Olay başına tek durum (upsert). Denetim izi ayrıca WriteAudit ile tutulur.
-- Not: admin_id'de FK yok (admins tablosu bu noktadan sonra tanımlı; ayrıca
-- device_id gibi uygulama katmanında doğrulanır). Kim işaretledi bilgisi
-- denetim iziyle (WriteAudit) sağlam tutulur; buradaki admin_id yalnız görüntü.
-- status nullable: bir olay yalnız atanabilir/notlanabilir (henüz ack'lenmeden) —
-- vaka yönetimi (#9). assignee: sorumlu analist; note: serbest triyaj notu.
CREATE TABLE IF NOT EXISTS event_ack (
    event_id   TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL DEFAULT 'default', -- KİRACI kapsamı (çok-kiracılı izolasyon)
    status     TEXT CHECK (status IS NULL OR status IN ('ACKNOWLEDGED', 'RESOLVED')),
    assignee   TEXT,
    note       TEXT,
    admin_id   UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_event_ack_tenant ON event_ack (tenant_id);

-- ---------------------------------------------------------------------------
-- AĞ KEŞFİ (Network Discovery)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS discovered_hosts (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    reporter_device  UUID REFERENCES devices(id) ON DELETE SET NULL,
    mac_bidx         BYTEA NOT NULL,          -- HMAC blind index (#2)
    mac_encrypted    BYTEA NOT NULL,
    ip_encrypted     BYTEA,
    vendor           VARCHAR(120),            -- OUI'den türetilmiş üretici (hassas değil)
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_authorized    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_discovered_mac ON discovered_hosts (mac_bidx);

-- ---------------------------------------------------------------------------
-- CİHAZ KOMUT KUYRUĞU
--   Admin'in ürettiği anlık komutlar (karantina vb.) burada bekler; heartbeat
--   ile ajana teslim edilir ve delivered_at işaretlenir (en-fazla-bir-kez).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS device_commands (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    type          command_type NOT NULL,
    params        JSONB,
    issued_by     UUID,                       -- admins.id (FK aşağıda bağlanır)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at  TIMESTAMPTZ,                -- son teslim anı (NULL => hiç teslim edilmedi)
    -- EN-AZ-BİR-KEZ teslim (§reliability): ajan komutu YÜRÜTÜP heartbeat'te
    -- acked_command_ids ile onaylayana dek komut "tamamlanmamış" sayılır. acked_at
    -- NULL iken kira (lease) süresi geçmişse komut YENİDEN teslim edilir (ajan çökse
    -- de kaybolmaz). Ajan-tarafı idempotency çift-yürütmeyi önler. attempt_count üst
    -- sınırı aşınca vazgeçilir (sonsuz yeniden-teslim yok).
    acked_at      TIMESTAMPTZ,                -- ajan yürütmeyi onayladı (NULL => beklemede)
    attempt_count INT NOT NULL DEFAULT 0      -- teslim denemesi sayısı
);
-- Bekleyen = hiç teslim edilmemiş VEYA onaylanmamış+kirası dolmuş (redelivery).
CREATE INDEX IF NOT EXISTS idx_device_commands_pending ON device_commands (device_id, created_at)
    WHERE acked_at IS NULL;

-- Adli/IR dosya toplama artefaktları: COLLECT_FILE komutuyla ajandan yüklenen
-- dosya içeriği (boyut-sınırlı, uygulama katmanında). content ham baytlar;
-- hassas olabileceğinden erişim RBAC + denetim iziyle korunur.
CREATE TABLE IF NOT EXISTS artifacts (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    command_id   UUID,
    path         TEXT NOT NULL,
    sha256       CHAR(64) NOT NULL,
    size_bytes   INTEGER NOT NULL,
    content      BYTEA NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_artifacts_device ON artifacts (device_id, collected_at DESC);
-- Saklama budaması (retention.PurgeArtifactsOlderThan): WHERE collected_at < cutoff.
-- Cihaz-index'in başı device_id olduğundan bu taramaya hizmet edemez; ayrı index.
CREATE INDEX IF NOT EXISTS idx_artifacts_collected ON artifacts (collected_at);

-- Delil GÖZETİM ZİNCİRİ — EKLE-YALNIZ, hash-zincirli. Genesis (seq=0, COLLECTED)
-- artefakt satırından TÜRETİLİR (saklanmaz); buraya toplama SONRASI olaylar (ACCESSED/
-- TRANSFERRED/SEALED, seq>=1) yazılır. Her kayıt bir öncekinin hash'ini (prev_hash)
-- içerir; UNIQUE(evidence_id, seq) çatallanmayı (eşzamanlı ekleme) engeller. evidence_id
-- = artefakt id (FK yerine uygulama katmanında doğrulanır; partition/silme esnekliği).
CREATE TABLE IF NOT EXISTS evidence_custody (
    evidence_id UUID NOT NULL,                  -- artefakt kimliği
    seq         INTEGER NOT NULL,               -- zincir sırası (genesis=0 türetilir; kalıcı >=1)
    actor       TEXT NOT NULL,                  -- eylemi yapan (admin e-posta/kimliği)
    action      TEXT NOT NULL CHECK (action IN ('ACCESSED','TRANSFERRED','SEALED')),
    at          TIMESTAMPTZ NOT NULL,           -- eylemin (hash'e giren) anı
    prev_hash   TEXT NOT NULL,                  -- bir önceki kaydın hash'i
    hash        TEXT NOT NULL,                  -- bu kaydın kanonik SHA-256'sı (hex)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (evidence_id, seq)
);

-- SCIM 2.0 KULLANICI SAĞLAMA (kurumsal IAM). Bir kimlik sağlayıcısı (Okta/Azure
-- AD) SCIM üzerinden kullanıcı yaşam-döngüsünü (create/replace/deactivate) yönetir.
-- Çekirdek alanlar sorgulanabilir sütunlarda; tam SCIM kaynağı `doc` JSONB'de (RFC 7643
-- tel-uyumu için esneklik). Deactivate soft-delete'tir (active=false).
CREATE TABLE IF NOT EXISTS scim_users (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id  TEXT NOT NULL DEFAULT 'default', -- KİRACI kapsamı (çok-kiracılı izolasyon)
    user_name  TEXT NOT NULL,
    external_id TEXT,
    active     BOOLEAN NOT NULL DEFAULT TRUE,
    doc        JSONB NOT NULL,                 -- tam iam.User kaynağı (SCIM)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- userName tekliği KİRACI başınadır: iki kiracı aynı userName'i kullanabilir,
    -- aynı kiracıda tekrar edemez (global çakışma engellenir).
    UNIQUE (tenant_id, user_name)
);

-- SOC VAKALARI (casemgmt): incident/case yaşam döngüsü. Tam kaynak (durum makinesi
-- + append-only zaman çizelgesi) `doc` JSONB'de; çekirdek alanlar sorgulanabilir
-- sütunlarda. id metindir (ör. "case-<incidentID>" ile incident'e bağlanır). Kiracı
-- kapsamı (tenant_id, id) bileşik anahtarıyla — id kiracılar arası yeniden kullanılabilir.
CREATE TABLE IF NOT EXISTS cases (
    id         TEXT NOT NULL,
    tenant_id  TEXT NOT NULL DEFAULT 'default',
    status     TEXT NOT NULL,
    severity   TEXT NOT NULL,
    owner      TEXT NOT NULL DEFAULT '',
    title      TEXT NOT NULL DEFAULT '',
    doc        JSONB NOT NULL,                 -- tam casemgmt.Case (timeline dahil)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_cases_tenant_created ON cases (tenant_id, created_at);

-- REMEDIATION DOĞRULAMA (verify): DETECTION→RESPONSE→VERIFICATION check'leri. Bir bulgu
-- "çözüldü" kapatılmadan önce kaynak tespit kuralı taze pencerede yeniden ölçülür. Tam
-- kaynak (factors/baseline/residual/outcome/pencere) `doc` JSONB'de; çekirdek alanlar
-- sorgulanabilir sütunlarda. Kiracı kapsamı (tenant_id, id) bileşik anahtarıyla — id
-- kiracılar arası yeniden kullanılabilir. Cluster-safe: okumalar doğrudan DB'den.
CREATE TABLE IF NOT EXISTS verify_checks (
    id         TEXT NOT NULL,
    tenant_id  TEXT NOT NULL DEFAULT 'default',
    device_id  TEXT NOT NULL DEFAULT '',
    rule_id    TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL DEFAULT '',
    outcome    TEXT NOT NULL DEFAULT 'PENDING',
    doc        JSONB NOT NULL,                 -- tam verify.Check
    opened_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_verify_tenant_opened ON verify_checks (tenant_id, opened_at);

-- YÖNETİLEN API TOKEN'LARI: metrics/ingest uçları için statik ortam token'larına
-- alternatif — oluşturma/İPTAL, SÜRE (expires_at) ve KAPSAM (scope) ile. Yalnız
-- SHA-256 özeti saklanır (düz sır yalnız oluşturmada döner). Rotation = yeni token
-- üret + eskiyi iptal et.
CREATE TABLE IF NOT EXISTS tokens (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash   TEXT NOT NULL UNIQUE,       -- sha256(hex) düz-sır özeti
    scope        TEXT NOT NULL,              -- 'metrics' | 'ingest'
    tenant_id    VARCHAR(63) NOT NULL DEFAULT '',  -- ingest token'ının bağlı kiracısı (sunucu-tarafı; '' = legacy/kiracısız)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,                -- NULL => süresiz
    revoked_at   TIMESTAMPTZ,               -- NULL => etkin
    last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_tokens_active ON tokens (scope) WHERE revoked_at IS NULL;

-- MSP MÜŞTERİLERİ (Managed Security Service Provider). Bir MSP birçok müşteriye
-- hizmet verir; her müşteri bir kiracıya (tenant) eşlenir. Deactivate soft-delete'tir.
-- Kullanım/faturalama ölçümü çalışma-zamanı sayaçlarıdır (kalıcı değil); burada yalnız
-- müşteri kaydı + müşteri-başına yapılandırma saklanır.
CREATE TABLE IF NOT EXISTS msp_customers (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name           TEXT NOT NULL,
    tenant_id      TEXT NOT NULL,
    active         BOOLEAN NOT NULL DEFAULT TRUE,
    retention_days INTEGER NOT NULL DEFAULT 30,
    plan           TEXT NOT NULL DEFAULT 'standard',
    policies       JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_msp_customers_tenant ON msp_customers (tenant_id);

-- ---------------------------------------------------------------------------
-- YÖNETİCİLER (RBAC) + DENETİM İZİ (#10)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admins (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email         VARCHAR(255) NOT NULL UNIQUE,
    display_name  VARCHAR(150),
    role          admin_role NOT NULL DEFAULT 'VIEWER',
    tenant_id     VARCHAR(63) NOT NULL DEFAULT '',  -- çok-tenant: admin'in kiracısı (okuma izolasyonu; boş = tüm kiracılar / platform admini)
    password_hash TEXT,                       -- Argon2id (uygulama katmanı)
    mfa_secret    BYTEA,                       -- AES-256-GCM ile şifreli TOTP sırrı (2FA)
    mfa_pending_secret BYTEA,                  -- yeniden kayıtta bekleyen (henüz etkin olmayan) şifreli TOTP sırrı; etkinleşene dek mfa_secret/mfa_enrolled DEĞİŞMEZ
    mfa_enrolled  BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_last_step BIGINT NOT NULL DEFAULT 0,    -- en son kabul edilen TOTP adımı (tek-kullanım/anti-replay)
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Mevcut kurulum için migrasyon: ALTER TABLE admins ADD COLUMN IF NOT EXISTS mfa_last_step BIGINT NOT NULL DEFAULT 0;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS mfa_pending_secret BYTEA;

-- FK'ları burada bağla (admins tablosu artık mevcut).
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_enroll_token_admin') THEN
        ALTER TABLE enrollment_tokens
            ADD CONSTRAINT fk_enroll_token_admin
            FOREIGN KEY (created_by) REFERENCES admins(id) ON DELETE SET NULL;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_device_command_admin') THEN
        ALTER TABLE device_commands
            ADD CONSTRAINT fk_device_command_admin
            FOREIGN KEY (issued_by) REFERENCES admins(id) ON DELETE SET NULL;
    END IF;
END
$$;
-- +goose StatementEnd

-- Kim, neyi, ne zaman yaptı — özellikle uninstall OTP üretimi gibi hassas
-- aksiyonların değiştirilemez kaydı.
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    admin_id    UUID REFERENCES admins(id) ON DELETE SET NULL,
    tenant_id   VARCHAR(63) NOT NULL DEFAULT '',
    action      VARCHAR(100) NOT NULL,       -- "ISSUE_UNINSTALL_OTP", "QUARANTINE", ...
    target_type VARCHAR(50),                 -- "device" | "policy" | ...
    target_id   UUID,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Kurcalama-kanıtı hash zinciri (SEC C-1): entry_hash =
    -- SHA-256(prev_hash || kanonik(alanlar)). Bir kaydın değiştirilmesi/silinmesi
    -- sonraki hash'leri geçersiz kılar. VerifyAuditChain ile doğrulanır.
    prev_hash   BYTEA,
    entry_hash  BYTEA
);
CREATE INDEX IF NOT EXISTS idx_audit_admin  ON audit_log (admin_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log (target_type, target_id);
-- Mevcut kurulum için migrasyon (H2): tenant_id sütunu tenant-öncesi sürümlerde
-- YOKTU; eklenmezse WriteAudit/VerifyAuditChain sorguları (SELECT ... tenant_id)
-- hata verir ve denetim yazımı fail-closed durur. DEFAULT '' ile eklenir;
-- AuditChainHash boş tenant_id'yi tenant-öncesi biçimle hash'lediğinden (bkz.
-- security/audithash.go) mevcut zincir re-hash GEREKTİRMEDEN doğrulanır.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(63) NOT NULL DEFAULT '';

-- ---------------------------------------------------------------------------
-- ÇİFT-KONTROL (DÖRT-GÖZ) BEKLEYEN WIPE TALEPLERİ
-- ---------------------------------------------------------------------------
-- WIPE geri döndürülemez olduğundan, KUT_WIPE_DUAL_CONTROL=1 iken bir ADMIN talep
-- eder ve FARKLI bir ADMIN onaylayana dek komut kuyruğa GİRMEZ. Tek ele geçirilmiş/
-- kötü-niyetli ADMIN filoyu silemez.
CREATE TABLE IF NOT EXISTS pending_wipes (
    device_id    UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    requested_by UUID NOT NULL REFERENCES admins(id),
    reason       TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- OLAY KORELASYONU (INCIDENT) — ilişkili tespitlerin gruplandığı olaylar
-- ---------------------------------------------------------------------------
-- Aynı cihaz + kural için bir zaman penceresindeki tespitler tek bir incident'e
-- katlanır (alarm-fırtınası bastırma + gruplama). count/last_seen güncellenir.
CREATE TABLE IF NOT EXISTS incidents (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id   UUID REFERENCES devices(id) ON DELETE CASCADE,
    corr_key    TEXT NOT NULL,
    rule_id     TEXT,
    technique   TEXT,
    severity    TEXT,
    sample_msg  TEXT,
    count       INTEGER NOT NULL DEFAULT 1,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    status      TEXT NOT NULL DEFAULT 'OPEN'
);
CREATE INDEX IF NOT EXISTS idx_incidents_last ON incidents (last_seen DESC);

-- Kayıtlı aramalar (SIEM): analistlerin kalıcılaştırdığı threat-hunting sorguları.
-- filter, /api/hunt isteği JSON'udur (mode + EventFilter alanları).
CREATE TABLE IF NOT EXISTS saved_searches (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    filter      JSONB NOT NULL,
    created_by  UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_saved_searches_created ON saved_searches (created_at DESC);

-- =============================================================================
-- TENANT İZOLASYONU (ROW-LEVEL SECURITY)
-- =============================================================================
-- Bu bölüm, "SEC-003: Row-Level Security (RLS) politikaları" implementasyonunu
-- içerir. Tüm tenant (kiracı) farkındalığı olan tablolarda RLS etkinleştirilerek
-- uygulama katmanındaki "WHERE tenant_id = ?" atlama hatalarına karşı derinlemesine
-- savunma (defense-in-depth) sağlanır.
-- 
-- Uygulama her transaction başlangıcında SET LOCAL app.tenant_id = '<tenant>';
-- çağırmak zorundadır.

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(63) NOT NULL DEFAULT '';

-- Bypass politikalarının hedef rolü (ADR-0002). Rol yoksa politika oluşturma
-- "role does not exist" ile şemayı yarıda keser; bu yüzden idempotent olarak
-- NOLOGIN (oturum açamaz, BYPASSRLS yok) bir rol olarak oluşturulur — yetki
-- genişletmez, yalnız politikaların başvurduğu rolü var eder.
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kut_admin') THEN
        CREATE ROLE kut_admin NOLOGIN;
    END IF;
END
$$;
-- +goose StatementEnd

-- event_logs
ALTER TABLE event_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_logs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_event_logs ON event_logs;
CREATE POLICY tenant_isolation_event_logs ON event_logs
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS superuser_bypass_event_logs ON event_logs;
CREATE POLICY superuser_bypass_event_logs ON event_logs
    TO kut_admin
    USING (true);

-- event_ack
ALTER TABLE event_ack ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_ack FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_event_ack ON event_ack;
CREATE POLICY tenant_isolation_event_ack ON event_ack
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS superuser_bypass_event_ack ON event_ack;
CREATE POLICY superuser_bypass_event_ack ON event_ack
    TO kut_admin
    USING (true);

-- scim_users
ALTER TABLE scim_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_scim_users ON scim_users;
CREATE POLICY tenant_isolation_scim_users ON scim_users
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS superuser_bypass_scim_users ON scim_users;
CREATE POLICY superuser_bypass_scim_users ON scim_users
    TO kut_admin
    USING (true);

-- cases
ALTER TABLE cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE cases FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_cases ON cases;
CREATE POLICY tenant_isolation_cases ON cases
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS superuser_bypass_cases ON cases;
CREATE POLICY superuser_bypass_cases ON cases
    TO kut_admin
    USING (true);

-- verify_checks
ALTER TABLE verify_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE verify_checks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_verify_checks ON verify_checks;
CREATE POLICY tenant_isolation_verify_checks ON verify_checks
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS superuser_bypass_verify_checks ON verify_checks;
CREATE POLICY superuser_bypass_verify_checks ON verify_checks
    TO kut_admin
    USING (true);

-- msp_customers
ALTER TABLE msp_customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE msp_customers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_msp_customers ON msp_customers;
CREATE POLICY tenant_isolation_msp_customers ON msp_customers
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS superuser_bypass_msp_customers ON msp_customers;
CREATE POLICY superuser_bypass_msp_customers ON msp_customers
    TO kut_admin
    USING (true);

-- devices
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_devices ON devices;
CREATE POLICY tenant_isolation_devices ON devices
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS superuser_bypass_devices ON devices;
CREATE POLICY superuser_bypass_devices ON devices
    TO kut_admin
    USING (true);

-- incidents
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_incidents ON incidents;
CREATE POLICY tenant_isolation_incidents ON incidents
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
DROP POLICY IF EXISTS superuser_bypass_incidents ON incidents;
CREATE POLICY superuser_bypass_incidents ON incidents
    TO kut_admin
    USING (true);

-- Güvenlik (SEC-012): evidence_custody tablosu için değiştirilemezlik (immutability) kuralları.
-- Adli bilişim delillerinin bütünlüğünü korumak için, kayıtların silinmesi veya güncellenmesi 
-- veritabanı seviyesinde engellenmiştir (append-only).
-- Bakım gerektiğinde geçici olarak tetikleyiciler devre dışı bırakılabilir:
-- Bakım: ALTER TABLE evidence_custody DISABLE TRIGGER ALL;
-- ... bakım işlemleri ...
-- ALTER TABLE evidence_custody ENABLE TRIGGER ALL;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION prevent_custody_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'evidence_custody tablosu değiştirilemez (append-only). Kayıt seq=%, evidence_id=%',
        COALESCE(OLD.seq::text, 'NULL'), COALESCE(OLD.evidence_id::text, 'NULL');
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE OR REPLACE TRIGGER trg_custody_no_update
    BEFORE UPDATE ON evidence_custody
    FOR EACH ROW EXECUTE FUNCTION prevent_custody_mutation();

CREATE OR REPLACE TRIGGER trg_custody_no_delete
    BEFORE DELETE ON evidence_custody
    FOR EACH ROW EXECUTE FUNCTION prevent_custody_mutation();

-- Güvenlik (SEC-012): audit_log tablosu için değiştirilemezlik (immutability) kuralları.
-- Denetim izlerinin güvenilirliği için, bu tabloya sadece ekleme yapılabilir (append-only).
-- Bakım: ALTER TABLE audit_log DISABLE TRIGGER ALL;
-- ...
-- ALTER TABLE audit_log ENABLE TRIGGER ALL;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION prevent_audit_log_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log tablosu değiştirilemez (append-only). Kayıt id=%',
        COALESCE(OLD.id::text, 'NULL');
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE OR REPLACE TRIGGER trg_audit_log_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();

CREATE OR REPLACE TRIGGER trg_audit_log_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();

-- =============================================================================
-- Kiracı Duvarı II YÜKSELTME BLOĞU (idempotent, yeniden çalıştırılabilir)
-- =============================================================================
-- Taze kurulumda yukarıdaki CREATE TABLE'lar zaten son biçimdedir ve bu blok
-- no-op'tur. Dosyanın tamamı da yeniden çalıştırılabilirdir (her ifade idempotent);
-- eski bir kurulumda yalnız BEGIN/END arasını uygulamak da yeterlidir:
--   sed -n '/^-- BEGIN TENANT-MAC-UPGRADE/,/^-- END TENANT-MAC-UPGRADE/p' db/schema.sql | psql "$KUT_DATABASE_URL"
-- BEGIN TENANT-MAC-UPGRADE

-- MAC-squat DoS: mac_address_bidx artık KÜRESEL tekil değil, KİRACI başınadır.
-- Tekillik anahtarı kanonik kiracıdır: kiracı öncesi (legacy) boş kiracı örtük 'default'
-- ile AYNI kiracı sayılır (tenant.Canonical), böylece '' ve 'default' aynı MAC için iki
-- satır üretemez. Önce yeni indeks oluşturulur, sonra eski küresel kısıt düşürülür
-- (mevcut veri zaten küresel tekil olduğundan indeks oluşturma çakışamaz).
CREATE UNIQUE INDEX IF NOT EXISTS uq_devices_tenant_mac
    ON devices ((COALESCE(NULLIF(tenant_id, ''), 'default')), mac_address_bidx);
ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_mac_address_bidx_key;

-- politikalar kiracı sahibi taşır. Boş = platform/paylaşımlı (mevcut
-- tüm politikalar böyle kalır; kiracıya bağlı admin okuyabilir/atayabilir, değiştiremez).
ALTER TABLE policies ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(63) NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies (tenant_id);

-- END TENANT-MAC-UPGRADE

-- =============================================================================
-- Kiracı Duvarı III YÜKSELTME BLOĞU (idempotent, yeniden çalıştırılabilir)
-- =============================================================================
-- Taze kurulumda yukarıdaki CREATE TABLE son biçimdedir ve bu blok no-op'tur.
-- MEVCUT kurulumlarda yalnız BEGIN/END arasını uygulayın:
--   sed -n '/^-- BEGIN INGEST-TOKEN-TENANT-UPGRADE/,/^-- END INGEST-TOKEN-TENANT-UPGRADE/p' db/schema.sql | psql "$KUT_DATABASE_URL"
-- BEGIN INGEST-TOKEN-TENANT-UPGRADE

-- yönetilen ingest token'ları bir kiracıya bağlanır (platform admini
-- oluşturmada verir; sunucu-tarafı). Mevcut tüm token'lar '' (kiracısız / legacy) kalır;
-- bunlarla alınan olaylar dağıtımın varsayılan kiracısına düşer (KUT_TENANT_ENFORCE=1
-- iken reddedilir).
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(63) NOT NULL DEFAULT '';

-- END INGEST-TOKEN-TENANT-UPGRADE

-- +goose Down
-- The baseline holds every table; there is no safe automatic rollback.
-- Restore from a backup instead.
-- +goose StatementBegin
DO $$
BEGIN
    RAISE EXCEPTION 'baseline migration cannot be rolled back; restore from a backup';
END
$$;
-- +goose StatementEnd
