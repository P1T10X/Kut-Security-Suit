# Veritabanı
# Database

**Türkçe** · [English](#english)

PostgreSQL şeması sürümlü migrasyonlarla (goose) yönetilir: `db/postgres/migrations/`
(PostgreSQL 14+). Migrasyonlar ikiliye gömülüdür; `server/cmd/kutctl` onları uygular.
`schema.sql`, `00001_baseline.sql` ile aynı ifadelerin (goose notasyonu olmadan) anlık
görüntüsüdür; bir test ikisinin birebir aynı kalmasını doğrular.

## Kurulum

Bağlantı, `-dsn` ile ya da `KUT_MIGRATE_DATABASE_URL`, yoksa `KUT_DATABASE_URL`
ortam değişkeniyle verilir (her ikisinin `_FILE` biçimi de çalışır).

```bash
createdb kut
export KUT_DATABASE_URL='postgres://<sahip-rol>@<sunucu>/kut'
go run ./server/cmd/kutctl migrate up        # bekleyen migrasyonları uygular
go run ./server/cmd/kutctl migrate status    # her migrasyonun durumunu listeler
```

`migrate up` tekrar çalıştırılabilir; uygulanmış migrasyonlar atlanır.

- **Sunucu kendiliğinden migrasyon çalıştırmaz.** `c2`, yalnız `KUT_MIGRATE_ON_START=1`
  verilirse açılışta `migrate up` çalıştırır (varsayılan kapalı). Üretimde `kutctl`'u sahip
  rolüyle ayrı bir adım olarak çalıştırın.
- Yeni şema değişiklikleri yalnız yeni bir `NNNNN_ad.sql` migrasyonu olarak eklenir;
  uygulanmış bir migrasyon düzenlenmez. `00001_baseline.sql` geri alınamaz (`Down` bilinçli
  olarak hata verir); yedekten dönün.

## Mevcut kurulumu migrasyonlara geçirme

`schema.sql` ile kurulmuş bir veritabanı veri değişikliği olmadan geçirilir:

1. Güncel şemadaysa (kiracı sütunları ve `uq_devices_tenant_mac` var), baseline'ı uygulanmış
   olarak işaretleyin; hiçbir şey çalıştırılmaz:
   ```bash
   go run ./server/cmd/kutctl migrate baseline
   go run ./server/cmd/kutctl migrate up        # yalnız sonraki migrasyonları uygular
   ```
   Şema baseline'ın son biçiminde değilse `baseline` komutu reddeder.
2. Daha eski bir şemadaysa doğrudan `migrate up` çalıştırın: baseline'ın her ifadesi
   idempotenttir (`IF NOT EXISTS`, korumalı `DO` blokları) ve eksik parçaları tamamlar.
   Canlı sistemlerde 1. yol tercih edilir; 2. yol politika/trigger'ları yeniden oluşturduğu
   için kısa süreli tablo kilidi alır ve `event_logs` bölümleri farklı adlarla yönetiliyorsa
   çakışabilir.

## Roller

| Rol | Amaç |
|---|---|
| sahip / migrasyon rolü | Migrasyonları çalıştıran oturum açma rolü. Tüm nesnelere sahiptir ve DDL'i (örn. `event_logs` bölüm bakımı) yalnız o yapar. Operatör oluşturur; öneri: `kut_owner`. |
| `kut_app` | Uygulama rolü: `NOSUPERUSER NOBYPASSRLS`, DDL yok. `NOLOGIN` oluşturulur. |
| `kut_admin` | RLS bypass politikalarının hedefi (`NOLOGIN`); baseline oluşturur, değiştirilmez. |

SQL dosyalarında parola yoktur. Oturum açma bilgisini operatör verir:

```sql
ALTER ROLE kut_app WITH LOGIN PASSWORD '<operatör-parolası>';
GRANT CONNECT ON DATABASE kut TO kut_app;
```

`00002_database_roles.sql` şu yetkileri verir:

- `USAGE ON SCHEMA public`.
- `SELECT, INSERT, UPDATE, DELETE`: `devices, enrollment_tokens, agent_certificates, policies,
  policy_rules, device_policies, ota_releases, event_logs, event_ack, discovered_hosts,
  device_commands, artifacts, scim_users, cases, verify_checks, tokens, msp_customers, admins,
  pending_wipes, incidents, saved_searches`.
- `SELECT, INSERT` (yalnız ekleme): `audit_log, evidence_custody`.
- `TRUNCATE`, `REFERENCES`, `TRIGGER`, DDL ve başka hiçbir yetki yoktur. Sonradan eklenen
  tablolara `kut_app` yetkisini o tabloyu ekleyen migrasyon açıkça verir.

**Uygulama henüz `kut_app` ile bağlanmaz.** Kiracı bağlamı (her işlemde
`SET LOCAL app.tenant_id`) henüz bağlanmadı; `FORCE ROW LEVEL SECURITY` altında `kut_app`
hiç satır görmez. Rol geçişi, kiracı bağlamının bağlanmasıyla birlikte yapılacaktır. Geçişte
ayrıca `event_logs` bölüm oluşturma/silme (`retention.go`) sahip rolüne taşınmalıdır; `kut_app`
DDL yapamaz.

## Notlar

- **Blind index (HMAC):** `*_bidx` sütunları uygulama katmanında
  `HMAC-SHA256(sunucu_gizli_anahtarı, normalize_değer)` ile üretilir. Düz hash
  kullanmayın (MAC adres uzayı brute-force'a açıktır).
- **At-rest şifreleme:** `event_logs` sorgulanabilir kalması için alan-bazlı
  şifrelenmez; gizliliği şifreli tablespace / disk (TDE) düzeyinde sağlanır.
  Serbest-metin kimlik alanları (`*_encrypted`) `pgcrypto` ile şifrelidir.
- **Partition yönetimi:** `event_logs` RANGE partition'lıdır. Üretimde
  `pg_partman` veya bir cron görevi ile gelecek partition'lar önceden
  oluşturulmalı ve saklama süresi dolanlar DROP edilmelidir (bkz. `docs/kvkk.md`).

---

# English

The PostgreSQL schema is managed with versioned migrations (goose) in
`db/postgres/migrations/` (PostgreSQL 14+). The migrations are embedded in the binary and
applied by `server/cmd/kutctl`. `schema.sql` is the same statements as `00001_baseline.sql`
without the goose annotations; a test keeps the two identical.

## Setup

The connection comes from `-dsn`, else `KUT_MIGRATE_DATABASE_URL`, else `KUT_DATABASE_URL`
(each also accepts a `_FILE` variant).

```bash
createdb kut
export KUT_DATABASE_URL='postgres://<owner-role>@<host>/kut'
go run ./server/cmd/kutctl migrate up        # apply pending migrations
go run ./server/cmd/kutctl migrate status    # list each migration and its state
```

`migrate up` can be re-run; applied migrations are skipped.

- **The server never migrates on its own.** `c2` runs `migrate up` at start only when
  `KUT_MIGRATE_ON_START=1` is set (default off). In production run `kutctl` as a separate
  step with the owner role.
- Schema changes are added only as a new `NNNNN_name.sql` migration; an applied migration is
  never edited. `00001_baseline.sql` cannot be rolled back (its `Down` fails on purpose);
  restore from a backup instead.

## Adopting migrations on an existing installation

A database created from `schema.sql` moves to migrations without any data change:

1. If it is on the current schema (tenant columns and `uq_devices_tenant_mac` exist), record
   the baseline as applied; nothing is executed:
   ```bash
   go run ./server/cmd/kutctl migrate baseline
   go run ./server/cmd/kutctl migrate up        # applies only the later migrations
   ```
   `baseline` refuses a database that is not in the baseline's final shape.
2. If it is on an older schema, run `migrate up` directly: every statement in the baseline is
   idempotent (`IF NOT EXISTS`, guarded `DO` blocks) and fills in whatever is missing. On a live
   system prefer path 1; path 2 recreates policies and triggers (a brief table lock) and can
   collide if `event_logs` partitions are managed under different names.

## Roles

| Role | Purpose |
|---|---|
| owner / migration role | The login that runs migrations. It owns every object and is the only role that performs DDL (for example `event_logs` partition upkeep). The operator creates it; suggested name `kut_owner`. |
| `kut_app` | The application role: `NOSUPERUSER NOBYPASSRLS`, no DDL. Created `NOLOGIN`. |
| `kut_admin` | Target of the row-level-security bypass policies (`NOLOGIN`); created by the baseline and left unchanged. |

No SQL file contains a password. The operator supplies the login:

```sql
ALTER ROLE kut_app WITH LOGIN PASSWORD '<operator-password>';
GRANT CONNECT ON DATABASE kut TO kut_app;
```

`00002_database_roles.sql` grants:

- `USAGE ON SCHEMA public`.
- `SELECT, INSERT, UPDATE, DELETE` on `devices, enrollment_tokens, agent_certificates,
  policies, policy_rules, device_policies, ota_releases, event_logs, event_ack,
  discovered_hosts, device_commands, artifacts, scim_users, cases, verify_checks, tokens,
  msp_customers, admins, pending_wipes, incidents, saved_searches`.
- `SELECT, INSERT` only (append-only) on `audit_log, evidence_custody`.
- No `TRUNCATE`, `REFERENCES`, `TRIGGER`, DDL or anything else. A table added later gets
  `kut_app` access only if the migration that adds it grants it explicitly.

**The application does not connect as `kut_app` yet.** The tenant context (`SET LOCAL
app.tenant_id` in every transaction) is not wired, and under `FORCE ROW LEVEL SECURITY`
`kut_app` sees no rows. The switch happens together with that wiring. It also requires moving
`event_logs` partition creation and removal (`retention.go`) to the owner role, because
`kut_app` cannot run DDL.

## Notes

- **Blind index (HMAC):** the `*_bidx` columns are produced at the application layer
  as `HMAC-SHA256(server_secret_key, normalized_value)`. Do not use a plain hash (the
  MAC address space is open to brute force).
- **At-rest encryption:** `event_logs` is not field-level encrypted so it stays
  queryable; its confidentiality is provided at the encrypted-tablespace / disk (TDE)
  level. Free-text identity fields (`*_encrypted`) are encrypted with `pgcrypto`.
- **Partition management:** `event_logs` is RANGE-partitioned. In production, future
  partitions must be pre-created and elapsed ones DROPped via `pg_partman` or a cron
  job (see `docs/kvkk.md`).
