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
  verilirse açılışta `migrate up` çalıştırır (varsayılan kapalı; demo modunda da çalışmaz).
  Üretimde `kutctl`'u sahip rolüyle ayrı bir adım olarak çalıştırın.
- Açılıştaki migrasyon DDL gerektirir; uygulama ayrıcalıksız bir rolle bağlanıyorsa o rol bunu
  yapamaz. Bu yüzden migrasyon bağlantısı sırayla `KUT_MIGRATE_DATABASE_URL`,
  `KUT_MIGRATE_DATABASE_URL_FILE`, yoksa `KUT_DATABASE_URL` değerinden alınır. Sahip bağlantısı
  yalnız migrasyon için açılıp hemen kapatılır; uygulama kendi `KUT_DATABASE_URL` bağlantısını
  kullanmaya devam eder. Sunucu bu değişkenleri okuduktan sonra ortamdan siler ve yalnız
  migrasyonu çalıştıran rolün adını loglar, bağlantı dizesini asla.
- Yeni şema değişiklikleri yalnız yeni bir `NNNNN_ad.sql` migrasyonu olarak eklenir;
  uygulanmış bir migrasyon düzenlenmez. `00001_baseline.sql` geri alınamaz (`Down` bilinçli
  olarak hata verir); yedekten dönün.

## Mevcut kurulumu migrasyonlara geçirme

`schema.sql` ile kurulmuş bir veritabanı veri değişikliği olmadan geçirilir:

İki yol vardır; ikisi birbirinin alternatifidir, art arda çalıştırılmaz (`up`'tan sonra baseline zaten uygulanmış olur ve `baseline`'ın yapacak işi kalmaz).

- **`migrate up` (varsayılan).** Baseline'ın ifadeleri tekrar çalıştırılabilir (`IF NOT EXISTS`,
  korumalı `DO` blokları) ve eksik tabloları, indeksleri, enum tiplerini ve politikaları
  oluşturur. Var olan nesnelerin içini yükseltmez: `CREATE TABLE IF NOT EXISTS` eski bir tablonun
  sütunlarını, korumalı `DO` blokları var olan bir enum'un değerlerini olduğu gibi bırakır; yalnız
  baseline'ın açıkça `ADD COLUMN IF NOT EXISTS` ile eklediği sütunlar tamamlanır. Baseline'dan çok
  eski bir şema bu yüzden `up` ile tam yükseltilmez. Aralığı baseline'ın `event_logs` bölümleriyle
  çakışan ama adı farklı bir bölüm varsa `up` hata verir ve işlemi geri alır; veri değişmez, ama
  önce çakışan bölüm giderilmelidir. Politika ve trigger'ları
  yeniden oluşturduğu için ACCESS EXCLUSIVE tablo kilidi alır; kilit beklemesi
  `KUT_MIGRATE_LOCK_TIMEOUT` (varsayılan `30s`) ile sınırlıdır.
  ```bash
  go run ./server/cmd/kutctl migrate up
  ```
- **`migrate baseline`.** Yalnızca veritabanı zaten baseline'ın son biçimindeyse kullanılır: baseline'ı
  uygulanmış olarak işaretler, tablo kilidi almaz ve saklama işinin sildiği `event_logs` bölümlerini
  yeniden oluşturmaz. Baseline'ın oluşturduğu herhangi bir nesne (tablo, RLS ayarı, politika, trigger,
  enum, sütun, rol) eksikse reddeder ve eksikleri listeler; bu durumda `migrate up` çalıştırın.
  ```bash
  go run ./server/cmd/kutctl migrate baseline
  go run ./server/cmd/kutctl migrate up        # yalnız sonraki migrasyonları uygular
  ```

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
  step with the owner role. It does not run in demo mode.
- Migrating needs DDL, which an unprivileged application role cannot run. The migration therefore
  connects with `KUT_MIGRATE_DATABASE_URL`, else `KUT_MIGRATE_DATABASE_URL_FILE`, else
  `KUT_DATABASE_URL`. The owner connection is opened only for the migration and closed right
  after; the application keeps using its own `KUT_DATABASE_URL`. The server removes these
  variables from the environment once read, and logs only the name of the role that ran the
  migration, never the connection string.
- Schema changes are added only as a new `NNNNN_name.sql` migration; an applied migration is
  never edited. `00001_baseline.sql` cannot be rolled back (its `Down` fails on purpose);
  restore from a backup instead.

## Adopting migrations on an existing installation

A database created from `schema.sql` moves to migrations without any data change:

There are two options. They are alternatives, not consecutive steps: after `up` the baseline has already run, so `baseline` has nothing left to do.

- **`migrate up` (default).** The baseline statements can be re-run (`IF NOT EXISTS`, guarded `DO`
  blocks) and create any missing tables, indexes, enum types and policies. It does not upgrade
  existing objects in place: `CREATE TABLE IF NOT EXISTS` leaves an older table's columns as they
  are and the guarded `DO` blocks leave an existing enum's values as they are; only the columns the
  baseline adds with an explicit `ADD COLUMN IF NOT EXISTS` are filled in. A schema much older than
  the baseline is therefore not fully upgraded by `up`. If a differently named `event_logs`
  partition overlaps the range of a baseline partition, `up` fails and rolls back; nothing is
  changed, but the overlapping partition has to be resolved first. It recreates policies
  and triggers, which takes ACCESS EXCLUSIVE table locks; the wait for a lock is capped by
  `KUT_MIGRATE_LOCK_TIMEOUT` (default `30s`).
  ```bash
  go run ./server/cmd/kutctl migrate up
  ```
- **`migrate baseline`.** Use it only when the database is already in the baseline's final shape: it
  records the baseline as applied, takes no table locks and does not recreate `event_logs` partitions
  that retention dropped. It refuses a database missing any object the baseline creates (tables,
  row-level security settings, policies, triggers, enums, columns, the `kut_admin` role) and lists
  what is missing; run `migrate up` in that case.
  ```bash
  go run ./server/cmd/kutctl migrate baseline
  go run ./server/cmd/kutctl migrate up        # applies only the later migrations
  ```

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
