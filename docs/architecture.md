# Mimari
# Architecture

**Türkçe** · [English](#english)

## Genel akış

```
                 mTLS + gRPC
  ┌──────────┐  ◄──────────────►  ┌────────────────────┐
  │  Ajan    │                    │   C2 Sunucusu      │
  │ (agent)  │   enrollment       │  - AgentService    │
  │          │  ─────(1-way TLS)─►│  - EnrollmentSvc   │
  │ Watchdog │                    │  - OTA / Politika  │
  └──────────┘                    └─────────┬──────────┘
                                            │
                                   ┌────────▼─────────┐
                                   │   PostgreSQL     │
                                   │ (at-rest şifreli)│
                                   └──────────────────┘
```

## Teknoloji kararları

- **Tek dil: Go** — C2 ve ajan ortak protobuf tiplerini paylaşır, bakım tek
  ekosistemde. Kernel sürücüsü (ileride) zorunlu olarak C/C++.
- **gRPC + mTLS** — çift yönlü sertifika doğrulaması; ajan gövdesindeki
  `device_id`'ye güvenilmez, kimlik istemci sertifikasından alınır.
- **PostgreSQL** — hassas serbest-metin alanları `pgcrypto` ile şifreli; yüksek
  hacimli `event_logs` sorgulanabilir kalır ve gizliliği at-rest (disk/tablespace)
  şifreleme ile korunur.

## Kurulum ve paketleme

### Sunucu (C2)
Tek dosya installer (Windows MSI / Linux deb-rpm) C2 servisini ve PostgreSQL
bağlantı yapılandırmasını kurar. Ana şifreleme anahtarı (master key) kurulumda
belirlenir ve serviste RAM'e alınır; diske düz saklanmaz.

### İstemci (agent) — benzersiz kurulum
Kurulum bir **enrollment token** ile bootstrap edilir:

1. IT, yönetim panelinden bir cihaz için tek kullanımlık, süreli token üretir
   (DB: `enrollment_tokens`, ham token saklanmaz — HMAC'i tutulur).
2. Token ajana iki moddan biriyle ulaşır (**karar: her ikisi de desteklenir**):
   - **Gömülü mod:** cihaz başına benzersiz installer, token damgalı → kullanıcı
     çift-tıkla kurar, sıfır yapılandırma. Dağıtım başına paket üretilir.
   - **Kod-giriş modu:** tek ortak installer; kurulumda IT'nin verdiği tek
     kullanımlık kod girilir. Dağıtımı basit.
   Çekirdek ajan her iki modda aynıdır; farklılık yalnızca paketleme katındadır.
3. Ajan ilk açılışta lokal anahtar çifti üretir, CSR oluşturur ve
   `EnrollmentService.Enroll(token, csr)` çağırır.
4. Sunucu token'ı doğrular, CSR'ı imzalar, kısa ömürlü istemci sertifikası döner.
5. Sonraki tüm iletişim mTLS iledir. Token tek kullanımlıktır ve tüketilir.

### Hedef platformlar
**Karar: hem sunucu hem istemci Linux + Windows.** Go cross-compile ile tek
kaynaktan üretilir; installer hedefleri: Windows **MSI**, Linux **deb/rpm**.
OS'e özgü parçalar (servis kaydı, süreç sonlandırma, firewall/iptables,
ileride sürücü) platform-spesifik dosyalarda soyutlanır.

## Bileşenler

- **İskelet:** yapı, proto sözleşmeleri, düzeltilmiş DB şeması.
- **Enrollment/PKI çekirdeği:** security ilkelleri (HMAC blind
  index, AES-256-GCM alan şifreleme, CA/CSR imzalama, KDF), config, transport'tan
  bağımsız enrollment domain servisi + birim testleri; pgx `Store` ve gRPC
  handler adaptörleri (proto/DB üretimi sonrası derlenir).
- **Politika anlık push:** `server/internal/policypush` per-cihaz pub/sub;
  `StreamPolicies` artık uzun-ömürlü — ilk paketi gönderir, sonra admin atama
  (`AssignPolicy`→`Publish`) ile yeni paketleri ANINDA iter. Ajan kalıcı abonelik
  tutar ve motoru `atomic.Pointer` ile sıcak değiştirir. e2e ile push doğrulandı.
- **Rutin akış:** ajan-domain (politika motoru,
  sunucu-saati çıpası, olay tamponu) + sunucu `AgentService` (Heartbeat +
  ReportEvents, kimlik mTLS peer sertifikasından) + iki gRPC sunucu mTLS/TLS ile
  ayağa kalkıyor + ajan ana döngüsü (enroll → heartbeat → olay flush).
- **Politika dağıtımı + canlı kanıt:** `StreamPolicies` uçtan
  uca bağlı (sunucu geçerli paketi sunar, ajan proto→domain çevirip motora
  yükler); dev sertifika aracı (`tools/gencerts`); `server/internal/e2e` gerçek
  mTLS gRPC ile enroll→heartbeat→olay→**politika**→token akışını doğruluyor.
  `RenewCertificate` bağlandı: kayıtlı ajan mTLS ile (token'sız) sertifikasını
  yeniler; enroll sunucusu "sertifika varsa doğrula" modunda, kimlik peer
  sertifikasından alınır. e2e ile doğrulandı. Ajan artık PROAKTİF yeniler:
  `agent/internal/certrenew` ömrün son 1/3'ünde, `transport.CertHolder` ile canlı
  bağlantıyı yeniden kurmadan (GetClientCertificate ile dinamik cert) yeniler.
- **Sertifika iptali:** `server/internal/revocation` — bellek-içi iptal
  kümesi (SHA-256 parmak izi), DB'den periyodik tazeleme, mTLS `VerifyPeerCertificate`
  kapısı; admin `RevokeDevice` (OPERATOR+, audit) + `/api/devices/revoke` + konsol
  düğmesi. e2e: iptal edilen sertifikayla yeni bağlantı reddedilir.
- **Politika uygulama:** süreç izleme + sonlandırma
  (`agent/internal/enforce`), sunucu-saatine çıpalı değerlendirme, saat
  senkronsuzken fail-safe (yalnız her-zaman-yasak), `POLICY_VIOLATION` olayı.
  Windows kontrolcüsü (Toolhelp/TerminateProcess) gerçek süreçlerle doğrulandı;
  Linux kontrolcüsü (`/proc` tarama + SIGKILL) cross-compile ile derlendi, macOS
  için desteklenmiyor stub'ı.
- **OTA imza doğrulama:** Ed25519 imzalı manifesto
  (`otawire` kanonik kodlama, `server/internal/ota` imzalayıcı, `agent/internal/update`
  doğrulayıcı), `CheckUpdate` uçtan uca bağlı ve e2e ile doğrulandı (geçerli
  kabul, değiştirilmiş red), `tools/otasign` (anahtar üretimi + sürüm imzalama +
  SQL).
- **OTA indirme + staging:** `agent/internal/update` —
  boyut-sınırlı indirici, `Prepare` boru hattı (imza → indir → SHA-256 → atomik
  staging + sürüm işaretçisi); imza/hash başarısızsa uygulanmaz. `httptest` ile
  doğrulandı.
- **Kademeli dağıtım / canary:** `server/internal/rollout` — cihaz+sürüm
  hash'ine göre deterministik kohort; `CheckUpdate`, cihaz `rollout_percent`
  kohortunda değilse güncelleme sunmaz. Monoton (yüzde artınca kohort büyür),
  dağılım/sınır testli; e2e ile %0 kapısı doğrulandı.
- **İmzalı script yürütme:** `scriptwire` + `agent/internal/script`
  — Ed25519 imza doğrulama (tek bayt değişse ret) + sınırlı yürütme (timeout,
  çıktı sınırı, minimal env); `RUN_SIGNED_SCRIPT` komutu ajanda bağlı, `tools/scriptsign`
  imzalar. **Sınır:** gerçek izolasyon sınırı DEĞİL; süreç-ağacı sonlandırma
  ve sandbox (Job Object / AppContainer / container) kapsam dışıdır.
- **Watchdog:** `agent/internal/watchdog` — süreç gözetimi + backoff'lu
  yeniden başlatma (Supervisor, sahte runner ile test), staged swap + yedek +
  **deneme penceresinde çöküşte rollback** (FileSwapper, geçici dizinle test),
  gerçek `os/exec` runner. OTA döngüsünü kapatır (Prepare→swap→rollback).
- **Çift-süreç karşılıklı gözetim:** `agent/internal/liveness` — dosya
  beacon'ları; watchdog ajanı süreç-çıkışıyla, ajan watchdog'u beacon
  bayatlamasıyla (`PeerGuard`) yeniden başlatır. Beacon + guard mantığı sahte
  saatle test edildi.
- **Ağ keşfi:** `agent/internal/discovery` — komşu/ARP tablosu
  (read-only) tarama, ARP ayrıştırıcı (Windows `arp -a`, Linux `/proc/net/arp`),
  yeni-cihaz takibi + yetkili/yetkisiz allowlist, `NETWORK_DISCOVERY` olayları.
  Windows'ta gerçek ağda doğrulandı (7 cihaz bulundu).
- **Karantina:** `agent/internal/quarantine` — idempotent
  durum yöneticisi (Apply/Release, geçişlerde SECURITY olayı) sahte izolatörle
  test edildi; Windows (`netsh`, varsayılan politika blok + C2 allow) ve Linux
  (`iptables` özel zincir) izolatörleri derlendi/cross-compile edildi. Ajan,
  heartbeat `pending_commands`'taki QUARANTINE/UNQUARANTINE'i uygular.
- **Admin çekirdeği:** `server/internal/admin` — RBAC'li
  (VIEWER/OPERATOR/ADMIN) işlemler: enrollment token üretimi (HMAC indeksli),
  karantina/serbest komutu verme, politika oluşturma/atama; her hassas işlem
  `audit_log`'a yazılır. Komut kuyruğu (`device_commands`) + heartbeat teslimi
  (en-fazla-bir-kez) e2e ile doğrulandı.
- **Admin HTTP API:** `server/internal/adminapi` — Argon2id parola
  doğrulama, HMAC-imzalı durumsuz oturum token'ı, Bearer korumalı REST uçları
  (login, enrollment-token, karantina/serbest, politika CRUD/atama);
  `httptest` ile uçtan uca doğrulandı (login→komut, RBAC 403, hatalı parola 401).
  `tools/adminseed` yönetici parolası hash'ler.
- **Web yönetim konsolu:** `server/internal/adminapi/console.html` — C2
  admin sunucusundan **aynı köken** gömülü (Go embed) tek-sayfa konsol: login,
  enrollment token üretimi, karantina/serbest, politika oluştur/ata. İkiliye
  gömülü, `GET /` ile sunulur; `httptest` ile doğrulandı.
- **Okuma API'si + görünürlük:** `server/internal/adminread` — cihaz
  listesi (şifreli hostname/mac sunucuda deşifre) ve olay logları; `GET /api/devices`,
  `GET /api/events`. Konsolda canlı **Cihazlar** ve **Olaylar** tabloları. Deşifre
  ve uç noktalar test edildi.
- **KVKK saklama otomasyonu:** `server/internal/retention` — saf plan
  (düşürülecek/oluşturulacak aylık partition'lar) + DB yürütücü; C2'de günlük
  çalışır (`KUT_RETENTION_DAYS`, varsayılan 90). Plan mantığı sahte store ile test edildi.

---

# English

## Overall flow

```
                 mTLS + gRPC
  +----------+  <-------------->  +--------------------+
  |  Agent   |                    |   C2 Server        |
  | (agent)  |   enrollment       |  - AgentService    |
  |          |  ----(1-way TLS)-->|  - EnrollmentSvc   |
  | Watchdog |                    |  - OTA / Policy    |
  +----------+                    +---------+----------+
                                            |
                                   +--------v---------+
                                   |   PostgreSQL     |
                                   | (at-rest crypto) |
                                   +------------------+
```

## Technology decisions

- **Single language: Go** — C2 and the agent share common protobuf types, so
  maintenance stays in one ecosystem. The kernel driver (later) is necessarily C/C++.
- **gRPC + mTLS** — mutual certificate verification; the `device_id` in the agent body
  is not trusted, identity is taken from the client certificate.
- **PostgreSQL** — sensitive free-text fields are encrypted with `pgcrypto`; the
  high-volume `event_logs` stays queryable and its confidentiality is protected by
  at-rest (disk/tablespace) encryption.

## Installation and packaging

### Server (C2)
A single-file installer (Windows MSI / Linux deb-rpm) installs the C2 service and the
PostgreSQL connection configuration. The master encryption key is set at installation
and held in the service's RAM; it is not stored in plaintext on disk.

### Client (agent) — unique installation
Installation is bootstrapped with an **enrollment token**:

1. IT generates a single-use, time-limited token for a device from the admin panel
   (DB: `enrollment_tokens`, the raw token is not stored — its HMAC is kept).
2. The token reaches the agent in one of two modes (**decision: both are supported**):
   - **Embedded mode:** a unique per-device installer with the token stamped in → the
     user installs with a double-click, zero configuration. A package is produced per
     deployment.
   - **Code-entry mode:** a single shared installer; a single-use code provided by IT
     is entered during installation. Simple to distribute.
   The core agent is identical in both modes; the difference is only at the packaging
   layer.
3. On first launch the agent generates a local key pair, creates a CSR, and calls
   `EnrollmentService.Enroll(token, csr)`.
4. The server verifies the token, signs the CSR, and returns a short-lived client
   certificate.
5. All subsequent communication is over mTLS. The token is single-use and consumed.

### Target platforms
**Decision: both server and client on Linux + Windows.** Produced from a single source
via Go cross-compilation; installer targets: Windows **MSI**, Linux **deb/rpm**.
OS-specific parts (service registration, process termination, firewall/iptables, and a
driver later) are abstracted in platform-specific files.

## Components

- **Skeleton:** structure, proto contracts, corrected DB schema.
- **Enrollment/PKI core:** security primitives (HMAC blind index,
  AES-256-GCM field encryption, CA/CSR signing, KDF), config, a transport-independent
  enrollment domain service + unit tests; pgx `Store` and gRPC handler adapters.
- **Policy instant push:** `server/internal/policypush` per-device pub/sub;
  `StreamPolicies` is now long-lived — it sends the first bundle, then instantly pushes
  new bundles on admin assignment (`AssignPolicy`→`Publish`). The agent keeps a
  persistent subscription and hot-swaps the engine via `atomic.Pointer`. Push verified
  by e2e.
- **Routine flow:** agent-domain (policy engine,
  server-clock anchor, event buffer) + server `AgentService` (Heartbeat + ReportEvents,
  identity from the mTLS peer certificate) + two gRPC servers coming up with mTLS/TLS +
  the agent main loop (enroll → heartbeat → event flush).
- **Policy distribution + live proof:** `StreamPolicies` wired
  end-to-end; a dev certificate tool (`tools/gencerts`); `server/internal/e2e` verifies
  the enroll→heartbeat→event→**policy**→token flow with real mTLS gRPC.
  `RenewCertificate` wired: an enrolled agent renews its certificate over mTLS (without
  a token). The agent now renews PROACTIVELY: `agent/internal/certrenew` renews in the
  last 1/3 of the lifetime, using `transport.CertHolder` (dynamic cert via
  GetClientCertificate) without re-establishing the live connection.
- **Certificate revocation:** `server/internal/revocation` — an in-memory
  revocation set (SHA-256 fingerprint), periodic refresh from the DB, an mTLS
  `VerifyPeerCertificate` gate; admin `RevokeDevice` (OPERATOR+, audit) +
  `/api/devices/revoke` + a console button. e2e: a new connection with a revoked
  certificate is rejected.
- **Policy enforcement:** process monitoring + termination
  (`agent/internal/enforce`), server-clock-anchored evaluation, fail-safe when the
  clock is unsynced (block-always rules only), a `POLICY_VIOLATION` event. The Windows
  controller (Toolhelp/TerminateProcess) verified with real processes; the Linux
  controller (`/proc` scan + SIGKILL) cross-compiled, with an unsupported stub for
  macOS.
- **OTA signature verification:** an Ed25519-signed manifest
  (`otawire` canonical encoding, `server/internal/ota` signer, `agent/internal/update`
  verifier), `CheckUpdate` wired end-to-end and verified by e2e (valid accepted,
  tampered rejected), `tools/otasign` (key generation + release signing + SQL).
- **OTA download + staging:** `agent/internal/update` — a
  size-limited downloader, the `Prepare` pipeline (signature → download → SHA-256 →
  atomic staging + version pointer); not applied if signature/hash fails. Verified with
  `httptest`.
- **Staged rollout / canary:** `server/internal/rollout` — a deterministic
  cohort based on the device+version hash; `CheckUpdate` offers no update if the device
  is not in the `rollout_percent` cohort. Monotonic (the cohort grows as the percentage
  increases), distribution/boundary-tested; the 0% gate verified by e2e.
- **Signed script execution:** `scriptwire` + `agent/internal/script` —
  Ed25519 signature verification (rejected if a single byte changes) + constrained
  execution (timeout, output limit, minimal env); the `RUN_SIGNED_SCRIPT` command wired
  in the agent, `tools/scriptsign` signs. **Boundary:** NOT a real isolation
  boundary; process-tree termination and a sandbox (Job Object / AppContainer /
  container) are out of scope.
- **Watchdog:** `agent/internal/watchdog` — process supervision + backoff
  restart (Supervisor, tested with a fake runner), staged swap + backup + **rollback on
  a crash within the trial window** (FileSwapper, tested with a temp dir), a real
  `os/exec` runner. Closes the OTA loop (Prepare→swap→rollback).
- **Dual-process mutual supervision:** `agent/internal/liveness` — file beacons;
  the watchdog restarts the agent on process exit, the agent restarts the watchdog on
  beacon staleness (`PeerGuard`). Beacon + guard logic tested with a fake clock.
- **Network discovery:** `agent/internal/discovery` — neighbor/ARP
  table (read-only) scanning, an ARP parser (Windows `arp -a`, Linux `/proc/net/arp`),
  new-device tracking + an authorized/unauthorized allowlist, `NETWORK_DISCOVERY`
  events. Verified on a real network on Windows (7 devices found).
- **Quarantine:** `agent/internal/quarantine` — an
  idempotent state manager (Apply/Release, a SECURITY event on transitions) tested with
  a fake isolator; Windows (`netsh`, default-block policy + C2 allow) and Linux
  (`iptables` custom chain) isolators compiled/cross-compiled. The agent applies
  QUARANTINE/UNQUARANTINE from the heartbeat `pending_commands`.
- **Admin core:** `server/internal/admin` — RBAC (VIEWER/OPERATOR/ADMIN)
  operations: enrollment token generation (HMAC-indexed), quarantine/release commands,
  policy creation/assignment; every sensitive operation is written to `audit_log`. The
  command queue (`device_commands`) + heartbeat delivery (at-most-once) verified by e2e.
- **Admin HTTP API:** `server/internal/adminapi` — Argon2id password
  verification, an HMAC-signed stateless session token, Bearer-protected REST endpoints;
  verified end-to-end with `httptest` (login→command, RBAC 403, wrong password 401).
- **Web admin console:** `server/internal/adminapi/console.html` — a same-origin
  embedded (Go embed) single-page console served from the C2 admin server via `GET /`;
  verified with `httptest`.
- **Read API + visibility:** `server/internal/adminread` — the device list
  (encrypted hostname/mac decrypted on the server) and event logs; `GET /api/devices`,
  `GET /api/events`. Live **Devices** and **Events** tables in the console.
- **Data-protection retention automation:** `server/internal/retention` — a pure
  plan (monthly partitions to drop/create) + a DB executor; runs daily in C2
  (`KUT_RETENTION_DAYS`, default 90). Plan logic tested with a fake store.
