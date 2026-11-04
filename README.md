<p align="center">
  <img src="assets/kut-logo.png" alt="KUT Security Suite" width="220">
</p>

# KUT Security Suite — Kurumsal Uç Nokta Güvenliği ve Ajan Yönetim Sistemi
# KUT Security Suite — Corporate Endpoint Security & Agent Management System

[![CI](https://github.com/cihanuralkaya/Kut-Security-Suit/actions/workflows/ci.yml/badge.svg)](https://github.com/cihanuralkaya/Kut-Security-Suit/actions/workflows/ci.yml)

**Türkçe** · [English](#english)

> **🇬🇧 EN —** Endpoint security & management platform (EDR/XDR + MDM) for authorized
> corporate environments. Single language **Go**; agent ↔ C2 over **gRPC + mTLS**
> (TLS 1.3). Feature-complete, CI green, deployment-ready. **Full English docs
> below → [English](#english).**
>
> **🇹🇷 TR —** Yetkili kurumsal ortamlar için uç nokta güvenlik ve yönetim platformu
> (EDR/XDR + MDM). Tek dil **Go**; ajan ↔ C2 **gRPC + mTLS** (TLS 1.3). Özellik-tam,
> CI yeşil, dağıtıma hazır.

---

Yetkili kurumsal ortam için (şirkete ait cihazlar, bildirilmiş kullanım
politikası, IT yönetimi) tasarlanmış uç nokta güvenlik ve yönetim platformu.
Tek dil: **Go**. Ajan ↔ C2 iletişimi **gRPC + mTLS** (TLS 1.3).

> **Durum: özellik-tam, CI yeşil, dağıtıma hazır.**
>
> - **1088 test (+16 fuzz) / 111 paket** geçiyor; **CI** (`.github/workflows/ci.yml`) her
>   push'ta `go vet` + `-race` test + **uçtan uca smoke** + **gerçek PostgreSQL'e karşı DB
>   testi** + çapraz derleme + **her iki derleme katmanı (Lite/Enterprise)** çalıştırır — hepsi yeşil.
> - Uçtan uca kanıtlı zincir: enroll (PKI) → mTLS heartbeat (sunucu-saati) → olay →
>   politika push → OTA imza + rollout → komut teslimi → tek-kullanımlık token
>   (`server/internal/e2e`, `make e2e`).
> - **Güvenlik:** HMAC blind index, AES-256-GCM alan şifreleme, Argon2id parola,
>   Ed25519 OTA/script imzası, RBAC + değişmez (hash-zincirli) denetim izi, giriş
>   kaba-kuvvet koruması, admin 2FA (TOTP), mTLS sunucu SPKI pinning, sıkılaştırılmış
>   güvenlik başlıkları (HSTS/CSP nonce).
> - **Tespit & müdahale:** MITRE ATT&CK eşleme, sunucu-taraflı tespit kuralları
>   (YAML-benzeri) + **Detection-as-Code** yaşam-döngüsü + **YAML içe aktarma**,
>   saf-Go **YARA-tarzı içerik tarama** (imzalı kurallar), IoC tehdit istihbaratı
>   (güven/kaynak), davranışsal anomali, C2 beacon tespiti, SOAR otomatik-karantina,
>   SOC webhook uyarı (**yönlendirme + yükseltme + HMAC imza**), SIEM (CEF/LEEF),
>   Prometheus `/metrics`.
> - **SOC istihbaratı:** çok-sinyal **korelasyon** (yüksek-güven saldırı zinciri),
>   çok-faktörlü **risk skorlama**, **saldırı hikâyesi** (kill-chain), **varlık grafı**,
>   **incident zaman çizelgesi**, **MTTD/MTTR** trendleri, **UEBA** (ayrıcalıklı-kullanıcı
>   davranış analitiği), uyum çerçevesi eşleme (**CIS/NIST/ISO 27001/KVKK**), bakım/
>   bastırma pencereleri.
> - **Tedarik zinciri güvenliği (CI):** `govulncheck` (bağımlılık CVE), **fuzzing**
>   (kritik ayrıştırıcılar), **SBOM** (CycloneDX), gosec; hız sınırlama, kurcalama-
>   kanıtlı imzalı denetim dışa aktarımı, imzalı çevrimdışı offboard, çok-kiracılı
>   çıktı atıfı.
> - **KVKK:** at-rest şifreleme + partition-bazlı saklama; **veri sahibi hakları**
>   (erişim/dışa aktarma + silme, denetim korunur).
> - **Konsol:** gömülü tek-sayfa SOC paneli — cihazlar/olaylar/politikalar/yöneticiler,
>   cihaz etiketleme, **canlı SSE push**, önem grafiği, arama, CSV dışa aktarma,
>   **TR/EN dil seçeneği** (GDPR/KVKK dil-duyarlı gizlilik metni), sağlık uçları (`/healthz`, `/readyz`).
> - **Dağıtım:** çapraz derleme + tek-dosya istemci installer üreteci (token gömülü
>   veya kod girişli, Win/Linux) + sunucu kurulum betikleri — bkz.
>   **[deploy/README.md](deploy/README.md)**.
> - Üçüncü taraf lisanslar (telif uyumu): **[docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md)**
>   (hepsi izin verici; copyleft yok).

## Bileşenler

| Bileşen | Dizin | Rol |
|---|---|---|
| C2 sunucusu | `server/` | Log toplama, politika dağıtımı, OTA, enrollment/PKI |
| Uç nokta ajanı | `agent/` | Politika uygulama, olay toplama, ağ keşfi |
| Watchdog | `agent/cmd/watchdog` + `internal/watchdog` | Ajanı canlı tutar + OTA swap/rollback (ilk savunma) |
| Proto sözleşmeleri | `proto/kut/v1` | gRPC servis + mesaj tanımları |
| Veritabanı | `db/` | Düzeltilmiş PostgreSQL şeması + migration'lar |
| Dokümantasyon | `docs/` | Mimari, tehdit modeli, KVKK notları |

## Gereksinimler (geliştirme)

- Go 1.26+
- [buf](https://buf.build) (proto üretimi) veya protoc + eklentiler
- PostgreSQL 14+ (`uuid-ossp`, `pgcrypto` eklentileri)

## Hızlı başlangıç

```bash
# 1) Proto kodunu üret
make proto

# 2) Bağımlılıkları düzenle
make tidy

# 3) İkilileri derle
make build        # bin/c2, bin/agent, bin/watchdog

# 4) Veritabanı şemasını kur
KUT_DATABASE_URL="postgres://postgres@localhost/kut" go run ./server/cmd/kutctl migrate up   # bkz. db/README.md
```

## Kurulum ve dağıtım ✅

Tam akış: **[deploy/README.md](deploy/README.md)**.

- **Release:** `scripts/build-release.sh 1.0.0` — c2/agent/watchdog/gencerts
  Windows+Linux için çapraz derlenir (`dist/`).
- **Sunucu (C2):** `deploy/server/install-linux.sh` (systemd) /
  `install-windows.ps1` (zamanlanmış görev) — PKI + ana anahtar + config + servis
  otomatik.
- **İstemci (agent):** `tools/mkclient` her cihaz için **tek-dosya** kurulum betiği
  üretir — **benzersiz** (enrollment token gömülü, otomatik kaydolur) veya
  **paylaşımlı** (kod girişli); ajan ikilisi base64 gömülü, servisi kurar.
  Windows (`.ps1`) + Linux (`.sh`).

## Yapılandırma (ortam değişkenleri)

Tüm ayarlar ortam değişkenleriyle yapılır. Tam liste + açıklama:
**[deploy/server/c2.env.example](deploy/server/c2.env.example)** (sunucu) ve
**[deploy/agent.env.example](deploy/agent.env.example)** (ajan).

- **Zorunlu (sunucu):** `KUT_MASTER_KEY` (32 bayt base64), TLS yolları
  (`KUT_CA_CERT`/`KUT_CA_KEY`/`KUT_SERVER_CERT`/`KUT_SERVER_KEY`); üretim için
  `KUT_DATABASE_URL` (boşsa `KUT_DEMO=1` ile bellek-içi demo).
- **Opsiyonel korumalar (sunucu):** `KUT_ALERT_WEBHOOK_URL`/`KUT_ALERT_FORMAT`
  (SOC uyarı, Slack/Teams), `KUT_AUTO_RESPONSE` (SOAR oto-karantina), `KUT_IOC_FILE`
  (tehdit istihbaratı), `KUT_DETECT_RULES_FILE` (özel tespit kuralları),
  `KUT_METRICS_TOKEN` (Prometheus), `KUT_LOG_FORMAT=json` (SIEM),
  **çift-kontrol (dört-göz) WIPE varsayılan AÇIK** — tek-admin doğrudan WIPE'a
  izin vermek için `KUT_WIPE_SINGLE_ADMIN_UNSAFE=1` (güvensiz), **Scope/ROE guardrail** (§4):
  `KUT_SCOPE_ENFORCE=1` + `KUT_SCOPE_ALLOW_DEVICES/TENANTS/NETWORKS/DOMAINS/…`
  ve `KUT_SCOPE_ALLOW_DESTRUCTIVE=1`.
- **Ajan:** bağlantı (`KUT_ENROLL_ADDR`/`KUT_AGENT_ADDR`/`KUT_SERVER_NAME`/`KUT_CA_PEM`),
  `KUT_SERVER_SPKI_PIN` (pinning), `KUT_UPDATE_PUBKEY`/`KUT_SCRIPT_PUBKEY` (imza),
  `KUT_ANOMALY_*`, `KUT_SAFE_MODE`, `KUT_LOG_FORMAT`.

Etkin korumaları konsoldan (Yönetim → **Koruma Katmanları**) veya `GET /api/features`
ile görebilirsiniz.

## Belgeler

Mimari: [docs/architecture.md](docs/architecture.md).
İnceleme bulguları ve karşılığında alınan kararlar [docs/threat-model.md](docs/threat-model.md)
içinde. Harici log alımı entegrasyonu için [docs/INGEST.md](docs/INGEST.md);
ONNX model entegrasyonu için [docs/ONNX.md](docs/ONNX.md); çekirdek-seviye kurcalama
koruması tasarımı için [docs/KERNEL-TAMPER.md](docs/KERNEL-TAMPER.md); Lite/Enterprise
derleme katmanları için [docs/BUILD-TIERS.md](docs/BUILD-TIERS.md); marka ve
uygulama ikonu üretimi için [docs/BRANDING.md](docs/BRANDING.md).

## Sürüm doğrulama / Release verification

Resmî ikilileri **GitHub Releases** üzerinden yayımlıyoruz. Bir `v*` etiketi push
edildiğinde [.github/workflows/release.yml](.github/workflows/release.yml) çapraz-derler,
her platformu arşivler (windows → `.zip`, linux → `.tar.gz`) ve **`SHA256SUMS`** üretir.
GPG anahtarı yapılandırılmışsa ayrıca ayrık imza **`SHA256SUMS.asc`** eklenir.

İndirdiğiniz arşivlerin bütünlüğünü doğrulayın:

```bash
# 1) Aynı dizine arşivleri + SHA256SUMS'u indirin, sonra:
sha256sum -c SHA256SUMS            # her arşiv için "OK" bekleyin

# 2) (Varsa) GPG imzasını doğrulayın — önce yayımcı anahtarını içe aktarın:
gpg --verify SHA256SUMS.asc SHA256SUMS
```

> **Not:** `SHA256SUMS`/`SHA256SUMS.asc` yalnızca **bütünlük** (tampering) doğrulamasıdır;
> Windows **Authenticode** kod-imzalama (EV/OV sertifika + zaman damgası) ayrı bir
> konudur ve ticari dağıtımda ele alınır — bkz. [docs/KERNEL-TAMPER.md](docs/KERNEL-TAMPER.md).

---

# English

Endpoint security and management platform designed for authorized corporate
environments (company-owned devices, a notified usage policy, IT management).
Single language: **Go**. Agent ↔ C2 communication over **gRPC + mTLS** (TLS 1.3).

> **Status: feature-complete, CI green, deployment-ready.**
>
> - **1088 tests (+16 fuzz) / 111 packages** pass; **CI** (`.github/workflows/ci.yml`) runs
>   `go vet` + `-race` tests + **end-to-end smoke** + **DB test against a real PostgreSQL** +
>   cross-compilation + **both build tiers (Lite/Enterprise)** on every push — all green.
> - End-to-end proven chain: enroll (PKI) → mTLS heartbeat (server-clock) → event →
>   policy push → OTA signature + rollout → command delivery → single-use token
>   (`server/internal/e2e`, `make e2e`).
> - **Security:** HMAC blind index, AES-256-GCM field encryption, Argon2id passwords,
>   Ed25519 OTA/script signing, RBAC + immutable (hash-chained) audit log, login
>   brute-force protection, admin 2FA (TOTP), mTLS server SPKI pinning, hardened
>   security headers (HSTS/CSP nonce).
> - **Detection & response:** MITRE ATT&CK mapping, server-side detection rules
>   (YAML-like) + **Detection-as-Code** lifecycle + **YAML import**, pure-Go
>   **YARA-style content scanning** (signed rules), IoC threat intelligence
>   (confidence/source), behavioral anomaly detection, C2 beacon detection, SOAR
>   auto-quarantine, SOC webhook alerting (**routing + escalation + HMAC signing**),
>   SIEM (CEF/LEEF), Prometheus `/metrics`.
> - **SOC intelligence:** multi-signal **correlation** (high-confidence attack chains),
>   multi-factor **risk scoring**, **attack story** (kill-chain), **entity graph**,
>   **incident timeline**, **MTTD/MTTR** trends, **UEBA** (privileged-user behavior
>   analytics), compliance-framework mapping (**CIS/NIST/ISO 27001/KVKK**), maintenance/
>   suppression windows.
> - **Supply-chain security (CI):** `govulncheck` (dependency CVEs), **fuzzing**
>   (critical parsers), **SBOM** (CycloneDX), gosec; rate limiting, tamper-evident
>   signed audit export, signed offline offboarding, multi-tenant output attribution.
> - **Data protection (KVKK/GDPR-style):** at-rest encryption + partition-based
>   retention; **data-subject rights** (access/export + erasure, audit preserved).
> - **Console:** embedded single-page SOC dashboard — devices/events/policies/admins,
>   **TR/EN language toggle** (GDPR/KVKK language-aware privacy notice),
>   device tagging, **live SSE push**, severity chart, search, CSV export, health
>   endpoints (`/healthz`, `/readyz`).
> - **Deployment:** cross-compilation + single-file client installer generator (token
>   embedded or code-entry, Win/Linux) + server install scripts — see
>   **[deploy/README.md](deploy/README.md)**.
> - Third-party licenses (copyright compliance): **[docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md)**
>   (all permissive; no copyleft).

## Components

| Component | Directory | Role |
|---|---|---|
| C2 server | `server/` | Log collection, policy distribution, OTA, enrollment/PKI |
| Endpoint agent | `agent/` | Policy enforcement, event collection, network discovery |
| Watchdog | `agent/cmd/watchdog` + `internal/watchdog` | Keeps the agent alive + OTA swap/rollback (first line of defense) |
| Proto contracts | `proto/kut/v1` | gRPC service + message definitions |
| Database | `db/` | Corrected PostgreSQL schema + migrations |
| Documentation | `docs/` | Architecture, threat model, data-protection notes |

## Requirements (development)

- Go 1.26+
- [buf](https://buf.build) (proto generation) or protoc + plugins
- PostgreSQL 14+ (`uuid-ossp`, `pgcrypto` extensions)

## Quick start

```bash
# 1) Generate proto code
make proto

# 2) Tidy dependencies
make tidy

# 3) Build the binaries
make build        # bin/c2, bin/agent, bin/watchdog

# 4) Install the database schema
KUT_DATABASE_URL="postgres://postgres@localhost/kut" go run ./server/cmd/kutctl migrate up   # see db/README.md
```

## Installation & deployment ✅

Full flow: **[deploy/README.md](deploy/README.md)**.

- **Release:** `scripts/build-release.sh 1.0.0` — c2/agent/watchdog/gencerts
  cross-compiled for Windows+Linux (`dist/`).
- **Server (C2):** `deploy/server/install-linux.sh` (systemd) /
  `install-windows.ps1` (scheduled task) — PKI + master key + config + service
  set up automatically.
- **Client (agent):** `tools/mkclient` produces a **single-file** installer per
  device — **unique** (enrollment token embedded, auto-enrolls) or **shared**
  (code-entry); the agent binary is base64-embedded and installs the service.
  Windows (`.ps1`) + Linux (`.sh`).

## Configuration (environment variables)

All settings are via environment variables. Full list + descriptions:
**[deploy/server/c2.env.example](deploy/server/c2.env.example)** (server) and
**[deploy/agent.env.example](deploy/agent.env.example)** (agent).

- **Required (server):** `KUT_MASTER_KEY` (32-byte base64), TLS paths
  (`KUT_CA_CERT`/`KUT_CA_KEY`/`KUT_SERVER_CERT`/`KUT_SERVER_KEY`); for production
  `KUT_DATABASE_URL` (if empty, in-memory demo with `KUT_DEMO=1`).
- **Optional protections (server):** `KUT_ALERT_WEBHOOK_URL`/`KUT_ALERT_FORMAT`
  (SOC alerting, Slack/Teams), `KUT_AUTO_RESPONSE` (SOAR auto-quarantine),
  `KUT_IOC_FILE` (threat intel), `KUT_DETECT_RULES_FILE` (custom detection rules),
  `KUT_METRICS_TOKEN` (Prometheus), `KUT_LOG_FORMAT=json` (SIEM).
- **Agent:** connection (`KUT_ENROLL_ADDR`/`KUT_AGENT_ADDR`/`KUT_SERVER_NAME`/`KUT_CA_PEM`),
  `KUT_SERVER_SPKI_PIN` (pinning), `KUT_UPDATE_PUBKEY`/`KUT_SCRIPT_PUBKEY` (signing),
  `KUT_ANOMALY_*`, `KUT_SAFE_MODE`, `KUT_LOG_FORMAT`.

You can see which protections are enabled from the console (Management → **Protection
Layers**) or via `GET /api/features`.

## Documentation

Architecture: [docs/architecture.md](docs/architecture.md). Review findings
and the decisions taken in response are in [docs/threat-model.md](docs/threat-model.md).
For external log ingest integration, see [docs/INGEST.md](docs/INGEST.md); for ONNX
model integration, see [docs/ONNX.md](docs/ONNX.md); for kernel-level tamper-protection
design, see [docs/KERNEL-TAMPER.md](docs/KERNEL-TAMPER.md); for the Lite/Enterprise build
tiers, see [docs/BUILD-TIERS.md](docs/BUILD-TIERS.md); for branding and application
icon generation, see [docs/BRANDING.md](docs/BRANDING.md).

## Release verification

Official binaries are published via **GitHub Releases**. When a `v*` tag is pushed,
[.github/workflows/release.yml](.github/workflows/release.yml) cross-compiles, archives
each platform (windows → `.zip`, linux → `.tar.gz`), and emits **`SHA256SUMS`**. If a
GPG key is configured, a detached signature **`SHA256SUMS.asc`** is attached as well.

Verify the integrity of the archives you download:

```bash
# 1) Download the archives + SHA256SUMS into the same directory, then:
sha256sum -c SHA256SUMS            # expect "OK" for each archive

# 2) (If present) verify the GPG signature — import the publisher key first:
gpg --verify SHA256SUMS.asc SHA256SUMS
```

> **Note:** `SHA256SUMS`/`SHA256SUMS.asc` provide **integrity** (tamper) verification
> only; Windows **Authenticode** code-signing (EV/OV certificate + timestamp) is a
> separate concern handled for commercial distribution — see
> [docs/KERNEL-TAMPER.md](docs/KERNEL-TAMPER.md).

## Lisans / License

Bu proje **Apache License 2.0** ile lisanslanmıştır — bkz. [LICENSE](LICENSE) ve
[NOTICE](NOTICE). Üçüncü taraf bileşenlerin lisansları
[docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md) içindedir.

This project is licensed under the **Apache License 2.0** — see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Third-party component licenses are listed in
[docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md).

```
Copyright 2026 Cihan Uralkaya

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
