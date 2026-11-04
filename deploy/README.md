# KUT Security Suite — Dağıtım ve Kurulum
# KUT Security Suite — Deployment & Installation

**Türkçe** · [English](#english)

Bu dizin, sunucu (C2) ve uç istemci (agent) kurulum akışını içerir. Tüm ikililer
tek dilde (Go) çapraz derlenir; kurulum betikleri **tek dosya, kendi kendine
yeten** olacak şekilde üretilir.

## 1. Release ikililerini derle

```bash
scripts/build-release.sh 1.0.0
```

Çıktı: `dist/<os>-<arch>/` altında `c2`, `agent`, `watchdog`, `gencerts`
(Windows ve Linux, amd64). `VERSION` ajan sürümüne damgalanır.

## 2. Sunucuyu (C2) kur

Sunucu ikililerini (`c2`, `gencerts`) hedef makineye kopyala; kurulum betiğini
yanına koy ve çalıştır. Betik: PKI üretir, 32 baytlık ana anahtar + rastgele
yönetici parolası üretir, yapılandırmayı yazar, servisi kurar ve başlatır.

**Linux (systemd):**
```bash
sudo deploy/server/install-linux.sh kut-c2      # arg: sertifika SAN adı
```

**Windows (zamanlanmış görev, SYSTEM):**
```powershell
.\deploy\server\install-windows.ps1 -ServerName kut-c2
```

Kurulum sonunda konsol girişi (admin@local / üretilen parola) ekrana yazılır.
Yönetim konsolu: `https://<sunucu>:8445/`

> Üretim: `KUT_DATABASE_URL` ayarlayıp PostgreSQL'e geçin ve yöneticiyi
> `tools/adminseed` ile ekleyin (bkz. `db/README.md`). Boş bırakılırsa
> **bellek-içi demo modu** (kalıcılık yok) çalışır.

## 3. İstemci (agent) setup'ı üret

Konsoldan bir **enrollment token** üretin, sonra `mkclient` ile hedef cihaz için
kurulum dosyası oluşturun. İki mod:

- **Benzersiz setup** (`-token <TOKEN>`): token betiğe gömülür; kullanıcı yalnız
  çalıştırır, otomatik kaydolur. Her cihaz için ayrı üretilir.
- **Paylaşımlı setup** (`-token` verilmez): tek betik birçok cihaza dağıtılır;
  çalışırken kullanıcıdan kayıt kodu istenir.

Ajan ikilisi `-agent` ile verilirse base64 **gömülür** (gerçek tek dosya).

**Windows (benzersiz, ajan gömülü):**
```bash
mkclient -os windows -server c2.sirket.local \
  -ca /etc/kut/pki/ca.crt -agent dist/windows-amd64/agent.exe \
  -token ABC123... -out kut-agent-setup.ps1
```
Hedefte (Yönetici): `.\kut-agent-setup.ps1`

**Linux (paylaşımlı, kod girişli):**
```bash
mkclient -os linux -server c2.sirket.local \
  -ca /etc/kut/pki/ca.crt -agent dist/linux-amd64/agent \
  -out kut-agent-setup.sh
```
Hedefte (root): `sudo ./kut-agent-setup.sh` → kayıt kodunu girin.

Tüm ajan ortam değişkenleri: `deploy/agent.env.example`.

`-safe-mode` bayrağı: karantina gerçek ağ değişikliği yapmaz (test/dağıtım
başlangıcı için güvenli).

## Yatay ölçekleme (çok-düğüm / HA)

Tek düğüm yükü kaldırmaya yetmezse birden çok C2 düğümü bir yük dengeleyici
arkasında koşabilir. Gereksinimler ve davranış:

- **Paylaşılan PostgreSQL zorunlu.** Tüm düğümler aynı `KUT_DATABASE_URL`'i
  kullanır (bellek-içi demo modu çok-düğümde çalışmaz). Şema tek sefer yüklenir.
- **`KUT_CLUSTER=1`** ile canlı konsol akışı (SSE) düğümler arası **Postgres
  LISTEN/NOTIFY** ile fan-out edilir: bir ajanın olayı hangi düğüme gelirse
  gelsin, tüm düğümlerdeki admin konsolları anında görür. Kanal adı
  `KUT_CLUSTER_CHANNEL` (varsayılan `kut_notice`).
- **Ajan/enroll trafiği durumsuzdur** — herhangi bir düğüme dengelenebilir (mTLS
  kimliği ve komut kuyruğu DB'dedir). Sertifika iptali her düğümde DB'den
  periyodik tazelenir.
- **Admin konsolu (SSE)** uzun-ömürlü bir bağlantıdır; yük dengeleyicide oturum
  yapışkanlığı (sticky session) önerilir — akışın koptuğunda konsol otomatik
  yeniden bağlanır ve periyodik yenileme tutarlılığı yakalar.
- `/api/features` → `cluster_enabled: true` ve konsol sistem kartındaki "Yatay
  ölçekleme" satırı fan-out'un etkin olduğunu doğrular.

## Kurulan konumlar

| | Sunucu | Ajan |
|---|---|---|
| Linux ikili | `/opt/kut/c2` | `/opt/kut-agent/agent` |
| Linux yapılandırma | `/etc/kut/` | `/etc/kut-agent/` |
| Linux servis | `kut-c2.service` | `kut-agent.service` |
| Windows ikili | `%ProgramFiles%\KUT Server\` | `%ProgramFiles%\KUT Agent\` |
| Windows servis | Görev: `KUT C2 Server` | Görev: `KUT Agent` |

## Güvenlik notları

- Ana anahtar (`KUT_MASTER_KEY`) ve CA özel anahtarı yalnız sunucuda kalır;
  yapılandırma dosyaları `600` izinlidir.
- Ajan setup'ı CA sertifikasını (genel) ve tek-kullanımlık enrollment token'ı
  taşır — özel anahtar taşımaz. Token kaydolunca tüketilir.
- mTLS TLS 1.3; ajan kimliği enrollment'ta CSR ile üretilir, özel anahtar
  cihazdan çıkmaz.

---

# English

This directory contains the installation flow for the server (C2) and the endpoint
client (agent). All binaries are cross-compiled in a single language (Go); the
install scripts are generated to be **single-file, self-contained**.

## 1. Build the release binaries

```bash
scripts/build-release.sh 1.0.0
```

Output: `c2`, `agent`, `watchdog`, `gencerts` under `dist/<os>-<arch>/` (Windows and
Linux, amd64). `VERSION` is stamped into the agent version.

## 2. Install the server (C2)

Copy the server binaries (`c2`, `gencerts`) to the target machine; place the install
script alongside and run it. The script generates PKI, a 32-byte master key + a random
admin password, writes the configuration, and installs and starts the service.

**Linux (systemd):**
```bash
sudo deploy/server/install-linux.sh kut-c2      # arg: certificate SAN name
```

**Windows (scheduled task, SYSTEM):**
```powershell
.\deploy\server\install-windows.ps1 -ServerName kut-c2
```

At the end of installation the console login (admin@local / generated password) is
printed to the screen. Admin console: `https://<server>:8445/`

> Production: set `KUT_DATABASE_URL` to switch to PostgreSQL and add the admin with
> `tools/adminseed` (see `db/README.md`). If left empty, an **in-memory demo mode**
> (no persistence) runs.

## 3. Generate the client (agent) setup

Generate an **enrollment token** from the console, then build an installer for the
target device with `mkclient`. Two modes:

- **Unique setup** (`-token <TOKEN>`): the token is embedded in the script; the user
  just runs it and it auto-enrolls. Generated separately per device.
- **Shared setup** (no `-token`): a single script is distributed to many devices; it
  prompts the user for an enrollment code at runtime.

If the agent binary is provided with `-agent`, it is base64-**embedded** (a true
single file).

**Windows (unique, agent embedded):**
```bash
mkclient -os windows -server c2.company.local \
  -ca /etc/kut/pki/ca.crt -agent dist/windows-amd64/agent.exe \
  -token ABC123... -out kut-agent-setup.ps1
```
On the target (Administrator): `.\kut-agent-setup.ps1`

**Linux (shared, code-entry):**
```bash
mkclient -os linux -server c2.company.local \
  -ca /etc/kut/pki/ca.crt -agent dist/linux-amd64/agent \
  -out kut-agent-setup.sh
```
On the target (root): `sudo ./kut-agent-setup.sh` -> enter the enrollment code.

All agent environment variables: `deploy/agent.env.example`.

The `-safe-mode` flag: quarantine makes no real network changes (safe for
testing / the start of a rollout).

## Horizontal scale (multi-node / HA)

When one node is not enough, multiple C2 nodes can run behind a load balancer.
Requirements and behavior:

- **Shared PostgreSQL is mandatory.** All nodes use the same `KUT_DATABASE_URL`
  (the in-memory demo mode does not work multi-node). Load the schema once.
- **`KUT_CLUSTER=1`** fans out the live console stream (SSE) across nodes via
  **Postgres LISTEN/NOTIFY**: whichever node an agent's event lands on, every
  node's admin console sees it instantly. Channel name via `KUT_CLUSTER_CHANNEL`
  (default `kut_notice`).
- **Agent/enroll traffic is stateless** — it can be balanced to any node (mTLS
  identity and the command queue live in the DB). Certificate revocation is
  refreshed from the DB on each node periodically.
- **The admin console (SSE)** is a long-lived connection; sticky sessions are
  recommended at the load balancer — the console auto-reconnects if the stream
  drops and periodic refresh reconciles state.
- `/api/features` → `cluster_enabled: true` and the "Horizontal scale" row on the
  console system card confirm the fan-out is active.

## Installed locations

| | Server | Agent |
|---|---|---|
| Linux binary | `/opt/kut/c2` | `/opt/kut-agent/agent` |
| Linux config | `/etc/kut/` | `/etc/kut-agent/` |
| Linux service | `kut-c2.service` | `kut-agent.service` |
| Windows binary | `%ProgramFiles%\KUT Server\` | `%ProgramFiles%\KUT Agent\` |
| Windows service | Task: `KUT C2 Server` | Task: `KUT Agent` |

## Security notes

- The master key (`KUT_MASTER_KEY`) and the CA private key stay on the server only;
  configuration files have `600` permissions.
- The agent setup carries the CA certificate (public) and a single-use enrollment
  token - it carries no private key. The token is consumed once enrollment succeeds.
- mTLS TLS 1.3; the agent identity is produced via a CSR at enrollment, and the
  private key never leaves the device.
