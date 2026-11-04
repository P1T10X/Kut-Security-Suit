# KUT Sertleştirme (Hardening) Kılavuzu

Bir güvenlik ürünü olarak KUT'in kendisi kritik bir saldırı yüzeyidir. Bu belge,
C2 sunucusu ve uç-nokta ajanı için üretim sertleştirme duruşunu tanımlar.

## 1. Tehdit modeli özeti

- **C2 sunucusu:** ayrıcalıksız kullanıcı-alanı ağ hizmeti. Hiçbir özel yeteneğe
  ihtiyaç duymaz → agresif kum-havuzu uygulanabilir.
- **Ajan:** EDR/MDM ürünü; geniş ayrıcalık gerektirir (süreç görünürlüğü, firewall/
  USB yönetimi, kripto-silme). Over-hardening ajanı işlevsiz bırakır → seçici koruma.

## 2. Linux — systemd sandbox

Referans birimler: [`systemd/kut-c2.service`](systemd/kut-c2.service) ve
[`systemd/kut-agent.service`](systemd/kut-agent.service).

**C2 (agresif):** `NoNewPrivileges`, boş `CapabilityBoundingSet`, `ProtectSystem=strict`,
`PrivateTmp`, `PrivateDevices`, `ProtectKernel*`, `RestrictNamespaces`,
`MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
`SystemCallFilter=@system-service` (privileged/resources hariç). Ayrıcalıksız
`kut` kullanıcısıyla çalıştırın.

Doğrulama:
```bash
systemd-analyze security kut-c2.service    # hedef: düşük exposure
```

**Ajan (seçici):** EDR işlevini bozmayan korumalar açık (`NoNewPrivileges`,
`ProtectKernelModules/Tunables`, `LockPersonality`); FIM/süreç-telemetri/WIPE için
gereken erişimler (tüm dosya sistemi, tüm `/proc`, blok cihazlar, geniş caps)
BİLİNÇLİ olarak açık bırakılır. Gerekçeler birim dosyasında satır-satır belgelidir.

## 3. Linux — MAC (AppArmor / SELinux)

- C2 için sıkı bir AppArmor profili: yalnız `/opt/kut/c2`, `/etc/kut/**` (r),
  `/var/lib/kut/**` (rw), ağ soketleri; gerisi reddedilir.
- Ajan için AppArmor "complain" modunda başlayıp telemetri toplandıkça
  daraltılmalı; EDR geniş okuma gerektirdiğinden profil dosya-okumayı kısıtlamaz,
  yazma/exec yüzeyini daraltır.

## 4. Windows — hizmet sertleştirme

- **Kod imzalama:** her iki ikili de Authenticode ile imzalanmalı (OTA zaten
  Ed25519 imza doğrular; OS-seviyesi imza ek katmandır).
- **Servis hesabı:** C2 için `NT SERVICE\kut-c2` sanal hesabı, minimum haklar.
- **WDAC / AppLocker:** ajan ikilisi allowlist'e alınmalı; imzasız ikili yürütme
  reddedilmeli (ajanın imzalı-script/OTA kapıları bunu tamamlar).
- **Protected Process Light (PPL) / ELAM:** ajanın kurcalamaya karşı korunması için
  hedeflenen ileri faz (sürücü + ELAM sertifikası) — mevcut watchdog + öz-tasdik
  (#4) yazılım-seviyesi ilk savunmadır.
- **Uninstall koruması:** servis silme/durdurma için yönetici + (ileride) tamper
  parolası.

## 5. Sırlar (secrets)

- Üretimde `KUT_MASTER_KEY`, `KUT_MASTER_KEY_OLD` ve `KUT_DATABASE_URL` düz-metin
  env yerine DOSYA-TABANLI sır olarak verilebilir: `KUT_MASTER_KEY_FILE=/path`
  (env öncelikli; yoksa dosya okunur, içerik kırpılır). systemd `LoadCredential=`,
  Docker/K8s secrets ve Vault agent bu dosyaları sağlar — böylece sır
  `/proc/<pid>/environ` veya `ps` üzerinden sızmaz.
  Açılışta migrasyon (`KUT_MIGRATE_ON_START=1`) için şema sahibi bağlantısı da aynı şekilde
  `KUT_MIGRATE_DATABASE_URL_FILE` ile verilmelidir; uygulama bağlantısından ayrıdır.
  Örnek (systemd): `LoadCredential=mk:/etc/kut/master.key` +
  `Environment=KUT_MASTER_KEY_FILE=%d/mk`.
- CA özel anahtarı ve imzalama anahtarları da benzer şekilde bir KMS/Vault'ta
  tutulmalı (dosya-tabanlı erişim veya kısa-ömürlü materyal).
- Alan-şifreleme (at-rest) + KDF zaten uygulanır; anahtar rotasyonu için keyring
  (#9) mevcuttur.

## 6. Ağ

- C2 yalnız gerekli portları (agent/enroll/admin mTLS) dinlemeli; admin ucu ayrı
  bir ağ segmentine/VPN'e alınmalı.
- Sunucu SPKI pinning (`KUT_SERVER_SPKI_PIN`) savunma derinliği için önerilir.

## 7. Kalan saldırı yüzeyi (residual)

- Ajan root çalışır; OS-çekirdek düzeyinde tam tamper-koruması (sürücü/PPL/ELAM)
  ayrı bir fazdır. Mevcut savunma: watchdog karşılıklı gözetim, öz-tasdik,
  kalıcılık izleme, imzalı offline offboard (yalnız yetkiyle stand-down).
- Bu belge, `systemd-analyze security` ve CI güvenlik taraması (govulncheck +
  fuzz + SBOM) ile periyodik gözden geçirilmelidir.
