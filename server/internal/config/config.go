// Package config, C2 sunucusunun yapılandırmasını ortam değişkenlerinden yükler.
package config

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"kut.corp/suite/server/internal/tenant"
)

// Config, C2 sunucusunun çalışma-zamanı ayarlarıdır.
type Config struct {
	// mTLS'li AgentService dinleyicisi (kayıtlı ajanlar).
	ListenAgent string
	// Tek yönlü TLS'li EnrollmentService dinleyicisi (henüz sertifikası olmayan ajanlar).
	ListenEnroll string
	// TLS'li admin HTTP API dinleyicisi.
	ListenAdmin string

	// Admin oturum token'ı ve enrollment token ömürleri.
	AdminSessionTTL time.Duration
	EnrollTokenTTL  time.Duration

	// event_logs saklama süresi (gün) — dolan partition'lar DROP edilir (KVKK).
	RetentionDays int

	// Giriş kaba-kuvvet koruması: istemci başına izin verilen başarısız deneme ve
	// eşik aşılınca kilit süresi.
	LoginMaxAttempts int
	LoginLockout     time.Duration

	// PostgreSQL bağlantı dizesi (pgx DSN / URL).
	DatabaseURL string

	// MigrateDatabaseURL is the owner-role connection string used only by migrate-on-start
	// (KUT_MIGRATE_DATABASE_URL or KUT_MIGRATE_DATABASE_URL_FILE). Empty means the migration
	// runs with DatabaseURL.
	MigrateDatabaseURL string

	// PEM dosya yolları.
	CACertPath     string // istemci sertifikalarını imzalayan CA
	CAKeyPath      string
	ServerCertPath string // gRPC sunucu (TLS) sertifikası
	ServerKeyPath  string

	// Ana anahtar (32 bayt), base64. Alan şifreleme ve blind index alt
	// anahtarları bundan türetilir. Diske DÜZ yazılmaz; ortamdan/sır yöneticisinden gelir.
	MasterKey []byte

	// Eski ana anahtarlar (anahtar rotasyonu örtüşmesi): KUT_MASTER_KEY_OLD,
	// virgülle ayrılmış base64 32-baytlık anahtarlar. Yeni veri MasterKey ile
	// şifrelenir; eski veri bu anahtarlarla ÇÖZÜLMEYE devam eder (veri kaybı yok).
	// Tüm eski veri yeniden şifrelendikten sonra kaldırılabilir.
	MasterKeysOld [][]byte

	// İmzalanan istemci sertifikalarının ömrü (kısa ömür + yenileme modeli).
	ClientCertTTL time.Duration

	// TenantID, bu dağıtımın kiracı kimliğidir (çok-kiracılı temel).
	// KUT_TENANT_ID; belirtilmezse "default" (tek-kiracılı, geriye uyumlu).
	TenantID string
	// TenantEnforce, çok-müşteri SaaS için sıkı kiracı zorlamasıdır (KUT_TENANT_ENFORCE=1).
	// Açıkken, kiracıya bağlı OLMAYAN bir cihazın olayları REDDEDİLİR (sunucu-varsayılana
	// sessizce atıflanıp cross-tenant karışma yaratmaz; INV-044 missing→DENY). Varsayılan
	// kapalı → tek-tenant/geriye-uyumlu (kiracısız cihaz sunucu kiracısına düşer).
	TenantEnforce bool
}

// Load, ortam değişkenlerinden Config üretir ve doğrular.
func Load() (*Config, error) {
	c := &Config{
		ListenAgent:      getenv("KUT_LISTEN_AGENT", ":8443"),
		ListenEnroll:     getenv("KUT_LISTEN_ENROLL", ":8444"),
		ListenAdmin:      getenv("KUT_LISTEN_ADMIN", ":8445"),
		AdminSessionTTL:  getdur("KUT_ADMIN_SESSION_TTL", 12*time.Hour),
		EnrollTokenTTL:   getdur("KUT_ENROLL_TOKEN_TTL", 24*time.Hour),
		CACertPath:       os.Getenv("KUT_CA_CERT"),
		CAKeyPath:        os.Getenv("KUT_CA_KEY"),
		ServerCertPath:   os.Getenv("KUT_SERVER_CERT"),
		ServerKeyPath:    os.Getenv("KUT_SERVER_KEY"),
		ClientCertTTL:    getdur("KUT_CLIENT_CERT_TTL", 720*time.Hour), // 30 gün
		RetentionDays:    getint("KUT_RETENTION_DAYS", 90),
		LoginMaxAttempts: getint("KUT_LOGIN_MAX_ATTEMPTS", 5),
		LoginLockout:     getdur("KUT_LOGIN_LOCKOUT", 15*time.Minute),
	}

	// Hassas değerler ya doğrudan env'den ya da <KEY>_FILE dosyasından okunur
	// (systemd LoadCredential / Docker-K8s secrets / Vault agent — düz-metin env
	// yerine dosya-tabanlı sır; bkz. deploy/HARDENING.md).
	dbURL, err := secretEnv("KUT_DATABASE_URL")
	if err != nil {
		return nil, err
	}
	c.DatabaseURL = dbURL

	migrateURL, err := secretEnv("KUT_MIGRATE_DATABASE_URL")
	if err != nil {
		return nil, err
	}
	c.MigrateDatabaseURL = migrateURL

	mk, err := secretEnv("KUT_MASTER_KEY")
	if err != nil {
		return nil, err
	}
	if mk == "" {
		return nil, fmt.Errorf("config: KUT_MASTER_KEY zorunlu (env veya KUT_MASTER_KEY_FILE)")
	}
	key, err := base64.StdEncoding.DecodeString(mk)
	if err != nil {
		return nil, fmt.Errorf("config: KUT_MASTER_KEY base64 çözülemedi: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("config: KUT_MASTER_KEY 32 bayt olmalı (base64 çözülünce), %d bayt", len(key))
	}
	c.MasterKey = key

	// Eski ana anahtarlar (rotasyon örtüşmesi; opsiyonel). Dosya-tabanlı sır da desteklenir.
	old, err := secretEnv("KUT_MASTER_KEY_OLD")
	if err != nil {
		return nil, err
	}
	if old != "" {
		for _, part := range strings.Split(old, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			ok, err := base64.StdEncoding.DecodeString(part)
			if err != nil {
				return nil, fmt.Errorf("config: KUT_MASTER_KEY_OLD base64 çözülemedi: %w", err)
			}
			if len(ok) != 32 {
				return nil, fmt.Errorf("config: KUT_MASTER_KEY_OLD her anahtar 32 bayt olmalı, %d bayt", len(ok))
			}
			c.MasterKeysOld = append(c.MasterKeysOld, ok)
		}
	}

	// Hassas değerler başarıyla yüklendikten sonra ortamdan temizlenir.
	// Bu, çekirdek dökümleri (core dumps), alt süreçlerin (subprocess)
	// ortamı miras alması veya /proc/environ sızıntılarını önler.
	clearSecretEnv()

	// Zorunlu TLS materyali yolları — erken, anlaşılır hata (yanlış-yapılandırmayı
	// başlangıçta yakala; demo modu dahil gRPC sunucuları TLS gerektirir).
	for _, m := range []struct{ name, val string }{
		{"KUT_CA_CERT", c.CACertPath}, {"KUT_CA_KEY", c.CAKeyPath},
		{"KUT_SERVER_CERT", c.ServerCertPath}, {"KUT_SERVER_KEY", c.ServerKeyPath},
	} {
		if m.val == "" {
			return nil, fmt.Errorf("config: %s zorunlu (TLS materyali yolu)", m.name)
		}
	}

	// Anahtar dosyası izinleri VARSAYILAN olarak fail-closed zorunludur: güvensiz
	// izin (ör. 0644) başlatmayı DURDURUR. Operatör bilerek kabul ediyorsa
	// KUT_ALLOW_INSECURE_KEY_PERMISSIONS=1 ile gevşetebilir (önerilmez → yalnız uyarı).
	// Önceki sürüm varsayılan uyarı-only idi (fail-open); projenin fail-closed etiğine
	// aykırıydı. Windows'ta checkKeyPermissions no-op (ACL kullanılır).
	allowInsecure := os.Getenv("KUT_ALLOW_INSECURE_KEY_PERMISSIONS") == "1"
	for _, keyPath := range []string{c.CAKeyPath, c.ServerKeyPath} {
		if err := checkKeyPermissions(keyPath); err != nil {
			if !allowInsecure {
				return nil, fmt.Errorf("config: %w — izinleri 0600/0400 yapın ya da bilerek kabul için KUT_ALLOW_INSECURE_KEY_PERMISSIONS=1", err)
			}
			log.Printf("[UYARI] Güvensiz anahtar izinleri (KUT_ALLOW_INSECURE_KEY_PERMISSIONS=1 ile kabul edildi): %v", err)
		}
	}
	// Sayısal alanlar makul olmalı (0/negatif değer sessiz hataya yol açar).
	if c.RetentionDays < 1 {
		return nil, fmt.Errorf("config: KUT_RETENTION_DAYS >= 1 olmalı, %d verildi", c.RetentionDays)
	}
	if c.LoginMaxAttempts < 1 {
		return nil, fmt.Errorf("config: KUT_LOGIN_MAX_ATTEMPTS >= 1 olmalı, %d verildi", c.LoginMaxAttempts)
	}

	// Kiracı kimliği (çok-kiracılı temel; boşsa "default"). Geçersizse başlatma durur.
	tid, err := tenant.Normalize(os.Getenv("KUT_TENANT_ID"))
	if err != nil {
		return nil, fmt.Errorf("config: KUT_TENANT_ID geçersiz: %w", err)
	}
	c.TenantID = string(tid)
	c.TenantEnforce = os.Getenv("KUT_TENANT_ENFORCE") == "1"

	// KUT_DATABASE_URL boşsa sunucu bellek-içi DEMO deposuyla başlar (kalıcılık yok).
	return c, nil
}

// secretEnv, hassas bir değeri döner: <key> ayarlıysa onu; değilse <key>_FILE
// ayarlıysa o dosyanın kırpılmış içeriğini (systemd LoadCredential / Docker-K8s
// secrets / Vault agent gibi dosya-tabanlı sır sağlayıcıları). İkisi de yoksa boş.
// Böylece sırlar düz-metin ortam değişkeni olarak sızmaz (proc/environ, ps).
func secretEnv(key string) (string, error) {
	if v := os.Getenv(key); v != "" {
		return v, nil
	}
	if p := os.Getenv(key + "_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("config: %s_FILE okunamadı: %w", key, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", nil
}

// clearSecretEnv, sırları (secret) okuduktan sonra ortam değişkenlerinden (environment)
// temizler (unset). Bu, sürecin belleğinde /proc/environ veya alt süreçlere aktarım
// üzerinden sızmasını engeller (fail-closed security).
func clearSecretEnv() {
	os.Unsetenv("KUT_MASTER_KEY")
	os.Unsetenv("KUT_MASTER_KEY_FILE")
	os.Unsetenv("KUT_MASTER_KEY_OLD")
	os.Unsetenv("KUT_MASTER_KEY_OLD_FILE")
	os.Unsetenv("KUT_DATABASE_URL")
	os.Unsetenv("KUT_DATABASE_URL_FILE")
	os.Unsetenv("KUT_MIGRATE_DATABASE_URL")
	os.Unsetenv("KUT_MIGRATE_DATABASE_URL_FILE")
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getint(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getdur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// checkKeyPermissions, özel anahtar dosyalarının güvenli izinlere sahip olup olmadığını kontrol eder.
func checkKeyPermissions(path string) error {
	if runtime.GOOS == "windows" {
		// Windows POSIX izinlerini kullanmaz, ACL kullanır.
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("anahtar dosyası okunamadı (%s): %w", path, err)
	}
	mode := info.Mode().Perm()
	if mode != 0o600 && mode != 0o400 {
		return fmt.Errorf("dosya izinleri çok açık: %s (beklenen 0600 veya 0400, mevcut %04o)", path, mode)
	}
	return nil
}
