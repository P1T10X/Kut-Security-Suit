package config

import (
	"encoding/base64"
	"os"
	"runtime"
	"strings"
	"testing"
)

// writeKeyFile, 0600 izinli GERÇEK bir anahtar dosyası yazar. checkKeyPermissions
// Linux'ta dosyayı gerçekten stat eder (Windows'ta no-op), bu yüzden sahte yollar
// CI'da (Linux) fail-closed izin kontrolüne takılır — testler cross-platform olsun
// diye gerçek 0600 dosya kullanılır.
func writeKeyFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// setValidTLS, Load'ın beklediği TLS materyali env'lerini ayarlar: anahtar dosyaları
// GERÇEK ve 0600 (izin kontrolünü her iki OS'ta geçer); sertifika yolları izin
// kontrol edilmediğinden (yalnız env'in dolu olması aranır) sahte kalabilir.
func setValidTLS(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	caKey := dir + "/ca.key"
	srvKey := dir + "/server.key"
	writeKeyFile(t, caKey)
	writeKeyFile(t, srvKey)
	t.Setenv("KUT_CA_CERT", "/x/ca.crt")
	t.Setenv("KUT_CA_KEY", caKey)
	t.Setenv("KUT_SERVER_CERT", "/x/s.crt")
	t.Setenv("KUT_SERVER_KEY", srvKey)
}

// setValid, geçerli bir yapılandırma için gereken tüm zorunlu env'leri ayarlar.
func setValid(t *testing.T) {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("KUT_MASTER_KEY", key)
	setValidTLS(t)
}

func TestLoadValid(t *testing.T) {
	setValid(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.MasterKey) != 32 || c.CACertPath == "" {
		t.Fatalf("geçerli config beklenirdi: %+v", c)
	}
}

func TestLoadRejectsMissingMasterKey(t *testing.T) {
	t.Setenv("KUT_MASTER_KEY", "")
	if _, err := Load(); err == nil {
		t.Fatal("eksik master key reddedilmeliydi")
	}
}

func TestLoadRejectsShortMasterKey(t *testing.T) {
	t.Setenv("KUT_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "32 bayt") {
		t.Fatalf("kısa master key reddedilmeliydi: %v", err)
	}
}

func TestLoadRejectsMissingTLSPaths(t *testing.T) {
	setValid(t)
	t.Setenv("KUT_SERVER_CERT", "") // birini kaldır
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "KUT_SERVER_CERT") {
		t.Fatalf("eksik TLS yolu reddedilmeliydi: %v", err)
	}
}

func TestLoadRejectsBadNumeric(t *testing.T) {
	setValid(t)
	t.Setenv("KUT_RETENTION_DAYS", "0")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "KUT_RETENTION_DAYS") {
		t.Fatalf("geçersiz saklama günü reddedilmeliydi: %v", err)
	}
}

func TestLoadMasterKeyFromFile(t *testing.T) {
	// TLS materyali + master-key dosyası; env'de KUT_MASTER_KEY YOK, _FILE var.
	setValidTLS(t)
	t.Setenv("KUT_MASTER_KEY", "")

	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	dir := t.TempDir()
	f := dir + "/mk"
	if err := os.WriteFile(f, []byte(key+"\n"), 0o600); err != nil { // sondaki newline kırpılmalı
		t.Fatal(err)
	}
	t.Setenv("KUT_MASTER_KEY_FILE", f)

	c, err := Load()
	if err != nil {
		t.Fatalf("dosya-tabanlı master key yüklenmeli: %v", err)
	}
	if len(c.MasterKey) != 32 {
		t.Fatalf("32 baytlık anahtar beklenirdi, %d", len(c.MasterKey))
	}
}

func TestLoadMasterKeyFileMissing(t *testing.T) {
	t.Setenv("KUT_CA_CERT", "/x/ca.crt")
	t.Setenv("KUT_CA_KEY", "/x/ca.key")
	t.Setenv("KUT_SERVER_CERT", "/x/s.crt")
	t.Setenv("KUT_SERVER_KEY", "/x/s.key")
	t.Setenv("KUT_MASTER_KEY", "")
	t.Setenv("KUT_MASTER_KEY_FILE", "/nonexistent/mk")
	if _, err := Load(); err == nil {
		t.Fatal("olmayan _FILE dosyası hata vermeli")
	}
}

func TestLoadClearsSecrets(t *testing.T) {
	setValid(t)

	t.Setenv("KUT_DATABASE_URL", "postgres://test")
	t.Setenv("KUT_MASTER_KEY_OLD", base64.StdEncoding.EncodeToString(make([]byte, 32)))

	_, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	secrets := []string{
		"KUT_MASTER_KEY",
		"KUT_MASTER_KEY_FILE",
		"KUT_MASTER_KEY_OLD",
		"KUT_MASTER_KEY_OLD_FILE",
		"KUT_DATABASE_URL",
		"KUT_DATABASE_URL_FILE",
	}

	for _, s := range secrets {
		if val, exists := os.LookupEnv(s); exists {
			t.Errorf("sır temizlenmedi, %s = %s", s, val)
		}
	}
}

func TestCheckKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows testlerinde POSIX izinleri atlanıyor")
	}

	dir := t.TempDir()

	// 1. Çok açık izin (0644)
	badPath := dir + "/bad.key"
	if err := os.WriteFile(badPath, []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := checkKeyPermissions(badPath)
	if err == nil {
		t.Fatal("0644 izinli dosya için hata dönmeliydi")
	}
	if !strings.Contains(err.Error(), "çok açık") {
		t.Fatalf("beklenmeyen hata mesajı: %v", err)
	}

	// 2. Güvenli izin (0600)
	goodPath := dir + "/good.key"
	if err := os.WriteFile(goodPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := checkKeyPermissions(goodPath); err != nil {
		t.Fatalf("0600 izinli dosya için hata dönmemeliydi: %v", err)
	}
}

func TestLoadStrictKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows testlerinde POSIX izinleri atlanıyor")
	}
	setValid(t)

	dir := t.TempDir()
	caPath := dir + "/ca.key"
	if err := os.WriteFile(caPath, []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUT_CA_KEY", caPath)

	serverPath := dir + "/server.key"
	if err := os.WriteFile(serverPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUT_SERVER_KEY", serverPath)

	// Varsayılan: fail-closed — güvensiz 0644 anahtar başlatmayı DURDURUR.
	t.Setenv("KUT_ALLOW_INSECURE_KEY_PERMISSIONS", "")
	if _, err := Load(); err == nil {
		t.Fatal("varsayılan fail-closed: güvensiz izinle hata dönmeliydi")
	}

	// Opt-out: operatör bilerek kabul ederse yalnız uyarı, boot devam.
	// Load, sırları okuyunca ortamdan temizler (clearSecretEnv); ikinci Load için
	// ana anahtar yeniden ayarlanmalı (Linux'ta ilk Load izin kontrolüne kadar ilerler).
	t.Setenv("KUT_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("KUT_ALLOW_INSECURE_KEY_PERMISSIONS", "1")
	if _, err := Load(); err != nil {
		t.Fatalf("opt-out açıkken hata dönmemeli (yalnız uyarı): %v", err)
	}
}

func TestConfigMigrateDatabaseURL(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/owner.url"
	if err := os.WriteFile(filePath, []byte("  postgres://owner@h/kut\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, url, file, want string
		bad                   bool
	}{
		{name: "neither", want: ""},
		{name: "url", url: "postgres://owner@h/kut", want: "postgres://owner@h/kut"},
		{name: "file is trimmed", file: filePath, want: "postgres://owner@h/kut"},
		{name: "url beats file", url: "postgres://direct@h/kut", file: filePath, want: "postgres://direct@h/kut"},
		{name: "unreadable file", file: dir + "/missing", bad: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			setValid(t)
			t.Setenv("KUT_DATABASE_URL", "postgres://app@h/kut")
			t.Setenv("KUT_MIGRATE_DATABASE_URL", c.url)
			t.Setenv("KUT_MIGRATE_DATABASE_URL_FILE", c.file)
			cfg, err := Load()
			if c.bad {
				if err == nil {
					t.Fatal("want an error")
				}
				if strings.Contains(err.Error(), "postgres://") {
					t.Errorf("error echoes a URL: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MigrateDatabaseURL != c.want {
				t.Errorf("MigrateDatabaseURL = %q, want %q", cfg.MigrateDatabaseURL, c.want)
			}
			if cfg.DatabaseURL != "postgres://app@h/kut" {
				t.Errorf("DatabaseURL changed: %q", cfg.DatabaseURL)
			}
		})
	}
}

func TestConfigClearsOwnerDatabaseURLFromEnvironment(t *testing.T) {
	setValid(t)
	t.Setenv("KUT_MIGRATE_DATABASE_URL", "postgres://owner@h/kut")
	t.Setenv("KUT_MIGRATE_DATABASE_URL_FILE", "/nonexistent")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"KUT_MIGRATE_DATABASE_URL", "KUT_MIGRATE_DATABASE_URL_FILE"} {
		if v, ok := os.LookupEnv(k); ok {
			t.Errorf("%s not cleared: %q", k, v)
		}
	}
}
