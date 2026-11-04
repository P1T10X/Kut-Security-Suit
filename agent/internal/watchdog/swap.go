// Package watchdog, ajanı canlı tutan gözetmen sürecin çekirdeğidir: süreç
// gözetimi + yeniden başlatma (backoff'lu) ve OTA staged güncellemesinin
// swap/rollback'i.
//
// NOT (tamper koruması): Bu, kaza sonucu sonlanmalara ve basit
// müdahalelere karşı İLK savunmadır. SYSTEM/root yetkili bir kullanıcıya karşı
// gerçek koruma ayrı bir fazda (MiniFilter sürücüsü + PPL/ELAM) gelir.
package watchdog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// FileSwapper, staging'deki yeni ikiliyi ajan ikilisiyle değiştirir; eskisini
// yedekler ve rollback edebilir. Swap DAİMA ajan durmuşken yapılır (Supervisor
// çalıştırmalar arasında çağırır), bu yüzden çalışan ikiliyi ezme sorunu olmaz.
type FileSwapper struct {
	binaryPath string // ajan ikilisinin yolu
	stageDir   string // update.Prepare'in yazdığı dizin
	// verify, swap'tan HEMEN ÖNCE staged ikiliyi yeniden doğrular (imza + SHA-256). nil ise
	// yeniden-doğrulama yapılmaz (imzasız dağıtım — OTA anahtarı yapılandırılmamış). Ayarlıysa
	// hata dönerse swap REDDEDİLİR (kurcalanmış/forge staged ikili çalıştırılmaz).
	verify func(stagedPath string) error
}

// NewFileSwapper oluşturur.
func NewFileSwapper(binaryPath, stageDir string) *FileSwapper {
	return &FileSwapper{binaryPath: binaryPath, stageDir: stageDir}
}

// SetVerify, swap-anı yeniden-doğrulama kancasını ayarlar (bkz. update.VerifyStaged).
func (s *FileSwapper) SetVerify(fn func(stagedPath string) error) { s.verify = fn }

func (s *FileSwapper) stagedPath() string  { return filepath.Join(s.stageDir, "agent-staged") }
func (s *FileSwapper) versionPath() string { return s.stagedPath() + ".version" }
func (s *FileSwapper) backupPath() string  { return s.binaryPath + ".bak" }

// PendingStaged, bekleyen bir staged güncelleme olup olmadığını döner.
func (s *FileSwapper) PendingStaged() (version, path string, ok bool) {
	if !exists(s.stagedPath()) {
		return "", "", false
	}
	ver, _ := os.ReadFile(s.versionPath())
	return string(ver), s.stagedPath(), true
}

func (s *FileSwapper) manifestPath() string { return s.stagedPath() + ".manifest" }
func (s *FileSwapper) sigPath() string      { return s.stagedPath() + ".sig" }

// Swap, mevcut ikiliyi yedekler ve staged ikiliyi yerine koyar. Yeniden-doğrulama kancası
// ayarlıysa swap'tan ÖNCE staged ikili yeniden doğrulanır; başarısızsa swap REDDEDİLİR ve
// kurcalanmış staged artefaktlar temizlenir (TOCTOU/forge koruması).
func (s *FileSwapper) Swap() error {
	staged := s.stagedPath()
	if s.verify != nil {
		if err := s.verify(staged); err != nil {
			// Kurcalanmış/forge staged ikiliyi çalıştırma; temizle.
			_ = os.Remove(staged)
			_ = os.Remove(s.versionPath())
			_ = os.Remove(s.manifestPath())
			_ = os.Remove(s.sigPath())
			return fmt.Errorf("watchdog: staged doğrulama başarısız, swap reddedildi: %w", err)
		}
	}
	if exists(s.binaryPath) {
		if err := copyFile(s.binaryPath, s.backupPath(), 0o755); err != nil {
			return fmt.Errorf("watchdog: yedek alma: %w", err)
		}
	}
	if err := os.Rename(staged, s.binaryPath); err != nil {
		// Farklı disk bölümü olabilir; kopyala-sil ile dene.
		if err2 := copyFile(staged, s.binaryPath, 0o755); err2 != nil {
			return fmt.Errorf("watchdog: swap: %w", err)
		}
		_ = os.Remove(staged)
	}
	_ = os.Remove(s.versionPath())
	_ = os.Remove(s.manifestPath())
	_ = os.Remove(s.sigPath())
	return nil
}

// Rollback, yedekten geri döner (yeni sürüm çabuk çökerse).
func (s *FileSwapper) Rollback() error {
	if !exists(s.backupPath()) {
		return fmt.Errorf("watchdog: rollback için yedek yok")
	}
	if err := copyFile(s.backupPath(), s.binaryPath, 0o755); err != nil {
		return fmt.Errorf("watchdog: rollback: %w", err)
	}
	return nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
