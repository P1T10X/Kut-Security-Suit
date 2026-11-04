package update

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"kut.corp/suite/otawire"
)

// Downloader, güncelleme paketini indirir (test edilebilirlik için arayüz).
type Downloader interface {
	Download(ctx context.Context, url string) ([]byte, error)
}

// StagedUpdate, indirilip doğrulanmış ve staging'e yazılmış bir güncellemedir.
// Gerçek swap (eskiyi durdur, yenisiyle değiştir, yeniden başlat) watchdog'un
// işidir; ajan yalnız hazırlar.
type StagedUpdate struct {
	Version string
	Path    string // staging'deki yeni ikilinin yolu
}

// Prepare, güncellemeyi uçtan uca hazırlar:
//  1. Manifesto imzasını doğrular (kimlik + bütünlük).
//  2. Paketi indirir.
//  3. İndirilen paketin SHA-256'sını doğrular.
//  4. Atomik olarak staging dizinine yazar ve sürüm işaretçisi bırakır.
//
// Herhangi bir adım başarısızsa güncelleme UYGULANMAZ (staging'e yazılmaz).
func Prepare(ctx context.Context, m otawire.Manifest, signature []byte, v *Verifier, dl Downloader, stageDir string) (*StagedUpdate, error) {
	if err := v.VerifyManifest(m, signature); err != nil {
		return nil, err // ErrBadSignature
	}
	data, err := dl.Download(ctx, m.DownloadURL)
	if err != nil {
		return nil, err
	}
	if err := VerifyPayload(data, m.SHA256Hex); err != nil {
		return nil, err // ErrHashMismatch
	}
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(stageDir, "agent-staged")
	if err := writeAtomic(path, data, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path+".version", []byte(m.TargetVersion), 0o644); err != nil {
		return nil, err
	}
	// İmzalı manifesto + imzayı staged ikilinin yanına yaz: watchdog (AYRI süreç),
	// swap'tan HEMEN ÖNCE imzayı + SHA-256'yı YENİDEN doğrular. Böylece stage↔swap
	// arasında staged dosyanın kurcalanması (TOCTOU) yakalanır — imzasız/bozuk ikili
	// SYSTEM watchdog tarafından çalıştırılamaz.
	mj, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("update: manifesto serileştirme: %w", err)
	}
	if err := os.WriteFile(path+".manifest", mj, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path+".sig", signature, 0o644); err != nil {
		return nil, err
	}
	return &StagedUpdate{Version: m.TargetVersion, Path: path}, nil
}

// writeAtomic, veriyi geçici dosyaya yazıp rename ile atomik olarak yerleştirir.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("update: staging yazma: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("update: staging rename: %w", err)
	}
	return nil
}
