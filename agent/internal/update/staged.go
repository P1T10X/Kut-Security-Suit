package update

// staged.go — swap-anı YENİDEN DOĞRULAMA. İmza doğrulaması Prepare'de
// (ajan süreci) yapılır; ancak staged ikiliyi AYRI bir watchdog süreci (genelde SYSTEM/root)
// swap edip çalıştırır. Stage ile swap arasında staged dosya yerel olarak değiştirilirse
// (TOCTOU), yalnız Prepare-anı doğrulaması bunu kaçırır. VerifyStaged, watchdog'un swap'tan
// HEMEN ÖNCE imzayı (ed25519) + SHA-256'yı yeniden doğrulamasını sağlar; forge edilemez imza
// olmadan hiçbir ikili çalıştırılmaz.

import (
	"encoding/json"
	"fmt"
	"os"

	"kut.corp/suite/otawire"
)

// VerifyStaged, stagedPath'teki ikiliyi yanındaki imzalı manifesto (.manifest) + imza (.sig)
// ile YENİDEN doğrular: (1) manifesto imzası güvenilen anahtarla doğrulanır (Prepare'de
// yazılan imza forge edilemez), (2) staged ikilinin SHA-256'sı manifestodaki (imzayla bağlı)
// değerle karşılaştırılır. İkisi de geçerliyse nil; aksi halde hata (swap REDDEDİLİR).
func VerifyStaged(stagedPath string, v *Verifier) error {
	if v == nil {
		return fmt.Errorf("update: staged doğrulayıcı yok")
	}
	mj, err := os.ReadFile(stagedPath + ".manifest")
	if err != nil {
		return fmt.Errorf("update: staged manifesto okunamadı: %w", err)
	}
	sig, err := os.ReadFile(stagedPath + ".sig")
	if err != nil {
		return fmt.Errorf("update: staged imza okunamadı: %w", err)
	}
	var m otawire.Manifest
	if err := json.Unmarshal(mj, &m); err != nil {
		return fmt.Errorf("update: staged manifesto çözülemedi: %w", err)
	}
	if err := v.VerifyManifest(m, sig); err != nil {
		return err // ErrBadSignature — forge edilemez imza doğrulanamadı
	}
	data, err := os.ReadFile(stagedPath)
	if err != nil {
		return fmt.Errorf("update: staged ikili okunamadı: %w", err)
	}
	if err := VerifyPayload(data, m.SHA256Hex); err != nil {
		return err // ErrHashMismatch — staged ikili kurcalanmış
	}
	return nil
}
