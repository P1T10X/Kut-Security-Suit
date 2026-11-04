// Package script, C2'den gelen imzalı otomasyon scriptlerini doğrular ve
// SINIRLI biçimde çalıştırır.
//
// GÜVENLİK: Script yalnız gömülü public key ile imzası doğrulanırsa çalıştırılır
// (tek bayt değişse reddedilir). Yürütme timeout + çıktı sınırı + minimal env
// ile SINIRLANDIRILIR; ancak bu GERÇEK bir izolasyon sınırı DEĞİLDİR.
// Gerçek sandbox: ayrı süreç + kısıtlı token / AppContainer / container —
// kapsam dışıdır. Bu paket imza-kapısını ve sınırlı yürütmeyi sağlar.
package script

import (
	"crypto/ed25519"
	"errors"

	"kut.corp/suite/scriptwire"
)

// ErrBadSignature, script imzası doğrulanamadığında döner.
var ErrBadSignature = errors.New("script: imza geçersiz")

// Verifier, gömülü Ed25519 public key ile scriptleri doğrular.
type Verifier struct {
	pub ed25519.PublicKey
}

// NewVerifier oluşturur.
func NewVerifier(pub ed25519.PublicKey) (*Verifier, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("script: geçersiz Ed25519 public key boyutu")
	}
	return &Verifier{pub: pub}, nil
}

// Verify, scriptin imzasını doğrular.
func (v *Verifier) Verify(s scriptwire.Script, signature []byte) error {
	if !ed25519.Verify(v.pub, scriptwire.CanonicalBytes(s), signature) {
		return ErrBadSignature
	}
	return nil
}
