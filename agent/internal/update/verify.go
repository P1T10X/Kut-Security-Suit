// Package update, OTA güncellemelerinin doğrulanmasını sağlar. Ajan bir
// güncelleme uygulamadan ÖNCE:
//  1. Manifesto imzasını gömülü public key ile doğrular (kimlik + bütünlük).
//  2. İndirilen paketin SHA-256'sını manifestodaki değerle karşılaştırır.
//
// Yalnız SHA-256 eşleşmesi YETMEZ: imza, paketin gerçekten
// yetkili yönetici tarafından yayımlandığını kanıtlar; hash yalnız transport
// bütünlüğüdür.
package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"kut.corp/suite/otawire"
)

var (
	// ErrBadSignature, manifesto imzası public key ile doğrulanamadığında döner.
	ErrBadSignature = errors.New("update: manifesto imzası geçersiz")
	// ErrHashMismatch, indirilen paketin SHA-256'sı manifestoyla uyuşmadığında döner.
	ErrHashMismatch = errors.New("update: paket SHA-256 uyuşmuyor")
)

// Verifier, GÜVENİLEN public key(ler)le güncellemeleri doğrular. Birden çok anahtar
// desteği imza-anahtarı ROTASYONU içindir: örtüşme penceresinde hem eski hem
// yeni anahtar güvenilir; yeni anahtarla imzalanır, ajanlar ikisini de kabul eder.
type Verifier struct {
	pubs []ed25519.PublicKey
}

// NewVerifier, tek Ed25519 public key ile doğrulayıcı oluşturur (geriye uyumlu).
func NewVerifier(pub ed25519.PublicKey) (*Verifier, error) {
	return NewVerifierMulti(pub)
}

// NewVerifierMulti, birden çok GÜVENİLEN public key ile doğrulayıcı oluşturur
// (rotasyon örtüşmesi). En az bir geçerli anahtar gerekir.
func NewVerifierMulti(pubs ...ed25519.PublicKey) (*Verifier, error) {
	var valid []ed25519.PublicKey
	for _, p := range pubs {
		if len(p) == ed25519.PublicKeySize {
			valid = append(valid, p)
		}
	}
	if len(valid) == 0 {
		return nil, errors.New("update: geçersiz Ed25519 public key boyutu")
	}
	return &Verifier{pubs: valid}, nil
}

// VerifyManifest, manifesto imzasını GÜVENİLEN anahtarlardan HERHANGİ biriyle
// doğrular (rotasyon: eski VEYA yeni anahtar kabul edilir).
func (v *Verifier) VerifyManifest(m otawire.Manifest, signature []byte) error {
	msg := otawire.CanonicalBytes(m)
	for _, p := range v.pubs {
		if ed25519.Verify(p, msg, signature) {
			return nil
		}
	}
	return ErrBadSignature
}

// VerifyPayload, indirilen paketin SHA-256'sını manifestodaki hex ile
// sabit-zamanlı karşılaştırır.
func VerifyPayload(payload []byte, sha256Hex string) error {
	sum := sha256.Sum256(payload)
	want, err := hex.DecodeString(sha256Hex)
	if err != nil {
		return ErrHashMismatch
	}
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return ErrHashMismatch
	}
	return nil
}
