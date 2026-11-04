// Package ota, OTA güncelleme sürümlerinin imzalanmasını sağlar.
// Yalnız SHA-256 bütünlüğü yeterli değildir; kimlik için imza gerekir.
//
// İmza şeması Ed25519'dur. Özel anahtar sistem yöneticisindedir (üretimde
// HSM/sır yöneticisi); ajanlara gömülü olan yalnız public key'dir.
package ota

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"kut.corp/suite/otawire"
)

// Signer, güncelleme manifestolarını imzalar.
type Signer struct {
	priv ed25519.PrivateKey
}

// NewSigner, Ed25519 özel anahtarıyla bir imzalayıcı oluşturur.
func NewSigner(priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("ota: geçersiz Ed25519 özel anahtar boyutu")
	}
	return &Signer{priv: priv}, nil
}

// Sign, manifesto alanlarının kanonik baytları üzerinde imza üretir.
func (s *Signer) Sign(m otawire.Manifest) []byte {
	return ed25519.Sign(s.priv, otawire.CanonicalBytes(m))
}

// SHA256Hex, bir güncelleme paketinin (ikili) SHA-256 özetini hex döner.
// İmza aşamasında paketin sha256'sı hesaplanıp manifestoya konur.
func SHA256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
