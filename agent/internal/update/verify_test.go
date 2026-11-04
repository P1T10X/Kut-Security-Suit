package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"kut.corp/suite/otawire"
)

func mustKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifyManifestRoundTrip(t *testing.T) {
	pub, priv := mustKeys(t)
	v, err := NewVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	m := otawire.Manifest{TargetVersion: "1.3.0", SHA256Hex: "deadbeef", DownloadURL: "https://c2/u/1.3.0", Mandatory: true}
	sig := ed25519.Sign(priv, otawire.CanonicalBytes(m))

	if err := v.VerifyManifest(m, sig); err != nil {
		t.Fatalf("geçerli imza doğrulanamadı: %v", err)
	}
}

func TestVerifyManifestTamperedField(t *testing.T) {
	pub, priv := mustKeys(t)
	v, _ := NewVerifier(pub)
	m := otawire.Manifest{TargetVersion: "1.3.0", SHA256Hex: "aa", DownloadURL: "u", Mandatory: false}
	sig := ed25519.Sign(priv, otawire.CanonicalBytes(m))

	// Saldırgan sürümü/URL'yi değiştirirse imza tutmamalı.
	m.DownloadURL = "https://evil/payload"
	if err := v.VerifyManifest(m, sig); err != ErrBadSignature {
		t.Fatalf("değiştirilmiş manifesto ErrBadSignature dönmeliydi, dönen: %v", err)
	}
}

func TestVerifyManifestWrongKey(t *testing.T) {
	_, priv := mustKeys(t)
	otherPub, _ := mustKeys(t)
	v, _ := NewVerifier(otherPub)
	m := otawire.Manifest{TargetVersion: "1", SHA256Hex: "h", DownloadURL: "u"}
	sig := ed25519.Sign(priv, otawire.CanonicalBytes(m))
	if err := v.VerifyManifest(m, sig); err != ErrBadSignature {
		t.Fatalf("yanlış anahtar reddedilmeliydi, dönen: %v", err)
	}
}

func TestVerifyPayload(t *testing.T) {
	payload := []byte("sahte güncelleme ikilisi")
	// Doğru hash.
	sum := sha256Hex(payload)
	if err := VerifyPayload(payload, sum); err != nil {
		t.Fatalf("doğru hash reddedildi: %v", err)
	}
	// Bozulmuş payload.
	if err := VerifyPayload([]byte("baskasi"), sum); err != ErrHashMismatch {
		t.Fatalf("yanlış payload ErrHashMismatch dönmeliydi, dönen: %v", err)
	}
}

// sha256Hex, test için küçük yardımcı (üretici tarafını taklit eder).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// İmza-anahtarı rotasyonu: birden çok güvenilen anahtar olduğunda ESKİ
// anahtarla imzalanmış manifesto YENİ anahtarı da tanıyan doğrulayıcıyla geçerli
// olmalı; güvenilmeyen anahtar reddedilmeli.
func TestVerifierMultiKeyRotation(t *testing.T) {
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	roguePub, roguePriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = roguePub

	m := otawire.Manifest{TargetVersion: "2.0.0", SHA256Hex: "ab", DownloadURL: "https://x/y"}
	oldSig := ed25519.Sign(oldPriv, otawire.CanonicalBytes(m))
	rogueSig := ed25519.Sign(roguePriv, otawire.CanonicalBytes(m))

	// Hem eski hem yeni anahtara güvenen doğrulayıcı.
	v, err := NewVerifierMulti(newPub, oldPub)
	if err != nil {
		t.Fatal(err)
	}
	// Eski anahtarla imzalı manifesto kabul edilmeli (rotasyon örtüşmesi).
	if err := v.VerifyManifest(m, oldSig); err != nil {
		t.Fatalf("eski anahtar imzası kabul edilmeliydi: %v", err)
	}
	// Güvenilmeyen (rogue) anahtarla imza reddedilmeli.
	if err := v.VerifyManifest(m, rogueSig); err != ErrBadSignature {
		t.Fatalf("güvenilmeyen imza reddedilmeliydi: %v", err)
	}
}
