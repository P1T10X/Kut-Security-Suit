package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"kut.corp/suite/otawire"
)

// payloadServer, sabit bir payload sunan test HTTPS sunucusu (indirici
// yalnız https kabul eder).
func payloadServer(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
}

// tlsDL, test TLS sunucusunun sertifikasına güvenen bir indirici döner.
func tlsDL(ts *httptest.Server) *HTTPDownloader {
	dl := NewHTTPDownloader(0)
	dl.client = ts.Client()
	return dl
}

func signedManifest(t *testing.T, url string, payload []byte) (otawire.Manifest, []byte, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	m := otawire.Manifest{TargetVersion: "1.5.0", SHA256Hex: hex.EncodeToString(sum[:]), DownloadURL: url}
	return m, ed25519.Sign(priv, otawire.CanonicalBytes(m)), pub
}

func TestPrepareHappyPath(t *testing.T) {
	payload := []byte("YENİ AJAN İKİLİSİ v1.5.0")
	ts := payloadServer(t, payload)
	defer ts.Close()

	m, sig, pub := signedManifest(t, ts.URL, payload)
	v, _ := NewVerifier(pub)
	dl := tlsDL(ts)
	stageDir := t.TempDir()

	su, err := Prepare(context.Background(), m, sig, v, dl, stageDir)
	if err != nil {
		t.Fatal(err)
	}
	if su.Version != "1.5.0" {
		t.Fatalf("sürüm yanlış: %s", su.Version)
	}
	// Staging'deki içerik indirilen payload ile aynı olmalı.
	got, err := os.ReadFile(su.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("staging içeriği payload ile uyuşmuyor")
	}
	// Sürüm işaretçisi yazılmış olmalı.
	ver, _ := os.ReadFile(filepath.Join(stageDir, "agent-staged.version"))
	if string(ver) != "1.5.0" {
		t.Fatalf("sürüm işaretçisi yanlış: %q", ver)
	}
}

func TestPrepareRejectsBadSignature(t *testing.T) {
	payload := []byte("payload")
	ts := payloadServer(t, payload)
	defer ts.Close()

	m, sig, _ := signedManifest(t, ts.URL, payload)
	// Farklı public key ile doğrula → imza tutmamalı, indirme bile yapılmamalı.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	v, _ := NewVerifier(otherPub)

	if _, err := Prepare(context.Background(), m, sig, v, tlsDL(ts), t.TempDir()); err != ErrBadSignature {
		t.Fatalf("ErrBadSignature beklenirdi, dönen: %v", err)
	}
}

func TestPrepareRejectsHashMismatch(t *testing.T) {
	payload := []byte("gerçek payload")
	// Sunucu FARKLI bir içerik sunuyor (saldırgan payload'ı değiştirmiş).
	ts := payloadServer(t, []byte("değiştirilmiş kötü payload"))
	defer ts.Close()

	m, sig, pub := signedManifest(t, ts.URL, payload) // manifesto orijinal payload'ın hash'ini taşır
	v, _ := NewVerifier(pub)

	if _, err := Prepare(context.Background(), m, sig, v, tlsDL(ts), t.TempDir()); err != ErrHashMismatch {
		t.Fatalf("ErrHashMismatch beklenirdi, dönen: %v", err)
	}
}

// TestVerifyStaged, swap-anı yeniden doğrulamanın geçerli staged seti kabul ettiğini,
// staged ikili veya imza kurcalanınca reddettiğini, ve yanlış anahtarla doğrulamanın
// başarısız olduğunu doğrular.
func TestVerifyStaged(t *testing.T) {
	payload := []byte("YENİ AJAN İKİLİSİ v1.5.0")
	ts := payloadServer(t, payload)
	defer ts.Close()
	m, sig, pub := signedManifest(t, ts.URL, payload)
	v, _ := NewVerifier(pub)
	stageDir := t.TempDir()
	su, err := Prepare(context.Background(), m, sig, v, tlsDL(ts), stageDir)
	if err != nil {
		t.Fatal(err)
	}

	// Geçerli staged set → kabul.
	if err := VerifyStaged(su.Path, v); err != nil {
		t.Fatalf("geçerli staged set doğrulanmalı: %v", err)
	}

	// Staged ikili kurcalanmış → ErrHashMismatch.
	if err := os.WriteFile(su.Path, []byte("KÖTÜ AMAÇLI İKİLİ"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyStaged(su.Path, v); err != ErrHashMismatch {
		t.Fatalf("kurcalanmış staged ikili ErrHashMismatch dönmeli: %v", err)
	}

	// İmza yanlış anahtarla doğrulanırsa → ErrBadSignature.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ov, _ := NewVerifier(otherPub)
	// İkiliyi geri yaz (hash geçsin ki imza kapısına ulaşsın).
	_ = os.WriteFile(su.Path, payload, 0o755)
	if err := VerifyStaged(su.Path, ov); err != ErrBadSignature {
		t.Fatalf("yanlış anahtar ErrBadSignature dönmeli: %v", err)
	}

	// nil doğrulayıcı → hata.
	if err := VerifyStaged(su.Path, nil); err == nil {
		t.Fatal("nil doğrulayıcı hata dönmeli")
	}
}
