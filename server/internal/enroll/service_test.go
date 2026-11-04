package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"kut.corp/suite/server/internal/security"
)

// memStore, testler için bellek-içi Store implementasyonudur.
type memStore struct {
	tokens  map[string]string // tokenIndex(hex) -> boundDeviceID (kullanılmamış)
	used    map[string]bool
	certs   []CertRecord
	revoked map[string]bool // deviceID -> iptal edildi (aktif sertifikası yok)
	seq     int
}

func newMemStore() *memStore {
	return &memStore{tokens: map[string]string{}, used: map[string]bool{}, revoked: map[string]bool{}}
}

func (m *memStore) DeviceHasActiveCert(_ context.Context, deviceID string) (bool, error) {
	if m.revoked[deviceID] {
		return false, nil
	}
	for _, c := range m.certs {
		if c.DeviceID == deviceID {
			return true, nil
		}
	}
	return false, nil
}

func (m *memStore) addToken(idx []byte, boundDeviceID string) {
	m.tokens[string(idx)] = boundDeviceID
}

func (m *memStore) ConsumeEnrollmentToken(_ context.Context, tokenIndex []byte, _ time.Time) (string, string, error) {
	k := string(tokenIndex)
	if m.used[k] {
		return "", "", ErrInvalidToken
	}
	bound, ok := m.tokens[k]
	if !ok {
		return "", "", ErrInvalidToken
	}
	m.used[k] = true // tek kullanımlık
	return bound, "", nil
}

func (m *memStore) UpsertEnrollingDevice(_ context.Context, in DeviceEnrollment) (string, error) {
	if in.PreferredDeviceID != "" {
		return in.PreferredDeviceID, nil
	}
	m.seq++
	return "device-" + string(rune('A'+m.seq-1)), nil
}

func (m *memStore) SaveCertificate(_ context.Context, c CertRecord) error {
	m.certs = append(m.certs, c)
	return nil
}

func newTestService(t *testing.T, store Store) (*Service, *security.BlindIndexer) {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	bidx := security.NewBlindIndexer(security.DeriveKey(master, security.LabelBlindIndex))
	cipher, err := security.NewFieldCipher(security.DeriveKey(master, security.LabelFieldEncryption))
	if err != nil {
		t.Fatal(err)
	}
	ca, caChain := newTestCA(t)
	svc := NewService(store, ca, bidx, cipher, caChain, time.Hour)
	return svc, bidx
}

func makeCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// iptal edilmiş bir cihaz sertifika yenileyerek iptali atlatamamalı.
func TestRenewRejectedForRevokedDevice(t *testing.T) {
	store := newMemStore()
	svc, _ := newTestService(t, store)
	dev := "device-1"

	// Aktif sertifikalı cihaz normalde yenileyebilir.
	_ = store.SaveCertificate(context.Background(), CertRecord{DeviceID: dev, Serial: "1"})
	if _, err := svc.Renew(context.Background(), dev, makeCSR(t)); err != nil {
		t.Fatalf("aktif cihaz yenileyebilmeliydi: %v", err)
	}

	// Cihaz iptal edilince (aktif sertifikası kalmayınca) yenileme reddedilmeli.
	store.revoked[dev] = true
	_, err := svc.Renew(context.Background(), dev, makeCSR(t))
	if !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("iptalli cihaz için ErrDeviceRevoked beklenirdi, dönen: %v", err)
	}
}

func TestEnrollHappyPath(t *testing.T) {
	store := newMemStore()
	svc, bidx := newTestService(t, store)

	token := "TOK-123456"
	store.addToken(bidx.Compute("enroll-token:"+token), "device-fixed")

	res, err := svc.Enroll(context.Background(), Input{
		Token:      token,
		CSRPEM:     makeCSR(t),
		Hostname:   "WS-07",
		MACAddress: "AA:BB:CC:DD:EE:FF",
		OSInfo:     "Windows 11 Pro",
		OSPlatform: "windows",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.DeviceID != "device-fixed" {
		t.Errorf("device id = %q, beklenen device-fixed (token'a bağlı)", res.DeviceID)
	}
	// Dönen sertifikanın CN'i atanan device_id olmalı.
	block, _ := pem.Decode(res.ClientCertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "device-fixed" {
		t.Errorf("cert CN = %q, beklenen device-fixed", cert.Subject.CommonName)
	}
	if len(store.certs) != 1 {
		t.Errorf("1 sertifika kaydı beklenirdi, %d", len(store.certs))
	}
}

func TestEnrollTokenSingleUse(t *testing.T) {
	store := newMemStore()
	svc, bidx := newTestService(t, store)

	token := "TOK-ONCE"
	store.addToken(bidx.Compute("enroll-token:"+token), "")

	in := Input{Token: token, CSRPEM: makeCSR(t), MACAddress: "00:11:22:33:44:55"}
	if _, err := svc.Enroll(context.Background(), in); err != nil {
		t.Fatalf("ilk kayıt başarısız: %v", err)
	}
	// İkinci kez aynı token → reddedilmeli.
	if _, err := svc.Enroll(context.Background(), Input{Token: token, CSRPEM: makeCSR(t)}); err != ErrInvalidToken {
		t.Fatalf("ikinci kullanım ErrInvalidToken dönmeliydi, dönen: %v", err)
	}
}

func TestEnrollUnknownToken(t *testing.T) {
	store := newMemStore()
	svc, _ := newTestService(t, store)
	_, err := svc.Enroll(context.Background(), Input{
		Token: "yok-boyle-token", CSRPEM: makeCSR(t), MACAddress: "00:11:22:33:44:55",
	})
	if err != ErrInvalidToken {
		t.Fatalf("bilinmeyen token ErrInvalidToken dönmeliydi, dönen: %v", err)
	}
}

// newTestCA, test için kendinden imzalı CA ve zincir PEM'i üretir.
func newTestCA(t *testing.T) (*security.CA, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "KUT Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	ca, err := security.LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca, certPEM
}
