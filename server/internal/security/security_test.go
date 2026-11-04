package security

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"AA:BB:CC:DD:EE:FF": "aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff": "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":    "aa:bb:cc:dd:ee:ff",
		"AABBCCDDEEFF":      "aa:bb:cc:dd:ee:ff",
	}
	for in, want := range cases {
		if got := NormalizeMAC(in); got != want {
			t.Errorf("NormalizeMAC(%q) = %q, beklenen %q", in, got, want)
		}
	}
}

func TestBlindIndexDeterministicAndKeyed(t *testing.T) {
	b1 := NewBlindIndexer([]byte("anahtar-1-32-baytlik-gizli-anahtar!!"))
	b2 := NewBlindIndexer([]byte("anahtar-2-farkli-gizli-anahtar-32byt!"))

	mac := NormalizeMAC("AA:BB:CC:11:22:33")
	got1a := b1.Compute(mac)
	got1b := b1.Compute(mac)
	if !Equal(got1a, got1b) {
		t.Fatal("aynı anahtar+değer farklı indeks üretti (deterministik olmalı)")
	}
	if Equal(got1a, b2.Compute(mac)) {
		t.Fatal("farklı anahtarlar aynı indeksi üretti (keyed olmalı)")
	}
	if len(got1a) != 32 {
		t.Fatalf("blind index 32 bayt olmalı, %d", len(got1a))
	}
}

func TestFieldCipherRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := NewFieldCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := "WORKSTATION-07 / 00:1A:2B:3C:4D:5E"
	blob, err := c.EncryptString(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob) == plain {
		t.Fatal("çıktı şifrelenmemiş görünüyor")
	}
	out, err := c.DecryptString(blob)
	if err != nil {
		t.Fatal(err)
	}
	if out != plain {
		t.Fatalf("round-trip uyuşmadı: %q != %q", out, plain)
	}
	// Bozulan ciphertext GCM tag doğrulamasında başarısız olmalı.
	blob[len(blob)-1] ^= 0xFF
	if _, err := c.Decrypt(blob); err == nil {
		t.Fatal("bozulmuş ciphertext hatasız çözüldü (GCM bütünlüğü başarısız)")
	}
}

func TestCASignCSR(t *testing.T) {
	ca := newTestCA(t)

	// Ajan tarafı: anahtar çifti + CSR üret.
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "istemcinin-istedigi-cn"}},
		agentKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	deviceID := "550e8400-e29b-41d4-a716-446655440000"
	signed, err := ca.SignCSR(csrPEM, deviceID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(signed.CertPEM)
	if block == nil {
		t.Fatal("imzalı sertifika PEM'i çözülemedi")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// Kimliği SUNUCU belirler: CN, CSR'daki değil atanan device_id olmalı.
	if cert.Subject.CommonName != deviceID {
		t.Errorf("CN = %q, beklenen %q (sunucu kimliği dayatmalı)", cert.Subject.CommonName, deviceID)
	}
	// İstemci kimlik doğrulama amacı taşımalı.
	foundClientAuth := false
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			foundClientAuth = true
		}
	}
	if !foundClientAuth {
		t.Error("sertifikada ClientAuth ExtKeyUsage yok")
	}
}

// newTestCA, test için kendinden imzalı bir CA üretir.
func newTestCA(t *testing.T) *CA {
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

	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestAuditChainHashIncludesTenant(t *testing.T) {
	prev := []byte("prev-hash")
	adminRef := "admin@test.com"
	action := "TEST_ACTION"
	targetType := "device"
	targetID := "dev-123"
	at := time.Now().UnixNano()

	hash1 := AuditChainHash(prev, "tenantA", adminRef, action, targetType, targetID, at)
	hash2 := AuditChainHash(prev, "tenantB", adminRef, action, targetType, targetID, at)

	if bytes.Equal(hash1, hash2) {
		t.Fatal("tenant_id değiştiğinde hash değişmeli (çapraz-kiracı log nakli koruması başarısız)")
	}

	hash3 := AuditChainHash(prev, "tenantA", adminRef, action, targetType, targetID, at)
	if !bytes.Equal(hash1, hash3) {
		t.Fatal("aynı girdiler aynı hash'i üretmeli")
	}
}

// TestAuditChainHashEmptyTenantBackwardCompatible, boş tenant_id'nin tenant-öncesi
// (tenant alanı hiç yazılmayan) hash biçimiyle BİREBİR aynı baytları ürettiğini
// doğrular. Böylece audit_log'a tenant_id sütunu eklendikten (ADD COLUMN DEFAULT ”)
// sonra mevcut tek-tenant denetim zincirleri re-hash GEREKMEDEN doğrulanabilir.
func TestAuditChainHashEmptyTenantBackwardCompatible(t *testing.T) {
	prev := []byte("prev-hash")
	adminRef := "admin@test.com"
	action := "TEST_ACTION"
	targetType := "device"
	targetID := "dev-123"
	at := time.Now().UnixNano()

	got := AuditChainHash(prev, "", adminRef, action, targetType, targetID, at)

	// Eski biçim: tenant alanı HİÇ yok.
	h := sha256.New()
	h.Write(prev)
	writeField(h, adminRef)
	writeField(h, action)
	writeField(h, targetType)
	writeField(h, targetID)
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], uint64(at))
	h.Write(num[:])
	want := h.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatal("boş tenant_id tenant-öncesi hash biçimiyle eşleşmeli — mevcut zincirler re-hash gerektirmemeli")
	}
	// Dolu tenant farklı hash üretmeli (izolasyon/transplant koruması korunur).
	if bytes.Equal(got, AuditChainHash(prev, "tenantA", adminRef, action, targetType, targetID, at)) {
		t.Fatal("dolu tenant_id, boş-tenant hash'inden farklı olmalı")
	}
}
