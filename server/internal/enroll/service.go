// Package enroll, ajan kayıt (enrollment / PKI bootstrap) iş mantığını içerir.
//
// Bilinçli olarak transport'tan (gRPC) ve DB'den (pgx) bağımsızdır: depolama
// bir arayüzün (Store) arkasındadır ve kriptografi security paketinden gelir.
// Böylece çekirdek akış proto üretimi veya çalışan bir veritabanı olmadan da
// derlenip test edilebilir.
package enroll

import (
	"context"
	"errors"
	"fmt"
	"time"

	"kut.corp/suite/server/internal/security"
)

// ErrInvalidToken, token geçersiz/kullanılmış/süresi geçmiş olduğunda döner.
var ErrInvalidToken = errors.New("enroll: geçersiz veya kullanılmış enrollment token")

// ErrDeviceRevoked, iptal edilmiş bir cihaz sertifika yenilemeye çalıştığında
// döner (iptal bypass koruması).
var ErrDeviceRevoked = errors.New("enroll: cihaz iptal edilmiş — yenileme reddedildi")

// ErrTenantMismatch, kayıt token'ının kiracısı ile mevcut cihaz kaydının kiracısı
// farklı olduğunda döner: bir cihaz ASLA kiracılar arası taşınmaz (devralma/re-homing
// koruması). Fail-closed: kayıt reddedilir, mevcut cihaz satırı değişmez.
var ErrTenantMismatch = errors.New("enroll: cihaz başka bir kiracıya ait — kayıt reddedildi")

// Store, enrollment'ın ihtiyaç duyduğu kalıcılık işlemleridir.
type Store interface {
	// ConsumeEnrollmentToken, token'ı ATOMİK olarak doğrular ve kullanılmış
	// işaretler. tokenIndex = HMAC(token). boundDeviceID: token bir cihaza önceden
	// bağlıysa o cihaz. tenantID: token'a atanan kiracı (çok-tenant; boş = tek-tenant).
	// device_id döner; değilse boş string döner. Geçersizse ErrInvalidToken.
	ConsumeEnrollmentToken(ctx context.Context, tokenIndex []byte, now time.Time) (boundDeviceID, tenantID string, err error)

	// UpsertEnrollingDevice, cihazı mac blind index'e göre oluşturur veya
	// bulur ve şifreli alanlarını günceller. Atanmış device_id döner.
	// KİRACI DUVARI: MAC yolunda tekillik KİRACI BAŞINADIR (kanonik kiracı + MAC):
	// aynı MAC başka kiracıda AYRI bir satırdır ve mevcut satıra DOKUNULMAZ (re-home yok) —
	// bu yolda ErrTenantMismatch dönmez. ErrTenantMismatch yalnız token'a ÖNCEDEN BAĞLI cihaz
	// yolunda (PreferredDeviceID) döner: bağlı cihazın kiracısı in.TenantID ile AYNI değilse
	// satır DEĞİŞMEZ (cihaz kiracılar arası taşınmaz).
	// Mevcut cihazın güvenlik durumu (QUARANTINE_PENDING/QUARANTINED) yeniden
	// kayıtla ACTIVE'e düşürülmez; yalnız PENDING_ENROLLMENT/OFFLINE/UNINSTALLED
	// cihazlar ACTIVE olur.
	UpsertEnrollingDevice(ctx context.Context, in DeviceEnrollment) (deviceID string, err error)

	// SaveCertificate, imzalanan istemci sertifikasını kaydeder.
	SaveCertificate(ctx context.Context, cert CertRecord) error

	// DeviceHasActiveCert, cihazın iptal EDİLMEMİŞ (revoked_at IS NULL) en az bir
	// sertifikası olup olmadığını DB'den döner. Yenilemede iptal bypass'ını
	// önlemek için kullanılır: admin cihazı iptal ettiğinde tüm sertifikaları
	// iptal edilir → aktif sertifika kalmaz → yenileme reddedilir (60 sn'lik
	// revocation cache penceresine güvenmeden, kesin kontrol).
	DeviceHasActiveCert(ctx context.Context, deviceID string) (bool, error)
}

// DeviceEnrollment, bir cihazın kaydında saklanacak (şifrelenmiş) verilerdir.
type DeviceEnrollment struct {
	PreferredDeviceID string // token'a bağlıysa; boşsa store yeni UUID atar
	MACBlindIndex     []byte
	HostnameEnc       []byte
	MACEnc            []byte
	OSInfoEnc         []byte
	OSPlatform        string
	AgentVersion      string
	TenantID          string // çok-tenant: cihazın kiracısı (enrollment token'dan)
}

// CertRecord, agent_certificates tablosuna yazılacak kayıttır.
type CertRecord struct {
	DeviceID    string
	Serial      string // decimal string (DB'de NUMERIC)
	Fingerprint []byte // SHA-256(DER)
	NotBefore   time.Time
	NotAfter    time.Time
}

// Input, bir enrollment isteğinin ham (deşifre edilmiş) girdisidir.
type Input struct {
	Token        string
	CSRPEM       []byte
	Hostname     string
	MACAddress   string
	OSInfo       string
	OSPlatform   string
	AgentVersion string
}

// Result, başarılı bir enrollment'ın çıktısıdır.
type Result struct {
	DeviceID      string
	ClientCertPEM []byte
	CAChainPEM    []byte
	NotAfter      time.Time
}

// Service, enrollment akışını yürütür.
type Service struct {
	store   Store
	ca      *security.CA
	bidx    *security.BlindIndexer
	cipher  *security.FieldCipher
	caChain []byte
	certTTL time.Duration
	now     func() time.Time
}

// NewService, bir enrollment servisi oluşturur. caChainPEM, ajanın sunucuyu
// mTLS'te doğrulaması için döneceğimiz CA zinciridir.
func NewService(store Store, ca *security.CA, bidx *security.BlindIndexer,
	cipher *security.FieldCipher, caChainPEM []byte, certTTL time.Duration) *Service {
	return &Service{
		store:   store,
		ca:      ca,
		bidx:    bidx,
		cipher:  cipher,
		caChain: caChainPEM,
		certTTL: certTTL,
		now:     time.Now,
	}
}

// Enroll, tek kullanımlık token + CSR ile bir ajanı kaydeder ve imzalı istemci
// sertifikası döner.
func (s *Service) Enroll(ctx context.Context, in Input) (*Result, error) {
	if len(in.CSRPEM) == 0 {
		return nil, errors.New("enroll: CSR boş")
	}
	if in.Token == "" {
		return nil, ErrInvalidToken
	}

	now := s.now()

	// 1) Token'ı doğrula ve tüket (atomik).
	tokenIndex := s.bidx.Compute("enroll-token:" + in.Token)
	boundDeviceID, tokenTenant, err := s.store.ConsumeEnrollmentToken(ctx, tokenIndex, now)
	if err != nil {
		return nil, err // ErrInvalidToken dahil
	}

	// 2) Hassas alanları şifrele + mac blind index'i hesapla.
	mac := security.NormalizeMAC(in.MACAddress)
	macBidx := s.bidx.Compute("mac:" + mac)

	hostnameEnc, err := s.cipher.EncryptString(in.Hostname)
	if err != nil {
		return nil, fmt.Errorf("enroll: hostname şifreleme: %w", err)
	}
	macEnc, err := s.cipher.EncryptString(mac)
	if err != nil {
		return nil, fmt.Errorf("enroll: mac şifreleme: %w", err)
	}
	osEnc, err := s.cipher.EncryptString(in.OSInfo)
	if err != nil {
		return nil, fmt.Errorf("enroll: os bilgisi şifreleme: %w", err)
	}

	// 3) Cihazı oluştur/bul.
	deviceID, err := s.store.UpsertEnrollingDevice(ctx, DeviceEnrollment{
		PreferredDeviceID: boundDeviceID,
		MACBlindIndex:     macBidx,
		HostnameEnc:       hostnameEnc,
		MACEnc:            macEnc,
		OSInfoEnc:         osEnc,
		OSPlatform:        in.OSPlatform,
		AgentVersion:      in.AgentVersion,
		TenantID:          tokenTenant, // çok-tenant: cihaz token'ın kiracısını devralır
	})
	if err != nil {
		return nil, fmt.Errorf("enroll: cihaz kaydı: %w", err)
	}

	// 4) CSR'ı imzala — kimliği (CN) SUNUCU atanan device_id ile dayatır.
	signed, err := s.ca.SignCSR(in.CSRPEM, deviceID, s.certTTL)
	if err != nil {
		return nil, fmt.Errorf("enroll: CSR imzalama: %w", err)
	}

	// 5) Sertifikayı kaydet.
	if err := s.store.SaveCertificate(ctx, CertRecord{
		DeviceID:    deviceID,
		Serial:      signed.Serial.String(),
		Fingerprint: security.CertFingerprint(signed.CertPEM),
		NotBefore:   now,
		NotAfter:    signed.NotAfter,
	}); err != nil {
		return nil, fmt.Errorf("enroll: sertifika kaydı: %w", err)
	}

	return &Result{
		DeviceID:      deviceID,
		ClientCertPEM: signed.CertPEM,
		CAChainPEM:    s.caChain,
		NotAfter:      signed.NotAfter,
	}, nil
}

// Renew, mevcut (mTLS ile doğrulanmış) bir cihaz için yeni bir CSR imzalar.
// Kimlik ÇAĞIRAN tarafından sağlanır — istemci sertifikasının CN'inden alınan
// device_id; token gerekmez. Kısa ömürlü sertifika modelinin sürdürülebilir
// olması için ajanlar süre dolmadan bununla yenilenir.
func (s *Service) Renew(ctx context.Context, deviceID string, csrPEM []byte) (*Result, error) {
	if deviceID == "" {
		return nil, errors.New("enroll: yenileme için device_id gerekli")
	}
	if len(csrPEM) == 0 {
		return nil, errors.New("enroll: CSR boş")
	}
	// İptal bypass koruması: iptal edilmiş bir cihaz, revocation
	// cache tazelenmeden (≤60 sn) yenileme çağırıp yeni parmak-izli bir
	// sertifika alarak iptali kalıcı atlatmamalı. DB'den kesin kontrol:
	// cihazın iptal edilmemiş aktif sertifikası yoksa yenileme reddedilir.
	active, err := s.store.DeviceHasActiveCert(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("enroll: yenileme iptal kontrolü: %w", err)
	}
	if !active {
		return nil, ErrDeviceRevoked
	}
	now := s.now()
	signed, err := s.ca.SignCSR(csrPEM, deviceID, s.certTTL)
	if err != nil {
		return nil, fmt.Errorf("enroll: yenileme CSR imzalama: %w", err)
	}
	if err := s.store.SaveCertificate(ctx, CertRecord{
		DeviceID:    deviceID,
		Serial:      signed.Serial.String(),
		Fingerprint: security.CertFingerprint(signed.CertPEM),
		NotBefore:   now,
		NotAfter:    signed.NotAfter,
	}); err != nil {
		return nil, fmt.Errorf("enroll: yenileme sertifika kaydı: %w", err)
	}
	return &Result{
		DeviceID:      deviceID,
		ClientCertPEM: signed.CertPEM,
		CAChainPEM:    s.caChain,
		NotAfter:      signed.NotAfter,
	}, nil
}
