// Package admin, yönetici işlemlerinin iş mantığıdır: RBAC ile korunmuş
// enrollment token üretimi, karantina komutu verme ve politika yönetimi.
// Her hassas işlem denetim izine (audit_log) yazılır.
//
// Transport'tan (HTTP/gRPC) ve DB'den bağımsızdır: depolama Store arayüzünün
// arkasındadır ve gerçek bir veritabanı olmadan test edilebilir.
package admin

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"kut.corp/suite/cmdenvelope"
	"kut.corp/suite/server/internal/commandplane"
	"kut.corp/suite/server/internal/metrics"
	"kut.corp/suite/server/internal/scope"
	"kut.corp/suite/server/internal/security"
	"kut.corp/suite/server/internal/tenant"
)

// Role, yönetici yetki seviyesidir.
type Role string

const (
	RoleViewer   Role = "VIEWER"
	RoleOperator Role = "OPERATOR"
	RoleAdmin    Role = "ADMIN"
)

func rank(r Role) int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}

// ErrForbidden, çağıran yöneticinin yetkisi yetersiz olduğunda döner.
var ErrForbidden = errors.New("admin: yetki yetersiz")

// ErrUnknownAdmin, kimliği çözülemeyen ya da PASİF bir yönetici için kiracı sorgulandığında
// döner (Store.AdminTenant). ErrForbidden'ı sarar (HTTP 403): "" kiracısı PLATFORM kapsamıdır,
// bu yüzden bilinmeyen/pasif bir yöneticinin sessizce platform admini gibi davranması (fail-open
// birleştirme) yerine çağıranlar bu hatayı yayar ve isteği reddeder.
var ErrUnknownAdmin = fmt.Errorf("%w: bilinmeyen veya pasif yönetici", ErrForbidden)

// ErrInvalidRule, kural girdisi doğrulamayı geçemediğinde döner (istemci hatası).
var ErrInvalidRule = errors.New("admin: geçersiz kural")

// RuleInput, bir politikaya eklenecek kuralın girdisidir.
type RuleInput struct {
	Type       string  // APP_TIME_BLOCK | APP_BLOCK_ALWAYS | NETWORK_RULE
	Target     string  // hedef (uygulama adı / ağ hedefi)
	Start      string  // "HH:MM" (APP_TIME_BLOCK için zorunlu; aksi halde boş)
	End        string  // "HH:MM"
	ActiveDays []int32 // 0=Pazar .. 6=Cumartesi (boşsa depoda varsayılan uygulanır)
}

// RuleView, bir politika kuralının okunabilir görünümüdür.
type RuleView struct {
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Target     string  `json:"target"`
	Start      string  `json:"start"`
	End        string  `json:"end"`
	ActiveDays []int32 `json:"active_days"`
}

// Store, admin işlemlerinin ihtiyaç duyduğu kalıcılıktır.
type Store interface {
	AdminRole(ctx context.Context, adminID string) (Role, error)
	SaveEnrollmentToken(ctx context.Context, tokenIndex []byte, createdBy, tenantID string, expiresAt time.Time) error
	// RevokeEnrollmentToken, kullanılmamış bir enrollment token'ı iptal eder
	// (used_at damgalar). Zaten kullanılmış/yok token için sessizdir (no-op). tenantID
	// boş değilse SQL yazımı DA token'ın kiracısıyla daraltılır (derinlemesine savunma: servis
	// katmanı hatası kiracı sınırını aşamaz); kiracıya bağlı çağıran için eşleşen token yoksa
	// ErrForbidden döner. Boş tenantID = platform kapsamı (süzme yok).
	RevokeEnrollmentToken(ctx context.Context, tokenID, tenantID string) error
	// EnrollmentTokenTenant, enrollment token'ın mühürlü kiracısını döner (iptal
	// yazma-yolunun kiracı zorunlu-kılması için). Token yoksa found=false.
	EnrollmentTokenTenant(ctx context.Context, tokenID string) (tenantID string, found bool, err error)
	EnqueueCommand(ctx context.Context, deviceID, cmdType, issuedBy string) error
	// EnqueueCommandParams, parametreli komut kuyruğa ekler (ör. COLLECT_FILE
	// için params.path). params ajana google.protobuf.Struct olarak iletilir.
	EnqueueCommandParams(ctx context.Context, deviceID, cmdType, issuedBy string, params map[string]string) error
	// SetDeviceStatus, cihazın durum sütununu doğrudan ayarlar (komut kuyruğa
	// girdikten sonra durumun UI'da yansıması için).
	SetDeviceStatus(ctx context.Context, deviceID, status string) error
	// SetDeviceTags, cihazın etiketlerini (filo gruplama) değiştirir. tenantID boş değilse
	// yazım cihazın kiracısıyla daraltılır (eşleşen cihaz yoksa ErrForbidden); boş = platform.
	SetDeviceTags(ctx context.Context, deviceID string, tags []string, tenantID string) error
	RevokeDeviceCerts(ctx context.Context, deviceID, reason string) error
	// EraseDeviceData, KVKK veri silme talebi için cihazın davranışsal/telemetri
	// verisini (olay logları, komut geçmişi) siler ve sertifikalarını iptal eder
	// (kalıcı erişim engeli). Denetim izi KORUNUR (işleme kaydı). Silinen olay/komut
	// ve iptal edilen sertifika sayısını döner.
	EraseDeviceData(ctx context.Context, deviceID string) (events, commands, certs int, err error)
	WriteAudit(ctx context.Context, adminID, action, targetType, targetID string) error
	// SetEventAck, bir olayın triyaj durumunu (ACKNOWLEDGED/RESOLVED) ayarlar
	// (olay başına upsert). Alarm yaşam-döngüsü.
	SetEventAck(ctx context.Context, eventID, adminID, status string) error
	// SetEventCase, bir olayın vaka alanlarını (sorumlu + not) ayarlar (upsert;
	// durum sütununa dokunmaz). Vaka yönetimi.
	SetEventCase(ctx context.Context, eventID, adminID, assignee, note string) error
	// CreatePolicy, yeni politika oluşturur. tenantID politikanın sahibi kiracıdır ("" =
	// platform/paylaşımlı; kiracıya bağlı admin için salt-okunur). Çağıran sunucu-tarafı çözer.
	CreatePolicy(ctx context.Context, name, version, tenantID string) (policyID string, err error)
	// PolicyTenant, politikanın sahibi kiracıyı döner ("" = platform/paylaşımlı). Politika
	// yoksa found=false (hata değil). Politika erişim kapısı ve atama değişmezi bunu kullanır.
	PolicyTenant(ctx context.Context, policyID string) (tenantID string, found bool, err error)
	AssignPolicy(ctx context.Context, deviceID, policyID string) error
	// AddPolicyRule, politikaya yeni bir kural ekler.
	AddPolicyRule(ctx context.Context, policyID string, in RuleInput) error
	// BumpPolicyVersion, politikanın sürümünü yükseltir ve yeni sürümü döner.
	BumpPolicyVersion(ctx context.Context, policyID string) (newVersion string, err error)
	// DevicesForPolicy, politikaya atanmış cihaz id'lerini döner (republish için).
	DevicesForPolicy(ctx context.Context, policyID string) ([]string, error)
	// ListPolicyRules, politikanın kurallarını döner.
	ListPolicyRules(ctx context.Context, policyID string) ([]RuleView, error)
	// CreateAdmin, yeni bir yönetici ekler ve id'sini döner. passwordHash zaten
	// Argon2id ile hash'lenmiştir (depo düz metin görmez). tenantID, yöneticinin
	// bağlı olduğu kiracıdır (boş → platform admini, tüm kiracıları görür).
	CreateAdmin(ctx context.Context, email, passwordHash string, role Role, tenantID string) (string, error)
	// AdminTenant, bir yöneticinin bağlı olduğu kiracıyı döner (okuma izolasyonu ve
	// ayrıcalık-yükseltme koruması için). Boş → platform admini. Bilinmeyen veya PASİF yönetici
	// için "" DÖNMEZ: ErrUnknownAdmin (403) döner — çağıranlar fail-closed reddeder, asla
	// platform kapsamına düşmez.
	AdminTenant(ctx context.Context, adminID string) (string, error)
	// TenantForDevice, cihazın bağlı olduğu kiracıyı döner (aksiyon/yazma-yolu kiracı
	// zorunlu-kılması için). Cihaz yoksa boş döner.
	TenantForDevice(ctx context.Context, deviceID string) (string, error)
	// EventTenant, bir olayın (event_logs.id) kiracısını döner (olay triyaj yazma-yolu
	// kiracı zorunlu-kılması için). Olay yoksa boş döner.
	EventTenant(ctx context.Context, eventID string) (string, error)
	// SetAdminRole, bir yöneticinin rolünü değiştirir. tenantID boş değilse yazım hedefin
	// kiracısıyla daraltılır (derinlemesine savunma; eşleşen yönetici yoksa ErrForbidden);
	// boş = platform kapsamı (süzme yok).
	SetAdminRole(ctx context.Context, id string, role Role, tenantID string) error
	// DeactivateAdmin, bir yöneticiyi pasifleştirir (is_active=false). tenantID semantiği
	// SetAdminRole ile aynıdır.
	DeactivateAdmin(ctx context.Context, id, tenantID string) error
	// ListAdmins, yöneticileri döner (parola hash'i olmadan). tenantID boş değilse
	// YALNIZ o kiracının yöneticileri döner (platform adminleri dahil DEĞİL); boş →
	// tüm yöneticiler (yalnız platform admini çağırır — service katmanı zorunlu kılar).
	ListAdmins(ctx context.Context, tenantID string) ([]AdminInfo, error)
	// SetPendingMFASecret, yöneticinin YENİ TOTP sırrını BEKLEYEN olarak saklar (at-rest
	// şifreli). Etkin sır ve mfa_enrolled DEĞİŞMEZ: yeniden kayıtta mevcut MFA, yeni sır
	// ActivateMFA ile etkinleşene dek aynen zorunlu kalır.
	SetPendingMFASecret(ctx context.Context, adminID, secret string) error
	// LookupMFA, yöneticinin ETKİN TOTP sırrını ve etkin (enrolled) durumunu döner
	// (bekleyen sırrı DÖNMEZ — giriş/devre dışı bırakma yalnız etkin sırra karşı doğrulanır).
	// Sır yoksa ("", false, nil) döner.
	LookupMFA(ctx context.Context, adminID string) (secret string, enrolled bool, err error)
	// LookupPendingMFA, bekleyen (etkinleştirilmemiş) TOTP sırrını döner; yoksa ("", nil).
	LookupPendingMFA(ctx context.Context, adminID string) (secret string, err error)
	// ActivateMFA, bekleyen sırrı ATOMİK olarak etkin sır yapar (mfa_enrolled=true; eski
	// sır geçersizleşir). Bekleyen sır yoksa hiçbir şey değişmez.
	ActivateMFA(ctx context.Context, adminID string) error
	// DisableMFA, etkin ve bekleyen TOTP sırrını siler ve MFA'yı kapatır.
	DisableMFA(ctx context.Context, adminID string) error
	// ConsumeTOTPStep, TOTP tek-kullanım (anti-replay) zorlamasıdır: verilen adım sayacını
	// (VerifyTOTPStep'ten) yöneticinin son kabul edilen adımından BÜYÜKSE atomik olarak
	// kaydeder ve accepted=true döner; aksi halde (adım <= son) accepted=false (replay).
	ConsumeTOTPStep(ctx context.Context, adminID string, step int64) (accepted bool, err error)
	// SavePendingWipe, bir cihaz için ikinci-onay bekleyen WIPE talebini saklar
	// (çift-kontrol / dört-göz). deviceID başına upsert.
	SavePendingWipe(ctx context.Context, deviceID, requestedBy, reason string) error
	// GetPendingWipe, cihaz için bekleyen WIPE talebini (talep eden admin id'si)
	// döner. Yoksa ("", false, nil).
	GetPendingWipe(ctx context.Context, deviceID string) (requestedBy string, exists bool, err error)
	// DeletePendingWipe, bekleyen WIPE talebini siler (onay/iptal sonrası). Yoksa no-op.
	DeletePendingWipe(ctx context.Context, deviceID string) error
	// ConsumePendingWipe, bekleyen WIPE talebini ATOMİK "claim" eder (approval
	// concurrency): talep VAR ve requestedBy != approverID ise talebi siler ve
	// (requestedBy, true) döner; approver talep edenle AYNIYSA silmeden (requestedBy,
	// false) döner (dört-göz); talep YOKSA ("", false). İki eşzamanlı onaylayandan EN
	// FAZLA biri true alır → WIPE komutu en fazla bir kez kuyruğa girer.
	ConsumePendingWipe(ctx context.Context, deviceID, approverID string) (requestedBy string, consumed bool, err error)
}

// validRuleType, kabul edilen kural tiplerini doğrular.
func validRuleType(t string) bool {
	switch t {
	case "APP_TIME_BLOCK", "APP_BLOCK_ALWAYS", "NETWORK_RULE":
		return true
	default:
		return false
	}
}

// Publisher, bir cihaza politika atandığında anlık push tetiklemek için
// kullanılır (opsiyonel; nil ise push tetiklenmez).
type Publisher interface {
	Publish(deviceID string)
}

// Service, admin işlemlerini yürütür.
type Service struct {
	store           Store
	bidx            *security.BlindIndexer
	tokenTTL        time.Duration
	now             func() time.Time
	genToken        func() (string, error)
	pub             Publisher
	wipeDualControl bool // açıksa WIPE iki farklı ADMIN onayı gerektirir (dört-göz)
	// scopeEng, yüksek-etkili operasyonların (WIPE/QUARANTINE/LOCK/RESTART) hedefe
	// uygulanmadan önce geçtiği merkezi Scope/ROE guardrail'ıdır (§4). nil = kapalı
	// (geriye uyumlu no-op). scopeEnforce false iken RED kararları yalnız denetlenir
	// (would-deny), engellenmez; true iken op reddedilir.
	scopeEng     *scope.Engine
	scopeEnforce bool
	scopeTenant  string // hedef Target.Tenant (dağıtımın kiracı kimliği)
	// scopeAllowUnconfigured, Scope/ROE motoru HİÇ bağlı değilken (scopeEng==nil)
	// yüksek-etkili/yıkıcı operasyonların yine de geçmesine izin verir. Varsayılan
	// false = FAIL-CLOSED: motor yapılandırılmadıysa HighImpact+ operasyon reddedilir.
	// Yalnız operatör riski açıkça kabul ederse (KUT_SCOPE_ALLOW_UNCONFIGURED=1) veya
	// demo modunda true'ya çekilir (geriye uyumlu kaçış kapağı).
	scopeAllowUnconfigured bool
	// cmdPlane, bağlıysa cihaz komutlarının geçtiği komut düzlemidir (tam hot-path
	// entegrasyonu). guardScope (scope/ROE) bu çağrıdan ÖNCE uygulanır; düzlem bunun
	// ÜSTÜNE Ed25519 imza + anti-replay + kanonik authz ekler ve kanıtlanmış enqueue
	// sınırına delege eder. nil = eski doğrudan-depo yolu (geriye uyumlu).
	cmdPlane *commandplane.Plane
}

// NewService oluşturur.
func NewService(store Store, bidx *security.BlindIndexer, tokenTTL time.Duration) *Service {
	return &Service{
		store:    store,
		bidx:     bidx,
		tokenTTL: tokenTTL,
		now:      time.Now,
		genToken: defaultGenToken,
	}
}

// SetPublisher, politika atamalarında anlık push için bir yayıncı bağlar.
func (s *Service) SetPublisher(p Publisher) { s.pub = p }

// ErrOutOfScope, bir operasyon Scope/ROE guardrail'ı tarafından reddedildiğinde döner (§4).
var ErrOutOfScope = errors.New("admin: operasyon scope/ROE dışı")

// SetScopeEngine, merkezi Scope/ROE guardrail'ını bağlar. enforce=false iken kararlar
// yalnız denetlenir (would-deny sayacı + audit), operasyon engellenmez — operatör
// politikayı üretimde açmadan önce ayarlayabilir. tenant, hedef Target.Tenant'ıdır.
func (s *Service) SetScopeEngine(e *scope.Engine, enforce bool, tenant string) {
	s.scopeEng, s.scopeEnforce, s.scopeTenant = e, enforce, tenant
}

// SetCommandPlane, cihaz komutlarının geçeceği komut düzlemini bağlar (tam hot-path
// entegrasyonu). nil geçilirse eski doğrudan-depo yolu korunur. Düzlem; mevcut
// RBAC/tenant/scope ön-kontrollerinin ÜSTÜNE imza + anti-replay + kanonik authz ekler.
func (s *Service) SetCommandPlane(p *commandplane.Plane) { s.cmdPlane = p }

// planeRoutable, komut tipinin yönetici yolunda komut düzleminden geçip geçmeyeceğini
// PAYLAŞILAN komut tablosundan (cmdenvelope.Spec.PlaneRouted) okur. Komut düzlemi
// bağlıyken YALNIZ PlaneRouted tipler düzlemden geçer; diğerleri (COLLECT_DIAGNOSTICS:
// sonraki bir sürümde taşınır; UNINSTALL: yönetici giriş noktası yok) doğrudan depo yoluna düşer
// (düzlem Validate'ini tetiklemeden, davranış korunur). Kayıtsız tip düzleme gitmez.
func planeRoutable(cmdType string) bool {
	spec, ok := cmdenvelope.Lookup(cmdType)
	return ok && spec.PlaneRouted
}

// enqueue, bir cihaz komutunu kuyruğa alır. Komut düzlemi bağlı VE komut türü
// düzlem-uyumluysa komut düzlemden geçer (imza+anti-replay+authz, ardından kanıtlanmış
// enqueue sınırına delege). guardScope bu çağrıdan ÖNCE uygulanmıştır. Aksi halde
// doğrudan depo (geriye uyumlu).
func (s *Service) enqueue(ctx context.Context, deviceID, cmdType, issuedBy string, params map[string]string) error {
	if s.cmdPlane != nil && planeRoutable(cmdType) {
		_, err := s.cmdPlane.Dispatch(ctx, commandplane.CommandRequest{
			DeviceID: deviceID,
			Type:     commandplane.CommandType(cmdType),
			IssuedBy: issuedBy,
			Params:   anyParams(params),
		})
		return err
	}
	if params != nil {
		return s.store.EnqueueCommandParams(ctx, deviceID, cmdType, issuedBy, params)
	}
	return s.store.EnqueueCommand(ctx, deviceID, cmdType, issuedBy)
}

// anyParams, string parametre haritasını komut düzleminin map[string]any biçimine çevirir.
func anyParams(in map[string]string) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// SetScopeAllowUnconfigured, Scope/ROE motoru bağlı değilken yüksek-etkili
// operasyonlara izin verilip verilmeyeceğini belirler. false (varsayılan) =
// fail-closed: motor yoksa HighImpact+ operasyon reddedilir. true = geriye uyumlu
// kaçış kapağı (operatör riski açıkça kabul etti veya demo modu).
func (s *Service) SetScopeAllowUnconfigured(allow bool) { s.scopeAllowUnconfigured = allow }

// guardScope, yüksek-etkili bir operasyonu Scope/ROE motorundan geçirir. Motor bağlı
// değilse no-op'tur (geriye uyumlu). RED + enforce → ErrOutOfScope; RED + denetim →
// izin verir ama sayaç/audit'e yazar.
func (s *Service) guardScope(ctx context.Context, adminID, deviceID string, act scope.Action) error {
	if s.scopeEng == nil {
		// FAIL-CLOSED: motor yapılandırılmadıysa yüksek-etkili/yıkıcı operasyonu
		// reddet — sessiz fail-open yerine güvenli varsayılan (§4). Yalnız operatör
		// açıkça izin verdiyse (veya demo) geçilir. Düşük-etkili (passive/active/
		// remote) operasyonlar motor yokken de geçebilir.
		if s.scopeAllowUnconfigured || scope.ImpactOf(act) < scope.HighImpact {
			return nil
		}
		metrics.IncScopeDenied()
		s.audit(ctx, adminID, "SCOPE_UNCONFIGURED_DENY:"+string(act), "device", deviceID)
		return fmt.Errorf("%w (%s): Scope/ROE motoru yapılandırılmadı — yüksek-etkili operasyon fail-closed reddedildi (kabul için KUT_SCOPE_ALLOW_UNCONFIGURED=1)", ErrOutOfScope, act)
	}
	// INV-044: yapılandırılmış motorda tenant bağı ZORUNLU. Boş tenant güvenlik
	// nesnesinde implicit "default"a düşemez; yüksek-etkili operasyon fail-closed reddedilir.
	if s.scopeTenant == "" && scope.ImpactOf(act) >= scope.HighImpact {
		metrics.IncScopeDenied()
		s.audit(ctx, adminID, "TENANT_MISSING_DENY:"+string(act), "device", deviceID)
		return fmt.Errorf("%w (%s): tenant bağı yok — yüksek-etkili operasyon fail-closed reddedildi (INV-044)", ErrOutOfScope, act)
	}
	d := s.scopeEng.Authorize(scope.Target{Tenant: s.scopeTenant, DeviceID: deviceID}, act)
	if d.Allowed {
		return nil
	}
	if s.scopeEnforce {
		metrics.IncScopeDenied()
		s.audit(ctx, adminID, "SCOPE_DENY:"+string(act), "device", deviceID)
		return fmt.Errorf("%w (%s): %s", ErrOutOfScope, act, d.Reason)
	}
	metrics.IncScopeWouldDeny()
	s.audit(ctx, adminID, "SCOPE_AUDIT:"+string(act), "device", deviceID)
	return nil
}

// require, adminID'nin en az min yetkiye sahip olduğunu doğrular.
func (s *Service) require(ctx context.Context, adminID string, min Role) error {
	role, err := s.store.AdminRole(ctx, adminID)
	if err != nil {
		return err
	}
	if rank(role) < rank(min) {
		return ErrForbidden
	}
	return nil
}

// IssueEnrollmentToken, tek kullanımlık bir kayıt token'ı üretir (OPERATOR+).
// Ham token YALNIZ burada döner (bir kez gösterilir); DB'de HMAC indeksi saklanır.
//
// KİRACI DUVARI: kiracıya bağlı bir çağıran HER ZAMAN kendi kiracısı için token üretir;
// tenantID boşsa "kendi kiracım" demektir, başka bir değer ErrForbidden'dır (başka
// kiracıya cihaz sokma / telemetri zehirleme engeli). Yalnız platform admini (kiracısız)
// kiracı seçebilir; çağıran (HTTP katmanı) doğrulanmış kiracıyı verir.
func (s *Service) IssueEnrollmentToken(ctx context.Context, adminID, tenantID string) (string, error) {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return "", err
	}
	callerTenant, err := s.store.AdminTenant(ctx, adminID)
	if err != nil {
		return "", err
	}
	if callerTenant != "" {
		if tenantID != "" && tenantID != callerTenant {
			return "", ErrForbidden
		}
		tenantID = callerTenant
	}
	token, err := s.genToken()
	if err != nil {
		return "", err
	}
	idx := s.bidx.Compute("enroll-token:" + token)
	if err := s.store.SaveEnrollmentToken(ctx, idx, adminID, tenantID, s.now().Add(s.tokenTTL)); err != nil {
		return "", err
	}
	s.audit(ctx, adminID, "ISSUE_ENROLLMENT_TOKEN", "device", "")
	return token, nil
}

// QuarantineDevice, cihazı karantinaya alma komutu kuyruğa ekler (OPERATOR+) ve
// durum sütununu QUARANTINED olarak yansıtır.
// RevokeEnrollmentToken, henüz kullanılmamış bir enrollment token'ı iptal eder
// (OPERATOR+). İptal edilen token bir sonraki kayıt denemesinde reddedilir.
func (s *Service) RevokeEnrollmentToken(ctx context.Context, adminID, tokenID string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	// KİRACI DUVARI: kiracıya bağlı çağıran yalnız KENDİ kiracısının token'ını iptal
	// edebilir; yok/yabancı token fail-closed ErrForbidden (varlık sızdırmaz).
	callerTenant, err := s.store.AdminTenant(ctx, adminID)
	if err != nil {
		return err
	}
	if callerTenant != "" {
		tokTenant, found, err := s.store.EnrollmentTokenTenant(ctx, tokenID)
		if err != nil {
			return err
		}
		if !found || tokTenant != callerTenant {
			return ErrForbidden
		}
	}
	if err := s.store.RevokeEnrollmentToken(ctx, tokenID, callerTenant); err != nil {
		return err
	}
	s.audit(ctx, adminID, "REVOKE_ENROLLMENT_TOKEN", "token", tokenID)
	return nil
}

// BeginMFAEnrollment, yönetici için yeni bir TOTP sırrı üretir, bekleyen olarak
// saklar ve authenticator uygulamasına eklenecek otpauth:// URI'sini döner. Yalnız
// oturum sahibinin kendi hesabı için çağrılır (adminID oturumdan gelir). Etkin
// olması için ActivateMFA ile doğrulama gerekir.
//
// MFA zaten ETKİNSE (yeniden kayıt) mevcut sırdan geçerli bir TOTP kodu (currentCode)
// ZORUNLUDUR: aksi halde çalınmış/uzun ömürlü bir oturum, kodsuz /mfa/enroll ile MFA'yı
// sessizce kapatabilirdi (DisableMFA kod ister, enroll istemiyordu). Kod, ActivateMFA/
// DisableMFA ile aynı anti-replay (ConsumeTOTPStep) yoluyla tüketilir. İlk kayıtta
// (MFA etkin değil) kod gerekmez. Yeni sır BEKLEYEN olarak ayrı saklanır; mevcut sır ve
// etkin durum, yeni sır ActivateMFA ile (YENİ sırdan geçerli kodla) etkinleşene dek
// DEĞİŞMEZ — böylece yeniden kayıt penceresinde giriş MFA'yı zorunlu kılmaya, DisableMFA
// ise mevcut sırdan kod istemeye devam eder; terk edilen yeniden kayıt MFA'yı kapatmaz.
// Her başlatma denetim izine yazılır.
func (s *Service) BeginMFAEnrollment(ctx context.Context, adminID, currentCode string) (secret, uri string, err error) {
	if err := s.require(ctx, adminID, RoleViewer); err != nil {
		return "", "", err
	}
	oldSecret, enrolled, err := s.store.LookupMFA(ctx, adminID)
	if err != nil {
		return "", "", err
	}
	if enrolled {
		step, ok := security.VerifyTOTPStep(oldSecret, currentCode, s.now())
		if !ok {
			s.audit(ctx, adminID, "MFA_REENROLL_DENIED", "admin", adminID)
			return "", "", fmt.Errorf("%w: MFA yeniden kaydı için mevcut doğrulama kodu gerekli", ErrForbidden)
		}
		if accepted, err := s.store.ConsumeTOTPStep(ctx, adminID, step); err != nil {
			return "", "", err
		} else if !accepted {
			s.audit(ctx, adminID, "MFA_REENROLL_DENIED", "admin", adminID)
			return "", "", fmt.Errorf("%w: kod zaten kullanıldı (tekrar reddi)", ErrForbidden)
		}
	}
	secret, err = security.GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	if err := s.store.SetPendingMFASecret(ctx, adminID, secret); err != nil {
		return "", "", err
	}
	if enrolled {
		s.audit(ctx, adminID, "MFA_REENROLL_BEGIN", "admin", adminID)
	} else {
		s.audit(ctx, adminID, "MFA_ENROLL_BEGIN", "admin", adminID)
	}
	uri = security.OTPAuthURI("KUT Konsol", adminID, secret)
	return secret, uri, nil
}

// ActivateMFA, BEKLEYEN TOTP sırrını yalnız o (YENİ) sırdan üretilmiş geçerli bir kod ile
// etkinleştirir (kullanıcının authenticator'ını doğru kurduğunu kanıtlar); depoda atomik
// takas yapılır: yeni sır etkin olur, eski sır GEÇERSİZLEŞİR. Doğrulama izi yazılır.
func (s *Service) ActivateMFA(ctx context.Context, adminID, code string) error {
	if err := s.require(ctx, adminID, RoleViewer); err != nil {
		return err
	}
	secret, err := s.store.LookupPendingMFA(ctx, adminID)
	if err != nil {
		return err
	}
	if secret == "" {
		return fmt.Errorf("%w: MFA kaydı başlatılmadı", ErrForbidden)
	}
	step, ok := security.VerifyTOTPStep(secret, code, s.now())
	if !ok {
		return fmt.Errorf("%w: doğrulama kodu geçersiz", ErrForbidden)
	}
	if accepted, err := s.store.ConsumeTOTPStep(ctx, adminID, step); err != nil {
		return err
	} else if !accepted {
		return fmt.Errorf("%w: kod zaten kullanıldı (tekrar reddi)", ErrForbidden)
	}
	if err := s.store.ActivateMFA(ctx, adminID); err != nil {
		return err
	}
	s.audit(ctx, adminID, "MFA_ENABLED", "admin", adminID)
	return nil
}

// DisableMFA, MFA'yı yalnız geçerli bir kod doğrulamasından sonra kapatır (kaza/
// yetkisiz kapatmayı önler). Kayıt başlatılmış ama etkinleşmemiş sır da temizlenir.
func (s *Service) DisableMFA(ctx context.Context, adminID, code string) error {
	if err := s.require(ctx, adminID, RoleViewer); err != nil {
		return err
	}
	secret, enrolled, err := s.store.LookupMFA(ctx, adminID)
	if err != nil {
		return err
	}
	if enrolled {
		step, ok := security.VerifyTOTPStep(secret, code, s.now())
		if !ok {
			return fmt.Errorf("%w: doğrulama kodu geçersiz", ErrForbidden)
		}
		if accepted, err := s.store.ConsumeTOTPStep(ctx, adminID, step); err != nil {
			return err
		} else if !accepted {
			return fmt.Errorf("%w: kod zaten kullanıldı (tekrar reddi)", ErrForbidden)
		}
	}
	if err := s.store.DisableMFA(ctx, adminID); err != nil {
		return err
	}
	if enrolled {
		s.audit(ctx, adminID, "MFA_DISABLED", "admin", adminID)
	}
	return nil
}

// maxTags, cihaz başına etiket üst sınırı; maxTagLen tek etiket uzunluk sınırı.
const (
	maxTags   = 20
	maxTagLen = 40
)

// SetDeviceTags, cihazın etiketlerini ayarlar (OPERATOR+). Etiketler kırpılır,
// boşlar atılır, tekilleştirilir; sayısı/uzunluğu sınırlanır (kaynak/DoS koruması).
// Denetim izine yazılır.
func (s *Service) SetDeviceTags(ctx context.Context, adminID, deviceID string, tags []string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	// KİRACI DUVARI: diğer cihaz mutasyonları gibi — yalnız kendi kiracısının cihazı.
	callerTenant, err := s.deviceCallerTenant(ctx, adminID, deviceID)
	if err != nil {
		return err
	}
	clean := normalizeTags(tags)
	if err := s.store.SetDeviceTags(ctx, deviceID, clean, callerTenant); err != nil {
		return err
	}
	s.audit(ctx, adminID, "SET_TAGS", "device", deviceID)
	return nil
}

// normalizeTags, etiketleri kırpar, boşları atar, tekilleştirir (sıra korunur) ve
// sayı/uzunluk sınırlarını uygular.
func normalizeTags(tags []string) []string {
	seen := make(map[string]bool, len(tags))
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len(t) > maxTagLen {
			t = t[:maxTagLen]
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) >= maxTags {
			break
		}
	}
	return out
}

// QuarantineDevice, cihazı karantinaya alma komutu kuyruğa ekler (OPERATOR+).
func (s *Service) QuarantineDevice(ctx context.Context, adminID, deviceID string) error {
	// DESIRED durum QUARANTINE_PENDING'dir: komut kuyruğa alındı ama cihaz henüz
	// gerçek izolasyonu onaylamadı. EFFECTIVE 'QUARANTINED', yalnız ajan komut SUCCESS
	// bildirince ApplyCommandResults ile verilir — SOC yanıltıcı "izole" görmez.
	return s.command(ctx, adminID, deviceID, cmdenvelope.TypeQuarantine, "QUARANTINE_PENDING")
}

// ReleaseDevice, karantinayı kaldırma komutu kuyruğa ekler (OPERATOR+) ve durum
// sütununu ACTIVE olarak geri yansıtır.
func (s *Service) ReleaseDevice(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, cmdenvelope.TypeUnquarantine, "ACTIVE")
}

// CollectDiagnostics, cihazdan tanılama toplama komutu kuyruğa ekler (OPERATOR+).
// Durum değiştirmez — zararsız, salt-toplama bir işlemdir.
func (s *Service) CollectDiagnostics(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, cmdenvelope.TypeCollectDiagnostics, "")
}

// LockDevice, uzaktan ekran kilitleme komutu kuyruğa ekler (OPERATOR+, MDM).
func (s *Service) LockDevice(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, cmdenvelope.TypeLock, "")
}

// RestartDevice, uzaktan yeniden başlatma komutu kuyruğa ekler (OPERATOR+, MDM).
func (s *Service) RestartDevice(ctx context.Context, adminID, deviceID string) error {
	return s.command(ctx, adminID, deviceID, cmdenvelope.TypeRestart, "")
}

// WipeDevice, uzaktan veri silme komutu kuyruğa ekler — YIKICI olduğundan ADMIN
// gerektirir ve denetim izine yazılır. (Ajan bu sürümde gerçek silme yapmaz;
// komut/RBAC/denetim akışı tamdır — bkz. deviceaction.Wipe.)
// audit, tamper-evident denetim izine bir kayıt yazar. Yazım BAŞARISIZ olursa SESSİZCE
// YUTMAZ: bir metrik artırır ve loglar (non-repudiation açığının tespit edilebilirliği —
// güvenlik eylemi audit kaydı olmadan gerçekleşmişse izleme/uyarı bunu görür). Operasyonun
// başarı/başarısızlığını DEĞİŞTİRMEZ: audit-store kesintisi meşru güvenlik operasyonlarını
// bloklamamalıdır (fail-open kararı bilinçli); kayıp görünür kılınır.
func (s *Service) audit(ctx context.Context, adminID, action, kind, target string) {
	if err := s.store.WriteAudit(ctx, adminID, action, kind, target); err != nil {
		metrics.IncAuditWriteFailure()
		log.Printf("[audit] YAZIM BAŞARISIZ (non-repudiation riski): action=%s kind=%s target=%s admin=%s: %v",
			action, kind, target, adminID, err)
	}
}

func (s *Service) WipeDevice(ctx context.Context, adminID, deviceID string) error {
	if err := s.requireCmd(ctx, adminID, cmdenvelope.TypeWipe); err != nil {
		return err
	}
	if err := s.enforceDeviceTenant(ctx, adminID, deviceID); err != nil {
		return err
	}
	if err := s.guardCmdScope(ctx, adminID, deviceID, cmdenvelope.TypeWipe); err != nil {
		return err
	}
	if err := s.enqueue(ctx, deviceID, cmdenvelope.TypeWipe, adminID, nil); err != nil {
		return err
	}
	s.audit(ctx, adminID, "WIPE", "device", deviceID)
	return nil
}

// SetWipeDualControl, WIPE için çift-kontrolü (iki farklı ADMIN onayı) açar/kapatır.
func (s *Service) SetWipeDualControl(on bool) { s.wipeDualControl = on }

// WipeDualControl, çift-kontrolün açık olup olmadığını döner (görünürlük/yönlendirme).
func (s *Service) WipeDualControl() bool { return s.wipeDualControl }

// RequestWipe, çift-kontrol modunda bir WIPE talebini kaydeder (ADMIN). Komut HENÜZ
// kuyruğa GİRMEZ — farklı bir ADMIN ApproveWipe ile onaylamalıdır (dört-göz ilkesi;
// tek ele geçirilmiş/kötü-niyetli ADMIN filo silemez). Denetim izine yazılır.
func (s *Service) RequestWipe(ctx context.Context, adminID, deviceID, reason string) error {
	if err := s.requireCmd(ctx, adminID, cmdenvelope.TypeWipe); err != nil {
		return err
	}
	if strings.TrimSpace(deviceID) == "" {
		return fmt.Errorf("%w: cihaz kimliği zorunlu", ErrInvalidInput)
	}
	if len(reason) > 500 {
		return fmt.Errorf("%w: gerekçe çok uzun", ErrInvalidInput)
	}
	if err := s.enforceDeviceTenant(ctx, adminID, deviceID); err != nil {
		return err
	}
	// Scope/ROE'yi ERKEN uygula: kapsam dışı bir WIPE talebi hiç kaydedilmesin.
	if err := s.guardCmdScope(ctx, adminID, deviceID, cmdenvelope.TypeWipe); err != nil {
		return err
	}
	if err := s.store.SavePendingWipe(ctx, deviceID, adminID, strings.TrimSpace(reason)); err != nil {
		return err
	}
	s.audit(ctx, adminID, "WIPE_REQUEST", "device", deviceID)
	return nil
}

// ApproveWipe, bekleyen bir WIPE talebini onaylar ve komutu kuyruğa alır (ADMIN).
// Onaylayan, talep edenden FARKLI olmalıdır — kendi talebini onaylayamaz (dört-göz).
// Onaydan sonra bekleyen talep silinir. Denetim izine yazılır.
func (s *Service) ApproveWipe(ctx context.Context, approverID, deviceID string) error {
	if err := s.requireCmd(ctx, approverID, cmdenvelope.TypeWipe); err != nil {
		return err
	}
	if err := s.enforceDeviceTenant(ctx, approverID, deviceID); err != nil {
		return err
	}
	// Onay anında da Scope/ROE uygulanır (talep ile onay arasında politika değişebilir);
	// kapsam dışıysa talebi TÜKETMEDEN reddet.
	if err := s.guardCmdScope(ctx, approverID, deviceID, cmdenvelope.TypeWipe); err != nil {
		return err
	}
	// Atomik claim: GetPendingWipe+DeletePendingWipe arasındaki TOCTOU yarışı
	// kapatıldı — iki eşzamanlı onaylayandan yalnız biri talebi tüketir, böylece WIPE
	// komutu en fazla BİR kez kuyruğa girer. Dört-göz (requester≠approver) da atomik.
	requestedBy, consumed, err := s.store.ConsumePendingWipe(ctx, deviceID, approverID)
	if err != nil {
		return err
	}
	if !consumed {
		if requestedBy == approverID {
			return ErrForbidden // kendi talebini onaylayamaz (dört-göz)
		}
		return fmt.Errorf("%w: bekleyen WIPE talebi yok", ErrInvalidInput) // yok ya da başka onaylayan tüketti
	}
	if err := s.enqueue(ctx, deviceID, cmdenvelope.TypeWipe, approverID, nil); err != nil {
		return err
	}
	s.audit(ctx, approverID, "WIPE_APPROVE", "device", deviceID)
	return nil
}

// CancelWipe, bekleyen bir WIPE talebini iptal eder (ADMIN). Denetim izine yazılır.
func (s *Service) CancelWipe(ctx context.Context, adminID, deviceID string) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	if err := s.enforceDeviceTenant(ctx, adminID, deviceID); err != nil {
		return err
	}
	if err := s.store.DeletePendingWipe(ctx, deviceID); err != nil {
		return err
	}
	s.audit(ctx, adminID, "WIPE_CANCEL", "device", deviceID)
	return nil
}

// UpdateEventCase, bir olayın vaka alanlarını (sorumlu analist + not) günceller
// (OPERATOR+). Vaka yönetimi. Denetim izine yazılır.
func (s *Service) UpdateEventCase(ctx context.Context, adminID, eventID, assignee, note string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if eventID == "" {
		return fmt.Errorf("%w: olay kimliği zorunlu", ErrInvalidInput)
	}
	if len(assignee) > 200 || len(note) > 2000 {
		return fmt.Errorf("%w: sorumlu/not çok uzun", ErrInvalidInput)
	}
	if err := s.enforceEventTenant(ctx, adminID, eventID); err != nil {
		return err
	}
	if err := s.store.SetEventCase(ctx, eventID, adminID, strings.TrimSpace(assignee), strings.TrimSpace(note)); err != nil {
		return err
	}
	s.audit(ctx, adminID, "EVENT_CASE", "event", eventID)
	return nil
}

// CollectFile, bir cihazdan adli/IR dosya toplama komutu kuyruğa ekler
// (OPERATOR+). Ajan dosyayı okuyup UploadArtifact ile yükler. Denetim izine yazılır.
func (s *Service) CollectFile(ctx context.Context, adminID, deviceID, path string) error {
	if err := s.requireCmd(ctx, adminID, cmdenvelope.TypeCollectFile); err != nil {
		return err
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: dosya yolu zorunlu", ErrInvalidInput)
	}
	if err := s.enforceDeviceTenant(ctx, adminID, deviceID); err != nil {
		return err
	}
	// uzaktan dosya toplama da diğer cihaz komutlarıyla TUTARLI biçimde Scope/ROE'den
	// geçer (kapsam dışı cihazdan kanıt/dosya toplanmasın; chain-of-custody).
	if err := s.guardCmdScope(ctx, adminID, deviceID, cmdenvelope.TypeCollectFile); err != nil {
		return err
	}
	if err := s.enqueue(ctx, deviceID, cmdenvelope.TypeCollectFile, adminID, map[string]string{"path": path}); err != nil {
		return err
	}
	s.audit(ctx, adminID, "COLLECT_FILE", "device", deviceID)
	return nil
}

// AckEvent, bir olayı triyaj durumuna geçirir (ACKNOWLEDGED "inceleniyor" veya
// RESOLVED "kapatıldı") — alarm yaşam-döngüsü (OPERATOR+). Denetim izine yazılır.
func (s *Service) AckEvent(ctx context.Context, adminID, eventID, status string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if status != "ACKNOWLEDGED" && status != "RESOLVED" {
		return fmt.Errorf("%w: geçersiz durum %q", ErrInvalidInput, status)
	}
	if eventID == "" {
		return fmt.Errorf("%w: olay kimliği zorunlu", ErrInvalidInput)
	}
	if err := s.enforceEventTenant(ctx, adminID, eventID); err != nil {
		return err
	}
	if err := s.store.SetEventAck(ctx, eventID, adminID, status); err != nil {
		return err
	}
	s.audit(ctx, adminID, "EVENT_"+status, "event", eventID)
	return nil
}

// command, RBAC kontrolü sonrası komutu kuyruğa ekler, denetim izine yazar ve
// (reflectStatus boş değilse) cihazın durum sütununu günceller. Durum güncelleme
// hatası akışı BOZMAZ: komut zaten kuyruğa girmiştir; hata yutulur (best-effort
// yansıma), çünkü asıl doğruluk kaynağı komut kuyruğudur.
// commandScope, komut tipinin Scope/ROE aksiyonunu PAYLAŞILAN komut tablosundan çözer
// (fabricauthz.CommandAuthorizer ile AYNI kaynak — admin ve komut düzlemi tek kararda
// uyuşur). exempt=true: tip scope DIŞLAMASINDAN muaftır (UNQUARANTINE,
// COLLECT_DIAGNOSTICS; kısıt kaldıran/salt-okuma). RBAC ve kiracı denetimi muafiyetten
// ETKİLENMEZ: UNQUARANTINE de QUARANTINE ile aynı rolü (OPERATOR+) ister. ok=false:
// kayıtsız tip → çağıran REDDEDER (fail-closed).
func commandScope(cmdType string) (act scope.Action, exempt, ok bool) {
	spec, found := cmdenvelope.Lookup(cmdType)
	if !found {
		return "", false, false
	}
	if spec.ScopeExempt {
		return "", true, true
	}
	return scope.Action(spec.ScopeAction), false, true
}

// guardCmdScope, komut tipini tablodaki scope aksiyonuyla guardScope'tan geçirir; tablo-muaf
// tip için no-op'tur, kayıtsız tip için ErrInvalidInput döner (fail-closed).
func (s *Service) guardCmdScope(ctx context.Context, adminID, deviceID, cmdType string) error {
	act, exempt, known := commandScope(cmdType)
	if !known {
		return fmt.Errorf("%w: bilinmeyen komut tipi %q", ErrInvalidInput, cmdType)
	}
	if exempt {
		return nil
	}
	return s.guardScope(ctx, adminID, deviceID, act)
}

// requireCmd, komut tipinin tablodaki asgari rolünü doğrular (kayıtsız tip →
// ErrInvalidInput, fail-closed). cmdenvelope.Role ile admin.Role aynı dizgelerdir.
func (s *Service) requireCmd(ctx context.Context, adminID, cmdType string) error {
	spec, ok := cmdenvelope.Lookup(cmdType)
	if !ok {
		return fmt.Errorf("%w: bilinmeyen komut tipi %q", ErrInvalidInput, cmdType)
	}
	return s.require(ctx, adminID, Role(spec.MinRole))
}

// enforceDeviceTenant, çağıran yöneticinin hedef cihaza AKSİYON uygulama yetkisini
// kiracıya göre doğrular (çok-tenant WRITE izolasyonu): platform admini (boş kiracı)
// her cihaza; kiracıya bağlı admin YALNIZ kendi kiracısının cihazına. Aksi halde
// ErrForbidden — bir kiracının başka kiracının cihazını kilitleme/silme/karantina
// gibi YIKICI aksiyonlarını (çapraz-kiracı WRITE IDOR) engeller. Kiracı SUNUCU-TARAFI
// çözülür (adminID → admins.tenant_id; deviceID → devices.tenant_id), istekten DEĞİL.
func (s *Service) enforceDeviceTenant(ctx context.Context, adminID, deviceID string) error {
	_, err := s.deviceCallerTenant(ctx, adminID, deviceID)
	return err
}

// deviceCallerTenant, enforceDeviceTenant ile aynı kapıdır ve ek olarak çağıranın (sunucu-
// tarafı çözülmüş) kiracısını döner; yazma-yolu SQL'inin kiracı predicate'ine verilir.
// Bilinmeyen/pasif çağıran ErrUnknownAdmin (403) alır — asla platform kapsamına düşmez.
func (s *Service) deviceCallerTenant(ctx context.Context, adminID, deviceID string) (string, error) {
	adminTenant, err := s.store.AdminTenant(ctx, adminID)
	if err != nil {
		return "", err
	}
	if adminTenant == "" {
		return "", nil // platform admini: tüm kiracıların cihazlarına yetkili
	}
	devTenant, err := s.store.TenantForDevice(ctx, deviceID)
	if err != nil {
		return "", err
	}
	if devTenant != adminTenant {
		return "", ErrForbidden
	}
	return adminTenant, nil
}

// enforceEventTenant, çağıran yöneticinin bir OLAYIN triyajını (ack/resolve/vaka)
// değiştirme yetkisini kiracıya göre doğrular: platform admini her olaya; kiracıya
// bağlı admin YALNIZ kendi kiracısının olayına. Aksi halde ErrForbidden (bir kiracının
// başka kiracının alarmını "çözüldü" işaretlemesini engeller). Kiracı server-side.
func (s *Service) enforceEventTenant(ctx context.Context, adminID, eventID string) error {
	adminTenant, err := s.store.AdminTenant(ctx, adminID)
	if err != nil {
		return err
	}
	if adminTenant == "" {
		return nil // platform admini
	}
	evTenant, err := s.store.EventTenant(ctx, eventID)
	if err != nil {
		return err
	}
	if evTenant != adminTenant {
		return ErrForbidden
	}
	return nil
}

func (s *Service) command(ctx context.Context, adminID, deviceID, cmdType, reflectStatus string) error {
	if err := s.requireCmd(ctx, adminID, cmdType); err != nil {
		return err
	}
	// Çok-tenant: hedef cihaz çağıranın kiracısında mı? (scope/ROE'den ÖNCE; UNQUARANTINE/
	// COLLECT_DIAGNOSTICS scope'tan muaf olsa da kiracı zorunlu-kılması AŞILAMAZ.)
	if err := s.enforceDeviceTenant(ctx, adminID, deviceID); err != nil {
		return err
	}
	// Yüksek-etkili komutlar Scope/ROE kapısından geçer; tablo-muaf tipler (UNQUARANTINE,
	// COLLECT_DIAGNOSTICS) dışlamaya takılmaz. Kayıtsız tip fail-closed reddedilir.
	if err := s.guardCmdScope(ctx, adminID, deviceID, cmdType); err != nil {
		return err
	}
	if err := s.enqueue(ctx, deviceID, cmdType, adminID, nil); err != nil {
		return err
	}
	s.audit(ctx, adminID, cmdType, "device", deviceID)
	if reflectStatus != "" {
		// Best-effort: komut kuyruğa girdiği için hata olsa da akışı bozma.
		_ = s.store.SetDeviceStatus(ctx, deviceID, reflectStatus)
	}
	return nil
}

// ErasureReport, bir KVKK veri silme işleminin sonucudur.
type ErasureReport struct {
	EventsDeleted   int `json:"events_deleted"`
	CommandsDeleted int `json:"commands_deleted"`
	CertsRevoked    int `json:"certs_revoked"`
}

// EraseDevice, KVKK veri sahibi SİLME talebini uygular (ADMIN). Cihazın
// davranışsal/telemetri verisini siler ve sertifikalarını iptal eder; işlemin
// kendisi denetim izine ("DATA_ERASURE") yazılır (silme kaydı korunur).
func (s *Service) EraseDevice(ctx context.Context, adminID, deviceID string) (ErasureReport, error) {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return ErasureReport{}, err
	}
	if err := s.enforceDeviceTenant(ctx, adminID, deviceID); err != nil {
		return ErasureReport{}, err
	}
	// en yıkıcı server mutasyonu artık Scope/ROE'den FAIL-CLOSED geçer (motor
	// yapılandırılmamışsa reddedilir; wipe = Destructive). Not: EraseDeviceData
	// tek transaction'da atomiktir (tümü-ya-hiç) → "veri silindi ama cert-revoke
	// başarısız" kısmi-hata tutarsızlığı DB katmanında zaten engellenmiştir.
	if err := s.guardScope(ctx, adminID, deviceID, scope.ActionWipe); err != nil {
		return ErasureReport{}, err
	}
	ev, cmd, cert, err := s.store.EraseDeviceData(ctx, deviceID)
	if err != nil {
		return ErasureReport{}, err
	}
	s.audit(ctx, adminID, "DATA_ERASURE", "device", deviceID)
	return ErasureReport{EventsDeleted: ev, CommandsDeleted: cmd, CertsRevoked: cert}, nil
}

// EnsureRole, adminID'nin en az verilen role sahip olduğunu doğrular (yoksa
// ErrForbidden). Okuma uçlarında RBAC kapısı olarak kullanılır.
func (s *Service) EnsureRole(ctx context.Context, adminID string, min Role) error {
	return s.require(ctx, adminID, min)
}

// AuthorizeExport, KVKK veri sahibi ERİŞİM (dışa aktarma) talebini yetkilendirir
// (ADMIN) ve denetim izine ("DATA_EXPORT") yazar. Asıl veri toplama okuma
// servisinde yapılır; bu yalnız RBAC + denetim kapısıdır.
func (s *Service) AuthorizeExport(ctx context.Context, adminID, deviceID string) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	s.audit(ctx, adminID, "DATA_EXPORT", "device", deviceID)
	return nil
}

// RecordAudit, denetim izine bir eylem yazar (delil erişimi gibi salt-okunur ama
// izlenmesi gereken işlemler için). Kanıt gözetim zinciri (chain-of-custody):
// hangi analistin hangi delili ne zaman indirdiği denetlenebilir kalır.
func (s *Service) RecordAudit(ctx context.Context, adminID, action, targetType, targetID string) {
	s.audit(ctx, adminID, action, targetType, targetID)
}

// RevokeDevice, cihazın sertifikalarını iptal eder (OPERATOR+). İptal edilen
// ajan bir sonraki mTLS el sıkışmasında reddedilir.
func (s *Service) RevokeDevice(ctx context.Context, adminID, deviceID string) error {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return err
	}
	if err := s.enforceDeviceTenant(ctx, adminID, deviceID); err != nil {
		return err
	}
	// kimlik/kredensiyel mutasyonu da Scope/ROE-farkında olsun (kapsam dışı cihazın
	// sertifikası keyfi iptal edilmesin). Cert-revoke geri-alınabilir bir savunma olduğundan
	// remote-etki: motor yapılandırıldığında zorlanır, yapılandırılmamışsa geçer (savunmayı
	// yanlış-yapılandırma yüzünden engellememek için).
	if err := s.guardScope(ctx, adminID, deviceID, scope.ActionRemoteCommand); err != nil {
		return err
	}
	if err := s.store.RevokeDeviceCerts(ctx, deviceID, "admin_revoke"); err != nil {
		return err
	}
	s.audit(ctx, adminID, "REVOKE_CERT", "device", deviceID)
	return nil
}

// policyOwner, politika erişim kapısıdır. Politikanın sahibi kiracıyı döner
// ("" = platform/paylaşımlı). Kural:
//   - bilinmeyen politika → ErrForbidden (varlık sızdırılmaz);
//   - platform admini (boş kiracı) her politikayı okuyabilir/değiştirebilir;
//   - kiracıya bağlı admin KENDİ kiracısının politikasını okuyabilir/değiştirebilir;
//     platform/paylaşımlı politikayı yalnız OKUYABİLİR (write=false), değiştiremez;
//     başka kiracının politikasına hiçbir şekilde erişemez.
//
// Çağıran kiracısı sunucu-tarafı çözülür (AdminTenant), istekten DEĞİL.
func (s *Service) policyOwner(ctx context.Context, adminID, policyID string, write bool) (string, error) {
	callerTenant, err := s.store.AdminTenant(ctx, adminID)
	if err != nil {
		return "", err
	}
	pt, found, err := s.store.PolicyTenant(ctx, policyID)
	if err != nil {
		return "", err
	}
	if !found {
		return "", ErrForbidden
	}
	if callerTenant == "" {
		return pt, nil // platform admini: kısıtsız
	}
	if pt == callerTenant || (!write && pt == "") {
		return pt, nil
	}
	return "", ErrForbidden
}

// policyFitsDevice, politikanın cihaza ATANABİLİR olup olmadığını söyler: politika
// platform/paylaşımlı ("") ya da cihazla AYNI kiracıya aittir (boş cihaz kiracısı legacy
// 'default' ile eşdeğerdir). Bu bir bütünlük değişmezidir: platform admini dahil kimse bir
// kiracının politikasını başka kiracının cihazına atayamaz (kural itmesi yalnız sahibine ulaşır).
func policyFitsDevice(policyTenant, deviceTenant string) bool {
	return policyTenant == "" || tenant.Equivalent(policyTenant, deviceTenant)
}

// CreatePolicy, yeni bir politika oluşturur (ADMIN). Sahip kiracı SUNUCU-TARAFI belirlenir:
// kiracıya bağlı admin HER ZAMAN kendi kiracısı için oluşturur (boş istek = "kendi kiracım";
// başka bir değer ErrForbidden). Yalnız platform admini kiracı seçebilir (doğrulanır:
// tenant.Normalize) ya da boş bırakıp platform/paylaşımlı politika oluşturabilir.
func (s *Service) CreatePolicy(ctx context.Context, adminID, name, version, tenantID string) (string, error) {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return "", err
	}
	callerTenant, err := s.store.AdminTenant(ctx, adminID)
	if err != nil {
		return "", err
	}
	owner := callerTenant
	if callerTenant == "" {
		// Platform admini: boş = paylaşımlı; dolu = doğrulanmış belirli kiracı.
		if t := strings.TrimSpace(tenantID); t != "" {
			n, err := tenant.Normalize(t)
			if err != nil {
				return "", ErrInvalidInput
			}
			owner = string(n)
		}
	} else if tenantID != "" && tenantID != callerTenant {
		return "", ErrForbidden
	}
	id, err := s.store.CreatePolicy(ctx, name, version, owner)
	if err != nil {
		return "", err
	}
	s.audit(ctx, adminID, "CREATE_POLICY", "policy", id)
	return id, nil
}

// AssignPolicy, bir politikayı cihaza atar (ADMIN). Cihaz çağıranın kiracısında olmalı
// (enforceDeviceTenant) VE politika platform/paylaşımlı ya da cihazın kiracısına ait olmalı
// (policyFitsDevice); aksi halde ErrForbidden.
func (s *Service) AssignPolicy(ctx context.Context, adminID, deviceID, policyID string) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	if err := s.enforceDeviceTenant(ctx, adminID, deviceID); err != nil {
		return err
	}
	pt, err := s.policyOwner(ctx, adminID, policyID, false)
	if err != nil {
		return err
	}
	devTenant, err := s.store.TenantForDevice(ctx, deviceID)
	if err != nil {
		return err
	}
	if !policyFitsDevice(pt, devTenant) {
		return ErrForbidden
	}
	// politika atama, ardından pub.Publish ile cihaza ANLIK push tetikler —
	// yani DOLAYLI bir executor edge'i. Bu yüzden diğer yüksek-etkili cihaz yollarıyla
	// TUTARLI biçimde Scope/ROE kapısından geçer (policy_enforce = HighImpact; motor
	// yapılandırılmamışsa fail-closed).
	if err := s.guardScope(ctx, adminID, deviceID, scope.ActionPolicyEnforce); err != nil {
		return err
	}
	if err := s.store.AssignPolicy(ctx, deviceID, policyID); err != nil {
		return err
	}
	s.audit(ctx, adminID, "ASSIGN_POLICY", "device", deviceID)
	// Cihazın açık politika akışını uyandır (anlık push).
	if s.pub != nil {
		s.pub.Publish(deviceID)
	}
	return nil
}

// AddPolicyRule, bir politikaya yeni bir kural ekler (ADMIN). Kuralı ekler,
// politikanın sürümünü yükseltir, denetim izine yazar ve politikaya atanmış her
// cihaza anlık push tetikler (açık StreamPolicies akışını uyandırır).
func (s *Service) AddPolicyRule(ctx context.Context, adminID, policyID string, in RuleInput) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	// Doğrulama: tip geçerli olmalı; APP_TIME_BLOCK ise Start ve End zorunlu.
	if !validRuleType(in.Type) {
		return ErrInvalidRule
	}
	if in.Type == "APP_TIME_BLOCK" && (in.Start == "" || in.End == "") {
		return ErrInvalidRule
	}
	// kural itme yetkisi — yalnız KENDİ kiracısının politikası (platform admini hepsi);
	// platform/paylaşımlı politikayı kiracıya bağlı admin değiştiremez.
	pt, err := s.policyOwner(ctx, adminID, policyID, true)
	if err != nil {
		return err
	}
	if err := s.store.AddPolicyRule(ctx, policyID, in); err != nil {
		return err
	}
	// Kural değişti; ajanların yeni paketi çekmesi için sürümü yükselt.
	if _, err := s.store.BumpPolicyVersion(ctx, policyID); err != nil {
		return err
	}
	s.audit(ctx, adminID, "ADD_POLICY_RULE", "policy", policyID)
	// Politikaya atanmış her cihazın açık akışını uyandır (anlık push).
	if s.pub != nil {
		devices, err := s.store.DevicesForPolicy(ctx, policyID)
		if err != nil {
			return err
		}
		for _, deviceID := range devices {
			// Kural itmesi YALNIZ politikanın kiracısındaki cihazlara ulaşır (eski/bozuk bir
			// çapraz-kiracı atama olsa bile). Paylaşımlı politika atanmış tüm cihazlara gider.
			if pt != "" {
				dt, err := s.store.TenantForDevice(ctx, deviceID)
				if err != nil {
					return err
				}
				if !policyFitsDevice(pt, dt) {
					continue
				}
			}
			s.pub.Publish(deviceID)
		}
	}
	return nil
}

// ListPolicyRules, bir politikanın kurallarını döner (OPERATOR+). Kiracıya bağlı admin
// yalnız kendi kiracısının ve platform/paylaşımlı politikaların kurallarını okuyabilir.
func (s *Service) ListPolicyRules(ctx context.Context, adminID, policyID string) ([]RuleView, error) {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return nil, err
	}
	if _, err := s.policyOwner(ctx, adminID, policyID, false); err != nil {
		return nil, err
	}
	return s.store.ListPolicyRules(ctx, policyID)
}

// defaultGenToken, 20 baytlık rastgele, okunabilir (base32) bir token üretir.
func defaultGenToken() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
