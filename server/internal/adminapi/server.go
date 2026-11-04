// Package adminapi, admin domain servisini bir HTTP/JSON API olarak dışa açar.
//
// Kimlik doğrulama: /api/login parolayı (Argon2id) doğrular ve HMAC-imzalı,
// durumsuz bir oturum token'ı döner. Korumalı uçlar "Authorization: Bearer
// <token>" bekler. Yetki (RBAC) admin domain servisinde uygulanır.
package adminapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/adminread"
	"kut.corp/suite/server/internal/aiassist"
	"kut.corp/suite/server/internal/aibrain"
	"kut.corp/suite/server/internal/aiprovider"
	"kut.corp/suite/server/internal/aisec"
	"kut.corp/suite/server/internal/auditexport"
	"kut.corp/suite/server/internal/authtoken"
	"kut.corp/suite/server/internal/authz"
	"kut.corp/suite/server/internal/casemgmt"
	"kut.corp/suite/server/internal/controlplane"
	"kut.corp/suite/server/internal/dedup"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/dlq"
	"kut.corp/suite/server/internal/entitygraph"
	"kut.corp/suite/server/internal/eventbus"
	"kut.corp/suite/server/internal/iam"
	"kut.corp/suite/server/internal/logingest"
	"kut.corp/suite/server/internal/metrics"
	"kut.corp/suite/server/internal/mitre"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/msp"
	"kut.corp/suite/server/internal/notify"
	"kut.corp/suite/server/internal/ratelimit"
	"kut.corp/suite/server/internal/report"
	"kut.corp/suite/server/internal/risk"
	"kut.corp/suite/server/internal/riskfusion"
	"kut.corp/suite/server/internal/scope"
	"kut.corp/suite/server/internal/security"
	"kut.corp/suite/server/internal/telemetryschema"
	"kut.corp/suite/server/internal/tenant"
	"kut.corp/suite/server/internal/trace"
	"kut.corp/suite/server/internal/verify"
	"kut.corp/suite/server/internal/vuln"
)

//go:embed console.html
var consoleHTML []byte

// AuthStore, e-postadan yönetici kimliği + parola hash'i çözer.
type AuthStore interface {
	LookupAdmin(ctx context.Context, email string) (adminID, passwordHash string, err error)
}

// Server, admin HTTP API'sidir.
type Server struct {
	adminSvc       *admin.Service
	reader         *adminread.Service
	auth           AuthStore
	authn          *controlplane.Authenticator // kanonik kimlik otoritesi (nil → eski satır-içi yol)
	sessions       *security.SessionSigner
	ttl            time.Duration
	now            func() time.Time
	stream         *eventbus.Bus
	health         func(context.Context) error
	partReady      func(context.Context) (bool, error) // /readyz olay-partition hazırlığı (yalnız DB; nil → atla)
	loginLim       *loginLimiter
	notice         string // TR/KVKK gizlilik metni
	noticeEN       string // EN/GDPR gizlilik metni (/api/notice?lang=en)
	dummyHash      string // bilinmeyen e-postada sabit-zaman için sahte Argon2 hash
	sseConns       int64  // aktif SSE bağlantı sayısı (atomik)
	auditVerify    func(context.Context) error
	auditExpKey    ed25519.PrivateKey             // ayarlıysa /api/audit/export imzalı manifest üretir
	maintWindows   func() []notify.Window         // ayarlıysa /api/maintenance bakım pencerelerini döner
	metricsToken   string                         // ayarlıysa /metrics bu Bearer token ile açılır; boşsa uç kapalı
	ingestToken    string                         // ayarlıysa POST /api/ingest bu Bearer token ile açılır
	tokens         authtoken.Store                // yönetilen API token'ları (rotation/expiry/iptal); nil => yalnız statik env token
	ingestSink     EventIngestor                  // harici log alımı için olay yazma yolu
	ingestLimiter  *ratelimit.Limiter             // /api/ingest IP-başına hız sınırı (nil = kapalı)
	ingestLayered  *ratelimit.Layered             // /api/ingest KATMANLI hız sınırı (§8; öncelikli, nil = kapalı)
	ingestDedup    *dedup.Seen                    // /api/ingest yineleme-tespiti (§6; nil = kapalı)
	ingestDLQ      *dlq.Queue                     // /api/ingest ölü-mektup kuyruğu (§6; nil = kapalı)
	eventProc      EventProcessor                 // ingest edilen olayları tespit+alarm hattından geçirir (nil = yalnız kaydet)
	detector       atomic.Pointer[detect.Engine]  // tespit kural kataloğu (görünürlük ucu; canlı hot-reload için atomik)
	vulnSet        *vuln.Set                      // zafiyet veri kümesi (nil = kapalı); envanterle eşleşir
	features       map[string]any                 // dağıtım koruma-duruşu (opsiyonel özellik bayrakları)
	tenantID       string                         // dağıtımın kiracı kimliği (rapor atıfı)
	tenantEnforce  bool                           // sıkı çok-tenant (KUT_TENANT_ENFORCE=1): kiracısız ingest token'ı REDDEDİLİR (INV-044)
	aiProvider     aiassist.Provider              // AI asistanı sağlayıcısı (nil → LocalProvider)
	tracer         *trace.Tracer                  // §14 dağıtık izleme (nil → kapalı)
	abacEngine     *iam.Engine                    // ABAC motoru (nil → uç kapalı)
	scim           iam.Provisioner                // SCIM kullanıcı sağlayıcı (nil → uç kapalı)
	mspStore       MSPStore                       // MSP müşteri deposu (nil → uç kapalı)
	gateway        *authz.Gateway                 // §4 merkezi Action Authorization Gateway (blast-radius + rate-limit)
	graph          *entitygraph.Graph             // varlık/tehdit grafı (salt-okunur pivot uçları; nil → uç kapalı)
	cases          casemgmt.Store                 // SOC vaka yönetimi (varsayılan bellek-içi; SetCaseStore ile DB destekli)
	seqModel       *aibrain.SeqModels             // kiracı-bölümlü süreç-zinciri sekans nadirlik modeli (salt-okunur skor sorgusu; nil → uç kapalı)
	agentSec       *aisec.Service                 // agentic tehdit savunması (salt-okunur bulgu uçları; nil → uç kapalı)
	brain          *aibrain.Brain                 // SOC AI brain (fail-open; dış AI yoksa deterministik yola döner)
	investigator   *aiprovider.InvestigationAgent // otonom soruşturma ajanı (salt-okunur/advisory; nil → uç kapalı)
	threatIntel    *aiprovider.ThreatIntelAgent   // otonom tehdit-istihbarat ajanı (salt-okunur IOC zenginleştirme; nil → uç kapalı)
	exposure       *aiprovider.ExposureAgent      // otonom maruziyet/ASM ajanı (salt-okunur varlık tarama; nil → uç kapalı)
	hunting        *aiprovider.HuntingAgent       // otonom tehdit-avı ajanı (salt-okunur graf-tabanlı av; nil → uç kapalı)
	detection      *aiprovider.DetectionAgent     // otonom tespit-mühendisliği ajanı (ADVISORY taslak kural; motora UYGULANMAZ; nil → uç kapalı)
	agentTrust     *aisec.TrustVerifier           // imzalı agent telemetri doğrulayıcı (nil → /api/agentsec/telemetry kapalı)
	verifyStore    verify.Store                   // remediation-doğrulama check deposu (nil → /api/verify uçları kapalı)
	verifier       verify.Verifier                // check değerlendirici (nil → run ucu kapalı)
	reqVerifyClose bool                           // true → CONTAINED→CLOSED vaka geçişi VERIFIED check ister (opt-in)
}

// MSPStore, MSP müşteri kaydının kalıcı deposudur. db.Store (kalıcı) ve
// memstore.Store (demo) karşılar.
type MSPStore interface {
	MSPAddCustomer(name, tenantID string) (msp.Customer, error)
	MSPListCustomers() ([]msp.Customer, error)
	MSPGetCustomer(id string) (msp.Customer, bool, error)
	MSPDeactivateCustomer(id string) (bool, error)
}

// SetSCIMProvisioner, SCIM 2.0 kullanıcı sağlayıcısını bağlar (IdP provisioning).
// nil → /scim/v2/Users uçları kapalı.
func (s *Server) SetSCIMProvisioner(p iam.Provisioner) { s.scim = p }

// SetMSPStore, MSP müşteri deposunu bağlar. nil → /api/msp/customers uçları kapalı.
func (s *Server) SetMSPStore(m MSPStore) { s.mspStore = m }

// SetABAC, öznitelik-tabanlı erişim kontrolü (ABAC) motorunu bağlar (RBAC'ı
// tamamlar). nil → /api/iam/abac/evaluate ucu kapalı.
func (s *Server) SetABAC(e *iam.Engine) { s.abacEngine = e }

// SetTracing, dağıtık izlemeyi (§14) etkinleştirir: her istek için bir span üretilir,
// gelen W3C traceparent başlığı çocuk-span'a bağlanır ve yanıt traceparent taşır
// (Agent→C2 ilişkilendirme). Recorder nil (span'lar bellek biriktirmeden atılır);
// değer, kimlik üretimi + sınır-ötesi yayılımdır. nil → kapalı (sıfır ek yük).
func (s *Server) SetTracing(on bool) {
	if on {
		s.tracer = &trace.Tracer{}
	} else {
		s.tracer = nil
	}
}

// SetAIProvider, AI SOC asistanı için bir sağlayıcı bağlar (nil → çevrimdışı LocalProvider).
// Sağlayıcı yalnız öneri üretir; hiçbir eylem yürütmez.
func (s *Server) SetAIProvider(p aiassist.Provider) { s.aiProvider = p }

// SetTenantID, dağıtımın kiracı kimliğini bağlar (rapor/çıktı atıfı; boş → "default").
func (s *Server) SetTenantID(id string) { s.tenantID = id }

// SetTenantEnforce, sıkı çok-tenant zorlamasını açar/kapatır (KUT_TENANT_ENFORCE=1; gRPC
// AgentHandler.SetTenantEnforce ile aynı bayrak, INV-044). Açıkken kiracıya bağlı OLMAYAN
// bir ingest token'ı ile gelen olaylar REDDEDİLİR (varsayılan kiracıya düşmez); kapalıyken
// kiracısız (legacy) token'lar dağıtımın varsayılan kiracısına düşer.
func (s *Server) SetTenantEnforce(on bool) { s.tenantEnforce = on }

// SetDetector, tespit kural motorunu bağlar (kural kataloğu ucu için). nil ise
// yerleşik varsayılan kurallar kullanılır.
func (s *Server) SetDetector(e *detect.Engine) {
	if e == nil {
		e = detect.NewEngine(nil)
	}
	s.detector.Store(e)
}

// SetFeatures, dağıtımın hangi opsiyonel korumalarının etkin olduğunu bildirir
// (main tarafından bir kez). /api/features ADMIN'e bu duruşu döner.
func (s *Server) SetFeatures(m map[string]any) { s.features = m }

// SetVulnSet, zafiyet veri kümesini (envanter eşleştirme) etkinleştirir. nil ise
// /api/vulnerabilities boş döner.
func (s *Server) SetVulnSet(v *vuln.Set) { s.vulnSet = v }

// EventIngestor, harici log alımının normalize edilmiş olayları yazdığı yoldur
// (ajan olay yazma yoluyla aynı: backend.SaveEvents).
type EventIngestor interface {
	SaveEvents(ctx context.Context, deviceID string, evs []model.Event) (uint64, error)
}

// SetIngest, POST /api/ingest harici log alım ucunu etkinleştirir: statik Bearer
// token (makine-makine) + olay yazma yolu. token boşsa uç kapalıdır.
func (s *Server) SetIngest(sink EventIngestor, token string) {
	s.ingestSink, s.ingestToken = sink, token
}

// EventProcessor, kaydedilen bir olayı sunucu-taraflı tespit + alarm hattından
// (kural değerlendirme, IoC, çok-aşama bitleri, tekrar-eşiği, korelasyon, alarm)
// geçiren bileşendir. gRPC ajan yolu ile AYNI hattı paylaşmak için kullanılır;
// böylece HTTP log-ingest ile gelen syslog/CEF/LEEF/WinEvent olayları da gerçek
// zamanlı tespit üretir (yalnız kaydedilmez).
type EventProcessor interface {
	ProcessEvent(ctx context.Context, deviceID string, e model.Event)
}

// SetEventProcessor, ingest edilen olayları tespit+alarm hattından geçirecek
// bileşeni bağlar (genellikle gRPC AgentHandler — durumlu bileşenler paylaşılır).
// nil ise ingest edilen olaylar yalnız kaydedilir (tespit çalışmaz — eski davranış).
func (s *Server) SetEventProcessor(p EventProcessor) { s.eventProc = p }

// SetIngestDedup, /api/ingest için içerik-adresli yineleme-tespiti bağlar (§6). Aynı
// olay (EventID) pencere içinde tekrar gelirse düşürülür. nil = kapalı.
func (s *Server) SetIngestDedup(d *dedup.Seen) { s.ingestDedup = d }

// SetIngestDLQ, /api/ingest için ölü-mektup kuyruğu bağlar (§6). SaveEvents geçici
// olarak başarısızsa (ör. DB erişilemez) olay grubu sessizce kaybolmak yerine kuyruğa
// alınır ve arka planda yeniden denenir. nil = kapalı (eski davranış: 500 döner).
func (s *Server) SetIngestDLQ(q *dlq.Queue) { s.ingestDLQ = q }

// SetIngestLayered, /api/ingest için KATMANLI hız sınırlayıcı bağlar (§8): global
// (toplam) + API (IP-başına) katmanları. Ayarlıysa tekil ingestLimiter yerine bu
// kullanılır. nil = kapalı.
func (s *Server) SetIngestLayered(l *ratelimit.Layered) { s.ingestLayered = l }

// SetIngestRateLimit, /api/ingest için IP-başına hız sınırlayıcı bağlar (DoS/sel
// koruması). nil ise sınırlama kapalıdır.
func (s *Server) SetIngestRateLimit(l *ratelimit.Limiter) { s.ingestLimiter = l }

// SetMetricsToken, Prometheus /metrics ucunu verilen statik Bearer token ile
// etkinleştirir. Boş bırakılırsa uç tamamen kapalıdır (cihaz sayıları gibi
// toplu veriyi kimliksiz sızdırmamak için güvenli varsayılan).
func (s *Server) SetMetricsToken(tok string) { s.metricsToken = tok }

// SetTokenStore, YÖNETİLEN API token deposunu bağlar (rotation/expiry/iptal). Ayarlıysa
// metrics/ingest doğrulaması ÖNCE yönetilen token'ı dener, sonra statik env token'a
// düşer (geriye uyumlu). nil => yalnız statik token.
func (s *Server) SetTokenStore(ts authtoken.Store) { s.tokens = ts }

// tokenAuthorized, bir istekteki Bearer token'ı verilen kapsam için doğrular:
// önce yönetilen token deposu (varsa), sonra statik env token (sabit-zamanlı).
func (s *Server) tokenAuthorized(scope, staticTok string, r *http.Request) bool {
	_, ok := s.tokenAuthorizedTenant(scope, staticTok, r)
	return ok
}

// tokenAuthorizedTenant, tokenAuthorized gibi doğrular ve token'ın bağlı KİRACISINI de
// döner. Kiracı yalnız yönetilen token'dan gelir (platform admininin oluşturmada verdiği,
// sunucu-tarafı bağ); statik env token kiracısızdır (legacy → ""). İstek içeriğinden
// (başlık/gövde/query) kiracı ASLA okunmaz.
func (s *Server) tokenAuthorizedTenant(scope, staticTok string, r *http.Request) (string, bool) {
	presented := bearer(r)
	if s.tokens != nil && presented != "" {
		if t, ok := s.tokens.VerifyTenant(scope, presented); ok {
			return t, true
		}
	}
	if staticTok != "" && subtle.ConstantTimeCompare([]byte(presented), []byte(staticTok)) == 1 {
		return "", true
	}
	return "", false
}

// ingestTenant, bir ingest isteğinin olay kiracısını SUNUCU-TARAFI çözer. tokenTenant
// kimlik doğrulanmış token'ın bağlı kiracısıdır. Boşsa (legacy/kiracısız token):
// KUT_TENANT_ENFORCE açıkken fail-closed ret (ok=false); kapalıyken dağıtımın varsayılan
// kiracısına (KUT_TENANT_ID; boş → "default") düşer.
func (s *Server) ingestTenant(tokenTenant string) (string, bool) {
	if tokenTenant != "" {
		return tokenTenant, true
	}
	if s.tenantEnforce {
		return "", false
	}
	return tenant.Canonical(strings.ToLower(strings.TrimSpace(s.tenantID))), true
}

// maxSSEConns, eşzamanlı SSE akış bağlantısı üst sınırıdır.
const maxSSEConns = 64

// maxSSELifetime, tek bir SSE bağlantısının AZAMİ ömrüdür. Admin HTTP sunucusunda
// WriteTimeout kasıtlı olarak yok (SSE uzun-ömürlü) — bu, sınırsız yazma yüzeyini
// dengeler: sunucu bu süre sonunda akışı kapatır, tarayıcının EventSource'u şeffaf
// biçimde yeniden bağlanır (kaynak sızıntısı / bayat bağlantı birikimi önlenir).
const maxSSELifetime = 30 * time.Minute

// defaultPrivacyNotice, KVKK aydınlatma metninin makul bir varsayılanıdır;
// kuruluma göre SetPrivacyNotice ile değiştirilebilir.
const defaultPrivacyNotice = "KVKK Aydınlatma: Bu cihaz kuruma aittir ve kurumsal " +
	"uç nokta güvenlik/yönetim (EDR/MDM) kapsamındadır. İş amaçlı kullanım " +
	"sırasında cihaz sağlık/güvenlik telemetrisi (çalışan süreçler, ağ keşfi, " +
	"güvenlik olayları) 6698 sayılı KVKK ve kurumsal politika uyarınca işlenir. " +
	"Veriler at-rest şifrelenir, erişim RBAC ile sınırlıdır ve saklama süresi " +
	"sonunda silinir. Veri sahibi erişim/silme talepleri için IT ile iletişime geçin."

// defaultPrivacyNoticeEN, GDPR çerçeveli İngilizce gizlilik metni (İngilizce dil seçeneği
// seçildiğinde /api/notice?lang=en döner). KVKK ve GDPR işlevsel eşdeğerdir (aynı veri-sahibi
// hakları: erişim/dışa-aktarma/silme + saklama + at-rest şifreleme).
const defaultPrivacyNoticeEN = "Privacy Notice (GDPR): This device is company-owned and within " +
	"corporate endpoint security/management (EDR/MDM) scope. During business use, device " +
	"health/security telemetry (running processes, network discovery, security events) is " +
	"processed under the EU General Data Protection Regulation (GDPR) and corporate policy, " +
	"on the legal bases of legitimate interest and legal obligation for information security. " +
	"Data is encrypted at rest, access is restricted via RBAC, and it is erased at the end of " +
	"the retention period. For data-subject requests (access/portability/erasure), contact IT."

// New oluşturur. Giriş ucu varsayılan olarak istemci başına 5 başarısız
// denemeden sonra 15 dk kilitlenir (kaba-kuvvet koruması).
func New(adminSvc *admin.Service, reader *adminread.Service, auth AuthStore, sessions *security.SessionSigner, ttl time.Duration) *Server {
	// bilinmeyen/pasif e-postada da Argon2 maliyeti ödensin diye rastgele
	// bir parolanın hash'i önceden hesaplanır (kullanıcı numaralandırmayı süre
	// bakımından sabitler). Hesaplanamazsa boş kalır (o durumda dallanma korunur).
	dummy := make([]byte, 16)
	_, _ = rand.Read(dummy)
	dummyHash, _ := security.HashPassword(string(dummy))
	s := &Server{
		adminSvc: adminSvc, reader: reader, auth: auth, sessions: sessions, ttl: ttl,
		now:       time.Now,
		loginLim:  newLoginLimiter(5, 15*time.Minute),
		notice:    defaultPrivacyNotice,
		noticeEN:  defaultPrivacyNoticeEN,
		dummyHash: dummyHash,
		gateway:   authz.NewGateway(authz.DefaultPolicy()),
		cases:     casemgmt.NewMemStore(),
	}
	s.detector.Store(detect.NewEngine(nil)) // atomik alan literal'de saklanamaz; kurulumda varsayılan
	// SEC: MFA, AuthStore'un MFAStore'u da karşılamasına bağlıdır. Karşılamıyorsa iki-faktörlü
	// doğrulama SESSİZCE devre dışı kalırdı — bunu görünür kıl (yapılandırma/regresyon uyarısı).
	if _, ok := auth.(MFAStore); !ok {
		log.Printf("[uyarı] AuthStore MFAStore'u karşılamıyor: iki-faktörlü doğrulama (TOTP) DEVRE DIŞI")
	}
	return s
}

// SetGateway, Action Authorization Gateway'i (blast-radius + rate-limit politikası)
// değiştirir. Kurulum, dağıtıma özel eşiklerle çağırabilir; nil verilirse yok sayılır.
func (s *Server) SetGateway(g *authz.Gateway) {
	if g != nil {
		s.gateway = g
	}
}

// SetEntityGraph, salt-okunur pivot uçları için varlık/tehdit grafını bağlar
// (aynı örneği ajan olay-işleyicisi besler). nil → /api/graph uçları kapalı.
func (s *Server) SetEntityGraph(g *entitygraph.Graph) { s.graph = g }

// SetCaseStore, SOC vaka deposunu değiştirir (varsayılan bellek-içi; kalıcı DB
// destekli bir Store ile geçersiz kılınabilir). nil verilirse yok sayılır.
func (s *Server) SetCaseStore(cs casemgmt.Store) {
	if cs != nil {
		s.cases = cs
	}
}

// SetVerifyStore, remediation-doğrulama check deposunu bağlar. nil → /api/verify uçları
// kapalı (404). Kalıcılık için DB destekli bir Store ile de sağlanabilir.
func (s *Server) SetVerifyStore(v verify.Store) { s.verifyStore = v }

// SetVerifier, doğrulama değerlendiricisini bağlar (tespit kuralını taze pencerede
// yeniden koşturur). nil → /api/verify/{id}/run kapalı.
func (s *Server) SetVerifier(v verify.Verifier) { s.verifier = v }

// SetRequireVerifyOnClose açılırsa (opt-in, default KAPALI), CONTAINED→CLOSED vaka
// geçişi vakaya bağlı en az bir VERIFIED remediation-doğrulaması ister; yoksa 409.
// Non-breaking: kapalıyken davranış aynen korunur (bkz. docs/REMEDIATION-VERIFICATION.md).
func (s *Server) SetRequireVerifyOnClose(on bool) { s.reqVerifyClose = on }

// SetSeqModel, süreç-zinciri sekans nadirlik modelini bağlar (ajan olay hattı canlı
// öğrenir; bu uç salt-okunur skor sorgular). nil → /api/hunt/sequence-score kapalı.
func (s *Server) SetSeqModel(m *aibrain.SeqModels) { s.seqModel = m }

// seqTenant, sekans taban çizgisinin hangi kiracı bölümünden okunacağını SUNUCU-TARAFI çözer:
// kiracılı çağıran kendi bölümü (istek değeri yok sayılır); platform admini doğrulanmış açık
// kiracı, yoksa dağıtımın kiracısı (taban çizgileri birleştirilemez → "hepsi" yoktur).
func (s *Server) seqTenant(ctx context.Context, adminID, requested string) (string, error) {
	t, all, err := s.readScope(ctx, adminID, requested)
	if err != nil {
		return "", err
	}
	if all {
		return s.caseTenant(), nil
	}
	return t, nil
}

// SetAgentSec, agentic tehdit savunması analiz servisini bağlar (Agent Causality Graph;
// salt-okunur bulgu uçları — ajan telemetrisi besler). nil → /api/agentsec uçları kapalı.
func (s *Server) SetAgentSec(a *aisec.Service) { s.agentSec = a }

// SetBrain, SOC AI brain'ini bağlar (aibrain; fail-open). Dış AI yapılandırılmamışsa
// (Provider nil) uçlar "available:false" döner ve çekirdek deterministik yola devam eder.
func (s *Server) SetBrain(b *aibrain.Brain) { s.brain = b }

// SetInvestigator, otonom soruşturma ajanını bağlar (aiprovider; salt-okunur/advisory —
// durum değiştirmez, aksiyon yürütmez). nil → /api/ai/investigate kapalı (available:false).
func (s *Server) SetInvestigator(a *aiprovider.InvestigationAgent) { s.investigator = a }

// SetThreatIntel, otonom tehdit-istihbarat ajanını bağlar (salt-okunur IOC zenginleştirme;
// yüklü göstergelerden köprülenir). nil → /api/ai/threatintel/enrich kapalı (available:false).
func (s *Server) SetThreatIntel(a *aiprovider.ThreatIntelAgent) { s.threatIntel = a }

// SetExposureAgent, otonom maruziyet/ASM ajanını bağlar (salt-okunur: açık port / cert /
// bilinen-zafiyetli yazılım değerlendirmesi). nil → /api/ai/exposure/scan kapalı.
func (s *Server) SetExposureAgent(a *aiprovider.ExposureAgent) { s.exposure = a }

// SetHuntingAgent, otonom tehdit-avı ajanını bağlar (salt-okunur: canlı entity-graf'ta
// nadir/şüpheli kenar taraması). nil → /api/ai/hunt kapalı.
func (s *Server) SetHuntingAgent(a *aiprovider.HuntingAgent) { s.hunting = a }

// SetDetectionAgent, otonom tespit-mühendisliği ajanını bağlar (ADVISORY: örnek sinyallerden
// taslak tespit kuralı üretir + doğrular). Taslak motora UYGULANMAZ — analist inceler.
// nil → /api/ai/detection/draft kapalı.
func (s *Server) SetDetectionAgent(a *aiprovider.DetectionAgent) { s.detection = a }

// SetAgentTrust, imzalı agent telemetri doğrulayıcısını bağlar. nil →
// /api/agentsec/telemetry kapalı. Bu uç session değil, ed25519 İMZA ile kimlik doğrular.
func (s *Server) SetAgentTrust(v *aisec.TrustVerifier) { s.agentTrust = v }

// SetPrivacyNotice, KVKK/TR aydınlatma metnini ayarlar (boş verilirse varsayılan
// korunur). Kurulum, kurumsal metni buradan geçebilir.
func (s *Server) SetPrivacyNotice(text string) {
	if text = strings.TrimSpace(text); text != "" {
		s.notice = text
	}
}

// SetPrivacyNoticeEN, GDPR/EN gizlilik metnini ayarlar (boş verilirse varsayılan korunur).
func (s *Server) SetPrivacyNoticeEN(text string) {
	if text = strings.TrimSpace(text); text != "" {
		s.noticeEN = text
	}
}

// SetLoginLimit, giriş kaba-kuvvet eşiğini ayarlar (test/yapılandırma için).
func (s *Server) SetLoginLimit(maxAttempts int, window time.Duration) {
	s.loginLim = newLoginLimiter(maxAttempts, window)
}

// SetAuthenticator, admin login'in kimlik+MFA kararını devrettiği KANONİK kimlik
// otoritesini (controlplane.Authenticator) bağlar. nil → eski satır-içi yol korunur.
// Transport-seviyesi kaba-kuvvet throttling + oturum üretimi adminapi'de kalır.
func (s *Server) SetAuthenticator(a *controlplane.Authenticator) { s.authn = a }

// SetStream, canlı SSE akışını (/api/stream) etkinleştirir. nil ise akış ucu
// 501 döner ve konsol yalnız periyodik yenilemeye düşer.
func (s *Server) SetStream(bus *eventbus.Bus) { s.stream = bus }

// SetHealthCheck, /readyz için depo sağlık kontrolünü bağlar (ör. db.Ping).
// Ayarlanmazsa /readyz yalnız süreç canlılığını (liveness gibi) döner.
func (s *Server) SetHealthCheck(fn func(context.Context) error) { s.health = fn }

// SetPartitionReadiness, /readyz için olay-partition hazırlık kontrolünü bağlar
// (yalnız DB modu). Ayarlıysa, depo erişilebilir olsa bile şu-anki ay partition'ı
// yoksa /readyz 503 döner — sessiz INSERT hatası yerine erken uyarı. nil (memstore)
// → kontrol atlanır.
func (s *Server) SetPartitionReadiness(fn func(context.Context) (bool, error)) { s.partReady = fn }

// SetAuditVerifier, GET /api/audit/verify için denetim izi hash-zinciri
// doğrulayıcıyı bağlar (ör. backend.VerifyAuditChain).
func (s *Server) SetAuditVerifier(fn func(context.Context) error) { s.auditVerify = fn }

// SetAuditExportKey, GET /api/audit/export imzalı dışa aktarım için Ed25519 özel
// anahtarı bağlar. nil/boşsa dışa aktarım imzasız (yalnız hash zinciri) olur.
func (s *Server) SetAuditExportKey(priv ed25519.PrivateKey) { s.auditExpKey = priv }

// SetMaintenanceProvider, GET /api/maintenance için bakım/bastırma pencerelerini
// sağlayan fonksiyonu bağlar. nil ise uç boş liste döner.
func (s *Server) SetMaintenanceProvider(fn func() []notify.Window) { s.maintWindows = fn }

// Handler, yönlendirmeleri kayıtlı bir http.Handler döner.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Web yönetim konsolu (aynı köken — API çağrıları CORS'suz çalışır).
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		// script-src 'unsafe-inline' yerine per-request NONCE. Böylece
		// olası bir XSS'te enjekte edilen inline script çalışmaz (yalnız nonce'lu
		// tek script yüklenir). style-src 'unsafe-inline' kalır (inline style=
		// öznitelikleri; stil enjeksiyonu düşük risk). Konsol dış kaynak kullanmaz.
		nb := make([]byte, 16)
		_, _ = rand.Read(nb)
		nonce := base64.StdEncoding.EncodeToString(nb)
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+"'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(bytes.Replace(consoleHTML, []byte("__CSP_NONCE__"), []byte(nonce), 1))
	})
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/enrollment-tokens", s.authed(s.handleIssueToken))
	// Enrollment token yönetimi: listele (meta veri; ham token asla) + iptal.
	mux.HandleFunc("GET /api/enrollment-tokens", s.authed(s.handleListTokens))
	mux.HandleFunc("POST /api/enrollment-tokens/{id}/revoke", s.authed(s.handleRevokeToken))
	mux.HandleFunc("POST /api/devices/quarantine", s.authed(s.handleQuarantine))
	mux.HandleFunc("POST /api/devices/release", s.authed(s.handleRelease))
	mux.HandleFunc("POST /api/devices/collect-diagnostics", s.authed(s.handleCollectDiagnostics))
	mux.HandleFunc("POST /api/devices/revoke", s.authed(s.handleRevoke))
	mux.HandleFunc("GET /api/policies", s.authed(s.handleListPolicies))
	mux.HandleFunc("POST /api/policies", s.authed(s.handleCreatePolicy))
	mux.HandleFunc("POST /api/policies/assign", s.authed(s.handleAssignPolicy))
	// Kural editörü: politikaya kural ekle / kuralları listele (Go 1.22 {id}).
	mux.HandleFunc("POST /api/policies/{id}/rules", s.authed(s.handleAddRule))
	mux.HandleFunc("GET /api/policies/{id}/rules", s.authed(s.handleListRules))
	// Yönetici (admin) kullanıcı yönetimi (listeleme OPERATOR+; mutasyonlar ADMIN).
	mux.HandleFunc("GET /api/admins", s.authed(s.handleListAdmins))
	mux.HandleFunc("POST /api/admins", s.authed(s.handleCreateAdmin))
	mux.HandleFunc("POST /api/admins/{id}/role", s.authed(s.handleSetAdminRole))
	mux.HandleFunc("POST /api/admins/{id}/deactivate", s.authed(s.handleDeactivateAdmin))
	// MFA (2FA/TOTP) öz-yönetimi — her admin kendi hesabı için (VIEWER+).
	mux.HandleFunc("POST /api/mfa/enroll", s.authed(s.handleMFAEnroll))
	mux.HandleFunc("POST /api/mfa/activate", s.authed(s.handleMFAActivate))
	mux.HandleFunc("POST /api/mfa/disable", s.authed(s.handleMFADisable))
	// Okuma (görünürlük) uçları — herhangi bir kimlik doğrulanmış admin (VIEWER+).
	mux.HandleFunc("GET /api/devices", s.authed(s.handleListDevices))
	mux.HandleFunc("GET /api/devices/{id}", s.authed(s.handleDeviceDetail))
	mux.HandleFunc("GET /api/devices/{id}/export", s.authed(s.handleExportDevice))
	mux.HandleFunc("POST /api/devices/{id}/erase", s.authed(s.handleEraseDevice))
	mux.HandleFunc("POST /api/devices/{id}/tags", s.authed(s.handleSetDeviceTags))
	mux.HandleFunc("POST /api/devices/bulk", s.authed(s.handleBulkAction))
	mux.HandleFunc("GET /api/events", s.authed(s.handleListEvents))
	mux.HandleFunc("GET /api/summary", s.authed(s.handleSummary))
	mux.HandleFunc("GET /api/mitre/coverage", s.authed(s.handleMitreCoverage))
	mux.HandleFunc("GET /api/detections/rules", s.authed(s.handleDetectionRules))
	mux.HandleFunc("POST /api/detections/test", s.authed(s.handleTestDetection))
	mux.HandleFunc("POST /api/detections/replay", s.authed(s.handleReplayDetection))
	mux.HandleFunc("POST /api/ai/analyze", s.authed(s.handleAIAnalyze))
	mux.HandleFunc("POST /api/iam/abac/evaluate", s.authed(s.handleABACEvaluate))
	mux.HandleFunc("POST /scim/v2/Users", s.authed(s.handleSCIMCreate))
	mux.HandleFunc("GET /scim/v2/Users/{id}", s.authed(s.handleSCIMGet))
	mux.HandleFunc("PUT /scim/v2/Users/{id}", s.authed(s.handleSCIMReplace))
	mux.HandleFunc("DELETE /scim/v2/Users/{id}", s.authed(s.handleSCIMDeactivate))
	mux.HandleFunc("POST /api/msp/customers", s.authed(s.handleMSPCreateCustomer))
	mux.HandleFunc("GET /api/msp/customers", s.authed(s.handleMSPListCustomers))
	mux.HandleFunc("DELETE /api/msp/customers/{id}", s.authed(s.handleMSPDeactivateCustomer))
	mux.HandleFunc("POST /api/hunt", s.authed(s.handleHunt))
	mux.HandleFunc("GET /api/incidents", s.authed(s.handleIncidents))
	mux.HandleFunc("GET /api/incidents/{id}/timeline", s.authed(s.handleIncidentTimeline))
	// Yönetilen API token'ları (ADMIN): metrics/ingest için rotation/expiry/iptal.
	mux.HandleFunc("POST /api/tokens", s.authed(s.handleTokenCreate))
	mux.HandleFunc("GET /api/tokens", s.authed(s.handleTokenList))
	mux.HandleFunc("POST /api/tokens/{id}/revoke", s.authed(s.handleTokenRevoke))
	mux.HandleFunc("GET /api/report", s.authed(s.handleReport))
	mux.HandleFunc("GET /api/coverage", s.authed(s.handleCoverage))
	mux.HandleFunc("GET /api/risk", s.authed(s.handleRisk))
	mux.HandleFunc("GET /api/compliance/frameworks", s.authed(s.handleFrameworks))
	mux.HandleFunc("GET /api/devices/{id}/attack-story", s.authed(s.handleAttackStory))
	mux.HandleFunc("GET /api/devices/{id}/graph", s.authed(s.handleEntityGraph))
	mux.HandleFunc("GET /api/graph/pivot", s.authed(s.handleGraphPivot))
	mux.HandleFunc("GET /api/graph/anomaly", s.authed(s.handleGraphAnomaly))
	mux.HandleFunc("GET /api/agentsec/findings", s.authed(s.handleAgentSecFindings))
	mux.HandleFunc("GET /api/agentsec/canonical", s.authed(s.handleAgentSecCanonical))
	mux.HandleFunc("POST /api/agentsec/events", s.authed(s.handleAgentSecEvents))
	mux.HandleFunc("POST /api/ai/triage", s.authed(s.handleAITriage))
	mux.HandleFunc("POST /api/ai/investigate", s.authed(s.handleAIInvestigate))
	mux.HandleFunc("POST /api/ai/threatintel/enrich", s.authed(s.handleAIThreatEnrich))
	mux.HandleFunc("POST /api/ai/exposure/scan", s.authed(s.handleAIExposureScan))
	mux.HandleFunc("POST /api/ai/hunt", s.authed(s.handleAIHunt))
	mux.HandleFunc("POST /api/ai/detection/draft", s.authed(s.handleAIDetectionDraft))
	mux.HandleFunc("POST /api/ai/risk", s.authed(s.handleAIRisk))
	// Session DEĞİL, ed25519 İMZA ile kimlik doğrulanan agent telemetri ucu.
	mux.HandleFunc("POST /api/agentsec/telemetry", s.handleAgentSecTelemetry)
	mux.HandleFunc("GET /api/hunt/sequence-score", s.authed(s.handleSequenceScore))
	mux.HandleFunc("POST /api/cases", s.authed(s.handleCaseCreate))
	mux.HandleFunc("GET /api/cases", s.authed(s.handleCaseList))
	mux.HandleFunc("GET /api/cases/{id}", s.authed(s.handleCaseGet))
	mux.HandleFunc("POST /api/cases/{id}/transition", s.authed(s.handleCaseTransition))
	mux.HandleFunc("POST /api/cases/{id}/attach", s.authed(s.handleCaseAttach))
	mux.HandleFunc("POST /api/verify/open", s.authed(s.handleVerifyOpen))
	mux.HandleFunc("POST /api/verify/{id}/run", s.authed(s.handleVerifyRun))
	mux.HandleFunc("GET /api/verify", s.authed(s.handleVerifyList))
	mux.HandleFunc("GET /api/metrics/trends", s.authed(s.handleMetricsTrends))
	mux.HandleFunc("GET /api/maintenance", s.authed(s.handleMaintenance))
	mux.HandleFunc("POST /api/hunt/saved", s.authed(s.handleSaveSearch))
	mux.HandleFunc("GET /api/hunt/saved", s.authed(s.handleListSavedSearches))
	mux.HandleFunc("DELETE /api/hunt/saved/{id}", s.authed(s.handleDeleteSavedSearch))
	mux.HandleFunc("GET /api/software", s.authed(s.handleSoftwareSearch))
	mux.HandleFunc("GET /api/vulnerabilities", s.authed(s.handleVulnerabilities))
	mux.HandleFunc("POST /api/events/{id}/ack", s.authed(s.handleAckEvent))
	mux.HandleFunc("POST /api/events/{id}/resolve", s.authed(s.handleResolveEvent))
	mux.HandleFunc("POST /api/events/{id}/case", s.authed(s.handleEventCase))
	mux.HandleFunc("POST /api/devices/{id}/collect-file", s.authed(s.handleCollectFile))
	mux.HandleFunc("POST /api/devices/{id}/lock", s.authed(s.handleLockDevice))
	mux.HandleFunc("POST /api/devices/{id}/restart", s.authed(s.handleRestartDevice))
	mux.HandleFunc("POST /api/devices/{id}/wipe", s.authed(s.handleWipeDevice))
	mux.HandleFunc("POST /api/devices/{id}/wipe/approve", s.authed(s.handleApproveWipe))
	mux.HandleFunc("POST /api/devices/{id}/wipe/cancel", s.authed(s.handleCancelWipe))
	mux.HandleFunc("GET /api/devices/pending-wipes", s.authed(s.handlePendingWipes))
	mux.HandleFunc("GET /api/devices/{id}/artifacts", s.authed(s.handleListArtifacts))
	mux.HandleFunc("GET /api/devices/{id}/evidence", s.authed(s.handleDeviceEvidence))
	mux.HandleFunc("POST /api/devices/{id}/evidence/{artifactID}/custody", s.authed(s.handleRecordCustody))
	mux.HandleFunc("GET /api/artifacts/{id}/download", s.authed(s.handleDownloadArtifact))
	mux.HandleFunc("GET /api/activity", s.authed(s.handleActivity))
	mux.HandleFunc("GET /api/features", s.authed(s.handleFeatures))
	mux.HandleFunc("GET /api/audit", s.authed(s.handleListAudit))
	mux.HandleFunc("GET /api/audit/verify", s.authed(s.handleVerifyAudit))
	mux.HandleFunc("GET /api/audit/export", s.authed(s.handleAuditExport))
	mux.HandleFunc("GET /api/ueba/admins", s.authed(s.handleAdminBehavior))
	mux.HandleFunc("GET /api/stream", s.authed(s.handleStream))
	// Sağlık uçları (kimlik doğrulama YOK — orkestrasyon/LB/monitoring için).
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /api/notice", s.handleNotice)  // KVKK aydınlatma (public)
	mux.HandleFunc("GET /metrics", s.handleMetrics)    // Prometheus (statik token ile)
	mux.HandleFunc("POST /api/ingest", s.handleIngest) // harici log alımı (statik token ile)
	h := requestLog(securityHeaders(mux))
	if s.tracer != nil {
		h = s.tracing(h)
	}
	return h
}

// statusWriter, yanıt durum kodunu yakalar (erişim logu için). SSE'yi bozmamak
// için http.Flusher'ı geçirir.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Flush, alttaki yazıcı destekliyorsa akışı boşaltır (/api/stream SSE için kritik).
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// safeRequestID, gelen X-Request-ID'yi LOG-ENJEKSİYONUNA karşı temizler: yalnız
// [A-Za-z0-9._-], en fazla 64 karakter; geçersizse yeni bir kimlik üretilir.
func safeRequestID(in string) string {
	if in != "" && len(in) <= 64 {
		ok := true
		for i := 0; i < len(in); i++ {
			c := in[i]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				ok = false
				break
			}
		}
		if ok {
			return in
		}
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// requestLog, her istek için bir korelasyon kimliği (X-Request-ID) üretir/iletir ve
// tek bir yapısal erişim-logu satırı yazar (yöntem, yol, durum, süre, rid). Dağıtık
// izlemenin (tracing) bağımlılıksız ilk adımı: istekler loglarda korele edilebilir.
// Sağlık uçları (yüksek-frekanslı prob) loglanmaz.
// tracing, her HTTP isteği için bir izleme span'ı üretir (§14). Gelen W3C
// "traceparent" başlığı varsa span onun ÇOCUĞU olur (Agent→C2 sınır-ötesi
// ilişkilendirme); yoksa kök span üretilir. Yanıta traceparent yazılır; izleme
// kimliği erişim logunda görünür. Recorder yok → span'lar bellek biriktirmez.
func (s *Server) tracing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if tid, sid, ok := trace.ParseTraceparent(r.Header.Get("traceparent")); ok {
			// Uzak ebeveyn span'ı (yalnız kimlikler) ctx'e koy — StartSpan çocuk üretir.
			ctx = trace.ContextWithSpan(ctx, &trace.Span{TraceID: tid, SpanID: sid})
		}
		ctx, span := s.tracer.StartSpan(ctx, "http "+r.Method+" "+r.URL.Path)
		span.SetAttr("http.method", r.Method)
		span.SetAttr("http.path", r.URL.Path)
		if tp := trace.InjectTraceparent(span); tp != "" {
			w.Header().Set("traceparent", tp)
			w.Header().Set("X-Trace-Id", span.TraceID.String())
		}
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(ctx))
		span.SetAttr("http.status", strconv.Itoa(sw.status))
		span.End(time.Now())
	})
}

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := safeRequestID(r.Header.Get("X-Request-ID"))
		w.Header().Set("X-Request-ID", rid)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r)
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
			// Path %q ile yazılır: içindeki CR/LF/kontrol karakterleri kaçışlanır, böylece
			// istemci bir yol içine sahte "[access]" satırı enjekte edemez (CWE-117 log injection).
			log.Printf("[access] %s %q %d %dms rid=%s", r.Method, r.URL.Path, sw.status, time.Since(start).Milliseconds(), rid)
		}
	})
}

// loginFailed, başarısız bir giriş denemesini kaydeder (metrik + limiter) ve bu
// denemeyle YENİ bir kaba-kuvvet kilidi başladıysa UYARI loglar + kilit metriğini
// artırır (SIEM: admin konsoluna kaba-kuvvet girişimi tespiti).
func (s *Server) loginFailed(key, email string) {
	metrics.IncLoginFailure()
	if s.loginLim.recordFailure(key) {
		metrics.IncLoginLockout()
		log.Printf("[auth] UYARI: kaba-kuvvet kilidi — istemci %s (hedef hesap %q)", key, email)
	}
}

// securityHeaders, tüm yanıtlara temel sertleştirme başlıkları ekler:
// MIME-sniffing kapalı, clickjacking (iframe) reddi, referrer sızıntısı yok.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// TLS-only sunucu: tarayıcıyı HTTPS'e kilitle (2 yıl). HTTP üzerinde
		// tarayıcı yok sayar.
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		// Güçlü tarayıcı özelliklerini kapat (konsol hiçbirini kullanmaz).
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		// Hassas admin verisi önbelleğe alınmasın (SSE handler kendi no-cache'ini
		// sonradan yazar). CDN/proxy önbelleklemesini de engeller.
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// authed, Bearer oturum token'ını doğrulayıp adminID'yi handler'a geçirir.
func (s *Server) authed(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		id, ok := s.sessions.Verify(tok, s.now())
		if !ok {
			writeErr(w, http.StatusUnauthorized, "yetkisiz")
			return
		}
		// durumsuz token iptal edilemediğinden, her istekte yöneticinin
		// HÂLÂ aktif olduğu depodan teyit edilir. Pasifleştirilen/silinen yönetici
		// (rolü boş döner) token TTL'i dolmadan da anında engellenir — böylece
		// salt-okuma uçları da eski oturumla erişime kapanır.
		if err := s.adminSvc.EnsureRole(r.Context(), id, admin.RoleViewer); err != nil {
			writeErr(w, http.StatusUnauthorized, "oturum artık geçerli değil")
			return
		}
		h(w, r, id)
	}
}

// handleNotice, gizlilik aydınlatma metnini döner (kimlik doğrulamasız — giriş öncesi
// konsolda gösterilir, şeffaflık gereği herkese açıktır). `?lang=en` GDPR/EN metnini,
// aksi halde KVKK/TR metnini döner (İngilizce dil seçeneği). Dönen `lang` alanı seçili dili belirtir.
func (s *Server) handleNotice(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("lang") == "en" {
		writeJSON(w, http.StatusOK, map[string]string{"notice": s.noticeEN, "lang": "en"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"notice": s.notice, "lang": "tr"})
}

// handleHealthz, süreç canlılığı (liveness): süreç yanıt veriyorsa 200.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"version":        metrics.Version(),
		"uptime_seconds": metrics.UptimeSeconds(),
	})
}

// handleReadyz, hazırlık (readiness): depo erişilebilirse 200, değilse 503.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.health != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.health(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": "depo erişilemiyor"})
			return
		}
	}
	// Olay-partition hazırlığı (DB modu): şu-anki ay partition'ı yoksa gelen olay
	// INSERT'leri patlar; hazır-değil bildir (yük dengeleyici trafiği kessin).
	if s.partReady != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if ok, err := s.partReady(ctx); err != nil || !ok {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": "olay partition'ı hazır değil (bu ay)"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Code     string `json:"code"` // MFA (TOTP) kodu — MFA etkin hesaplarda zorunlu
	}
	if !decode(w, r, &req) {
		return
	}
	// kaba-kuvvet sayacı IP+e-posta bileşimine bağlıdır. Böylece bir ters
	// vekil/LB arkasında (tüm istemciler aynı RemoteAddr) bir hesabın başarısız
	// denemeleri DİĞER yöneticileri kilitlemez (küresel-kilit DoS'u önlenir).
	key := clientIP(r) + "|" + strings.ToLower(strings.TrimSpace(req.Email))
	if ok, retry := s.loginLim.allowed(key); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "çok fazla başarısız deneme — sonra tekrar deneyin")
		return
	}

	// Kanonik kimlik otoritesi bağlıysa (controlplane.Authenticator), kimlik+MFA
	// kararını ona devret; adminapi yalnız transport-seviyesi throttling, hata
	// eşlemesi ve oturum üretimini yapar. Davranış eski satır-içi yolla birebir aynıdır.
	if s.authn != nil {
		res, err := s.authn.Authenticate(r.Context(), req.Email, req.Password, req.Code)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "MFA durumu okunamadı")
			return
		}
		switch res.Status {
		case controlplane.AuthMFARequired:
			writeJSON(w, http.StatusOK, map[string]bool{"mfa_required": true})
			return
		case controlplane.AuthMFAInvalidCode:
			s.loginFailed(key, req.Email)
			writeErr(w, http.StatusUnauthorized, "geçersiz doğrulama kodu")
			return
		case controlplane.AuthMFAReplay:
			s.loginFailed(key, req.Email)
			writeErr(w, http.StatusUnauthorized, "doğrulama kodu zaten kullanıldı")
			return
		case controlplane.AuthOK:
			s.loginLim.recordSuccess(key)
			metrics.IncLoginSuccess()
			token := s.sessions.Sign(res.AdminID, s.now().Add(s.ttl))
			writeJSON(w, http.StatusOK, map[string]string{"token": token})
			return
		default: // AuthInvalid
			s.loginFailed(key, req.Email)
			writeErr(w, http.StatusUnauthorized, "geçersiz kimlik bilgileri")
			return
		}
	}

	adminID, hash, err := s.auth.LookupAdmin(r.Context(), req.Email)
	if err != nil || adminID == "" {
		// bilinmeyen/pasif e-postada da Argon2 maliyetini öde (sabit-zaman;
		// kullanıcı numaralandırma yan-kanalını kapatır). Sonuç yok sayılır.
		_, _ = security.VerifyPassword(s.dummyHash, req.Password)
		s.loginFailed(key, req.Email)
		writeErr(w, http.StatusUnauthorized, "geçersiz kimlik bilgileri")
		return
	}
	ok, err := security.VerifyPassword(hash, req.Password)
	if err != nil || !ok {
		s.loginFailed(key, req.Email)
		writeErr(w, http.StatusUnauthorized, "geçersiz kimlik bilgileri")
		return
	}
	// MFA (2FA): parola doğruysa ve hesapta MFA etkinse, ikinci faktör (TOTP) de
	// doğrulanmalı. Kod yoksa {mfa_required:true} ile 200 döneriz (token YOK) —
	// konsol bunu görüp kod ister; yanlış kod başarısız deneme sayar.
	if mfa, ok := s.auth.(MFAStore); ok {
		secret, enrolled, err := mfa.LookupMFA(r.Context(), adminID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "MFA durumu okunamadı")
			return
		}
		if enrolled {
			if strings.TrimSpace(req.Code) == "" {
				writeJSON(w, http.StatusOK, map[string]bool{"mfa_required": true})
				return
			}
			step, vok := security.VerifyTOTPStep(secret, req.Code, s.now())
			if !vok {
				s.loginFailed(key, req.Email)
				writeErr(w, http.StatusUnauthorized, "geçersiz doğrulama kodu")
				return
			}
			// Tek-kullanım: aynı kodun (adım) pencere içinde yeniden oynatılması reddedilir.
			if accepted, err := mfa.ConsumeTOTPStep(r.Context(), adminID, step); err != nil {
				writeErr(w, http.StatusInternalServerError, "MFA durumu güncellenemedi")
				return
			} else if !accepted {
				s.loginFailed(key, req.Email)
				writeErr(w, http.StatusUnauthorized, "doğrulama kodu zaten kullanıldı")
				return
			}
		}
	}
	s.loginLim.recordSuccess(key)
	metrics.IncLoginSuccess()
	token := s.sessions.Sign(adminID, s.now().Add(s.ttl))
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// isWinlogBody, JSON gövdesinin Windows olay günlüğü şekli olup olmadığını sezer
// (winlogbeat "winlog"/"event_id", nxlog "EventID", render-XML "Event.System").
// KUT-yerel JSON şeması (source+message) YANLIŞLIKLA winlog'a yönlendirilmesin diye
// yalnız ayırt edici Windows imlerine bakar.
func isWinlogBody(body []byte) bool {
	s := string(body)
	if len(s) > 4096 { // yalnız baş kısma bak (imler baştadır)
		s = s[:4096]
	}
	for _, marker := range []string{`"winlog"`, `"event_id"`, `"EventID"`, `"System"`} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// handleIngest, HARİCİ kaynaklardan (güvenlik duvarı, bulut, SIEM) gelen logları
// alır, KUT olay modeline normalize eder ve olay yoluna yazar (SIEM alımı).
// ingestToken ayarlı değilse uç KAPALIDIR (404). Ayarlıysa doğru Bearer token
// gerekir (sabit-zaman). Content-Type application/json → JSON dizi/nesne; aksi
// halde metin (satır başına CEF). Body üst sınırı 4 MiB.
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if s.ingestSink == nil || (s.ingestToken == "" && s.tokens == nil) {
		http.NotFound(w, r)
		return
	}
	tokenTenant, authOK := s.tokenAuthorizedTenant(authtoken.ScopeIngest, s.ingestToken, r)
	if !authOK {
		writeErr(w, http.StatusUnauthorized, "geçersiz ingest token")
		return
	}
	// Olay kiracısı SUNUCU-TARAFI: token'ın (oluşturmada platform admininin verdiği) bağlı
	// kiracısı. İstek başlığı/gövdesi/query'si kiracı SEÇEMEZ. Kiracısız (legacy) token
	// KUT_TENANT_ENFORCE=1 iken REDDEDİLİR (INV-044: eksik kiracı → DENY); kapalıyken
	// dağıtımın varsayılan kiracısına düşer.
	evTenant, tenantOK := s.ingestTenant(tokenTenant)
	if !tenantOK {
		writeErr(w, http.StatusForbidden, "kiracı zorunlu: ingest token'ı bir kiracıya bağlı değil")
		return
	}
	// Hız sınırı (DoS/sel koruması): katmanlı (global + IP) öncelikli; yoksa tekil IP.
	// Aşılırsa 429 (hangi katmanın reddettiği mesajda).
	if s.ingestLayered != nil {
		if ok, layer := s.ingestLayered.Allow(map[ratelimit.Layer]string{ratelimit.API: clientIP(r)}); !ok {
			writeErr(w, http.StatusTooManyRequests, "hız sınırı aşıldı ("+string(layer)+")")
			return
		}
	} else if s.ingestLimiter != nil && !s.ingestLimiter.Allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "hız sınırı aşıldı")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "gövde okunamadı")
		return
	}
	now := time.Now()
	var records []logingest.Record
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		// Windows olay günlüğü JSON'u (winlogbeat/nxlog): açık ?format=winlog ya da
		// gövdede Windows olay imleri varsa WinEvent normalize et; aksi halde KUT JSON.
		if r.URL.Query().Get("format") == "winlog" || isWinlogBody(body) {
			records, err = logingest.NormalizeWinEvent(body, now)
		} else {
			records, err = logingest.NormalizeJSON(body, now)
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		// Satır-başına CEF; tanınmayan satırlar atlanır.
		// Satır-başına CEF veya LEEF; tanınmayan satırlar atlanır.
		for _, line := range strings.Split(string(body), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var rec logingest.Record
			var e error
			switch {
			case strings.Contains(line, "LEEF:"):
				rec, e = logingest.NormalizeLEEF(line, now)
			case strings.Contains(line, "CEF:"):
				rec, e = logingest.NormalizeCEF(line, now)
			case strings.HasPrefix(strings.TrimSpace(line), "<"):
				rec, e = logingest.NormalizeSyslog(line, now) // düz syslog (rsyslog/fluent-bit HTTP)
			default:
				rec, e = logingest.NormalizeCEF(line, now)
			}
			if e == nil {
				records = append(records, rec)
			}
		}
	}
	if len(records) == 0 {
		writeErr(w, http.StatusBadRequest, "normalize edilebilir kayıt yok")
		return
	}
	// Kaynağa (device_id) göre grupla ve yaz. Yineleme-tespiti (§6) açıksa, içerik-adresli
	// EventID pencere içinde tekrar geliyorsa olay düşürülür (retransmit/çift-gönderim).
	byDevice := map[string][]model.Event{}
	duplicates := 0
	// Cihaz kimliği ad-alanı: YALNIZ açıkça kiracıya bağlı token (dağıtım kiracısından farklı)
	// için. Legacy/kiracısız token dağıtım kiracısıyla damgalanır ama eski kimliği korur
	// (KUT_TENANT_ID=acme dağıtımında mevcut kaynakların geçmişi bölünmez).
	idTenant := logingest.SourceIDTenant(tokenTenant, s.tenantID)
	for _, rec := range records {
		ev := rec.Event
		// Kiracı damgası SaveEvents'ten ve EventID türetmesinden ÖNCE: olay kalıcı kayda
		// kiracısıyla girer (kiracı-kapsamlı okumalarda görünür, SSE/alarm kiracıya atfedilir)
		// ve cihaz kimliği kiracıya ad-alanlanır → aynı kaynak adını kullanan iki kiracı
		// AYRI cihaz/eşik/korelatör durumuna sahip olur. Normalizer'ın (ya da istemcinin)
		// verdiği her kiracı değeri EZİLİR.
		devID := logingest.TenantDeviceID(idTenant, rec.DeviceID)
		ev.TenantID = evTenant
		ev.DeviceID = devID
		if s.ingestDedup != nil {
			if s.ingestDedup.Duplicate(ev.EnsureID()) {
				duplicates++
				continue
			}
		}
		byDevice[devID] = append(byDevice[devID], ev)
	}
	accepted, deferred := 0, 0
	// ÖNCE tüm cihazları KAYDET; tespit+alarm hattı SONRA çalıştırılır. Böylece
	// DLQ'suz bir kısmi-başarısızlıkta (bir cihazın kaydı patlar → 500) hiçbir olay
	// işlenmemiş olur; istemci tüm yükü yeniden gönderdiğinde daha önce işlenmiş
	// cihazlar için ÇİFT alarm/oto-karantina tetiklenmez.
	type savedBatch struct {
		dev string
		evs []model.Event
	}
	var toProcess []savedBatch
	for dev, evs := range byDevice {
		if _, err := s.ingestSink.SaveEvents(r.Context(), dev, evs); err != nil {
			// DLQ açıksa: sessizce kaybetme — kuyruğa al, arka planda yeniden dene (§6).
			// (DLQ retry başarılı kayıttan sonra olayları tespit hattından geçirir.)
			if s.ingestDLQ != nil {
				s.ingestDLQ.Enqueue(dev, evs)
				deferred += len(evs)
				continue
			}
			writeErr(w, http.StatusInternalServerError, "olaylar yazılamadı")
			return
		}
		accepted += len(evs)
		toProcess = append(toProcess, savedBatch{dev, evs})
	}
	// Tüm kayıtlar başarılı: kaydedilen olayları tespit+alarm hattından geçir (gRPC
	// ajan yoluyla AYNI motoru/durumu paylaşır): syslog/CEF/LEEF/WinEvent logları da
	// gerçek-zamanlı kural/IoC/eşik/bit/korelasyon tespiti ve alarmı üretir. eventProc
	// nil ise olaylar yalnız kaydedilir (eski davranış).
	if s.eventProc != nil {
		for _, b := range toProcess {
			for i := range b.evs {
				s.eventProc.ProcessEvent(r.Context(), b.dev, b.evs[i])
			}
		}
	}
	metrics.AddEventsIngested(accepted)
	metrics.AddEventsDuplicate(duplicates)
	metrics.AddEventsDeferred(deferred)
	writeJSON(w, http.StatusOK, map[string]any{
		"accepted": accepted, "duplicate": duplicates, "deferred": deferred, "sources": len(byDevice)})
}

// handleMetrics, Prometheus metin-exposition'ını döner. metricsToken ayarlı
// değilse uç kapalıdır (404). Ayarlıysa doğru Bearer token gerekir (sabit-zaman
// karşılaştırma); cihaz sayıları özet okuyucudan, sayaçlar süreç-içinden gelir.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.metricsToken == "" && s.tokens == nil {
		http.NotFound(w, r)
		return
	}
	if !s.tokenAuthorized(authtoken.ScopeMetrics, s.metricsToken, r) {
		writeErr(w, http.StatusUnauthorized, "geçersiz metrics token")
		return
	}
	sum, err := s.reader.Summary(r.Context(), "") // operatör metrikleri: filo-geneli (kiracı-üstü), token-yetkili
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "özet okunamadı")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	metrics.Write(w, metrics.Snapshot{
		DevicesTotal:       sum.DevicesTotal,
		DevicesOnline:      sum.DevicesOnline,
		DevicesOffline:     sum.DevicesOffline,
		DevicesQuarantined: sum.DevicesQuarantined,
		EventsBySeverity:   sum.EventsBySeverity,
		SSEConnections:     int(atomic.LoadInt64(&s.sseConns)),
	})
}

// handleTokenCreate, yeni bir yönetilen API token'ı üretir (ADMIN). Düz sır YALNIZ
// yanıtta bir kez döner; sunucu yalnız özetini saklar.
func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	// Yönetilen metrics/ingest token'ları DAĞITIM GENELİ kimlik bilgileridir (tüm kiracıların
	// özetini okur / herhangi bir kaynak için olay yazar) → yalnız PLATFORM admini.
	if respondErr(w, s.requirePlatformAdmin(r.Context(), adminID)) {
		return
	}
	if s.tokens == nil {
		writeErr(w, http.StatusNotImplemented, "yönetilen token deposu yapılandırılmadı")
		return
	}
	var req struct {
		Scope      string `json:"scope"`
		TTLSeconds int    `json:"ttl_seconds"`
		Tenant     string `json:"tenant"` // ingest token'ının bağlanacağı kiracı (platform admini verir; sunucu-tarafı bağ)
	}
	if !decode(w, r, &req) {
		return
	}
	switch req.Scope {
	case authtoken.ScopeMetrics, authtoken.ScopeIngest:
	default:
		writeErr(w, http.StatusBadRequest, "geçersiz kapsam (metrics|ingest)")
		return
	}
	// Kiracı bağı: yalnız ingest kapsamı; biçim sınırda doğrulanır. Metrics
	// token'ı filo-geneli okuduğundan kiracıya bağlanamaz. KUT_TENANT_ENFORCE=1 iken
	// kiracısız ingest token'ı hiç üretilmez (kullanımda zaten reddedilirdi).
	tokTenant, terr := authtoken.ValidateTenantBinding(req.Scope, strings.TrimSpace(req.Tenant))
	if terr != nil {
		writeErr(w, http.StatusBadRequest, "geçersiz tenant (yalnız ingest kapsamı; küçük harf/rakam/tire, 1-63)")
		return
	}
	if req.Scope == authtoken.ScopeIngest && tokTenant == "" && s.tenantEnforce {
		writeErr(w, http.StatusBadRequest, "tenant zorunlu: kiracı zorlaması açıkken ingest token'ı bir kiracıya bağlanmalı")
		return
	}
	id, secret, err := s.tokens.CreateForTenant(req.Scope, tokTenant, time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token oluşturulamadı")
		return
	}
	audit := "API_TOKEN_CREATE:" + req.Scope
	if tokTenant != "" {
		audit += ":" + tokTenant
	}
	s.adminSvc.RecordAudit(r.Context(), adminID, audit, "token", id)
	resp := map[string]any{
		"id": id, "scope": req.Scope, "secret": secret,
		"note": "Bu sır YALNIZCA burada gösterilir — güvenli saklayın.",
	}
	if tokTenant != "" {
		resp["tenant"] = tokTenant
	}
	writeJSON(w, http.StatusCreated, resp)
}

// handleTokenList, yönetilen token'ları (SIR OLMADAN) listeler (ADMIN).
func (s *Server) handleTokenList(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	if respondErr(w, s.requirePlatformAdmin(r.Context(), adminID)) {
		return
	}
	if s.tokens == nil {
		writeJSON(w, http.StatusOK, map[string]any{"tokens": []any{}})
		return
	}
	list, err := s.tokens.List(r.URL.Query().Get("scope"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token listesi okunamadı")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": list})
}

// handleTokenRevoke, bir yönetilen token'ı iptal eder (ADMIN).
func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	if respondErr(w, s.requirePlatformAdmin(r.Context(), adminID)) {
		return
	}
	if s.tokens == nil {
		writeErr(w, http.StatusNotImplemented, "yönetilen token deposu yapılandırılmadı")
		return
	}
	if err := s.tokens.Revoke(r.PathValue("id")); err != nil {
		if errors.Is(err, authtoken.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "token bulunamadı")
		} else {
			writeErr(w, http.StatusInternalServerError, "token iptal edilemedi")
		}
		return
	}
	s.adminSvc.RecordAudit(r.Context(), adminID, "API_TOKEN_REVOKE", "token", r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]any{"revoked": r.PathValue("id")})
}

// MFAStore, MFA (TOTP) durumunu çözen isteğe bağlı arayüzdür. AuthStore bunu da
// karşılıyorsa login akışı ikinci faktörü zorlar; karşılamıyorsa MFA devre dışıdır
// (geriye dönük uyumluluk).
type MFAStore interface {
	LookupMFA(ctx context.Context, adminID string) (secret string, enrolled bool, err error)
	// ConsumeTOTPStep, TOTP tek-kullanım (anti-replay): verilen adım son kabul edilenden
	// büyükse atomik kaydeder ve true döner; değilse false (replay — kod tekrar kullanıldı).
	ConsumeTOTPStep(ctx context.Context, adminID string, step int64) (accepted bool, err error)
}

// handleMFAEnroll, oturum sahibi için yeni bir TOTP sırrı üretir ve otpauth URI'si
// ile birlikte döner (authenticator uygulamasına eklenir). Etkin olması için
// activate gerekir.
func (s *Server) handleMFAEnroll(w http.ResponseWriter, r *http.Request, adminID string) {
	// MFA zaten etkinse yeniden kayıt için mevcut TOTP kodu gerekir ({"code":"123456"});
	// ilk kayıtta gövde boş/{} olabilir.
	var req struct {
		Code string `json:"code"`
	}
	if !decodeOptional(w, r, &req) {
		return
	}
	secret, uri, err := s.adminSvc.BeginMFAEnrollment(r.Context(), adminID, req.Code)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_uri": uri})
}

// handleMFAActivate, girilen kodu doğrulayıp MFA'yı etkinleştirir.
func (s *Server) handleMFAActivate(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.ActivateMFA(r.Context(), adminID, req.Code)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enrolled": true})
}

// handleMFADisable, geçerli kod doğrulamasıyla MFA'yı kapatır.
func (s *Server) handleMFADisable(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.DisableMFA(r.Context(), adminID, req.Code)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enrolled": false})
}

// clientIP, istemci IP'sini RemoteAddr'dan çıkarır (port'suz). Not: X-Forwarded-For
// bilinçli olarak GÜVENİLMEZ (sahte olabilir); güvenilir bir ters vekil arkasında
// dağıtım, gerçek IP'yi RemoteAddr'da sunmalı ya da bu katman ona göre ayarlanmalı.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request, adminID string) {
	// Çok-tenant SaaS: token'ın kiracısı SUNUCU tarafında token'a mühürlenir ve enroll'da
	// cihaza bağlanır — ajan/client kiracıyı belirleyemez. Kiracıya bağlı admin: daima kendi
	// kiracısı (gövde farklıysa 403, boşsa kendi kiracısı). Platform admini: opsiyonel gövdeden
	// ({"tenant_id":"..."}) tenant.Normalize ile doğrulanmış kiracı; boşsa dağıtımın
	// varsayılan kiracısı (s.tenantID).
	var body struct {
		TenantID string `json:"tenant_id"`
	}
	if !decodeOptional(w, r, &body) { // opsiyonel; boş gövde tolere edilir
		return
	}
	callerTenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	tokTenant, err := resolveTokenTenant(callerTenant, body.TenantID, s.tenantID)
	if respondErr(w, err) {
		return
	}
	token, err := s.adminSvc.IssueEnrollmentToken(r.Context(), adminID, tokTenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"enrollment_token": token})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request, adminID string) {
	// enrollment token meta verisi hassastır — OPERATOR+ gerekir.
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	tokens, err := s.reader.EnrollmentTokens(r.Context(), intParam(r, "limit"), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.RevokeEnrollmentToken(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "token_revoked"})
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.QuarantineDevice(r.Context(), adminID, req.DeviceID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "quarantine_queued"})
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.ReleaseDevice(r.Context(), adminID, req.DeviceID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "release_queued"})
}

func (s *Server) handleCollectDiagnostics(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.CollectDiagnostics(r.Context(), adminID, req.DeviceID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "diagnostics_queued"})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.RevokeDevice(r.Context(), adminID, req.DeviceID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		// TenantID yalnız PLATFORM admini için anlamlıdır (belirli bir kiracının politikası;
		// boş = paylaşımlı). Kiracıya bağlı admin için servis katmanı sunucu-tarafı kiracısını
		// kullanır; farklı bir değer 403'tür (istemci kiracı seçemez).
		TenantID string `json:"tenant_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	id, err := s.adminSvc.CreatePolicy(r.Context(), adminID, req.Name, req.Version, req.TenantID)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"policy_id": id})
}

func (s *Server) handleAssignPolicy(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		DeviceID string `json:"device_id"`
		PolicyID string `json:"policy_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.AssignPolicy(r.Context(), adminID, req.DeviceID, req.PolicyID)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

func (s *Server) handleAddRule(w http.ResponseWriter, r *http.Request, adminID string) {
	policyID := r.PathValue("id")
	var req struct {
		Type       string  `json:"type"`
		Target     string  `json:"target"`
		Start      string  `json:"start"`
		End        string  `json:"end"`
		ActiveDays []int32 `json:"active_days"`
	}
	if !decode(w, r, &req) {
		return
	}
	in := admin.RuleInput{
		Type: req.Type, Target: req.Target, Start: req.Start, End: req.End, ActiveDays: req.ActiveDays,
	}
	if respondErr(w, s.adminSvc.AddPolicyRule(r.Context(), adminID, policyID, in)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rule_added"})
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request, adminID string) {
	rules, err := s.adminSvc.ListPolicyRules(r.Context(), adminID, r.PathValue("id"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handleListAdmins(w http.ResponseWriter, r *http.Request, adminID string) {
	admins, err := s.adminSvc.ListAdmins(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"admins": admins})
}

func (s *Server) handleCreateAdmin(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
		TenantID string `json:"tenant_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	// tenant_id yalnızca bir öneridir; Service katmanı oluşturan yöneticinin kendi
	// kiracısına göre bunu güvenli değere sabitler (ayrıcalık-yükseltme koruması).
	newID, err := s.adminSvc.CreateAdmin(r.Context(), adminID, req.Email, req.Password, admin.Role(req.Role), req.TenantID)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"admin_id": newID})
}

func (s *Server) handleSetAdminRole(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Role string `json:"role"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.SetAdminRole(r.Context(), adminID, r.PathValue("id"), admin.Role(req.Role))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "role_updated"})
}

func (s *Server) handleDeactivateAdmin(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.DeactivateAdmin(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deactivated"})
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request, adminID string) {
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	devices, err := s.reader.Devices(r.Context(), intParam(r, "limit"), tenant)
	if respondErr(w, err) {
		return
	}
	// Opsiyonel etiket filtresi (?tag=...): yalnız o etikete sahip cihazlar (filo
	// gruplama). Sunucu-tarafında filtreleme; büyük filolarda kısayol.
	if tag := strings.TrimSpace(r.URL.Query().Get("tag")); tag != "" {
		filtered := devices[:0]
		for _, d := range devices {
			for _, t := range d.Tags {
				if t == tag {
					filtered = append(filtered, d)
					break
				}
			}
		}
		devices = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

// handleBulkAction, bir etikete sahip TÜM cihazlara toplu eylem uygular (etiket-
// bazlı filo yönetimi). Gövde: {"tag":"prod","action":"quarantine|release|
// collect-diagnostics|assign-policy","policy_id":"..."}. Her cihaz için ilgili
// admin servis metodu çağrılır (RBAC + denetim izi servis içinde). matched=eşleşen
// cihaz, applied=başarıyla uygulanan sayısı döner.
func (s *Server) handleBulkAction(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Tag      string `json:"tag"`
		Action   string `json:"action"`
		PolicyID string `json:"policy_id"`
		DryRun   bool   `json:"dry_run"` // true: yalnız etkilenecek cihazları döndür, UYGULAMA
		Confirm  bool   `json:"confirm"` // büyük parti (> maxBulkDevices) için açık onay
	}
	if !decode(w, r, &req) {
		return
	}
	tag := strings.TrimSpace(req.Tag)
	if tag == "" {
		writeErr(w, http.StatusBadRequest, "tag gerekli")
		return
	}
	if req.Action == "assign-policy" && strings.TrimSpace(req.PolicyID) == "" {
		writeErr(w, http.StatusBadRequest, "assign-policy için policy_id gerekli")
		return
	}
	if req.Action != "assign-policy" && req.Action != "quarantine" &&
		req.Action != "release" && req.Action != "collect-diagnostics" {
		writeErr(w, http.StatusBadRequest, "geçersiz eylem")
		return
	}
	// Toplu eylem yalnız çağıranın kiracısındaki cihazlara uygulanmalı (çapraz-kiracı
	// eylem sızıntısını önler); kiracı sunucu-tarafı çözülür.
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	devices, err := s.reader.Devices(r.Context(), 0, tenant)
	if respondErr(w, err) {
		return
	}
	// Önce eşleşen cihazları topla (önizleme + parti sınırı için).
	type match struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
	}
	var matches []match
	for _, d := range devices {
		for _, t := range d.Tags {
			if t == tag {
				matches = append(matches, match{ID: d.ID, Hostname: d.Hostname})
				break
			}
		}
	}
	// KURU ÇALIŞTIRMA: hiçbir şey uygulanmaz; SOC önce etkiyi görür.
	if req.DryRun {
		writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "matched": len(matches), "devices": matches})
		return
	}
	// Merkezi Action Authorization Gateway (§4): blast-radius + rate-limit. Yüksek-
	// etkili toplu eylemler (quarantine/assign-policy) buradan geçer; geri-döndürülebilir
	// eylemler (release/collect-diagnostics) düşük-etkili olduğundan gateway'i doğrudan
	// geçer. İnsan talepçi yumuşak-tavanı (maxBulkDevices) açık onayla aşabilir.
	dec := s.gateway.Authorize(authz.Request{
		Requester:   authz.Human,
		Principal:   adminID,
		Action:      bulkAction(req.Action),
		TargetCount: len(matches),
		Confirmed:   req.Confirm,
	})
	if !dec.Allow {
		if dec.NeedApproval {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": "parti çok büyük (kazara filo-geneli eylem koruması)", "matched": len(matches),
				"max": maxBulkDevices, "hint": "confirm:true ile onaylayın veya etiketi daraltın",
			})
			return
		}
		writeErr(w, http.StatusTooManyRequests, dec.Reason)
		return
	}
	applied := 0
	var firstErr error
	for _, m := range matches {
		var e error
		switch req.Action {
		case "assign-policy":
			e = s.adminSvc.AssignPolicy(r.Context(), adminID, m.ID, req.PolicyID)
		case "quarantine":
			e = s.adminSvc.QuarantineDevice(r.Context(), adminID, m.ID)
		case "release":
			e = s.adminSvc.ReleaseDevice(r.Context(), adminID, m.ID)
		case "collect-diagnostics":
			e = s.adminSvc.CollectDiagnostics(r.Context(), adminID, m.ID)
		}
		if e == nil {
			applied++
		} else if firstErr == nil {
			firstErr = e
		}
	}
	// RBAC reddi (ör. VIEWER) ilk denemede hata verir ve hiçbir cihaza uygulanmaz.
	if len(matches) > 0 && applied == 0 && firstErr != nil {
		respondErr(w, firstErr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"matched": len(matches), "applied": applied})
}

// maxBulkDevices, açık onay olmadan toplu eylemin uygulanacağı üst sınırdır
// (kazara filo-geneli yıkıcı eylem koruması). authz.DefaultPolicy.SoftBlastRadius
// ile hizalıdır.
const maxBulkDevices = 500

// bulkAction, toplu-eylem adını Gateway etki sınıflandırması için bir scope.Action'a
// eşler. quarantine/assign-policy yüksek-etkilidir (gateway'de blast-radius+rate-limit);
// release/collect-diagnostics geri-döndürülebilir olduğundan düşük-etkili sayılır ve
// gateway'i doğrudan geçer.
func bulkAction(action string) scope.Action {
	switch action {
	case "quarantine":
		return scope.ActionQuarantine
	case "assign-policy":
		return scope.ActionPolicyEnforce
	default: // release, collect-diagnostics — geri-döndürülebilir/düşük-etkili
		return scope.ActionRemoteCommand
	}
}

// handleGraphPivot, varlık/tehdit grafında pivot sorgusu yapar (salt-okunur):
// ?kind=<tür>&id=<kimlik>&rel=<ilişki>&dir=sources|targets. dir=sources (varsayılan)
// → düğüme GİREN kaynaklar ("bu IP ile hangi cihazlar konuştu?"); dir=targets → çıkan
// hedefler ("bu cihaz hangi alanları çözümledi?"). rel boşsa tüm ilişkiler. Graf
// bağlı değilse 404.
func (s *Server) handleGraphPivot(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.graph == nil {
		writeErr(w, http.StatusNotFound, "varlık grafı etkin değil")
		return
	}
	q := r.URL.Query()
	kind := strings.TrimSpace(q.Get("kind"))
	id := strings.TrimSpace(q.Get("id"))
	if kind == "" || id == "" {
		writeErr(w, http.StatusBadRequest, "kind ve id gerekli")
		return
	}
	// Kiracı SUNUCU-TARAFI: kiracıya bağlı admin yalnız kendi kiracı-grafını pivotlar
	// (kiracı-anahtarlı Node); platform admini (boş kiracı) kiracılar-arası birleşik görür.
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	gk := entitygraph.Kind(kind)
	rel := entitygraph.Relation(strings.TrimSpace(q.Get("rel")))
	targets := q.Get("dir") == "targets"
	var nodes []entitygraph.Node
	switch {
	case tenant == "" && targets:
		nodes = s.graph.TargetsAny(gk, id, rel)
	case tenant == "":
		nodes = s.graph.SourcesAny(gk, id, rel)
	case targets:
		nodes = s.graph.Targets(entitygraph.Node{Kind: gk, ID: id, Tenant: tenant}, rel)
	default:
		nodes = s.graph.Sources(entitygraph.Node{Kind: gk, ID: id, Tenant: tenant}, rel)
	}
	out := make([]map[string]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, map[string]string{"kind": string(n.Kind), "id": n.ID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "nodes": out})
}

// handleGraphAnomaly, bir düğümün YAPISAL anomali skorunu döner (fan-out/in + nadir
// kenar → aibrain.ScoreGraph): ?kind=X&id=Y. Ör. çok sayıda farklı IP'ye bağlanan bir
// cihaz veya alışılmadık çocuk süreçler yayan bir süreç yüksek skorlanır. Graf bağlı
// değilse 404.
func (s *Server) handleGraphAnomaly(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.graph == nil {
		writeErr(w, http.StatusNotFound, "varlık grafı etkin değil")
		return
	}
	q := r.URL.Query()
	kind := strings.TrimSpace(q.Get("kind"))
	id := strings.TrimSpace(q.Get("id"))
	if kind == "" || id == "" {
		writeErr(w, http.StatusBadRequest, "kind ve id gerekli")
		return
	}
	// Kiracı sunucu-tarafı: kiracıya bağlı admin kendi grafındaki düğümü skorlar; platform
	// admini (boş kiracı) kiracılar-arası birleşik yapısal skor alır.
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	gk := entitygraph.Kind(kind)
	var fanOut, fanIn, rareEdges int
	if tenant == "" {
		fanOut, fanIn, rareEdges = s.graph.FeaturesAny(gk, id, 1)
	} else {
		fanOut, fanIn, rareEdges = s.graph.Features(entitygraph.Node{Kind: gk, ID: id, Tenant: tenant}, 1)
	}
	sc := aibrain.ScoreGraphFeatures(aibrain.GraphFeatures{FanOut: fanOut, FanIn: fanIn, RareEdges: rareEdges})
	writeJSON(w, http.StatusOK, map[string]any{
		"score": sc.Score, "rationale": sc.Rationale, "source": sc.Source,
		"fan_out": fanOut, "fan_in": fanIn, "rare_edges": rareEdges,
	})
}

// handleAITriage, opsiyonel SOC AI brain'inden bir incident için triyaj ÖNERİSİ ister
// (aksiyon DEĞİL, salt-öneri). FAIL-OPEN: brain yoksa/dış AI yapılandırılmamışsa ya da
// çağrı başarısızsa "available:false" döner — SOC deterministik yola devam eder. Öneri,
// §0 zinciri dışında hiçbir yürütme tetiklemez.
func (s *Server) handleAITriage(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		IncidentID string   `json:"incident_id"`
		Events     []string `json:"events"`
	}
	if !decode(w, r, &req) {
		return
	}
	if s.brain == nil || !s.brain.Enabled() {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "available": false})
		return
	}
	tr, ok := s.brain.SuggestTriage(r.Context(), aibrain.TriageInput{IncidentID: req.IncidentID, Events: req.Events})
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "available": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "available": true,
		"triage": map[string]any{
			"priority": tr.Priority, "likely_fp": tr.LikelyFP,
			"next_steps": tr.NextSteps, "confidence": tr.Confidence, "source": tr.Source,
		},
	})
}

// handleAIInvestigate, bir olay için otonom soruşturma ajanını çalıştırır (SALT-OKUNUR/
// advisory — durum DEĞİŞTİRMEZ, aksiyon YÜRÜTMEZ). FAIL-OPEN: ajan bağlı değilse veya
// analiz başarısızsa {available:false} döner. Hassas olay metni Restricted hassasiyetle
// router tarafından YALNIZ yerel sağlayıcıya yönlendirilir (egemenlik; buluta gitmez).
func (s *Server) handleAIInvestigate(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		IncidentID string `json:"incident_id"`
		Category   string `json:"category"`
		Message    string `json:"message"`
	}
	if !decode(w, r, &req) {
		return
	}
	if s.investigator == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	rep, err := s.investigator.Investigate(r.Context(), req.IncidentID, req.Category, req.Message, nil, nil)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "report": rep})
}

// handleAIThreatEnrich, bir IOC'yi otonom tehdit-istihbarat ajanıyla zenginleştirir
// (SALT-OKUNUR). FAIL-OPEN: ajan bağlı değilse {available:false}. Yüklü göstergelerden
// köprülenen itibar skoru + eşleşen aktör/aile döner (düz IOC eşleşmesinden zengin).
func (s *Server) handleAIThreatEnrich(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		IOC  string `json:"ioc"`
		Type string `json:"type"`
	}
	if !decode(w, r, &req) {
		return
	}
	if s.threatIntel == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	res := s.threatIntel.EnrichIOC(strings.ToLower(strings.TrimSpace(req.IOC)), aiprovider.IOCType(req.Type))
	writeJSON(w, http.StatusOK, map[string]any{
		"available": true,
		"enrichment": map[string]any{
			"indicator": res.Indicator, "known_malicious": res.IsKnownMalicious,
			"reputation_score": res.ReputationScore, "matched_actors": res.MatchedActors,
			"matched_families": res.MatchedFamilies,
		},
	})
}

// handleAIExposureScan, bir varlığın maruziyet/ASM taramasını otonom ajanla çalıştırır
// (SALT-OKUNUR, deterministik: tehlikeli açık port / süresi dolmuş-dolan cert / bilinen-
// zafiyetli yazılım). FAIL-OPEN: ajan bağlı değilse {available:false}. Varlık bilgileri
// (port/cert/yazılım) çağırandan gelir (admin-güdümlü tarama).
func (s *Server) handleAIExposureScan(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		AssetID          string            `json:"asset_id"`
		OpenPorts        []int             `json:"open_ports"`
		CertExpiryDays   int               `json:"cert_expiry_days"`
		SoftwareVersions map[string]string `json:"software_versions"`
	}
	if !decode(w, r, &req) {
		return
	}
	if s.exposure == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	findings, err := s.exposure.ScanAsset(r.Context(), s.tenantID, req.AssetID, req.OpenPorts, req.CertExpiryDays, req.SoftwareVersions)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "findings": findings})
}

// handleAIHunt, bir ATT&CK taktiği için tehdit-avı hipotezi üretir ve canlı entity-graf
// üzerinde yürütür (SALT-OKUNUR: nadir/şüpheli kenarları işaretler). FAIL-OPEN: ajan bağlı
// değilse {available:false}. Boş taktik → 400.
func (s *Server) handleAIHunt(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Tactic string `json:"tactic"`
		Tenant string `json:"tenant"` // YALNIZ platform admini için açık kiracı filtresi; kiracılı çağıranda yok sayılır
	}
	if !decode(w, r, &req) {
		return
	}
	if s.hunting == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	// Av yalnız çağıranın kiracısının graf düğümlerini tarar: kiracı SUNUCU-TARAFI
	// çözülür; kiracılı çağıran başka kiracının süreç/IP/cihaz düğümlerini GÖREMEZ. Platform
	// admini varsayılan olarak hepsini görür, açık "tenant" ile daraltabilir.
	scopeTenant, scopeAll, serr := s.readScope(r.Context(), adminID, req.Tenant)
	if respondErr(w, serr) {
		return
	}
	huntScope := aiprovider.HuntScope{Tenant: scopeTenant, AllTenants: scopeAll}
	hyps, err := s.hunting.GenerateHypotheses(r.Context(), strings.TrimSpace(req.Tactic))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "taktik (tactic) gerekli")
		return
	}
	var findings []aiprovider.HuntFinding
	for _, h := range hyps {
		f, herr := s.hunting.ExecuteHunt(r.Context(), h, huntScope)
		if herr == nil {
			findings = append(findings, f...)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "hypotheses": hyps, "findings": findings})
}

// handleAIDetectionDraft, örnek sinyallerden bir TASLAK tespit kuralı üretir ve doğrular
// (ADVISORY — taslak detect motoruna UYGULANMAZ; analist inceleyip ince-ayar yapar).
// FAIL-OPEN: ajan bağlı değilse {available:false}. hypothesis_id zorunlu.
func (s *Server) handleAIDetectionDraft(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		HypothesisID   string   `json:"hypothesis_id"`
		Title          string   `json:"title"`
		MITRETactic    string   `json:"mitre_tactic"`
		MITRETechnique string   `json:"mitre_technique"`
		Description    string   `json:"description"`
		SampleSignals  []string `json:"sample_signals"`
	}
	if !decode(w, r, &req) {
		return
	}
	if s.detection == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	h := aiprovider.HuntHypothesis{
		ID: req.HypothesisID, Title: req.Title, MITRETactic: req.MITRETactic,
		MITRETechnique: req.MITRETechnique, Description: req.Description,
	}
	proposal, err := s.detection.DraftRuleFromHypothesis(r.Context(), h, req.SampleSignals)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "hypothesis_id gerekli")
		return
	}
	valid, issues := s.detection.ValidateProposal(proposal)
	writeJSON(w, http.StatusOK, map[string]any{
		"available": true, "valid": valid, "issues": issues, "applied": false, "proposal": proposal,
	})
}

// handleAIRisk, deterministik sinyalleri (ve opsiyonel sekans/graf'ı) AI ile zenginleştirip
// AÇIKLANABİLİR bir füzyon sonucu döner (P4.4 tüketicisi). SALT-OKUNUR/ADVISORY: durum
// değiştirmez, hiçbir aksiyon yürütmez. FAIL-OPEN: AI yoksa/başarısızsa sonuç, verilen
// sinyallerin deterministik füzyonuyla BİREBİR aynıdır (ai_available:false). AI sinyalleri
// (ai_sequence/ai_graph) sonuçta ayrı katkı olarak görünür → nihai skora etkisi denetlenebilir.
func (s *Server) handleAIRisk(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Signals []struct {
			Name   string  `json:"name"`
			Score  float64 `json:"score"`
			Weight float64 `json:"weight"`
		} `json:"signals"`
		Sequence []string `json:"sequence"`
		Graph    *struct {
			FanOut       int     `json:"fan_out"`
			FanIn        int     `json:"fan_in"`
			RareEdges    int     `json:"rare_edges"`
			NewNodeRatio float64 `json:"new_node_ratio"`
		} `json:"graph"`
	}
	if !decode(w, r, &req) {
		return
	}
	base := make([]riskfusion.Signal, 0, len(req.Signals))
	for _, sg := range req.Signals {
		base = append(base, riskfusion.Signal{Name: sg.Name, Score: sg.Score, Weight: sg.Weight})
	}
	var seq *aibrain.SequenceInput
	if len(req.Sequence) > 0 {
		st, serr := s.seqTenant(r.Context(), adminID, r.URL.Query().Get("tenant"))
		if respondErr(w, serr) {
			return
		}
		seq = &aibrain.SequenceInput{Tokens: req.Sequence, Tenant: st} // taban çizgisi çağıranın kiracısından
	}
	var graph *aibrain.GraphInput
	if req.Graph != nil {
		graph = &aibrain.GraphInput{Features: aibrain.GraphFeatures{
			FanOut: req.Graph.FanOut, FanIn: req.Graph.FanIn,
			RareEdges: req.Graph.RareEdges, NewNodeRatio: req.Graph.NewNodeRatio,
		}}
	}
	// nil-safe: s.brain nil olsa bile FuseWithAI yalnız base'i füzyonlar (fail-open).
	res := s.brain.FuseWithAI(r.Context(), base, seq, graph)
	contribs := make([]map[string]any, 0, len(res.Contributions))
	for _, c := range res.Contributions {
		contribs = append(contribs, map[string]any{"name": c.Name, "points": c.Points, "share": c.Share})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ai_available":  s.brain != nil && s.brain.Enabled(),
		"score":         res.Score,
		"level":         res.Level,
		"contributions": contribs,
		"top":           res.Top,
	})
}

// handleSequenceScore, bir süreç zincirinin (virgül-ayrımlı ?tokens=a,b,c) ortama
// göre nadirlik skorunu döner — salt-okunur tehdit-avı. Model canlı PROCESS
// olaylarından PASİF öğrenir; bu uç yalnız SORGULAR (taban çizgisini değiştirmez).
// Model bağlı değilse 404.
func (s *Server) handleSequenceScore(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.seqModel == nil {
		writeErr(w, http.StatusNotFound, "sekans modeli etkin değil")
		return
	}
	raw := strings.TrimSpace(r.URL.Query().Get("tokens"))
	if raw == "" {
		writeErr(w, http.StatusBadRequest, "tokens gerekli (virgül-ayrımlı süreç zinciri, ör: explorer.exe,winword.exe,powershell.exe)")
		return
	}
	var tokens []string
	for _, t := range strings.Split(raw, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tokens = append(tokens, t)
		}
	}
	st, serr := s.seqTenant(r.Context(), adminID, r.URL.Query().Get("tenant"))
	if respondErr(w, serr) {
		return
	}
	sc := s.seqModel.Score(st, tokens)
	writeJSON(w, http.StatusOK, map[string]any{
		"score": sc.Score, "rationale": sc.Rationale, "source": sc.Source, "tokens": tokens,
	})
}

// caseTenant, işlem yapılacak kiracıyı DAĞITIMIN yapılandırılmış tenant'ından (KUT_TENANT_ID)
// türetir — İSTEMCİ header'ından DEĞİL. Model dağıtım-başına tek-kiracılıdır (MSP her müşteriyi
// ayrı deployment'a eşler). Eskiden tenant X-Tenant-ID başlığından alınıyordu ve oturuma bağlı
// değildi; bu, kimliği doğrulanmış herhangi birinin başlığı değiştirerek başka kiracının
// vakalarına erişmesine izin veriyordu (cross-tenant IDOR). Artık başlık YOK SAYILIR.
func (s *Server) caseTenant() string {
	if t := casemgmt.NormTenant(strings.TrimSpace(s.tenantID)); t != "" {
		return t
	}
	return "default"
}

// writeCaseErr, casemgmt alan hatalarını uygun HTTP durumuna eşler; hata yoksa false.
func writeCaseErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, casemgmt.ErrCaseNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, casemgmt.ErrInvalidTransition), errors.Is(err, casemgmt.ErrCaseExists):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, casemgmt.ErrInvalidStatus), errors.Is(err, casemgmt.ErrUnknownAttachKind),
		errors.Is(err, casemgmt.ErrTenantRequired), errors.Is(err, casemgmt.ErrIDRequired):
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "vaka işlemi başarısız")
	}
	return true
}

// newCaseID, kısa, rastgele (içerik-adresli olmayan) bir vaka kimliği üretir.
func newCaseID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "case-" + hex.EncodeToString(b)
}

// handleCaseCreate, yeni bir SOC vakası açar (OPERATOR+). Durum OPEN, sahip çağıran.
func (s *Server) handleCaseCreate(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	var req struct {
		Title    string   `json:"title"`
		Severity string   `json:"severity"`
		Assets   []string `json:"assets"`
		Users    []string `json:"users"`
		MITRE    []string `json:"mitre"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		writeErr(w, http.StatusBadRequest, "title gerekli")
		return
	}
	// Vaka çağıranın kiracısına açılır (server-side). Platform admini (boş kiracı) için
	// dağıtım varsayılan kovası kullanılır (vaka tenant'sız oluşturulamaz).
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	if tenant == "" {
		tenant = s.caseTenant()
	}
	created, err := s.cases.Create(casemgmt.Case{
		ID: newCaseID(), TenantID: tenant, Title: strings.TrimSpace(req.Title),
		Severity: casemgmt.Severity(strings.ToUpper(strings.TrimSpace(req.Severity))),
		Status:   casemgmt.StatusOpen, Owner: adminID,
		Assets: req.Assets, Users: req.Users, MITRE: req.MITRE,
	})
	if writeCaseErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, created)
}

// handleCaseList, çağıranın kiracısının vakalarını listeler (VIEWER+; salt-okuma).
// Kiracı SUNUCU-TARAFI çözülür; platform admini (boş kiracı) tüm kiracıların vakalarını görür.
func (s *Server) handleCaseList(w http.ResponseWriter, r *http.Request, adminID string) {
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	var list []casemgmt.Case
	if tenant == "" {
		list, err = s.cases.ListAll()
	} else {
		list, err = s.cases.List(tenant)
	}
	if writeCaseErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(list), "cases": list})
}

// handleCaseGet, tek bir vakayı (zaman çizelgesiyle) döner (VIEWER+). Çağıranın
// kiracısıyla daraltılır (başka kiracının vakası → 404); platform admini herhangi birini görür.
func (s *Server) handleCaseGet(w http.ResponseWriter, r *http.Request, adminID string) {
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	var c casemgmt.Case
	if tenant == "" {
		c, err = s.cases.GetAny(r.PathValue("id"))
	} else {
		c, err = s.cases.Get(tenant, r.PathValue("id"))
	}
	if writeCaseErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// caseOpTenant, bir vaka MUTASYONU için etkin kiracıyı çözer: kiracıya bağlı admin →
// kendi kiracısı (casestore başka kiracının vakasında ErrCaseNotFound döner → çapraz-
// kiracı mutasyon 404, IDOR kapalı); platform admini (boş) → vakanın kendi kiracısı.
func (s *Server) caseOpTenant(ctx context.Context, adminID, caseID string) (string, error) {
	tenant, err := s.callerTenant(ctx, adminID)
	if err != nil {
		return "", err
	}
	if tenant != "" {
		return tenant, nil
	}
	c, err := s.cases.GetAny(caseID)
	if err != nil {
		return "", err
	}
	return c.TenantID, nil
}

// handleCaseTransition, vakayı yeni bir duruma geçirir (OPERATOR+). Geçersiz geçiş 409.
func (s *Server) handleCaseTransition(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	var req struct {
		To   string `json:"to"`
		Note string `json:"note"`
	}
	if !decode(w, r, &req) {
		return
	}
	tenant, err := s.caseOpTenant(r.Context(), adminID, r.PathValue("id"))
	if writeCaseErr(w, err) {
		return
	}
	to := casemgmt.Status(strings.ToUpper(strings.TrimSpace(req.To)))
	// Opt-in guard (default KAPALI): CONTAINED→CLOSED, vakaya bağlı doğrulanmış
	// (VERIFIED) bir remediation-doğrulaması ister. Kapalıyken bu blok atlanır.
	if s.reqVerifyClose && to == casemgmt.StatusClosed {
		cur, gerr := s.cases.Get(tenant, r.PathValue("id"))
		if writeCaseErr(w, gerr) {
			return
		}
		if cur.Status == casemgmt.StatusContained && !s.hasVerifiedCheck(tenant, cur.Verifications) {
			writeErr(w, http.StatusConflict,
				"CONTAINED→CLOSED için vakaya bağlı doğrulanmış (VERIFIED) bir remediation-doğrulaması gerekli")
			return
		}
	}
	c, err := s.cases.Transition(tenant, r.PathValue("id"), adminID, to, req.Note)
	if writeCaseErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// hasVerifiedCheck, verilen referanslardan en az birinin VERIFIED sonuçlu bir
// remediation-doğrulama check'ine çözüldüğünü döndürür (kiracı-kapsamlı; boş kiracı
// = platform admini → GetAny). Fail-closed: depo yoksa veya hiçbiri çözülmezse false.
func (s *Server) hasVerifiedCheck(tenant string, refs []string) bool {
	if s.verifyStore == nil {
		return false
	}
	for _, ref := range refs {
		var (
			chk verify.Check
			err error
		)
		if strings.TrimSpace(tenant) == "" {
			chk, err = s.verifyStore.GetAny(ref)
		} else {
			chk, err = s.verifyStore.Get(tenant, ref)
		}
		if err == nil && chk.Outcome == verify.OutcomeVerified {
			return true
		}
	}
	return false
}

// handleCaseAttach, vakaya bir referans (asset/user/mitre/evidence) ekler (OPERATOR+).
func (s *Server) handleCaseAttach(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	var req struct {
		Kind string `json:"kind"`
		Ref  string `json:"ref"`
	}
	if !decode(w, r, &req) {
		return
	}
	tenant, err := s.caseOpTenant(r.Context(), adminID, r.PathValue("id"))
	if writeCaseErr(w, err) {
		return
	}
	c, err := s.cases.Attach(tenant, r.PathValue("id"), adminID,
		casemgmt.AttachKind(strings.ToLower(strings.TrimSpace(req.Kind))), strings.TrimSpace(req.Ref))
	if writeCaseErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// newVerifyID, kısa rastgele bir doğrulama-check kimliği üretir.
func newVerifyID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "vchk-" + hex.EncodeToString(b)
}

// handleVerifyOpen, bir remediation-doğrulama check'i açar (OPERATOR+): aksiyon sonrası
// bulgunun sinyalinin gerçekten kalkıp kalkmadığını ölçmek için. Kiracı SUNUCU-TARAFI.
func (s *Server) handleVerifyOpen(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.verifyStore == nil {
		writeErr(w, http.StatusNotFound, "doğrulama motoru etkin değil")
		return
	}
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	var req struct {
		FindingRef string       `json:"finding_ref"`
		DeviceID   string       `json:"device_id"`
		RuleID     string       `json:"rule_id"`
		Kind       string       `json:"kind"`
		Expected   string       `json:"expected"` // Kind=device_status: beklenen efektif durum
		Factors    risk.Factors `json:"factors"`
		WindowSecs int          `json:"window_secs"`
	}
	if !decode(w, r, &req) {
		return
	}
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	if tenant == "" {
		tenant = "default" // platform admini: dağıtım varsayılan kovası (check tenant'sız açılamaz)
	}
	kind := req.Kind
	if kind == "" {
		kind = verify.KindDetection
	}
	win := req.WindowSecs
	if win <= 0 {
		win = 900 // varsayılan 15 dk doğrulama penceresi
	}
	c, err := s.verifyStore.Open(verify.Check{
		ID: newVerifyID(), TenantID: tenant, FindingRef: req.FindingRef, DeviceID: req.DeviceID,
		RuleID: req.RuleID, Kind: kind, Expected: req.Expected, Factors: req.Factors,
		WindowEnd: s.now().Add(time.Duration(win) * time.Second),
	})
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

// handleVerifyList, çağıranın kiracısının doğrulama check'lerini listeler (VIEWER+).
// Platform admini (boş kiracı) tümünü görür.
func (s *Server) handleVerifyList(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.verifyStore == nil {
		writeErr(w, http.StatusNotFound, "doğrulama motoru etkin değil")
		return
	}
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	var list []verify.Check
	if tenant == "" {
		list, err = s.verifyStore.ListAll()
	} else {
		list, err = s.verifyStore.List(tenant)
	}
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(list), "checks": list})
}

// handleVerifyRun, bir check'i ÇALIŞTIRIR (OPERATOR+): cihazın açılıştan bu yana taze
// olaylarını çekip kaynak tespit kuralını yeniden koşturur, sonucu ve kalan riski Resolve
// eder. Kiracı-kapsamlı (çapraz-kiracı check → 404). Fail-closed: değerlendirilemezse
// INCONCLUSIVE.
// parseIndicator, Kind=graph_containment check'inin Expected alanında taşınan
// gösterge spesini ("kind|id|relation", ör. "ip|1.2.3.4|connected") ayrıştırır.
// Üç boş-olmayan parça yoksa ok=false (çağıran INCONCLUSIVE'e düşer — fail-closed).
func parseIndicator(expected string) (kind, id, rel string, ok bool) {
	parts := strings.Split(expected, "|")
	if len(parts) != 3 {
		return "", "", "", false
	}
	kind = strings.ToLower(strings.TrimSpace(parts[0]))
	id = strings.TrimSpace(parts[1])
	rel = strings.ToLower(strings.TrimSpace(parts[2]))
	if kind == "" || id == "" || rel == "" {
		return "", "", "", false
	}
	return kind, id, rel, true
}

func (s *Server) handleVerifyRun(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.verifyStore == nil || s.verifier == nil {
		writeErr(w, http.StatusNotFound, "doğrulama motoru etkin değil")
		return
	}
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	id := r.PathValue("id")
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	var c verify.Check
	if tenant == "" {
		c, err = s.verifyStore.GetAny(id)
	} else {
		c, err = s.verifyStore.Get(tenant, id)
	}
	if err == verify.ErrCheckNotFound {
		writeErr(w, http.StatusNotFound, "check bulunamadı")
		return
	}
	if respondErr(w, err) {
		return
	}
	var (
		outcome  verify.Outcome
		residual int
	)
	if c.Kind == verify.KindDeviceStatus {
		// Cihazın GÜNCEL efektif durumunu beklenen duruma karşı ölç (olay değil durum sinyali).
		// desired≠effective boşluğu: "karantina gerçekten uygulandı mı?" doğrulaması.
		dd, ok, derr := s.reader.DeviceDetail(r.Context(), c.DeviceID, c.TenantID)
		if respondErr(w, derr) {
			return
		}
		cur := ""
		if ok {
			cur = dd.Device.Status // cihaz yoksa boş → INCONCLUSIVE (fail-closed)
		}
		outcome, residual = verify.EvaluateDeviceStatus(c, cur)
	} else if c.Kind == verify.KindVuln {
		// CVE re-scan: cihazın GÜNCEL yazılım envanterini zafiyet veri kümesiyle eşleştir;
		// beklenen CVE artık eşleşmiyorsa yamalanmış (VERIFIED). Veri yoksa INCONCLUSIVE.
		dataAvail := false
		var cur []string
		if s.vulnSet != nil && s.vulnSet.Size() > 0 {
			byDev, derr := s.reader.LatestSoftwareByDevice(r.Context(), c.TenantID)
			if respondErr(w, derr) {
				return
			}
			if sw, ok := byDev[c.DeviceID]; ok {
				dataAvail = true
				for _, f := range s.vulnSet.Match(sw) {
					cur = append(cur, f.CVE)
				}
			}
		}
		outcome, residual = verify.EvaluateVulnCleared(c, dataAvail, cur)
	} else if c.Kind == verify.KindGraphContainment {
		// Blast-radius kapsamı: remediasyona yol açan göstergeye (Expected="kind|id|rel",
		// ör. "ip|1.2.3.4|connected") entity-grafta bağlı AKRAN cihazlar KİRACI-KAPSAMLI
		// çözülür (Sources — *Any DEĞİL; çapraz-kiracı sızıntıyı önler) ve her birinin
		// kontrol-altında olup olmadığı DeviceDetail ile ölçülür. Graf yoksa/indikatör
		// ayrıştırılamazsa dataAvail=false → INCONCLUSIVE (fail-closed).
		dataAvail := false
		var peers []string
		if s.graph != nil {
			if ik, iid, rel, ok := parseIndicator(c.Expected); ok {
				dataAvail = true
				target := entitygraph.Node{Kind: entitygraph.Kind(ik), ID: iid, Tenant: c.TenantID}
				for _, n := range s.graph.Sources(target, entitygraph.Relation(rel)) {
					if n.Kind == entitygraph.Device && n.ID != c.DeviceID {
						peers = append(peers, n.ID)
					}
				}
			}
		}
		contained := func(deviceID string) bool {
			dd, ok, derr := s.reader.DeviceDetail(r.Context(), deviceID, c.TenantID)
			if derr != nil || !ok {
				return false // durum okunamadı → kontrol-altında SAYILMAZ (fail-closed)
			}
			st := strings.ToUpper(strings.TrimSpace(dd.Device.Status))
			return st == "QUARANTINED" || st == "ISOLATED" || strings.Contains(st, "QUARANTINE")
		}
		outcome, residual = verify.EvaluateGraphContainment(c, dataAvail, peers, contained)
	} else {
		// Açılıştan bu yana cihazın taze olayları (aksiyon-sonrası pencere), kiracı-kapsamlı.
		rows, err := s.reader.QueryEvents(r.Context(), adminread.EventFilter{
			DeviceID: c.DeviceID, TenantID: c.TenantID, Since: c.OpenedAt, Limit: 500,
		})
		if respondErr(w, err) {
			return
		}
		fresh := make([]model.Event, 0, len(rows))
		for _, d := range rows {
			fresh = append(fresh, eventDTOToModel(d))
		}
		outcome, residual, err = s.verifier.Evaluate(r.Context(), c, fresh)
		if respondErr(w, err) {
			return
		}
	}
	resolved, err := s.verifyStore.Resolve(c.TenantID, c.ID, outcome, residual)
	if respondErr(w, err) {
		return
	}
	switch outcome {
	case verify.OutcomeVerified:
		metrics.IncVerifyVerified()
	case verify.OutcomeRegressed:
		metrics.IncVerifyRegressed()
	case verify.OutcomeInconclusive:
		metrics.IncVerifyInconclusive()
	}
	s.adminSvc.RecordAudit(r.Context(), adminID, "VERIFY_RUN", "verify", c.ID)
	writeJSON(w, http.StatusOK, resolved)
}

// handleSetDeviceTags, cihazın etiketlerini ayarlar (OPERATOR+, servis içinde
// RBAC). Gövde: {"tags":["prod","finans"]}.
func (s *Server) handleSetDeviceTags(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Tags []string `json:"tags"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.SetDeviceTags(r.Context(), adminID, r.PathValue("id"), req.Tags)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tags": normalizeTagsForResponse(req.Tags)})
}

// normalizeTagsForResponse, yanıt için etiketleri kırpar/tekilleştirir (servis
// katmanıyla aynı normalize; yanıtta güncel hali göstermek için).
func normalizeTagsForResponse(tags []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

func (s *Server) handleDeviceDetail(w http.ResponseWriter, r *http.Request, adminID string) {
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	detail, ok, err := s.reader.DeviceDetail(r.Context(), r.PathValue("id"), tenant)
	if respondErr(w, err) {
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "cihaz bulunamadı")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_detail": detail})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request, adminID string) {
	// politikalar kiracı sahibi taşır; kiracıya bağlı çağıran yalnız kendi kiracısının
	// ve platform/paylaşımlı politikaları görür (kiracı SUNUCU-TARAFI çözülür).
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	policies, err := s.reader.Policies(r.Context(), intParam(r, "limit"), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies})
}

// handleExportDevice, KVKK ERİŞİM talebi: cihaz hakkındaki tüm veriyi tek JSON
// dosyası olarak indirir (ADMIN; AuthorizeExport RBAC + denetim yazar).
func (s *Server) handleExportDevice(w http.ResponseWriter, r *http.Request, adminID string) {
	id := r.PathValue("id")
	if respondErr(w, s.adminSvc.AuthorizeExport(r.Context(), adminID, id)) {
		return
	}
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	export, ok, err := s.reader.ExportDevice(r.Context(), id, tenant)
	if respondErr(w, err) {
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "cihaz bulunamadı")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="kvkk-export-`+id+`.json"`)
	writeJSON(w, http.StatusOK, export)
}

// handleEraseDevice, KVKK SİLME talebi: cihazın davranışsal/telemetri verisini
// siler ve sertifikalarını iptal eder (ADMIN).
func (s *Server) handleEraseDevice(w http.ResponseWriter, r *http.Request, adminID string) {
	report, err := s.adminSvc.EraseDevice(r.Context(), adminID, r.PathValue("id"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// ocsfProduct, OCSF çıktısında metadata.product alanıdır (CEF/LEEF ile tutarlı kimlik).
var ocsfProduct = telemetryschema.Product{Name: "Suite", VendorName: "KUT"}

// eventDTOToModel, salt-okuma DTO'sunu kanonik model.Event'e köprüler (OCSF eşlemesi için).
func eventDTOToModel(d adminread.EventDTO) model.Event {
	return model.Event{
		EventID:       d.EventID,
		Category:      d.Category,
		Severity:      d.Severity,
		Message:       d.Message,
		OccurredAt:    d.OccurredAt,
		DeviceID:      d.DeviceID,
		Source:        d.Source,
		EventType:     d.EventType,
		Confidence:    d.Confidence,
		CorrelationID: d.CorrelationID,
		ParentEventID: d.ParentEventID,
		Details:       string(d.Details),
	}
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request, adminID string) {
	q := r.URL.Query()
	// Kiracıyı sunucu-tarafı çöz (kimlik-doğrulanmış adminID'den, istekten değil):
	// platform admini (boş kiracı) tümünü, kiracıya bağlı admin yalnız kendi olaylarını
	// görür. Çözümleme hatası fail-closed (okuma reddi).
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	events, err := s.reader.Events(r.Context(), q.Get("device_id"), q.Get("severity"), q.Get("category"), intParam(r, "limit"), tenant)
	if respondErr(w, err) {
		return
	}
	// format=ocsf: olayları sektör-standardı OCSF şemasına eşleyip döner (SIEM/veri-gölü
	// interop). Kanonik EventID korunur → OCSF çıktısı da yinelenebilir.
	if q.Get("format") == "ocsf" {
		evs := make([]model.Event, 0, len(events))
		for _, d := range events {
			evs = append(evs, eventDTOToModel(d))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema":         "ocsf",
			"schema_version": telemetryschema.OCSFSchemaVersion,
			"events":         telemetryschema.ToOCSFBatch(evs, ocsfProduct),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request, adminID string) {
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	summary, err := s.reader.Summary(r.Context(), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary})
}

// handleMitreCoverage, sistemin eşleyebildiği MITRE ATT&CK teknikleri kataloğunu
// döner (kapsama matrisi). Konsol bunu ATT&CK kapsama görünümünde kullanır.
func (s *Server) handleMitreCoverage(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, http.StatusOK, map[string]any{"techniques": mitre.Catalog()})
}

// handleDetectionRules, devrede olan sunucu-taraflı tespit kurallarını (katalog)
// döner. Konsol bunu "hangi tespitler etkin" görünümünde kullanır.
func (s *Server) handleDetectionRules(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": s.detector.Load().Rules()})
}

// handleTestDetection, örnek bir olayı (kategori + mesaj) tespit motorundan
// geçirir ve hangi kuralların eşleştiğini döner (kuru çalıştırma / dry-run).
// SOC analistinin gerçek bir olay beklemeden tespit kapsamını doğrulaması
// içindir. Salt-okunur bir değerlendirmedir; hiçbir olay saklanmaz veya
// alarm üretilmez, bu yüzden herhangi bir kimliği doğrulanmış kullanıcı erişebilir.
func (s *Server) handleTestDetection(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		Category string `json:"category"`
		Message  string `json:"message"`
	}
	if !decode(w, r, &req) {
		return
	}
	matches := s.detector.Load().Evaluate(model.Event{Category: req.Category, Message: req.Message})
	writeJSON(w, http.StatusOK, map[string]any{
		"matches": matches,
		"matched": len(matches),
	})
}

// handleAIAnalyze, AI SOC ASİSTANI: bir analiz isteğini (alarm/olay özeti,
// MITRE eşleme, yanlış-pozitif, düzeltme önerisi) sağlayıcıya iletir ve ÖNERİ döner.
// KRİTİK: yalnız öneridir — hiçbir eylem YÜRÜTÜLMEZ. Önerilen eylemler ancak
// policy + insan onayı (aiassist.Gate) ile uygulanabilir; bu uç yürütme yapmaz.
// Varsayılan sağlayıcı çevrimdışı/deterministik LocalProvider'dır (dış LLM yok).
func (s *Server) handleAIAnalyze(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		Task    string            `json:"task"`
		Input   string            `json:"input"`
		Context map[string]string `json:"context"`
	}
	if !decode(w, r, &req) {
		return
	}
	provider := s.aiProvider
	if provider == nil {
		provider = aiassist.NewLocalProvider()
	}
	rec, err := provider.Analyze(r.Context(), aiassist.Request{
		Task: aiassist.Task(req.Task), Input: req.Input, Context: req.Context,
	})
	if respondErr(w, err) {
		return
	}
	// Öneri PendingApproval durumunda döner: eylemler için policy + insan onayı gerekir.
	writeJSON(w, http.StatusOK, map[string]any{
		"recommendation": rec,
		"note":           "öneri yalnızca; eylemler policy + insan onayı gerektirir (yürütülmedi)",
	})
}

// handleABACEvaluate, ÖZNİTELİK-TABANLI ERİŞİM KONTROLÜ: bir erişim isteğini
// (özne/kaynak öznitelikleri + eylem) yapılandırılmış ABAC politikalarına göre
// değerlendirir ve karar (izin/ret + eşleşen politika) döner. RBAC'ı tamamlar; salt
// değerlendirme (politikaları uygulamaz, yalnız yanıtlar). Motor yapılandırılmamışsa 404.
func (s *Server) handleABACEvaluate(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.abacEngine == nil {
		http.NotFound(w, r)
		return
	}
	// Politika-oracle'ı: yetkilendirme yüzeyini haritalamak isteyen düşük-yetkili bir
	// kullanıcıya kapalı olmalı (ADMIN).
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	var req iam.Request
	if !decode(w, r, &req) {
		return
	}
	allowed, matched := s.abacEngine.Evaluate(req)
	writeJSON(w, http.StatusOK, map[string]any{"allowed": allowed, "matched_policy": matched})
}

// --- SCIM 2.0 kullanıcı sağlama — ADMIN; IdP provisioning ------------------

// scimUUID, yeni bir SCIM kullanıcısı için rastgele RFC4122 v4 UUID üretir (DB ::uuid
// kolonuyla uyumlu). Provisioner sözleşmesi id'yi çağırandan bekler.
func scimUUID() string {
	var u [16]byte
	_, _ = rand.Read(u[:])
	u[6] = (u[6] & 0x0f) | 0x40 // sürüm 4
	u[8] = (u[8] & 0x3f) | 0x80 // RFC4122 varyantı
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// handleSCIMCreate, yeni bir SCIM kullanıcısı sağlar (sunucu id atar).
func (s *Server) handleSCIMCreate(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.scim == nil {
		http.NotFound(w, r)
		return
	}
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	var u iam.User
	if !decode(w, r, &u) {
		return
	}
	u.ID = scimUUID()
	tenant, err := s.scimOpTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	created, err := s.scim.Create(tenant, u)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// scimOpTenant, SCIM işleminin kiracısını SUNUCU-TARAFI çözer: kiracıya bağlı admin
// kendi kiracısına sabitlenir (başka kiracının SCIM kullanıcısına erişemez — provisioner
// izolasyonu); platform admini (boş kiracı) dağıtım varsayılan kiracısına düşer. İstemci
// header'ı ASLA kullanılmaz (cross-tenant IDOR kapalı).
func (s *Server) scimOpTenant(ctx context.Context, adminID string) (string, error) {
	t, err := s.callerTenant(ctx, adminID)
	if err != nil {
		return "", err
	}
	if t == "" {
		return s.scimTenant(), nil
	}
	return iam.NormTenant(t), nil
}

// scimTenant, dağıtımın yapılandırılmış tenant'ını döner (platform admini için SCIM
// varsayılan kovası). İstemci header'ından DEĞİL.
func (s *Server) scimTenant() string {
	return iam.NormTenant(strings.TrimSpace(s.tenantID))
}

// handleSCIMGet, bir SCIM kullanıcısını döner.
func (s *Server) handleSCIMGet(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.scim == nil {
		http.NotFound(w, r)
		return
	}
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	tenant, err := s.scimOpTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	u, err := s.scim.Get(tenant, r.PathValue("id"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// handleSCIMReplace, bir SCIM kullanıcısını tümüyle değiştirir (PUT).
func (s *Server) handleSCIMReplace(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.scim == nil {
		http.NotFound(w, r)
		return
	}
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	var u iam.User
	if !decode(w, r, &u) {
		return
	}
	tenant, err := s.scimOpTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	replaced, err := s.scim.Replace(tenant, r.PathValue("id"), u)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, replaced)
}

// handleSCIMDeactivate, bir SCIM kullanıcısını devre dışı bırakır (soft-delete; active=false).
func (s *Server) handleSCIMDeactivate(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.scim == nil {
		http.NotFound(w, r)
		return
	}
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	tenant, err := s.scimOpTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	u, err := s.scim.Deactivate(tenant, r.PathValue("id"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// --- MSP müşteri yönetimi — ADMIN --------------------------------------

// handleMSPCreateCustomer, yeni bir MSP müşterisi ekler.
func (s *Server) handleMSPCreateCustomer(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.mspStore == nil {
		http.NotFound(w, r)
		return
	}
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	if respondErr(w, s.requirePlatformAdmin(r.Context(), adminID)) {
		return
	}
	var req struct {
		Name     string `json:"name"`
		TenantID string `json:"tenant_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.TenantID) == "" {
		writeErr(w, http.StatusBadRequest, "name ve tenant_id zorunlu")
		return
	}
	// kiracı kimliği sınırda doğrulanır/normalleştirilir (küçük harf, [a-z0-9-], 1-63);
	// büyük-küçük harf varyantları ayrı müşteri olamaz, uzun değer VARCHAR(63) taşmasıyla 500 vermez.
	normTenant, nerr := normalizeTenantInput(req.TenantID)
	if nerr != nil {
		writeErr(w, http.StatusBadRequest, "geçersiz tenant_id (küçük harf/rakam/tire, 1-63)")
		return
	}
	c, err := s.mspStore.MSPAddCustomer(req.Name, normTenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

// handleMSPListCustomers, tüm MSP müşterilerini döner.
func (s *Server) handleMSPListCustomers(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.mspStore == nil {
		http.NotFound(w, r)
		return
	}
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	if respondErr(w, s.requirePlatformAdmin(r.Context(), adminID)) {
		return
	}
	list, err := s.mspStore.MSPListCustomers()
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"customers": list})
}

// handleMSPDeactivateCustomer, bir MSP müşterisini devre dışı bırakır (soft-delete).
func (s *Server) handleMSPDeactivateCustomer(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.mspStore == nil {
		http.NotFound(w, r)
		return
	}
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	if respondErr(w, s.requirePlatformAdmin(r.Context(), adminID)) {
		return
	}
	ok, err := s.mspStore.MSPDeactivateCustomer(r.PathValue("id"))
	if respondErr(w, err) {
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "müşteri bulunamadı")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deactivated": true})
}

// scopeTenant, çağıran yöneticinin kiracısını bir EventFilter'a uygular (okuma
// izolasyonu). Kiracı SUNUCU-TARAFI çözülür (kimlik-doğrulanmış adminID'den, istekten
// DEĞİL): platform admini (boş kiracı) tüm kiracıları görür, kiracıya bağlı admin yalnız
// kendi kiracısını. Çözümleme hatası → fail-closed (okuma reddedilir, sızıntı yerine 500).
func (s *Server) scopeTenant(ctx context.Context, adminID string, f *adminread.EventFilter) error {
	t, err := s.adminSvc.AdminTenant(ctx, adminID)
	if err != nil {
		return err
	}
	f.TenantID = t
	return nil
}

// callerTenant, çağıran yöneticinin kiracısını (okuma kapsamı için) döner. Boş kiracı
// → platform admini (tüm kiracılar). Kiracı SUNUCU-TARAFI çözülür (adminID'den, istekten
// DEĞİL). Filtre yerine düz string alan okuma yolları (device export/graf/hikâye) kullanır.
func (s *Server) callerTenant(ctx context.Context, adminID string) (string, error) {
	return s.adminSvc.AdminTenant(ctx, adminID)
}

// requirePlatformAdmin, çağıranın PLATFORM admini (kiracısız) olduğunu doğrular. Kiracıya
// bağlı bir admin (RoleAdmin olsa bile) KONTROL-DÜZLEMİ uçlarını (MSP = kiracı/müşteri
// yönetimi — tüm kiracılara dokunur) kullanamaz → ErrForbidden. Kiracı sunucu-tarafı çözülür.
func (s *Server) requirePlatformAdmin(ctx context.Context, adminID string) error {
	t, err := s.adminSvc.AdminTenant(ctx, adminID)
	if err != nil {
		return err
	}
	if t != "" {
		return admin.ErrForbidden
	}
	return nil
}

// handleReplayDetection, EVENT REPLAY (§19): aday bir tespit kuralını (ya da mevcut
// kural setini) zaman-pencereli GEÇMİŞ olaylara uygular ve "bu kural geçmişte kaç olayı
// yakalardı?" raporunu döner. Kuralı üretime almadan önce etkisini ölçmek için. Salt-okuma.
// rules verilmezse mevcut motor kuralları kullanılır (mevcut setin geçmiş kapsamı).
func (s *Server) handleReplayDetection(w http.ResponseWriter, r *http.Request, adminID string) {
	// Aday kuralı tüm geçmiş olaylara uygular (pahalı + tespit mühendisliği): vaka/doğrulama
	// koşusu gibi OPERATOR+.
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	var req struct {
		Rules           []detect.Rule `json:"rules"` // aday kural(lar); boşsa mevcut set
		DeviceID        string        `json:"device_id"`
		Severity        string        `json:"severity"`
		Category        string        `json:"category"`
		MessageContains string        `json:"message_contains"`
		Since           string        `json:"since"` // RFC3339, opsiyonel
		Until           string        `json:"until"`
		Limit           int           `json:"limit"`
	}
	if !decode(w, r, &req) {
		return
	}
	f := adminread.EventFilter{
		DeviceID: req.DeviceID, Severity: req.Severity, Category: req.Category,
		MessageContains: req.MessageContains, Limit: req.Limit,
	}
	if req.Since != "" {
		if t, err := time.Parse(time.RFC3339, req.Since); err == nil {
			f.Since = t
		}
	}
	if req.Until != "" {
		if t, err := time.Parse(time.RFC3339, req.Until); err == nil {
			f.Until = t
		}
	}
	if respondErr(w, s.scopeTenant(r.Context(), adminID, &f)) {
		return
	}
	rules := req.Rules
	if len(rules) == 0 {
		rules = s.detector.Load().Rules() // aday verilmediyse mevcut seti geçmişe uygula
	}
	report, err := s.reader.ReplayDetections(r.Context(), f, rules)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// handleHunt, RETRO-HUNT / SIEM arama: geçmiş olaylar üzerinde çalışır. mode
// "rules" ise mevcut tespit motoru geçmiş olaylara UYGULANIR ("yeni kuralla eski
// olayları tarama" — bir gösterge sonradan öğrenildiğinde "zaten vurulduk mu?"),
// "query" ise zaman-pencereli + alan-filtreli arama sonuçlarını döner. Salt-okunur.
func (s *Server) handleHunt(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Mode            string `json:"mode"` // "rules" | "query"
		DeviceID        string `json:"device_id"`
		Severity        string `json:"severity"`
		Category        string `json:"category"`
		MessageContains string `json:"message_contains"`
		Since           string `json:"since"` // RFC3339, opsiyonel
		Until           string `json:"until"`
		Limit           int    `json:"limit"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Limit <= 0 || req.Limit > 1000 { // sunucu-tarafı tavan: aşırı LIMIT ile bellek şişmesini önle
		req.Limit = 200
	}
	f := adminread.EventFilter{
		DeviceID: req.DeviceID, Severity: req.Severity, Category: req.Category,
		MessageContains: req.MessageContains, Limit: req.Limit,
	}
	if req.Since != "" {
		if t, err := time.Parse(time.RFC3339, req.Since); err == nil {
			f.Since = t
		}
	}
	if req.Until != "" {
		if t, err := time.Parse(time.RFC3339, req.Until); err == nil {
			f.Until = t
		}
	}
	if respondErr(w, s.scopeTenant(r.Context(), adminID, &f)) {
		return
	}
	events, err := s.reader.QueryEvents(r.Context(), f)
	if respondErr(w, err) {
		return
	}
	type hit struct {
		Event   adminread.EventDTO `json:"event"`
		Matched []string           `json:"matched,omitempty"`
	}
	hits := make([]hit, 0)
	if req.Mode == "rules" {
		eng := s.detector.Load()
		for _, e := range events {
			dets := eng.Evaluate(model.Event{
				Category: e.Category, Severity: e.Severity, Message: e.Message,
				Details: string(e.Details), OccurredAt: e.OccurredAt,
			})
			if len(dets) == 0 {
				continue
			}
			ids := make([]string, 0, len(dets))
			for _, d := range dets {
				ids = append(ids, d.RuleID)
			}
			hits = append(hits, hit{Event: e, Matched: ids})
		}
	} else { // "query" (varsayılan): filtrelenmiş olayları döndür
		for _, e := range events {
			hits = append(hits, hit{Event: e})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": req.Mode, "scanned": len(events), "hits": hits})
}

// buildReportData, güvenlik-duruş raporu verisini adminread + metrics'ten toplar.
// tenantID boş değilse rapor yalnız o kiracının verisinden üretilir ve kiracı etiketi
// çağıranın kiracısı olur; boş (platform admini) ise dağıtım-geneli + dağıtım kiracı etiketi.
func (s *Server) buildReportData(r *http.Request, tenantID string) (report.Data, error) {
	sum, err := s.reader.Summary(r.Context(), tenantID)
	if err != nil {
		return report.Data{}, err
	}
	incs, _ := s.reader.Incidents(r.Context(), 20, tenantID)
	// Süreç-geneli sayaçlar (tespit/alarm/IoC...) TÜM kiracıların etkinliğini toplar: kiracıya
	// bağlı rapora KONMAZ. Platform raporu (tenantID == "") bunları taşır.
	var c map[string]int64
	if tenantID == "" {
		c = metrics.Counters()
	}
	reportTenant := s.tenantID
	if tenantID != "" {
		reportTenant = tenantID // kiracıya bağlı admin: rapor kendi kiracısına etiketlenir
	}
	d := report.Data{
		GeneratedAt: s.now(), SchemaVersion: model.EventSchemaVersion, TenantID: reportTenant, Title: "Güvenlik Duruş Raporu",
		DevicesTotal: sum.DevicesTotal, DevicesOnline: sum.DevicesOnline, DevicesOffline: sum.DevicesOffline,
		DevicesQuarantined: sum.DevicesQuarantined, NonCompliant: sum.NonCompliantDevices,
		EventsBySeverity: sum.EventsBySeverity, DevicesByOS: sum.DevicesByOS,
		Detections: c["detections"], AlertsRaised: c["alerts_raised"],
		AlertsSuppressed: c["alerts_suppressed"], IocHits: c["ioc_hits"],
		CountersOmitted: tenantID != "",
	}
	for _, in := range incs {
		d.TopIncidents = append(d.TopIncidents, report.Incident{
			DeviceID: in.DeviceID, RuleID: in.RuleID, Severity: in.Severity, Count: in.Count, LastSeen: in.LastSeen,
		})
	}
	return d, nil
}

// handleReport, dışa aktarılabilir güvenlik-duruş raporu üretir (format=html
// varsayılan | csv). Salt-okunur; nokta-zaman görünümü (kurumsal/denetim/KVKK).
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, adminID string) {
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	d, err := s.buildReportData(r, tenant)
	if respondErr(w, err) {
		return
	}
	switch r.URL.Query().Get("format") {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="kut-report.csv"`)
		_, _ = w.Write([]byte(report.RenderCSV(d)))
		return
	case "json":
		// Makine-okunur rapor (otomasyon / zamanlanmış raporlama / SIEM).
		writeJSON(w, http.StatusOK, d)
		return
	case "md", "markdown":
		// Markdown rapor — kind=executive|technical|incident (varsayılan technical).
		kind := report.Kind(r.URL.Query().Get("kind"))
		switch kind {
		case report.KindExecutive, report.KindTechnical, report.KindIncident:
		default:
			kind = report.KindTechnical
		}
		d.Title = kind.Title() // rapor türü başlığı belirler (yönetici/teknik/olay)
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="kut-report.md"`)
		_, _ = w.Write([]byte(report.RenderMarkdown(d, kind)))
		return
	}
	html, err := report.RenderHTML(d)
	if respondErr(w, err) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

// handleEntityGraph, bir cihazın olaylarından cihaz-merkezli varlık grafiğini
// (süreç/alan adı/IP/dosya düğümleri) döner (IR investigation görselleştirmesi).
func (s *Server) handleEntityGraph(w http.ResponseWriter, r *http.Request, adminID string) {
	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		writeErr(w, http.StatusBadRequest, "cihaz kimliği zorunlu")
		return
	}
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	g, err := s.reader.DeviceEntityGraph(r.Context(), id, intParam(r, "limit"), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// handleAttackStory, bir cihazın olaylarını kill-chain aşamalarına göre sıralanmış
// tek bir saldırı hikâyesi olarak döner (SOC investigation — yüzlerce olayı elle
// ilişkilendirmeye gerek kalmadan).
func (s *Server) handleAttackStory(w http.ResponseWriter, r *http.Request, adminID string) {
	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		writeErr(w, http.StatusBadRequest, "cihaz kimliği zorunlu")
		return
	}
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	story, err := s.reader.DeviceAttackStory(r.Context(), id, intParam(r, "limit"), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, story)
}

// handleFrameworks, filo güvenlik-duruşunu uyum çerçevelerine (CIS/NIST/ISO/KVKK)
// eşleyen skor raporunu döner (denetçi görünürlüğü).
func (s *Server) handleFrameworks(w http.ResponseWriter, r *http.Request, adminID string) {
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	rep, err := s.reader.FrameworkCompliance(r.Context(), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleRisk, çok-faktörlü filo risk skorunu döner: açık incident'ler,
// uyum ihlalleri ve karantina durumundan cihaz + filo risk skoru hesaplar.
func (s *Server) handleRisk(w http.ResponseWriter, r *http.Request, adminID string) {
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	rk, err := s.reader.FleetRisk(r.Context(), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rk)
}

// handleCoverage, filo koruma-kapsamı + ajan sürüm-kayması ("kim korunuyor?").
func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request, adminID string) {
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	cov, err := s.reader.Coverage(r.Context(), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, cov)
}

// handleAdminBehavior, ayrıcalıklı-kullanıcı (yönetici) davranış analitiğini döner
// (UEBA): yıkıcı-eylem serisi / yüksek yıkıcı oran anomalileri. Denetim izi hassas —
// OPERATOR+ gerekir.
func (s *Server) handleAdminBehavior(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	rep, err := s.reader.AdminBehavior(r.Context(), intParam(r, "limit"))
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleAuditExport, denetim izini KURCALAMA-KANITLI, taşınabilir bir hash-zinciri
// (JSONL) olarak dışa aktarır. Anahtar bağlıysa (SetAuditExportKey) son
// satıra imzalı bir manifest eklenir. Denetçi/WORM arşiv bunu C2'DEN BAĞIMSIZ
// doğrulayabilir (tools/auditverify). OPERATOR+ gerekir (denetim izi hassas).
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	rows, err := s.reader.Audit(r.Context(), intParam(r, "limit"), tenant)
	if respondErr(w, err) {
		return
	}
	// Audit en yeniden eskiye döner; zincir KRONOLOJİK (eskiden yeniye) olmalı.
	entries := make([]auditexport.Entry, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		a := rows[i]
		entries = append(entries, auditexport.Entry{
			TenantID: tenant, Admin: a.AdminEmail, Action: a.Action,
			TargetType: a.TargetType, TargetID: a.TargetID, CreatedAt: a.CreatedAt,
		})
	}
	data, err := auditexport.MarshalJSONL(auditexport.BuildChain(entries), s.auditExpKey)
	if respondErr(w, err) {
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-export.jsonl"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleSaveSearch, bir threat-hunting sorgusunu adla kalıcılaştırır (SIEM kayıtlı
// arama). Gövde: {"name": "...", "filter": {<hunt isteği>}}. filter ham JSON olarak
// saklanır; sonradan /api/hunt'a aynen gönderilebilir.
func (s *Server) handleSaveSearch(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Name   string          `json:"name"`
		Filter json.RawMessage `json:"filter"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "ad zorunlu")
		return
	}
	if len(req.Filter) == 0 || string(req.Filter) == "null" {
		writeErr(w, http.StatusBadRequest, "filter zorunlu")
		return
	}
	row, err := s.reader.SaveSearch(r.Context(), req.Name, string(req.Filter), adminID)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, row)
}

// handleListSavedSearches, kayıtlı aramaları listeler.
func (s *Server) handleListSavedSearches(w http.ResponseWriter, r *http.Request, adminID string) {
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	rows, err := s.reader.SavedSearches(r.Context(), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"searches": rows})
}

// handleDeleteSavedSearch, bir kayıtlı aramayı siler.
func (s *Server) handleDeleteSavedSearch(w http.ResponseWriter, r *http.Request, adminID string) {
	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		writeErr(w, http.StatusBadRequest, "kimlik zorunlu")
		return
	}
	// Sahiplik: yalnız kaydı oluşturan analist silebilir (IDOR önlemi).
	deleted, err := s.reader.DeleteSavedSearch(r.Context(), id, adminID)
	if respondErr(w, err) {
		return
	}
	if !deleted {
		// Bulunamadı VEYA çağıran owner değil → yanıltıcı "deleted" dönme, 404 ver.
		writeErr(w, http.StatusNotFound, "kayıtlı arama bulunamadı")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

// handleMaintenance, yapılandırılmış bakım/bastırma pencerelerini döner:
// her pencere için zaman aralığı, kapsam (cihaz/kategori), gerekçe ve şu an ETKİN
// olup olmadığı. Konsol "neden uyarı gelmiyor?" görünürlüğü.
func (s *Server) handleMaintenance(w http.ResponseWriter, r *http.Request, _ string) {
	type windowDTO struct {
		Start  time.Time `json:"start"`
		End    time.Time `json:"end"`
		Reason string    `json:"reason,omitempty"`
		Active bool      `json:"active"`
	}
	out := []windowDTO{}
	if s.maintWindows != nil {
		now := time.Now()
		for _, wd := range s.maintWindows() {
			out = append(out, windowDTO{
				Start: wd.Start, End: wd.End, Reason: wd.Reason, Active: wd.Active(now),
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"windows": out})
}

// handleMetricsTrends, MTTD/MTTR metriklerini ve günlük trendini döner (SOC
// olgunluk göstergesi). ?days=N ile pencere ayarlanır (varsayılan 7, üst sınır 90).
func (s *Server) handleMetricsTrends(w http.ResponseWriter, r *http.Request, _ string) {
	days := intParam(r, "days")
	if days <= 0 {
		days = 7
	}
	if days > 90 {
		days = 90
	}
	tr, err := s.reader.DetectionResponseTrends(r.Context(), days)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, tr)
}

// handleIncidentTimeline, bir incident'i ve onu oluşturan cihazın penceredeki
// olaylarını kronolojik döner (IR araştırması). Bulunamazsa 404.
func (s *Server) handleIncidentTimeline(w http.ResponseWriter, r *http.Request, adminID string) {
	id := r.PathValue("id")
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	tl, ok, err := s.reader.IncidentTimeline(r.Context(), id, tenant)
	if respondErr(w, err) {
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "incident bulunamadı")
		return
	}
	writeJSON(w, http.StatusOK, tl)
}

// handleIncidents, korelasyonla gruplanmış olayları (incident) listeler (salt-okunur).
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request, adminID string) {
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	rows, err := s.reader.Incidents(r.Context(), 200, tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": rows})
}

// handleLockDevice, uzaktan ekran kilitleme komutu kuyruğa ekler (OPERATOR+).
// gateAction, tekil yüksek-etkili bir cihaz aksiyonunu Action Authorization
// Gateway'den geçirir (istek sınırında rate-limit; tekil op olduğundan
// blast-radius=1 her zaman geçer). Reddedilirse 429 yazıp false döner. Böylece
// toplu VE tekil yüksek-etkili op'lar aynı merkezi kapıdan geçer; ele geçirilmiş
// bir oturumun tekil cihazlarda hızlı kitlesel yıkıcı komut yağmuru sınırlanır.
func (s *Server) gateAction(w http.ResponseWriter, adminID string, act scope.Action) bool {
	dec := s.gateway.Authorize(authz.Request{
		Requester: authz.Human, Principal: adminID, Action: act, TargetCount: 1,
	})
	if !dec.Allow {
		writeErr(w, http.StatusTooManyRequests, dec.Reason)
		return false
	}
	return true
}

func (s *Server) handleLockDevice(w http.ResponseWriter, r *http.Request, adminID string) {
	if !s.gateAction(w, adminID, scope.ActionLock) {
		return
	}
	if respondErr(w, s.adminSvc.LockDevice(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "lock_queued"})
}

// handleRestartDevice, uzaktan yeniden başlatma komutu kuyruğa ekler (OPERATOR+).
func (s *Server) handleRestartDevice(w http.ResponseWriter, r *http.Request, adminID string) {
	if !s.gateAction(w, adminID, scope.ActionRestart) {
		return
	}
	if respondErr(w, s.adminSvc.RestartDevice(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "restart_queued"})
}

// handleWipeDevice, uzaktan veri silme başlatır (ADMIN; yıkıcı + audit). Çift-kontrol
// AÇIKSA komut hemen kuyruğa GİRMEZ — WIPE talebi kaydedilir ve farklı bir ADMIN'in
// onayı beklenir (dört-göz). KAPALIYSA doğrudan kuyruğa alınır (eski davranış).
func (s *Server) handleWipeDevice(w http.ResponseWriter, r *http.Request, adminID string) {
	if !s.gateAction(w, adminID, scope.ActionWipe) {
		return
	}
	if s.adminSvc.WipeDualControl() {
		var req struct {
			Reason string `json:"reason"`
		}
		// Gövde MaxBytesReader ile sınırlanır (OOM DoS önlenir); gerekçe opsiyonel olduğundan
		// boş gövde (io.EOF) kabul edilir, ama diğer hatalar (aşırı boyut/bozuk JSON) reddedilir.
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeErr(w, http.StatusBadRequest, "geçersiz istek gövdesi")
			return
		}
		if respondErr(w, s.adminSvc.RequestWipe(r.Context(), adminID, r.PathValue("id"), req.Reason)) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "wipe_pending_approval"})
		return
	}
	if respondErr(w, s.adminSvc.WipeDevice(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "wipe_queued"})
}

// handleApproveWipe, bekleyen bir WIPE talebini onaylar ve komutu kuyruğa alır
// (ADMIN; onaylayan talep edenden FARKLI olmalı — dört-göz).
func (s *Server) handleApproveWipe(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.ApproveWipe(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "wipe_queued"})
}

// handleCancelWipe, bekleyen bir WIPE talebini iptal eder (ADMIN).
func (s *Server) handleCancelWipe(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.CancelWipe(r.Context(), adminID, r.PathValue("id"))) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "wipe_cancelled"})
}

// handlePendingWipes, ikinci-onay bekleyen WIPE taleplerini listeler (çift-kontrol
// konsol görünümü; onay/iptal için).
func (s *Server) handlePendingWipes(w http.ResponseWriter, r *http.Request, adminID string) {
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	rows, err := s.reader.PendingWipes(r.Context(), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending_wipes": rows})
}

// handleCollectFile, bir cihazdan adli/IR dosya toplama komutu kuyruğa ekler
// (OPERATOR+). Ajan dosyayı okuyup yükler; sonuç /artifacts uçlarından görülür.
func (s *Server) handleCollectFile(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Path string `json:"path"`
	}
	if !decode(w, r, &req) {
		return
	}
	if respondErr(w, s.adminSvc.CollectFile(r.Context(), adminID, r.PathValue("id"), req.Path)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "queued"})
}

// handleListArtifacts, bir cihazdan toplanan artefaktların meta listesini döner (OPERATOR+).
// Meta veri de adli kayıttır: uç noktadan toplanan dosya YOLLARI (kullanıcı adı/inceleme
// kapsamı içerir), boyut ve hash — ham içerik (indirme) ve gözetim-zinciri yazımı ile aynı
// eşik; VIEWER bunları keşfedemez.
func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	arts, err := s.reader.Artifacts(r.Context(), r.PathValue("id"), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"artifacts": arts})
}

// handleDeviceEvidence, cihazın toplanan artefaktlarını kurcalamaya-dayanıklı delil
// kayıtları (SHA-256 + gözetim-zinciri, doğrulanmış) olarak döner (; adli/IR zinciri).
// OPERATOR+: zincir, delile kimin dokunduğunu (actor) ve dosya yollarını içerir; indirme/
// gözetim-yazımı ile tek tutarlı adli eşik.
func (s *Server) handleDeviceEvidence(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	ev, err := s.reader.DeviceEvidence(r.Context(), r.PathValue("id"), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"evidence": ev})
}

// handleRecordCustody, bir delile (artefakt) KALICI bir gözetim olayı (ACCESSED/
// TRANSFERRED/SEALED) ekler: eylemi yapan = oturum açan admin. Zincirin ucuna
// hash-bağlı yeni kayıt hesaplanır ve depolanır. Adli/IR zinciri.
func (s *Server) handleRecordCustody(w http.ResponseWriter, r *http.Request, adminID string) {
	// Delil zincirine KALICI yazma: salt-okur VIEWER değil, OPERATOR+ (adli/IR rolü).
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if !decode(w, r, &req) {
		return
	}
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	entry, err := s.reader.RecordCustody(r.Context(), r.PathValue("id"), r.PathValue("artifactID"), adminID, req.Action, tenant)
	if respondErr(w, err) {
		return
	}
	// Kalıcı gözetim yazımı yönetici denetim izine de düşer (CUSTODY_<EYLEM>): delil zinciri
	// ile admin audit zinciri birbirini çapraz doğrular; yazımı kimin yaptığı iki yerde kalır.
	s.adminSvc.RecordAudit(r.Context(), adminID, "CUSTODY_"+entry.Action, "artifact", r.PathValue("artifactID"))
	writeJSON(w, http.StatusOK, map[string]any{"custody": entry})
}

// handleDownloadArtifact, tek bir artefaktın ham içeriğini indirir (attachment).
func (s *Server) handleDownloadArtifact(w http.ResponseWriter, r *http.Request, adminID string) {
	// Uç noktadan toplanmış HAM dosya içeriği: toplamayı tetikleyen (COLLECT_FILE) rolle
	// aynı eşik — OPERATOR+. VIEWER ham delil indiremez.
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	id := r.PathValue("id")
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	c, ok, err := s.reader.ArtifactBytes(r.Context(), id, tenant)
	if respondErr(w, err) {
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "artefakt bulunamadı")
		return
	}
	// Kanıt gözetim zinciri (chain-of-custody): delil erişimini denetim izine yaz
	// (hangi analist, hangi artefakt, ne zaman) — adli bütünlük.
	s.adminSvc.RecordAudit(r.Context(), adminID, "DOWNLOAD_ARTIFACT", "artifact", id)
	name := c.Path
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		name = "artifact.bin"
	}
	// filename token'ından çıkış yapılmasını önle: tırnak/ters-eğik/kontrol karakterlerini
	// etkisizleştir (CWE-116 — Content-Disposition filename injection/spoofing).
	name = strings.NewReplacer(`"`, "_", `\`, "_", "\r", "_", "\n", "_").Replace(name)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(c.Content)
}

// handleAckEvent, bir olayı ACKNOWLEDGED (inceleniyor) işaretler (OPERATOR+).
func (s *Server) handleAckEvent(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.AckEvent(r.Context(), adminID, r.PathValue("id"), "ACKNOWLEDGED")) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ACKNOWLEDGED"})
}

// handleResolveEvent, bir olayı RESOLVED (kapatıldı) işaretler (OPERATOR+).
func (s *Server) handleResolveEvent(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.AckEvent(r.Context(), adminID, r.PathValue("id"), "RESOLVED")) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "RESOLVED"})
}

// handleEventCase, bir olaya sorumlu (assignee) ve serbest-metin not atar —
// vaka/olay yönetimi. OPERATOR+ yetkisi gerektirir.
func (s *Server) handleEventCase(w http.ResponseWriter, r *http.Request, adminID string) {
	var req struct {
		Assignee string `json:"assignee"`
		Note     string `json:"note"`
	}
	if !decode(w, r, &req) { // decode: gövde MaxBytesReader ile sınırlı + hata yanıtı
		return
	}
	if respondErr(w, s.adminSvc.UpdateEventCase(r.Context(), adminID, r.PathValue("id"), req.Assignee, req.Note)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"assignee": req.Assignee, "note": req.Note})
}

// handleVulnerabilities, her cihazın en son yazılım envanterini yüklü zafiyet
// veri kümesiyle eşleştirir ve zafiyetli cihazları (bulgularla) döner. Salt-
// okunur; herhangi bir kimliği doğrulanmış kullanıcı erişebilir.
func (s *Server) handleVulnerabilities(w http.ResponseWriter, r *http.Request, adminID string) {
	type deviceVulns struct {
		DeviceID string         `json:"device_id"`
		Hostname string         `json:"hostname"`
		Findings []vuln.Finding `json:"findings"`
	}
	out := []deviceVulns{}
	loaded := s.vulnSet.Size()
	if s.vulnSet != nil && loaded > 0 {
		tenant, err := s.callerTenant(r.Context(), adminID)
		if respondErr(w, err) {
			return
		}
		byDev, err := s.reader.LatestSoftwareByDevice(r.Context(), tenant)
		if respondErr(w, err) {
			return
		}
		devs, err := s.reader.Devices(r.Context(), 0, tenant)
		if respondErr(w, err) {
			return
		}
		hn := make(map[string]string, len(devs))
		for _, d := range devs {
			hn[d.ID] = d.Hostname
		}
		for id, sw := range byDev {
			if f := s.vulnSet.Match(sw); len(f) > 0 {
				out = append(out, deviceVulns{DeviceID: id, Hostname: hn[id], Findings: f})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dataset_size": loaded, "vulnerable_devices": len(out), "devices": out,
	})
}

// handleSoftwareSearch, filo-geneli yazılım araması yapar (?q=...): adı query'yi
// içeren paketi yüklü cihazları döner. Zafiyet müdahalesi ("X kurulu cihazlar").
// Salt-okunur; herhangi bir kimliği doğrulanmış kullanıcı erişebilir.
func (s *Server) handleSoftwareSearch(w http.ResponseWriter, r *http.Request, adminID string) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeErr(w, http.StatusBadRequest, "q parametresi zorunlu")
		return
	}
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	matches, err := s.reader.SoftwareSearch(r.Context(), q, tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": q, "matches": matches, "device_count": len(matches)})
}

// handleActivity, süreç-içi tehdit/etkinlik sayaçlarını döner (konsol Genel Bakış
// etkinlik kartı). Süreç başından beri kümülatiftir (/metrics ile aynı kaynak).
func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request, adminID string) {
	// Sayaçlar süreç-geneldir (tüm kiracıların etkinliği): kiracıya bağlı çağırana VERİLMEZ
	// yalnız platform admini görür. Kiracılı yanıt boş sayaç + counters_omitted bayrağı taşır.
	ct, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	if ct != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"counters":         map[string]int64{},
			"counters_omitted": true,
			"uptime_seconds":   metrics.UptimeSeconds(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"counters":       metrics.Counters(),
		"uptime_seconds": metrics.UptimeSeconds(),
	})
}

// handleFeatures, dağıtımın koruma-duruşunu döner (ADMIN): hangi opsiyonel
// korumalar etkin, kaç tespit kuralı yüklü, /metrics açık mı. Yapılandırma
// görünürlüğü hassas olduğundan ADMIN gerekir.
func (s *Server) handleFeatures(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	out := map[string]any{}
	for k, v := range s.features {
		out[k] = v
	}
	out["detection_rules"] = len(s.detector.Load().Rules())
	out["metrics_enabled"] = s.metricsToken != ""
	writeJSON(w, http.StatusOK, map[string]any{"features": out})
}

// handleStream, Server-Sent Events (SSE) ile canlı değişiklik bildirimleri iletir.
// Konsol bunu Authorization başlıklı fetch akışı ile tüketir (token URL'de YER
// ALMAZ). Bildirim yalnız bir "değişti" tetikleyicisidir; konsol tazeler.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request, adminID string) {
	if s.stream == nil {
		writeErr(w, http.StatusNotImplemented, "canlı akış devre dışı")
		return
	}
	// Kiracı SUNUCU-TARAFI çözülür: kiracıya bağlı admin YALNIZ kendi kiracısının canlı
	// bildirimlerini alır (platform admini / boş kiracı → tümü). Çapraz-kiracı canlı-olay
	// sızıntısını önler.
	streamTenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	// eşzamanlı SSE bağlantısı üst sınırı (kaynak tükenmesini önle).
	if n := atomic.AddInt64(&s.sseConns, 1); n > maxSSEConns {
		atomic.AddInt64(&s.sseConns, -1)
		w.Header().Set("Retry-After", "10")
		writeErr(w, http.StatusServiceUnavailable, "eşzamanlı akış sınırı aşıldı")
		return
	}
	defer atomic.AddInt64(&s.sseConns, -1)

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "akış desteklenmiyor")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	ch, cancel := s.stream.Subscribe()
	defer cancel()
	fmt.Fprint(w, ": bağlandı\n\n")
	flusher.Flush()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	// Azami akış ömrü: WriteTimeout yokluğunu dengeler; süre dolunca kapat, istemci
	// (EventSource) otomatik yeniden bağlanır (bayat bağlantı birikimini önler).
	life := time.NewTimer(maxSSELifetime)
	defer life.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-life.C:
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n") // yorum satırı: bağlantıyı canlı tutar
			flusher.Flush()
		case n, ok := <-ch:
			if !ok {
				return
			}
			// Çok-tenant: kiracıya bağlı admin başka kiracının bildirimini görmez.
			if streamTenant != "" && n.TenantID != streamTenant {
				continue
			}
			b, err := json.Marshal(n)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

// handleVerifyAudit, denetim izi hash-zincirinin bütünlüğünü doğrular
// (ADMIN). Zincir sağlamsa 200 {valid:true}; kırıksa 200 {valid:false, error}.
func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request, adminID string) {
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleAdmin)) {
		return
	}
	if s.auditVerify == nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": true, "note": "doğrulayıcı yapılandırılmadı"})
		return
	}
	if err := s.auditVerify(r.Context()); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request, adminID string) {
	// denetim izi hassastır — OPERATOR+ gerekir.
	if respondErr(w, s.adminSvc.EnsureRole(r.Context(), adminID, admin.RoleOperator)) {
		return
	}
	tenant, err := s.callerTenant(r.Context(), adminID)
	if respondErr(w, err) {
		return
	}
	audit, err := s.reader.Audit(r.Context(), intParam(r, "limit"), tenant)
	if respondErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": audit})
}

// --- yardımcılar ---

func intParam(r *http.Request, name string) int {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

// maxRequestBody, admin API JSON gövdeleri için üst sınırdır. Kimliği
// doğrulanmış bir kullanıcının bile devasa gövde göndererek bellek tüketmesini
// (DoS) önler; 1 MiB tüm meşru yükler (politika kuralları, kural testi vb.) için
// fazlasıyla yeterlidir.
const maxRequestBody = 1 << 20 // 1 MiB

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "istek gövdesi çok büyük")
			return false
		}
		writeErr(w, http.StatusBadRequest, "geçersiz JSON")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// respondErr, admin servis hatasını uygun HTTP durumuna çevirir. Hata varsa
// yanıtı yazar ve true döner.
func respondErr(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, admin.ErrForbidden) {
		writeErr(w, http.StatusForbidden, "yetki yetersiz")
		return true
	}
	// Scope/ROE guardrail reddi bir YETKİ sonucudur (sunucu hatası değil): 403. İstemciye motor
	// gerekçesi (ROE kapsamı) sızdırılmaz; ayrıntı admin servisinin audit/log kaydındadır.
	if errors.Is(err, admin.ErrOutOfScope) {
		writeErr(w, http.StatusForbidden, "operasyon scope/ROE kapsamı dışı")
		return true
	}
	if errors.Is(err, admin.ErrInvalidRule) {
		writeErr(w, http.StatusBadRequest, "geçersiz kural")
		return true
	}
	if errors.Is(err, admin.ErrInvalidInput) {
		writeErr(w, http.StatusBadRequest, "geçersiz girdi")
		return true
	}
	if errors.Is(err, adminread.ErrInvalidCustodyAction) {
		writeErr(w, http.StatusBadRequest, "geçersiz gözetim eylemi")
		return true
	}
	if errors.Is(err, adminread.ErrArtifactNotFound) {
		writeErr(w, http.StatusNotFound, "artefakt bulunamadı")
		return true
	}
	if errors.Is(err, iam.ErrUserNotFound) {
		writeErr(w, http.StatusNotFound, "SCIM kullanıcısı bulunamadı")
		return true
	}
	if errors.Is(err, iam.ErrUserExists) {
		writeErr(w, http.StatusConflict, "SCIM kullanıcısı zaten var")
		return true
	}
	writeErr(w, http.StatusInternalServerError, "işlem başarısız")
	return true
}
