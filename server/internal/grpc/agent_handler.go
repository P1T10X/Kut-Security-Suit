package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"kut.corp/suite/cmdenvelope"
	kutv1 "kut.corp/suite/gen/kut/v1"
	"kut.corp/suite/server/internal/aibrain"
	"kut.corp/suite/server/internal/correlate"
	"kut.corp/suite/server/internal/detbits"
	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/detectpipe"
	"kut.corp/suite/server/internal/entitygraph"
	"kut.corp/suite/server/internal/ioc"
	"kut.corp/suite/server/internal/metrics"
	"kut.corp/suite/server/internal/mitre"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/notify"
	"kut.corp/suite/server/internal/response"
	"kut.corp/suite/server/internal/rollout"
	"kut.corp/suite/server/internal/threshold"
)

// DeviceRegistry, cihaz durumu ve politika sürümü için sunucu-tarafı depolamadır.
type DeviceRegistry interface {
	// TouchHeartbeat, last_seen ve metrikleri günceller; cihazın SUNUCUDAKI
	// geçerli politika sürümünü döner.
	TouchHeartbeat(ctx context.Context, deviceID, agentVersion, osVersion string, at time.Time) (currentPolicyVersion string, err error)
	// TenantForDevice, cihazın SUNUCU-TARAFI bağlı kiracısını döner (enrollment'ta atanır;
	// çok-tenant izolasyonu). Boş → tek-tenant (çağıran sunucu kiracısına düşer). Kimlik
	// mTLS ile doğrulanmış deviceID'den okunur — client kiracıyı belirleyemez.
	TenantForDevice(ctx context.Context, deviceID string) (string, error)
	// PendingCommands, cihaz için bekleyen komutları döner (karantina vb.).
	PendingCommands(ctx context.Context, deviceID string) ([]*kutv1.Command, error)
	// AckCommands, ajanın heartbeat'te bildirdiği (yürütmeyi tamamladığı) komutları
	// ONAYLANMIŞ işaretler — en-az-bir-kez teslimde yeniden-teslimi durdurur.
	AckCommands(ctx context.Context, deviceID string, commandIDs []string) error
	// RecordAgentBinary, ajanın bildirdiği ikili SHA-256'sını kaydeder ve KURCALAMA
	// sinyali döner: saklı hash boş değilse, SÜRÜM değişmediği hâlde hash değişmişse
	// (takas/yamalanmış ikili) tampered=true. hash boşsa (öz-tasdik yok) no-op.
	RecordAgentBinary(ctx context.Context, deviceID, version, hash string) (tampered bool, err error)
	// ApplyCommandResults, ajanın bildirdiği komut YÜRÜTME sonuçlarını işler: başarılı
	// bir QUARANTINE/UNQUARANTINE sonucunda cihazın EFFECTIVE durumunu günceller
	// (desired→effective). Başarısız/ilgisiz sonuçlar durum değiştirmez. Best-effort.
	ApplyCommandResults(ctx context.Context, deviceID string, outcomes []model.CommandOutcome) error
}

// EventSink, gelen olayları kalıcılaştırır ve kabul edilen son sırayı döner.
type EventSink interface {
	SaveEvents(ctx context.Context, deviceID string, evs []model.Event) (lastAccepted uint64, err error)
}

// PolicyProvider, cihaza atanmış geçerli politika paketini üretir.
type PolicyProvider interface {
	// CurrentPolicy, cihazın geçerli politika paketini döner. Cihaza politika
	// atanmamışsa (nil, nil) döner.
	CurrentPolicy(ctx context.Context, deviceID string) (*kutv1.PolicyBundle, error)
}

// UpdateProvider, cihaz için geçerli OTA güncelleme manifestosunu döner.
type UpdateProvider interface {
	// LatestUpdate, platforma uygun en güncel sürümü döner. Güncelleme yoksa
	// (nil, nil). Dönen manifesto İMZALIDIR (imza DB'de saklanır).
	LatestUpdate(ctx context.Context, deviceID, currentAgentVersion, platform string) (*kutv1.UpdateManifest, error)
}

// PolicyNotifier, açık politika akışlarını politika değişince uyandırır.
type PolicyNotifier interface {
	Subscribe(deviceID string) (<-chan struct{}, func())
}

// noopNotifier, notifier verilmediğinde kullanılır: hiç bildirim üretmez, akış
// yalnız ilk paketi gönderip istemci kapatana dek bekler.
type noopNotifier struct{}

func (noopNotifier) Subscribe(string) (<-chan struct{}, func()) {
	return make(chan struct{}), func() {}
}

// AdminNotifier, ajan-kaynaklı değişiklikleri admin konsoluna (SSE) iletmek için
// yayınlanır. nil verilmezse noop kullanılır; SSE bağımlılığı zorunlu değildir.
type AdminNotifier interface {
	PublishEvent(deviceID, severity, message string)
	PublishDevice(deviceID string)
}

// AdminTenantNotifier, kiracı-atıflı yayını destekleyen OPSİYONEL arayüzdür (çok-tenant
// veri-düzlemi). AdminNotifier'ı bozmadan (type-assert ile) eklenir: eventbus.Bus bunu
// karşılar; karşılamayan implementer'lar kiracısız yola düşer. Kiracı SUNUCU-TARAFI bağlanır.
type AdminTenantNotifier interface {
	PublishTenantEvent(tenant, deviceID, severity, message string)
	PublishTenantDevice(tenant, deviceID string)
}

// publishEvent, admin notifier kiracı-farkındaysa kiracı-atıflı, değilse klasik yayınlar.
func (h *AgentHandler) publishEvent(tenant, deviceID, severity, message string) {
	if tn, ok := h.admin.(AdminTenantNotifier); ok {
		tn.PublishTenantEvent(tenant, deviceID, severity, message)
		return
	}
	h.admin.PublishEvent(deviceID, severity, message)
}

// publishDevice, publishEvent'in cihaz-durumu karşılığıdır.
func (h *AgentHandler) publishDevice(tenant, deviceID string) {
	if tn, ok := h.admin.(AdminTenantNotifier); ok {
		tn.PublishTenantDevice(tenant, deviceID)
		return
	}
	h.admin.PublishDevice(deviceID)
}

// noopAdminNotifier, admin notifier verilmediğinde kullanılır.
type noopAdminNotifier struct{}

func (noopAdminNotifier) PublishEvent(string, string, string) {}
func (noopAdminNotifier) PublishDevice(string)                {}

// noopAlerter, dış uyarı yapılandırılmadığında kullanılır (hiçbir şey yapmaz).
type noopAlerter struct{}

func (noopAlerter) Notify(notify.Alert) {}

// AutoResponder, kritik olaylara otomatik müdahale eder (ör. karantina). nil ise
// noop kullanılır (otomatik müdahale kapalı).
type AutoResponder interface {
	AutoQuarantine(ctx context.Context, deviceID, reason string) error
}

// noopResponder, otomatik müdahale yapılandırılmadığında kullanılır.
type noopResponder struct{}

func (noopResponder) AutoQuarantine(context.Context, string, string) error { return nil }

// AgentHandler, AgentService gRPC sunucusunu uygular.
type AgentHandler struct {
	kutv1.UnimplementedAgentServiceServer
	devices       DeviceRegistry
	events        EventSink
	policies      PolicyProvider
	updates       UpdateProvider
	notifier      PolicyNotifier
	admin         AdminNotifier
	alerter       notify.Notifier
	responder     AutoResponder
	detector      atomic.Pointer[detect.Engine] // tespit motoru (canlı hot-reload için atomik)
	correlator    *correlate.Correlator         // olay korelasyonu (nil = gruplama/bastırma yok)
	chain         *correlate.ChainDetector      // çok-sinyal korelasyon (nil = kapalı)
	threshold     *threshold.Gate               // tekrar-eşiği kapısı (kural bazlı brute-force/tarama)
	detbits       *detbits.Store                // çok-aşamalı tespit durum bitleri (flowbits/xbits)
	iocSet        atomic.Pointer[ioc.Set]       // tehdit istihbaratı göstergeleri (nil = kapalı; canlı hot-reload için atomik)
	artifacts     ArtifactSink                  // adli/IR dosya toplama deposu
	graph         *entitygraph.Graph            // varlık/tehdit grafı — olaylardan kenar besler (nil = kapalı)
	seqModel      *aibrain.SeqModels            // kiracı-bölümlü süreç-zinciri sekans nadirlik modeli — canlı öğrenir (nil = kapalı)
	observer      ProcessedObserver             // yalnızca-export tap (nil = kapalı); tespit+kapı SONRASI beslenir
	tenant        string                        // sunucu-tarafı kiracı (KUT_TENANT_ID); olaylara atanır (boş = tek-tenant)
	tenantEnforce bool                          // sıkı çok-tenant: kiracısız cihazın olaylarını reddet (INV-044)
	now           func() time.Time
}

// SetTenant, bu sunucunun kiracı kimliğini ayarlar (sunucu-tarafı bağlama). Ayarlıysa,
// kimlik-doğrulanmış cihazlardan gelen olaylar bu kiracıyla atıflanır (asla client'tan).
// Boş → tek-tenant (Notice.TenantID boş kalır). Gerçek çok-tenant'ta ileride cihaz-başına çözülür.
func (h *AgentHandler) SetTenant(t string) { h.tenant = t }

// SetTenantEnforce, sıkı çok-tenant zorlamasını açar/kapatır. Açıkken, kiracıya bağlı
// olmayan bir cihazın olayları reddedilir (sunucu-varsayılana düşmez; INV-044 missing→DENY).
func (h *AgentHandler) SetTenantEnforce(on bool) { h.tenantEnforce = on }

// SetEntityGraph, varlık/tehdit grafını bağlar. Bağlıysa ProcessEvent, olaylardan
// (DNS→alan, bağlantı→IP) cihaz-merkezli kenarlar besler (pivot/hunting temeli).
func (h *AgentHandler) SetEntityGraph(g *entitygraph.Graph) { h.graph = g }

// SetSeqModel, süreç-zinciri sekans nadirlik modelini bağlar. Bağlıysa PROCESS
// olaylarındaki soyağacı (root→leaf) taban çizgisi olarak PASİF öğrenilir; skorlama
// analist tarafından salt-okunur sorgulanır (otomatik alarm yok → gürültü yok).
func (h *AgentHandler) SetSeqModel(m *aibrain.SeqModels) { h.seqModel = m }

// Ajan-kontrollü dizgelerin graf/sekans modeline girişindeki SERT sınırlar:
// bir cihaz sınırsız uzun ya da sınırsız derin zincirle belleği şişiremez. Kiracı başına toplam
// düğüm/kenar tavanı ve LRU/TTL tahliyesi entitygraph/aibrain içinde uygulanır.
const (
	maxGraphStringLen = 256 // alan adı / IP / süreç adı azami uzunluğu (bayt)
	maxParentChain    = 32  // işlenen azami parent_chain derinliği
)

// graphStr, grafa girecek ajan-kontrollü bir dizgeyi doğrular: boş ya da aşırı uzunsa false
// (gözlem atlanır ve sayılır).
func graphStr(s string) bool {
	if s == "" {
		return false
	}
	if len(s) > maxGraphStringLen {
		metrics.AddGraphFeedDropped(1)
		return false
	}
	return true
}

// observeGraph, bir olayın yapılandırılmış Details alanlarından varlık grafına
// güvenilir kenarlar ekler: DNS olayı → cihaz→alan (Resolved), ağ bağlantısı →
// cihaz→IP (Connected). Bilinmeyen/eksik alanlar sessizce atlanır (best-effort).
func (h *AgentHandler) observeGraph(deviceID string, e model.Event) {
	if (h.graph == nil && h.seqModel == nil) || deviceID == "" || e.Details == "" {
		return
	}
	var d map[string]any
	if json.Unmarshal([]byte(e.Details), &d) != nil {
		return
	}
	if h.graph != nil {
		// Düğümler olayın kiracısıyla etiketlenir (çok-kiracılı graf izolasyonu):
		// e.TenantID sunucu-tarafı damgalıdır (cihazdan), böylece kenarlar kiracı
		// sınırını geçmez ve pivot/anomali yalnız çağıranın kiracısını görür.
		dev := entitygraph.Node{Kind: entitygraph.Device, ID: deviceID, Tenant: e.TenantID}
		if s, ok := d["domain"].(string); ok && graphStr(s) {
			h.graph.ObserveBy(deviceID, dev, entitygraph.Node{Kind: entitygraph.Domain, ID: s, Tenant: e.TenantID}, entitygraph.Resolved, e.OccurredAt)
		}
		if s, ok := d["remote_ip"].(string); ok && graphStr(s) {
			h.graph.ObserveBy(deviceID, dev, entitygraph.Node{Kind: entitygraph.IP, ID: s, Tenant: e.TenantID}, entitygraph.Connected, e.OccurredAt)
		}
	}
	// Süreç soyağacı: PROCESS olayının process + parent_chain (en yakın ata önce).
	// Grafa ChildOf (çocuk→ebeveyn) kenarları — "bu süreç neyi başlattı?" (Sources) /
	// "ebeveyni ne?" (Targets) pivotları. Ayrıca root→leaf zinciri sekans nadirlik
	// modeline PASİF öğrenilir (taban çizgisi; skorlama analistçe salt-okunur sorgulanır).
	proc, ok := d["process"].(string)
	if !ok || !graphStr(proc) {
		return
	}
	chainRaw, ok := d["parent_chain"].([]any)
	if !ok {
		return
	}
	if len(chainRaw) > maxParentChain { // derinlik tavanı: yalnız en yakın atalar işlenir
		metrics.AddGraphFeedDropped(len(chainRaw) - maxParentChain)
		chainRaw = chainRaw[:maxParentChain]
	}
	ancestors := make([]string, 0, len(chainRaw)) // en yakın ata önce
	child := proc
	for _, pa := range chainRaw {
		parent, ok := pa.(string)
		if !ok || !graphStr(parent) {
			continue
		}
		if h.graph != nil {
			h.graph.ObserveBy(deviceID,
				entitygraph.Node{Kind: entitygraph.Process, ID: child, Tenant: e.TenantID},
				entitygraph.Node{Kind: entitygraph.Process, ID: parent, Tenant: e.TenantID},
				entitygraph.ChildOf, e.OccurredAt)
		}
		ancestors = append(ancestors, parent)
		child = parent
	}
	if h.seqModel != nil && len(ancestors) > 0 {
		// root→leaf sıralı zinciri kur (ata→...→süreç) ve taban çizgisine öğren.
		lineage := make([]string, 0, len(ancestors)+1)
		for i := len(ancestors) - 1; i >= 0; i-- {
			lineage = append(lineage, ancestors[i])
		}
		lineage = append(lineage, proc)
		h.seqModel.Observe(e.TenantID, lineage) // kiracı-bölümlü taban çizgisi (e.TenantID sunucu-damgalı)
	}
}

// ArtifactSink, ajanın topladığı dosya artefaktlarını saklar (adli/IR).
type ArtifactSink interface {
	SaveArtifact(ctx context.Context, deviceID, commandID, path, sha256 string, content []byte) (string, error)
}

type noopArtifactSink struct{}

func (noopArtifactSink) SaveArtifact(context.Context, string, string, string, string, []byte) (string, error) {
	return "", nil
}

// SetArtifactSink, dosya-toplama depolamasını etkinleştirir. Ayarlanmazsa
// yüklenen artefaktlar sessizce yok sayılır (noop).
func (h *AgentHandler) SetArtifactSink(a ArtifactSink) {
	if a == nil {
		a = noopArtifactSink{}
	}
	h.artifacts = a
}

// maxArtifactBytes, tek bir toplanan dosyanın üst sınırıdır (gRPC mesaj sınırı +
// depolama şişmesi koruması). Bundan büyük yüklemeler reddedilir.
const maxArtifactBytes = 3 << 20 // 3 MiB

// UploadArtifact, ajanın COLLECT_FILE komutuyla topladığı dosyayı saklar. Kimlik
// istemci sertifikasından; boyut ve SHA-256 doğrulanır.
func (h *AgentHandler) UploadArtifact(ctx context.Context, req *kutv1.UploadArtifactRequest) (*kutv1.UploadArtifactResponse, error) {
	deviceID, err := DeviceIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "kimlik doğrulanamadı")
	}
	content := req.GetContent()
	if len(content) == 0 {
		return nil, status.Error(codes.InvalidArgument, "boş içerik")
	}
	if len(content) > maxArtifactBytes {
		return nil, status.Errorf(codes.InvalidArgument, "dosya çok büyük (>%d bayt)", maxArtifactBytes)
	}
	sum := sha256.Sum256(content)
	if got := hex.EncodeToString(sum[:]); req.GetSha256() != "" && got != req.GetSha256() {
		return nil, status.Error(codes.InvalidArgument, "SHA-256 uyuşmuyor")
	}
	if _, err := h.artifacts.SaveArtifact(ctx, deviceID, req.GetCommandId(), req.GetPath(), hex.EncodeToString(sum[:]), content); err != nil {
		return nil, status.Error(codes.Internal, "artefakt kaydedilemedi")
	}
	return &kutv1.UploadArtifactResponse{Ok: true}, nil
}

// SetIoCSet, tehdit istihbaratı (IoC) eşleştirmesini etkinleştirir/günceller. nil
// ise kapalı. Atomik saklama sayesinde ingest yolu eşzamanlı okurken canlı olarak
// (yeniden başlatmadan) güncellenebilir — hot-reload.
func (h *AgentHandler) SetIoCSet(s *ioc.Set) { h.iocSet.Store(s) }

// SetDetector, sunucu-taraflı tespit kural motorunu ayarlar/günceller. nil ise
// yerleşik varsayılan kural seti kullanılır. Atomik saklama sayesinde ingest
// yolu eşzamanlı değerlendirirken canlı (yeniden başlatmadan) güncellenebilir.
func (h *AgentHandler) SetDetector(e *detect.Engine) {
	if e == nil {
		e = detect.NewEngine(nil)
	}
	h.detector.Store(e)
}

// SetCorrelator, olay korelasyonunu (incident gruplama + alarm-fırtınası bastırma)
// etkinleştirir. nil ise her tespit ayrı alarm üretir (eski davranış).
func (h *AgentHandler) SetCorrelator(c *correlate.Correlator) { h.correlator = c }

// SetChainDetector, çok-sinyal (multi-signal) korelasyonu etkinleştirir: aynı
// cihazda kısa pencerede birden çok FARKLI sinyal → yüksek-güvenli zincir uyarısı.
func (h *AgentHandler) SetChainDetector(c *correlate.ChainDetector) { h.chain = c }

// SetThresholdGate, kural-bazlı tekrar-eşiği kapısını ayarlar. nil verilirse
// varsayılan (time.Now saatli) kapı kurulur — eşik tanımlı kurallar yine çalışır.
// Eşik durumu motorun DIŞINDA tutulduğundan detektör hot-reload'ları sayacı bozmaz.
func (h *AgentHandler) SetThresholdGate(g *threshold.Gate) {
	if g == nil {
		g = threshold.New(h.now)
	}
	h.threshold = g
}

// SetBitStore, çok-aşamalı tespit bit deposunu ayarlar. nil verilirse varsayılan
// (time.Now saatli) depo kurulur. Bit durumu motor DIŞINDA tutulur — detektör
// hot-reload'ları çok-aşamalı ilerlemeyi bozmaz.
func (h *AgentHandler) SetBitStore(s *detbits.Store) {
	if s == nil {
		s = detbits.New(h.now)
	}
	h.detbits = s
}

// scopeKey, Track'e göre kapsam anahtarı üretir (eşik sayacı ve tespit bitleri
// bu ortak kapsamlamayı paylaşır).
// scopeKey, bastırma-kapısı kapsam anahtarı için detectpipe.ScopeKey'in yerel
// adıdır (tek kaynak orada; grpc testleri bu adı kullanmaya devam eder).
var scopeKey = detectpipe.ScopeKey

// SetAlerter, yüksek önem düzeyli olaylarda dış uyarı (webhook) gönderimini
// etkinleştirir. nil ise noop kalır (uyarı gönderilmez).
func (h *AgentHandler) SetAlerter(a notify.Notifier) {
	if a == nil {
		a = noopAlerter{}
	}
	h.alerter = a
}

// SetAutoResponder, kritik olaylara otomatik müdahaleyi (karantina) etkinleştirir.
// nil ise noop kalır (otomatik müdahale kapalı — güvenli varsayılan).
func (h *AgentHandler) SetAutoResponder(r AutoResponder) {
	if r == nil {
		r = noopResponder{}
	}
	h.responder = r
}

// SetAdminNotifier, admin-tarafı SSE yayınını etkinleştirir. nil ise noop kalır.
func (h *AgentHandler) SetAdminNotifier(n AdminNotifier) {
	if n == nil {
		n = noopAdminNotifier{}
	}
	h.admin = n
}

// NewAgentHandler oluşturur. notifier nil ise anlık push devre dışıdır (akış
// yalnız ilk paketi gönderir ve istemci kapatana dek açık kalır).
func NewAgentHandler(devices DeviceRegistry, events EventSink, policies PolicyProvider, updates UpdateProvider, notifier PolicyNotifier) *AgentHandler {
	if notifier == nil {
		notifier = noopNotifier{}
	}
	h := &AgentHandler{devices: devices, events: events, policies: policies, updates: updates, notifier: notifier, admin: noopAdminNotifier{}, alerter: noopAlerter{}, responder: noopResponder{}, artifacts: noopArtifactSink{}, now: time.Now}
	h.detector.Store(detect.NewEngine(nil)) // atomik alan literal'de saklanamaz; kurulumda varsayılan
	h.threshold = threshold.New(h.now)      // eşik kapısı daima hazır (eşiksiz kurallar etkilenmez)
	h.detbits = detbits.New(h.now)          // bit deposu daima hazır (bitsiz kurallar etkilenmez)
	return h
}

// Heartbeat, yaşam sinyalini işler. Yanıt SUNUCU SAATİNİ taşır — ajan, politika
// zaman pencerelerini bu çıpaya göre değerlendirir.
func (h *AgentHandler) Heartbeat(ctx context.Context, req *kutv1.HeartbeatRequest) (*kutv1.HeartbeatResponse, error) {
	deviceID, err := DeviceIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "kimlik doğrulanamadı")
	}
	now := h.now()

	agentVersion, osVersion := "", ""
	if id := req.GetIdentity(); id != nil {
		agentVersion = id.GetAgentVersion()
		osVersion = id.GetOsVersion()
	}

	serverPolicyVersion, err := h.devices.TouchHeartbeat(ctx, deviceID, agentVersion, osVersion, now)
	if err != nil {
		return nil, status.Error(codes.Internal, "heartbeat kaydedilemedi")
	}
	// Konsola canlı: cihaz görüldü. Bildirim CİHAZIN kiracısına atfedilir — sunucu
	// varsayılan kiracısına DEĞİL: aksi halde B kiracısının cihaz canlılığı "default" abonelerine
	// sızar ve B'nin kendi konsolu bildirimi hiç almaz. Kiracı çözülemezse (hata ya da zorlama
	// açıkken kiracısız cihaz) bildirim YAYINLANMAZ (fail-closed); heartbeat'i etkilemez.
	if nt, ok := h.noticeTenant(ctx, deviceID); ok {
		h.publishDevice(nt, deviceID)
	}

	// Öz-tasdik: ajanın ikili hash'i sürüm değişmeden değiştiyse (takas/yama)
	// KRİTİK kurcalama olayı üret. Best-effort; heartbeat'i kesmez.
	if bh := req.GetBinaryHash(); bh != "" {
		if tampered, terr := h.devices.RecordAgentBinary(ctx, deviceID, agentVersion, bh); terr == nil && tampered {
			// Sunucu-üretilen kurcalama olayına cihazın kiracısını ata (nadir yol → lookup ucuz).
			evTenant, _ := h.devices.TenantForDevice(ctx, deviceID)
			if evTenant == "" {
				evTenant = h.tenant
			}
			ev := model.Event{
				Category: "SECURITY", Severity: "CRITICAL",
				TenantID:   evTenant,
				Message:    "ajan ikilisi sürüm değişmeden değişti — olası kurcalama/takas (öz-tasdik)",
				OccurredAt: now,
				Details:    `{"self_attestation":true,"binary_hash":"` + bh + `","agent_version":"` + agentVersion + `"}`,
			}
			_, _ = h.events.SaveEvents(ctx, deviceID, []model.Event{ev})
			h.publishEvent(evTenant, deviceID, ev.Severity, ev.Message)
			metrics.IncAlertRaised()
			h.alerter.Notify(notify.Alert{
				DeviceID: deviceID, Category: ev.Category, Severity: ev.Severity,
				Message: ev.Message, OccurredAt: now,
				TechniqueID: "T1554", TechniqueName: "Compromise Host Software Binary", Tactic: "Persistence",
			})
		}
	}
	// Ajanın onayladığı komutları (yürütmesi tamamlanan) işaretle — bunlar artık
	// yeniden teslim edilmez. PendingCommands'tan ÖNCE yapılır ki bu heartbeat'te
	// onaylanan bir komut yeniden gönderilmesin (best-effort; hata olay-alımını kesmez).
	if acked := req.GetAckedCommandIds(); len(acked) > 0 {
		_ = h.devices.AckCommands(ctx, deviceID, acked)
	}
	// Komut YÜRÜTME sonuçları (SUCCESS/FAILED) — effective-state geçişi. ACK'ten
	// (yalnız teslim) ayrı; başarılı karantina cihazın gerçekten izole olduğunu gösterir.
	if crs := req.GetCommandResults(); len(crs) > 0 {
		outs := make([]model.CommandOutcome, 0, len(crs))
		for _, cr := range crs {
			outs = append(outs, model.CommandOutcome{
				CommandID: cr.GetCommandId(),
				Type:      commandTypeName(cr.GetCommandType()),
				OK:        cr.GetStatus() == kutv1.CommandStatus_COMMAND_STATUS_SUCCEEDED,
			})
		}
		_ = h.devices.ApplyCommandResults(ctx, deviceID, outs)
	}
	cmds, err := h.devices.PendingCommands(ctx, deviceID)
	if err != nil {
		return nil, status.Error(codes.Internal, "komutlar alınamadı")
	}

	return &kutv1.HeartbeatResponse{
		ServerTime:            timestamppb.New(now),
		PolicyUpdateAvailable: serverPolicyVersion != "" && serverPolicyVersion != req.GetCurrentPolicyVersion(),
		PendingCommands:       cmds,
	}, nil
}

// noticeTenant, bir cihaz bildiriminin (SSE) atfedileceği kiracıyı SUNUCU-TARAFI çözer:
// cihazın kayıtlı kiracısı; kayıtsız/legacy cihazda sunucu varsayılanı — YALNIZ zorlama
// kapalıyken. Arama hatası ya da zorlama açıkken kiracısız cihaz → ok=false (yayınlama).
func (h *AgentHandler) noticeTenant(ctx context.Context, deviceID string) (string, bool) {
	t, err := h.devices.TenantForDevice(ctx, deviceID)
	if err != nil {
		return "", false
	}
	if t != "" {
		return t, true
	}
	if h.tenantEnforce {
		return "", false
	}
	return h.tenant, true
}

// commandTypeName, proto komut tipini kuyruk-türü string'ine çevirir (EnqueueCommand
// ile aynı adlar). Yalnız effective-state ile ilgili tipler adlandırılır; diğerleri "".
func commandTypeName(t kutv1.Command_CommandType) string {
	switch t {
	case kutv1.Command_COMMAND_TYPE_QUARANTINE:
		return cmdenvelope.TypeQuarantine
	case kutv1.Command_COMMAND_TYPE_UNQUARANTINE:
		return cmdenvelope.TypeUnquarantine
	case kutv1.Command_COMMAND_TYPE_LOCK:
		return cmdenvelope.TypeLock
	case kutv1.Command_COMMAND_TYPE_RESTART:
		return cmdenvelope.TypeRestart
	case kutv1.Command_COMMAND_TYPE_WIPE:
		return cmdenvelope.TypeWipe
	default:
		return ""
	}
}

// ReportEvents, olay akışını alır (store-and-forward), kalıcılaştırır ve kabul
// edilen son sıra numarasını döner; ajan yalnız onaylananları tamponundan siler.
func (h *AgentHandler) ReportEvents(stream kutv1.AgentService_ReportEventsServer) error {
	deviceID, err := DeviceIDFromContext(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, "kimlik doğrulanamadı")
	}
	// Cihazın kiracısını SUNUCU-TARAFI çöz (mTLS ile doğrulanmış deviceID'den; akış başına
	// bir kez, uzun-ömürlü akışta amortize ucuz). Boşsa ProcessEvent sunucu kiracısına düşer.
	deviceTenant, _ := h.devices.TenantForDevice(stream.Context(), deviceID)

	var lastAccepted uint64
	autoTriggered := false // akış başına en çok bir kez otomatik karantina
	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&kutv1.EventAck{LastAcceptedSequence: lastAccepted})
		}
		if err != nil {
			return err
		}
		// Etkin kiracı: cihazın kiracısı, yoksa sunucu-varsayılan. Olaylara SAVE'DEN ÖNCE
		// damgalanır → hem event_logs (çekirdek depo) hem downstream (data-plane) tenant-atıflı.
		effTenant := deviceTenant
		if effTenant == "" {
			// Sıkı çok-tenant: kiracısız cihazı sunucu-varsayılana atıflama — REDDET (INV-044).
			if h.tenantEnforce {
				return status.Error(codes.FailedPrecondition, "kiracı zorunlu: cihaz bir kiracıya bağlı değil")
			}
			effTenant = h.tenant
		}
		domainEvents := make([]model.Event, 0, len(batch.GetEvents()))
		for _, e := range batch.GetEvents() {
			domainEvents = append(domainEvents, model.Event{
				Sequence:   e.GetSequence(),
				TenantID:   effTenant,
				Category:   dbCategory(e.GetCategory()),
				Severity:   dbSeverity(e.GetSeverity()),
				Message:    e.GetMessage(),
				OccurredAt: e.GetOccurredAt().AsTime(),
				Details:    detailsJSON(e.GetDetails()),
			})
		}
		acc, err := h.events.SaveEvents(stream.Context(), deviceID, domainEvents)
		if err != nil {
			return status.Error(codes.Internal, "olaylar kaydedilemedi")
		}
		metrics.AddEventsIngested(len(domainEvents))
		for _, e := range domainEvents {
			h.ProcessEvent(stream.Context(), deviceID, e) // olaylar zaten effTenant ile damgalı
		}
		// Otomatik müdahale (SOAR): kritik olay geldiyse cihazı otomatik karantinaya
		// al (akış başına bir kez; noop responder'da maliyetsiz). Hata olay-alımını
		// KESMEZ (best-effort; komut kuyruğu kalıcıdır).
		if !autoTriggered {
			if reason, ok := response.ShouldTrigger(domainEvents); ok {
				if err := h.responder.AutoQuarantine(stream.Context(), deviceID, reason); err == nil {
					autoTriggered = true
					metrics.IncAutoQuarantine()
					h.publishDevice(effTenant, deviceID) // konsol durumu tazelesin (cihazın kiracısına atıflı)
				}
			}
		}
		if acc > lastAccepted {
			lastAccepted = acc
		}
	}
}

// ProcessedObserver, bir olayı tespit + bastırma-kapısı BİTTİKTEN sonra alan
// gözlemcidir: kanonik olay + kapıdan geçen (admitted) tespitler. Telemetri
// düzleminin yalnızca-export tap'i bunu uygular. Gözlemci ASLA kendisi tespit
// veya gate çalıştırmamalıdır — bu sorumluluk tek sahipli olarak burada kalır.
type ProcessedObserver interface {
	ObserveProcessed(ctx context.Context, deviceID string, e model.Event, admitted []detect.Detection)
}

// SetProcessedObserver, yalnızca-export tap'ini bağlar (opsiyonel; nil = export yok).
// Wiring sırasında, herhangi bir listener başlamadan önce ayarlanır (race-free).
func (h *AgentHandler) SetProcessedObserver(o ProcessedObserver) { h.observer = o }

// processEvent, tek bir olayı sunucu-taraflı tespit + alarm hattından geçirir:
// konsol push → kural değerlendirme → çok-aşama bitleri (Require/RequireNot/Set) →
// tekrar-eşiği → korelasyon → alarm/zincir → IoC. Hem gRPC ajan yolu (ReportEvents)
// hem HTTP log-ingest yolu (adminapi.EventProcessor) BU metodu paylaşır; durumlu
// bileşenler (threshold.Gate/detbits.Store/correlate) tek örnek olduğundan log ve
// ajan olayları aynı pencereleri/sayaçları görür. ctx, çağıranın bağlamıdır (gRPC
// akışı ya da HTTP isteği).
func (h *AgentHandler) ProcessEvent(ctx context.Context, deviceID string, e model.Event) {
	// Sunucu-tarafı kiracı bağlama: olay kiracı taşımıyorsa bu sunucunun kiracısını ata
	// (kimlik-doğrulanmış bağlam; asla client'tan). Downstream (bus→ingest, bit/eşik kapsamı)
	// böylece kiracı-atıflı olur.
	if e.TenantID == "" && h.tenant != "" {
		e.TenantID = h.tenant
	}
	h.publishEvent(e.TenantID, deviceID, e.Severity, e.Message) // konsola canlı push (kiracı-atıflı)
	h.observeGraph(deviceID, e)                                 // varlık/tehdit grafını besle (nil'de no-op)
	// Sunucu-taraflı tespit: kural eşleşirse ADLANDIRILMIŞ, normalize önem
	// düzeyli + MITRE bağlamlı uyarı üret (ham olayın yerine geçer). Eşleşme
	// yoksa jenerik yol: ham önem düzeyi + MITRE sınıflandırması. Uyarı
	// best-effort; eşik/filtre notifier içinde. noop notifier'da maliyetsiz.
	var admitted []detect.Detection // kapıdan geçen/alarma dönen tespitler — export tap'ine verilir
	// raise, bir alarmı HEM operatör yoluna (notify) HEM export tap'ine (admitted)
	// gönderir; d, alarmın tap'teki sentetik tespit karşılığıdır. Böylece IoC ve
	// zincir alarmları da SIEM'e finding olarak gider (konsol/webhook ile parite,
	// ADR-0040). Jenerik eşleşmesiz olay buradan GEÇMEZ — o ham olay zaten EventSink
	// ile export edilir; finding'e çevirmek her olayı alarm yapardı.
	raise := func(a notify.Alert, d detect.Detection) {
		metrics.IncAlertRaised()
		h.alerter.Notify(a)
		admitted = append(admitted, d)
	}
	if dets := h.detector.Load().Evaluate(e); len(dets) > 0 { // atomik Load: hot-reload ile yarışsız
		metrics.AddDetections(len(dets))
		// Bastırma kapıları (bitler + tekrar-eşiği + korelasyon) PAYLAŞILAN
		// detectpipe.Gate'te — gRPC ajan, HTTP log-ingest ve telemetri düzlemi
		// AYNI durumsal örnekleri görür; hiçbir yol diğerinin bastıracağı alarmı
		// üretemez. Gate aynı pointer'ları sarar, durum paylaşılır.
		gate := detectpipe.NewGate(h.threshold, h.detbits, h.correlator)
		for _, d := range dets {
			if !gate.Admit(ctx, deviceID, e, d) {
				continue // kapı bastırdı (ilgili metrik gate içinde artırıldı)
			}
			admitted = append(admitted, d)
			metrics.IncAlertRaised()
			h.alerter.Notify(notify.Alert{
				DeviceID:      deviceID,
				Category:      e.Category,
				Severity:      d.Severity,
				Message:       "[" + d.RuleName + "] " + e.Message,
				OccurredAt:    e.OccurredAt,
				TechniqueID:   d.Technique.ID,
				TechniqueName: d.Technique.Name,
				Tactic:        d.Technique.Tactic,
			})
			// Çok-sinyal korelasyon: farklı kill-chain sinyalleri birikirse
			// yüksek-güvenli zincir uyarısı üret (tek tespitten daha güçlü kanıt).
			if h.chain != nil {
				sig := d.Technique.Tactic
				if sig == "" {
					sig = d.Technique.ID
				}
				if sig == "" {
					sig = e.Category
				}
				if fired, signals := h.chain.Observe(deviceID, sig, e.OccurredAt); fired {
					metrics.IncChainFired()
					raise(notify.Alert{
						DeviceID:   deviceID,
						Category:   "SECURITY",
						Severity:   "CRITICAL",
						Message:    "yüksek-güvenli saldırı zinciri (çok-sinyal): " + strings.Join(signals, " + "),
						OccurredAt: e.OccurredAt,
					}, detect.Detection{
						RuleID: "chain", RuleName: "attack-chain", Severity: "CRITICAL",
						Technique: d.Technique, // zinciri tetikleyen son sinyalin tekniği
					})
				}
			}
		}
	} else {
		al := notify.Alert{
			DeviceID:   deviceID,
			Category:   e.Category,
			Severity:   e.Severity,
			Message:    e.Message,
			OccurredAt: e.OccurredAt,
		}
		if tq, ok := mitre.Classify(e.Category, e.Message); ok {
			al.TechniqueID, al.TechniqueName, al.Tactic = tq.ID, tq.Name, tq.Tactic
		}
		metrics.IncAlertRaised()
		h.alerter.Notify(al)
	}
	// Tehdit istihbaratı (IoC): olayın yapısal Details'i (ip/mac/process) veya
	// mesajı bilinen-kötü bir göstergeyle eşleşirse KRİTİK uyarı (yüksek-güven).
	// Atomik Load: eşzamanlı hot-reload (SetIoCSet) ile yarışsız.
	if iocSet := h.iocSet.Load(); iocSet.Size() > 0 {
		var dm map[string]any
		if e.Details != "" {
			_ = json.Unmarshal([]byte(e.Details), &dm)
		}
		if ti, ind, ok := iocSet.MatchIndicator(dm, e.Message); ok {
			metrics.IncIocHit()
			// Zenginleştirme: eşleşen göstergenin güven + kaynak bilgisini mesaja iliştir.
			enrich := "IoC eşleşmesi [" + ti.Label + "] " + ind
			if ti.Confidence != "" {
				enrich += " (güven=" + ti.Confidence
				if ti.Source != "" {
					enrich += ", kaynak=" + ti.Source
				}
				enrich += ")"
			}
			raise(notify.Alert{
				DeviceID:      deviceID,
				Category:      e.Category,
				Severity:      "CRITICAL",
				Message:       enrich + ": " + e.Message,
				OccurredAt:    e.OccurredAt,
				TechniqueID:   "T1071",
				TechniqueName: "Application Layer Protocol",
				Tactic:        "Command and Control",
			}, detect.Detection{
				RuleID: "ioc", RuleName: ti.Label, Severity: "CRITICAL",
				Technique: mitre.Technique{ID: "T1071", Name: "Application Layer Protocol", Tactic: "Command and Control"},
			})
		}
	}

	// Export tap'i (nil = bağlı değil): tespit + kapı BİTTİKTEN sonra, olayı ve
	// kapıdan geçen tespitleri yalnızca-export düzlemine devret. Tap asla gate
	// çağırmaz; bu yüzden ikinci bir gate'li yol oluşmaz (ADR-0040).
	if h.observer != nil {
		h.observer.ObserveProcessed(ctx, deviceID, e, admitted)
	}
}

// detailsJSON, proto Event.details (structpb.Struct) alanını kalıcılaştırılacak
// JSON metnine çevirir. Ayrıntı yoksa (nil) boş string döner; böylece db katmanı
// alanı NULL saklar. Serileştirme hatası olası değildir (structpb her zaman geçerli
// JSON üretir), yine de güvenli tarafta boş string döneriz.
func detailsJSON(d *structpb.Struct) string {
	if d == nil {
		return ""
	}
	b, err := protojson.Marshal(d)
	if err != nil {
		return ""
	}
	return string(b)
}

// dbCategory, proto enum'unu DB event_category ENUM'una eşler
// ("EVENT_CATEGORY_SECURITY" -> "SECURITY"). Belirsiz değer SYSTEM'e düşer.
func dbCategory(c kutv1.EventCategory) string {
	s := strings.TrimPrefix(c.String(), "EVENT_CATEGORY_")
	if s == "" || s == "UNSPECIFIED" {
		return "SYSTEM"
	}
	return s
}

// dbSeverity, proto enum'unu DB severity ENUM'una eşler. Belirsiz değer INFO'ya düşer.
func dbSeverity(v kutv1.Severity) string {
	s := strings.TrimPrefix(v.String(), "SEVERITY_")
	if s == "" || s == "UNSPECIFIED" {
		return "INFO"
	}
	return s
}

// StreamPolicies, UZUN-ÖMÜRLÜ bir akıştır: önce ajanın bildirdiği sürümden
// farklıysa güncel paketi gönderir, sonra açık kalıp politika değiştikçe (admin
// atama → Publish) yeni paketleri ANINDA iter. İstemci akışı kapatınca (ctx
// iptal) döngü sonlanır.
func (h *AgentHandler) StreamPolicies(req *kutv1.PolicySubscribeRequest, stream kutv1.AgentService_StreamPoliciesServer) error {
	deviceID, err := DeviceIDFromContext(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, "kimlik doğrulanamadı")
	}
	notify, cancel := h.notifier.Subscribe(deviceID)
	defer cancel()
	return streamPolicyLoop(stream.Context(), deviceID, req.GetCurrentPolicyVersion(),
		h.policies, notify, stream.Send)
}

// streamPolicyLoop, transport'tan bağımsız push döngüsüdür (test edilebilir):
// güncel paketi (sürüm değiştiyse) gönderir, sonra her bildirimde tekrar dener.
func streamPolicyLoop(ctx context.Context, deviceID, currentVersion string,
	provider PolicyProvider, notify <-chan struct{}, send func(*kutv1.PolicyBundle) error) error {

	lastVer := currentVersion
	sendIfNewer := func() error {
		b, err := provider.CurrentPolicy(ctx, deviceID)
		if err != nil {
			return status.Error(codes.Internal, "politika alınamadı")
		}
		if b == nil || b.GetPolicyVersion() == lastVer {
			return nil
		}
		if err := send(b); err != nil {
			return err
		}
		lastVer = b.GetPolicyVersion()
		return nil
	}

	if err := sendIfNewer(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil // istemci kapattı; akışı nazikçe bitir
		case <-notify:
			if err := sendIfNewer(); err != nil {
				return err
			}
		}
	}
}

// CheckUpdate, OTA güncelleme manifestosunu döner. Manifesto İMZALIDIR; ajan
// indirmeden önce imzayı gömülü public key ile doğrular.
func (h *AgentHandler) CheckUpdate(ctx context.Context, req *kutv1.UpdateCheckRequest) (*kutv1.UpdateManifest, error) {
	deviceID, err := DeviceIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "kimlik doğrulanamadı")
	}
	id := req.GetIdentity()
	m, err := h.updates.LatestUpdate(ctx, deviceID, id.GetAgentVersion(), id.GetOsPlatform())
	if err != nil {
		return nil, status.Error(codes.Internal, "güncelleme sorgulanamadı")
	}
	if m == nil || !m.GetUpdateAvailable() {
		return &kutv1.UpdateManifest{UpdateAvailable: false}, nil
	}
	// Kademeli dağıtım: cihaz bu sürümün rollout kohortunda değilse henüz sunma.
	if !rollout.InCohort(deviceID, m.GetTargetVersion(), int(m.GetRolloutPercent())) {
		return &kutv1.UpdateManifest{UpdateAvailable: false}, nil
	}
	return m, nil
}
