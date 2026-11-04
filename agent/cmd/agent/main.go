// Command agent, uç nokta ajanını başlatır.
//
// Akış: (1) kayıtlı sertifika yoksa tek kullanımlık token + CSR ile enroll et,
// (2) mTLS ile AgentService'e bağlan, (3) heartbeat döngüsü — her turda sunucu
// saatini çıpa al ve tamponlanmış olayları store-and-forward ile gönder.
//
// Not: Süreç izleme ve politika uygulama (mesai-dışı kontrol) OS'e özgüdür ve
// agent/internal/enforce içinde uygulanır; politika motoru (agent/internal/policy) ve saat çıpası
// (agent/internal/agentclock) hazır ve test edilmiştir.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"kut.corp/suite/agent/internal/agentclock"
	"kut.corp/suite/agent/internal/anomaly"
	"kut.corp/suite/agent/internal/certrenew"
	"kut.corp/suite/agent/internal/cmdlog"
	"kut.corp/suite/agent/internal/collector"
	"kut.corp/suite/agent/internal/compliance"
	"kut.corp/suite/agent/internal/deviceaction"
	"kut.corp/suite/agent/internal/discovery"
	"kut.corp/suite/agent/internal/dlp"
	"kut.corp/suite/agent/internal/dnsmon"
	"kut.corp/suite/agent/internal/enforce"
	"kut.corp/suite/agent/internal/fim"
	"kut.corp/suite/agent/internal/inventory"
	"kut.corp/suite/agent/internal/liveness"
	"kut.corp/suite/agent/internal/netconn"
	"kut.corp/suite/agent/internal/osinfo"
	"kut.corp/suite/agent/internal/persistence"
	"kut.corp/suite/agent/internal/policy"
	"kut.corp/suite/agent/internal/quarantine"
	"kut.corp/suite/agent/internal/resource"
	"kut.corp/suite/agent/internal/script"
	"kut.corp/suite/agent/internal/standdown"
	"kut.corp/suite/agent/internal/tamperprotect"
	"kut.corp/suite/agent/internal/transport"
	"kut.corp/suite/agent/internal/update"
	"kut.corp/suite/agent/internal/usbmon"
	"kut.corp/suite/contentscan"
	kutv1 "kut.corp/suite/gen/kut/v1"
	"kut.corp/suite/logx"
	"kut.corp/suite/offboard"
	"kut.corp/suite/otawire"
	"kut.corp/suite/scriptwire"
)

type envConfig struct {
	enrollAddr   string
	agentAddr    string
	serverName   string
	caPath       string
	token        string
	dataDir      string
	updatePubKey string   // base64 Ed25519 public key (OTA imza doğrulama)
	scriptPubKey string   // base64 Ed25519 public key (imzalı script doğrulama)
	authMACs     []string // ağ keşfi allowlist'i (yetkili MAC'ler)
	watchdogBin  string   // watchdog ikilisi (verilirse karşılıklı gözetim açık)
	offboardPub  []string // base64 Ed25519 public key(ler) (imzalı offline offboard)
	offboardTok  string   // offboard jetonu (metin) — dosyadan da okunabilir
	offboardFile string   // offboard jetonunu içeren dosya yolu (alternatif)
	interval     time.Duration
}

func loadEnv() envConfig {
	return envConfig{
		enrollAddr:   getenv("KUT_ENROLL_ADDR", "localhost:8444"),
		agentAddr:    getenv("KUT_AGENT_ADDR", "localhost:8443"),
		serverName:   getenv("KUT_SERVER_NAME", "kut-c2"),
		caPath:       os.Getenv("KUT_CA_PEM"),
		token:        os.Getenv("KUT_ENROLL_TOKEN"),
		dataDir:      getenv("KUT_AGENT_DATA", "./agent-data"),
		updatePubKey: os.Getenv("KUT_UPDATE_PUBKEY"),
		scriptPubKey: os.Getenv("KUT_SCRIPT_PUBKEY"),
		authMACs:     splitCSV(os.Getenv("KUT_AUTHORIZED_MACS")),
		watchdogBin:  os.Getenv("KUT_WATCHDOG_BIN"),
		offboardPub:  splitCSV(os.Getenv("KUT_OFFBOARD_PUBKEY")),
		offboardTok:  os.Getenv("KUT_OFFBOARD_TOKEN"),
		offboardFile: os.Getenv("KUT_OFFBOARD_TOKEN_FILE"),
		interval:     getdur("KUT_HEARTBEAT_INTERVAL", 30*time.Second),
	}
}

// checkOffboard, imzalı çevrimdışı offboard jetonunu (varsa) doğrular. Jeton
// geçerliyse (imza + cihaz + expiry) stand-down işareti bırakır ve true döner —
// çağıran ajanı durdurmalıdır. Jeton yoksa ya da geçersizse false döner (ajan
// normal çalışmaya devam eder). ÇEVRİMDIŞI çalışır: sunucuya erişim gerekmez.
func checkOffboard(cfg envConfig, deviceID string) bool {
	if len(cfg.offboardPub) == 0 {
		return false // özellik kapalı (güvenilen anahtar yok)
	}
	raw := strings.TrimSpace(cfg.offboardTok)
	if raw == "" && cfg.offboardFile != "" {
		b, err := os.ReadFile(cfg.offboardFile)
		if err != nil {
			log.Printf("offboard jeton dosyası okunamadı: %v", err)
			return false
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		return false // jeton verilmemiş
	}

	var pubs []ed25519.PublicKey
	for _, b64 := range cfg.offboardPub {
		if p, err := base64.StdEncoding.DecodeString(b64); err == nil {
			pubs = append(pubs, ed25519.PublicKey(p))
		}
	}
	v, err := offboard.NewVerifier(pubs...)
	if err != nil {
		log.Printf("offboard: geçerli public key yok: %v", err)
		return false
	}
	tok, sig, err := offboard.Decode(raw)
	if err != nil {
		log.Printf("offboard jetonu ayrıştırılamadı: %v", err)
		return false
	}
	if err := v.Verify(tok, sig, deviceID, time.Now().Unix()); err != nil {
		log.Printf("offboard jetonu REDDEDİLDİ: %v", err)
		return false
	}
	if err := standdown.Write(cfg.dataDir, deviceID, "signed offline offboard token"); err != nil {
		log.Printf("stand-down işareti yazılamadı: %v", err)
		return false
	}
	log.Printf("offboard jetonu DOĞRULANDI (device=%s) — ajan stand-down; tamper-koruması bilinçli olarak durduruldu", deviceID)
	return true
}

// selfBinaryHash, ajanın kendi çalışan ikilisinin SHA-256'sını (hex) döner —
// öz-tasdik. Hesaplanamazsa boş döner (sunucu boş hash'i yok sayar).
func selfBinaryHash() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	f, err := os.Open(exe)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// parseSize, bayt boyutu string'ini ayrıştırır: düz tamsayı (bayt) veya "KB"/"MB"/
// "GB" son eki (1024-tabanlı). Geçersizse 0 döner.
func parseSize(s string) int64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "KB"):
		mult, s = 1<<10, strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "MB"):
		mult, s = 1<<20, strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "GB"):
		mult, s = 1<<30, strings.TrimSuffix(s, "GB")
	}
	s = strings.TrimSpace(s)
	var n int64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
		n = n*10 + int64(s[i]-'0')
	}
	return n * mult
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	// KUT_LOG_FORMAT=json → yapısal JSON loglama (SIEM); aksi halde "[agent] " metin.
	logx.Setup(os.Getenv("KUT_LOG_FORMAT"), "[agent] ")
	if err := run(); err != nil {
		log.Fatalf("hata: %v", err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := loadEnv()

	// İmzalı çevrimdışı offboard: stand-down işareti zaten varsa ajan çalışmaz
	// (watchdog da yeniden başlatmaz). Yetkili imzalı jeton bir kez uygulandıktan
	// sonra bu durum kalıcıdır — işaret dosyası elle silinene dek.
	if standdown.Exists(cfg.dataDir) {
		log.Printf("stand-down işareti mevcut — ajan durdu (imzalı offline offboard).")
		return nil
	}

	// Sunucu SPKI pinning (savunma derinliği): KUT_SERVER_SPKI_PIN ayarlıysa (virgülle
	// ayrılmış base64 SHA-256 pinleri) sunucu sertifikası CA'ya EK OLARAK pin'e karşı
	// doğrulanır. Ayarlı değilse pinning devre dışıdır (yalnız CA doğrulaması).
	if pins := splitCSV(os.Getenv("KUT_SERVER_SPKI_PIN")); len(pins) > 0 {
		transport.SetServerPins(pins)
		log.Printf("mTLS: sunucu SPKI pinning etkin (%d pin)", len(pins))
	}

	ident, err := ensureEnrolled(ctx, cfg)
	if err != nil {
		return err
	}
	log.Printf("kimlik hazır: device_id=%s", ident.deviceID)

	// İmzalı çevrimdışı offboard denetimi: geçerli bir jeton verilmişse ajan
	// stand-down yapar (işaret bırakılır, sunucuya erişim gerekmez).
	if checkOffboard(cfg, ident.deviceID) {
		return nil
	}

	// İstemci sertifikasını dinamik tutucuya al: yenileme sonrası yeni
	// bağlantılar güncel sertifikayı kullanır (yeniden bağlanma zorlamadan).
	certHolder, err := transport.NewCertHolder(ident.certPEM, ident.keyPEM)
	if err != nil {
		return err
	}
	cli, conn, err := transport.DialAgent(cfg.agentAddr, certHolder, ident.caPEM, cfg.serverName)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Proaktif sertifika yenileme: ömrün son üçte birinde süre dolmadan yenile.
	go runCertRenewal(ctx, cfg, certHolder, ident)

	clock := agentclock.New(time.Now)
	buf := collector.NewBuffer(10000)
	selfHash := selfBinaryHash() // öz-tasdik: kendi ikilisinin SHA-256'sı (bir kez)
	// Motor birden çok goroutine'den (heartbeat + politika akışı) erişildiğinden
	// atomik tutulur; politika akışı sıcak değiştirir, enforcement okur.
	var engine atomic.Pointer[policy.Engine]
	engine.Store(policy.New(policy.Bundle{}))
	monitor := enforce.NewMonitor(enforce.NewProcessController(), clock, buf, uint32(os.Getpid()))
	// Davranışsal anomali tespiti (varsayılan AÇIK; KUT_ANOMALY_DISABLE ile kapatılır).
	// KUT_ANOMALY_MODEL verilirse eğitilmiş JSON model (ModelScorer) yüklenir;
	// aksi halde saf-Go çevrimiçi istatistiksel scorer kullanılır. Muhafazakâr
	// eşik (0.85): yalnız güçlü aykırı değerler SECURITY olayı üretir.
	if os.Getenv("KUT_ANOMALY_DISABLE") == "" {
		var scorer anomaly.Scorer
		if mp := os.Getenv("KUT_ANOMALY_MODEL"); mp != "" {
			// model YALNIZ Ed25519 imzası doğrulanınca yüklenir. İmzasız
			// ya da doğrulanamayan model YÜKLENMEZ (fail-closed) — tespiti sıfırlayan
			// kurcalamayı önler; istatistiksel scorer'a düşülür.
			pubB64 := os.Getenv("KUT_ANOMALY_PUBKEY")
			if pubB64 == "" {
				log.Printf("anomali modeli verildi ama KUT_ANOMALY_PUBKEY yok — imzasız model YÜKLENMEZ; istatistiksel scorer")
			} else if pub, err := base64.StdEncoding.DecodeString(pubB64); err != nil {
				log.Printf("KUT_ANOMALY_PUBKEY geçersiz (%v) — istatistiksel scorer", err)
			} else if m, err := anomaly.LoadModelSigned(mp, ed25519.PublicKey(pub)); err != nil {
				log.Printf("imzalı anomali modeli reddedildi (%v) — istatistiksel scorer", err)
			} else {
				scorer = m
				log.Printf("imzalı anomali modeli doğrulandı + yüklendi: %s", mp)
			}
		}
		monitor.SetAnomalyDetector(anomaly.NewDetector(0.85, scorer))
	}
	// Süreç-yürütme telemetrisi (EDR görünürlüğü; varsayılan AÇIK,
	// KUT_PROCESS_TELEMETRY_DISABLE ile kapatılır). İlk tur taban çizgisidir;
	// sonraki turlarda yeni süreçler PROCESS olayı olarak yayınlanır.
	if os.Getenv("KUT_PROCESS_TELEMETRY_DISABLE") == "" {
		monitor.SetProcessTelemetry(true)
	}
	// Enforcement DENETİM modu (audit vs block): KUT_ENFORCE_AUDIT ayarlıysa yasaklı
	// süreçler tespit edilip olay üretilir ama SONLANDIRILMAZ — operatör gerçek
	// engellemeyi açmadan önce politikayı canlıda güvenle doğrular.
	if os.Getenv("KUT_ENFORCE_AUDIT") != "" {
		monitor.SetAuditOnly(true)
		log.Println("[enforce] DENETİM modu etkin: yasaklı süreçler sonlandırılmayacak, yalnız raporlanacak")
	}
	neighbors := discovery.NewNeighborSource()
	netTracker := discovery.NewTracker(cfg.authMACs)
	// Giden bağlantı telemetrisi (EDR/IoC; varsayılan AÇIK, KUT_NETCONN_DISABLE
	// ile kapatılır). İlk tarama taban çizgisi; sonra yeni bağlantılar yayınlanır.
	var connTr *connTracker
	if os.Getenv("KUT_NETCONN_DISABLE") == "" {
		connTr = &connTracker{}
	}
	// Çıkarılabilir medya (USB) izleme (DLP-bitişik). KUT_USB_POLICY: audit
	// (varsayılan) | block | off. off dışında yeni takılan medya olay üretir.
	var usbTr *usbTracker
	if usbPolicy := getenv("KUT_USB_POLICY", "audit"); usbPolicy != "off" {
		usbTr = &usbTracker{policy: usbPolicy}
	}
	// Dosya bütünlüğü izleme (FIM): KUT_FIM_PATHS (virgülle ayrılmış dosya/dizin)
	// ayarlıysa bu yolların SHA-256'sı periyodik alınır; ekleme/değiştirme/silme
	// SECURITY olayı olarak bildirilir. İlk tarama taban çizgisi. Boşsa kapalı.
	var fimTr *fimTracker
	if paths := splitCSV(os.Getenv("KUT_FIM_PATHS")); len(paths) > 0 {
		fimTr = &fimTracker{paths: paths}
	}
	// İçerik-tarama (YARA-tarzı): KUT_YARA_PATHS + KUT_YARA_RULES (imzalı)
	// + KUT_YARA_PUBKEY ayarlıysa yollar imza kurallarına karşı taranır; eşleşme
	// SECURITY olayı olur. Kurallar YALNIZ imza doğrulanınca yüklenir (fail-closed):
	// imza/anahtar geçersizse tarama DEVRE DIŞI kalır (kural gömülü değildir).
	var scanner *contentScanner
	if paths := splitCSV(os.Getenv("KUT_YARA_PATHS")); len(paths) > 0 {
		rulesPath := os.Getenv("KUT_YARA_RULES")
		pubB64 := os.Getenv("KUT_YARA_PUBKEY")
		switch {
		case rulesPath == "" || pubB64 == "":
			log.Printf("içerik-tarama yolları verildi ama KUT_YARA_RULES/KUT_YARA_PUBKEY eksik — tarama DEVRE DIŞI")
		default:
			if pub, err := base64.StdEncoding.DecodeString(pubB64); err != nil {
				log.Printf("KUT_YARA_PUBKEY geçersiz (%v) — içerik-tarama DEVRE DIŞI", err)
			} else if rs, err := contentscan.LoadSigned(rulesPath, ed25519.PublicKey(pub)); err != nil {
				log.Printf("imzalı tarama kuralları reddedildi (%v) — içerik-tarama DEVRE DIŞI", err)
			} else {
				maxSize := int64(10 << 20) // 10 MiB varsayılan üst sınır
				if v := os.Getenv("KUT_YARA_MAXSIZE"); v != "" {
					if n := parseSize(v); n > 0 {
						maxSize = n
					}
				}
				scanner = &contentScanner{paths: paths, rules: rs, maxSize: maxSize}
				log.Printf("içerik-tarama etkin: %d kural, %d yol", len(rs.Rules), len(paths))
			}
		}
	}
	// Kalıcılık (autostart) izleme (varsayılan AÇIK, KUT_PERSISTENCE_DISABLE ile
	// kapatılır). Run anahtarları/görevler/cron/systemd; yeni girdiler POLICY_VIOLATION
	// olayı olarak bildirilir. İlk tarama taban çizgisidir.
	var persistTr *persistenceTracker
	if os.Getenv("KUT_PERSISTENCE_DISABLE") == "" {
		persistTr = &persistenceTracker{}
	}
	// DNS telemetri + DGA tespiti (opt-in KUT_DNS_MONITOR=1). OS DNS önbelleği
	// periyodik taranır; YENİ alanlar NETWORK_DISCOVERY, DGA-şüphelileri SECURITY
	// olayı olur. İlk tarama taban çizgisidir. (Toplama Windows'ta; skorlama her yerde.)
	var dnsTr *dnsTracker
	if os.Getenv("KUT_DNS_MONITOR") == "1" {
		dnsTr = &dnsTracker{sc: dnsmon.NewScanner()}
	}
	// Çıkarılabilir medya DLP (opt-in KUT_DLP_PATHS). Verilen yollar (ör. USB
	// bağlama noktaları) hassas veri (kredi kartı/TCKN/IBAN/e-posta) için taranır;
	// bulgu POLICY_VIOLATION olur (yalnız TÜR+SAYI — ham değer yazılmaz). I/O-ağır:
	// uyum kadansında çalışır.
	var dlpSc *dlpScanner
	if paths := splitCSV(os.Getenv("KUT_DLP_PATHS")); len(paths) > 0 {
		maxSize := int64(5 << 20) // 5 MiB varsayılan üst sınır
		if v := os.Getenv("KUT_DLP_MAXSIZE"); v != "" {
			if n := parseSize(v); n > 0 {
				maxSize = n
			}
		}
		dlpSc = &dlpScanner{paths: paths, maxSize: maxSize}
		log.Printf("DLP tarama etkin: %d yol", len(paths))
	}

	// Karantina yöneticisi: izolasyonda yalnız C2'ye izin verilir.
	// SAFE MODE (KUT_SAFE_MODE): gerçek firewall'a dokunmaz — demo/test için.
	c2Host, _, _ := net.SplitHostPort(cfg.agentAddr)
	safeMode := os.Getenv("KUT_SAFE_MODE") != ""
	var isolator quarantine.Isolator = quarantine.NewIsolator()
	if safeMode {
		isolator = quarantine.NoopIsolator{}
		log.Println("SAFE MODE açık: karantina/MDM eylemleri gerçek değişiklik yapmayacak")
	}
	quar := quarantine.NewManager(isolator, buf, filterEmpty([]string{c2Host}))

	// OTA doğrulayıcı (opsiyonel): public key(ler) verilmişse güncelleme imzaları
	// doğrulanır. KUT_UPDATE_PUBKEY virgülle ayrılmış birden çok anahtar alabilir —
	// imza-anahtarı ROTASYONU örtüşmesi: eski + yeni anahtar aynı anda güvenilir.
	var updVerifier *update.Verifier
	if cfg.updatePubKey != "" {
		var pubs []ed25519.PublicKey
		for _, k := range splitCSV(cfg.updatePubKey) {
			if raw, err := base64.StdEncoding.DecodeString(k); err == nil && len(raw) == ed25519.PublicKeySize {
				pubs = append(pubs, ed25519.PublicKey(raw))
			}
		}
		if v, err := update.NewVerifierMulti(pubs...); err == nil {
			updVerifier = v
			if len(pubs) > 1 {
				log.Printf("OTA: %d güvenilen imza anahtarı (rotasyon örtüşmesi)", len(pubs))
			}
		} else {
			log.Printf("OTA public key geçersiz, güncelleme kontrolü kapalı: %v", err)
		}
	}
	downloader := update.NewHTTPDownloader(0)
	stageDir := filepath.Join(cfg.dataDir, "updates")

	// İmzalı script doğrulayıcı (opsiyonel): yalnız imzalı scriptler çalıştırılır.
	var scriptVerifier *script.Verifier
	if cfg.scriptPubKey != "" {
		if raw, err := base64.StdEncoding.DecodeString(cfg.scriptPubKey); err == nil {
			if v, err := script.NewVerifier(raw); err == nil {
				scriptVerifier = v
			}
		}
	}

	// Başlangıç yaşam-döngüsü olayı (gerçek olay; uydurma telemetri değil). Host
	// bilgisi Details'e iliştirilir (konsol olay-detayında filo görünürlüğü).
	hostname, _ := os.Hostname()
	osVersion := osinfo.Version() // okunabilir OS sürümü (bir kez; Windows'ta exec)
	buf.Add(collector.Event{Category: "SYSTEM", Severity: "INFO", Message: "ajan başladı", OccurredAt: time.Now(),
		Details: map[string]any{"os": runtime.GOOS, "os_version": osVersion, "arch": runtime.GOARCH, "agent_version": agentVersion, "hostname": hostname}})

	// Kurcalama-koruma duruşu (SECURITY görünürlüğü): hangi savunmalar aktif ve çekirdek
	// koruma sürücüsü mevcut mu (bkz. docs/KERNEL-TAMPER.md — gerçek sürücü ayrı C/C++
	// projesidir; bu depoda userland savunma-derinliği sevk edilir). Savunmacı, uç noktanın
	// koruma seviyesini (none/userland/kernel) tek bir olayda görür.
	kdPresent, kdName := tamperprotect.KernelDriverProbe()
	posture := tamperprotect.Assess(tamperprotect.Defenses{
		Watchdog:   cfg.watchdogBin != "",
		Liveness:   cfg.watchdogBin != "",
		FIM:        len(splitCSV(os.Getenv("KUT_FIM_PATHS"))) > 0,
		SelfAttest: selfHash != "",
		SignedOTA:  os.Getenv("KUT_UPDATE_PUBKEY") != "",
	}, kdPresent, kdName)
	// Sürücü diskte mevcutsa, iletişim portundan CANLI durumu sorgula (yüklü mü,
	// filtreliyor mu, kaç kurcalama engellendi) — "mevcut"tan "aktif"e yükseltir.
	if posture.KernelDriver {
		if kActive, kDenied, derr := tamperprotect.DriverStatus(); derr == nil {
			posture.KernelActive = kActive
			posture.KernelDeniedOps = kDenied
		}
	}
	postureSev := "INFO"
	if posture.Level == "none" {
		postureSev = "LOW" // hiç kurcalama koruması yok → güvenlik-duruşu uyarısı
	}
	buf.Add(collector.Event{Category: "SECURITY", Severity: postureSev, Message: posture.Summary, OccurredAt: time.Now(),
		Details: map[string]any{"tamper_level": posture.Level, "userland": posture.Userland,
			"kernel_driver": posture.KernelDriver, "kernel_active": posture.KernelActive,
			"kernel_denied_ops": posture.KernelDeniedOps}})

	// Uyum durumu: başlangıçta disk şifreleme kontrol edilir ve raporlanır. Şifreleme
	// KAPALIYSA güvenlik-duruşu ihlali (SECURITY/MEDIUM); açık/bilinmiyor bilgi amaçlı.
	reportCompliance(buf, compliance.NewChecker())
	// Yazılım envanteri: başlangıçta yüklü yazılım listesi raporlanır (MDM varlık
	// görünürlüğü). Exec-ağır; periyodik olarak uyumla birlikte yenilenir.
	reportInventory(buf)
	// Kaynak kullanımı (bellek/disk/uptime): uç-nokta sağlığı.
	reportResource(buf)
	// İçerik-tarama + DLP (etkinse): başlangıçta bir kez tara (I/O-ağır).
	if scanner != nil {
		scanner.scan(buf)
	}
	if dlpSc != nil {
		dlpSc.scan(buf)
	}
	// Periyodik uyum + envanter + kaynak + içerik-tarama yeniden-kontrolü: açılıştan
	// sonra değişiklikler yakalanır (EDR duruş takibi). Seyrek (exec/IO-ağır).
	go func() {
		t := time.NewTicker(complianceInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				reportCompliance(buf, compliance.NewChecker())
				reportInventory(buf)
				reportResource(buf)
				if scanner != nil {
					scanner.scan(buf)
				}
				if dlpSc != nil {
					dlpSc.scan(buf)
				}
			}
		}
	}()

	// Kalıcı politika aboneliği: sunucu politika değiştikçe anında iter.
	go runPolicyStream(ctx, cli, ident, &engine)

	// Çift-süreç karşılıklı gözetim: watchdog verilmişse, onun beacon'unu izle;
	// bayatlarsa yeniden başlat (watchdog da ajanı süreç-çıkışıyla izler).
	if cfg.watchdogBin != "" {
		selfBeacon := liveness.NewBeacon(filepath.Join(cfg.dataDir, "agent.beacon"))
		wdBeacon := liveness.NewBeacon(filepath.Join(cfg.dataDir, "watchdog.beacon"))
		guard := liveness.NewPeerGuard(selfBeacon, wdBeacon, liveness.Options{
			Restart: func() { spawnDetached(cfg.watchdogBin) },
			Log:     func(m string) { log.Println("[liveness] " + m) },
		})
		go guard.Run(ctx)
	}

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	// Komut idempotency + onay günlüğü (en-az-bir-kez teslim): yürütülen komutlar
	// diske kaydedilir (yeniden teslimde ÇİFT YÜRÜTME önlenir) ve heartbeat'te onaylanır.
	clog := cmdlog.Open(cfg.dataDir)

	beat := func() {
		hbCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		acks := clog.TakeAcks()       // yürütülüp henüz onaylanmamış komutlar
		results := clog.TakeResults() // yürütme sonuçları (SUCCEEDED/FAILED); effective-state için
		resp, err := cli.Heartbeat(hbCtx, &kutv1.HeartbeatRequest{
			Identity: &kutv1.AgentIdentity{
				DeviceId:     ident.deviceID,
				AgentVersion: agentVersion,
				OsPlatform:   runtime.GOOS,
				OsVersion:    osVersion,
			},
			CurrentPolicyVersion: engine.Load().Version(),
			BinaryHash:           selfHash, // öz-tasdik: kendi ikilisinin SHA-256'sı
			AckedCommandIds:      acks,
			CommandResults:       toProtoResults(results),
		})
		if err != nil {
			log.Printf("heartbeat başarısız: %v", err)
			return // acks/results temizlenmez → sonraki heartbeat'te yeniden bildirilir
		}
		clog.ConfirmAcks(acks)                  // sunucu onayları aldı; kuyruktan çıkar
		clog.ConfirmResults(resultIDs(results)) // sonuçlar bildirildi; kuyruktan çıkar
		// Sunucu saatini çıpa al (yerel saate güvenilmez).
		if resp.GetServerTime() != nil {
			clock.Sync(resp.GetServerTime().AsTime())
		}
		// Sunucudan gelen komutları işle (karantina, imzalı script vb.).
		// ctx (hbCtx değil) geçilir: uzun scriptler heartbeat penceresini bloklamamalı.
		handleCommands(ctx, resp.GetPendingCommands(), quar, scriptVerifier, buf, cli, safeMode, clog, cfg.dataDir)
		// Politika uygulaması: yasaklı süreçleri sonlandır.
		if n, err := monitor.Tick(engine.Load()); err != nil {
			log.Printf("enforcement hatası: %v", err)
		} else if n > 0 {
			log.Printf("enforcement: %d yasaklı süreç sonlandırıldı", n)
		}
		// OTA: güncelleme var mı, varsa İMZASINI doğrula, indir ve hazırla.
		if updVerifier != nil {
			checkUpdate(hbCtx, cli, ident, updVerifier, downloader, stageDir, buf)
		}
		// Pasif ağ keşfi: yeni cihazları tespit et ve raporla (mimari 4.3).
		scanNetwork(neighbors, netTracker, buf)
		// Giden bağlantı telemetrisi (etkinse): yeni bağlantıları yayınla.
		if connTr != nil {
			connTr.report(buf)
		}
		// Çıkarılabilir medya izleme (etkinse): yeni takılan USB medyayı bildir.
		if usbTr != nil {
			usbTr.report(buf, safeMode)
		}
		// Dosya bütünlüğü izleme (etkinse): izlenen yollardaki değişiklikleri bildir.
		if fimTr != nil {
			fimTr.report(buf)
		}
		// Kalıcılık izleme (etkinse): yeni autostart girdilerini bildir.
		if persistTr != nil {
			persistTr.report(buf)
		}
		// DNS telemetri + DGA (etkinse): yeni alan sorgularını + DGA-şüphelileri bildir.
		if dnsTr != nil {
			dnsTr.report(buf)
		}
		flushEvents(hbCtx, cli, ident, buf)
	}

	beat() // ilk tur hemen
	for {
		select {
		case <-ctx.Done():
			log.Println("kapatılıyor.")
			return nil
		case <-ticker.C:
			beat()
		}
	}
}

// flushEvents, tamponlanmış olayları gönderir ve yalnız sunucunun onayladığı
// sıraya kadar tampondan siler (store-and-forward).
func flushEvents(ctx context.Context, cli kutv1.AgentServiceClient, ident *identity, buf *collector.Buffer) {
	pending := buf.Pending(500)
	if len(pending) == 0 {
		return
	}
	stream, err := cli.ReportEvents(ctx)
	if err != nil {
		log.Printf("olay akışı açılamadı: %v", err)
		return
	}
	protoEvents := make([]*kutv1.Event, 0, len(pending))
	for _, e := range pending {
		pe := &kutv1.Event{
			Sequence:   e.Seq,
			Category:   protoCategory(e.Category),
			Severity:   protoSeverity(e.Severity),
			Message:    e.Message,
			OccurredAt: timestamppb.New(e.OccurredAt),
		}
		// Yapısal ek veri (varsa) structpb'ye çevrilip iletilir — konsol olay-detay
		// panelinde gösterilir ve sunucu tarafında event_logs.details'e saklanır.
		if len(e.Details) > 0 {
			if ds, err := structpb.NewStruct(e.Details); err == nil {
				pe.Details = ds
			}
		}
		protoEvents = append(protoEvents, pe)
	}
	if err := stream.Send(&kutv1.EventBatch{
		Identity: &kutv1.AgentIdentity{DeviceId: ident.deviceID, AgentVersion: agentVersion, OsPlatform: runtime.GOOS},
		Events:   protoEvents,
	}); err != nil {
		log.Printf("olay gönderilemedi: %v", err)
		return
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		log.Printf("olay onayı alınamadı: %v", err)
		return
	}
	removed := buf.Ack(ack.GetLastAcceptedSequence())
	log.Printf("olay gönderildi: %d, onaylanan sıra: %d, silinen: %d", len(pending), ack.GetLastAcceptedSequence(), removed)
}

// runPolicyStream, sunucuya KALICI bir politika aboneliği açar ve gelen her
// paketle motoru sıcak değiştirir. Akış koparsa yeniden bağlanır (ctx bitene dek).
func runPolicyStream(ctx context.Context, cli kutv1.AgentServiceClient, ident *identity, engine *atomic.Pointer[policy.Engine]) {
	for ctx.Err() == nil {
		stream, err := cli.StreamPolicies(ctx, &kutv1.PolicySubscribeRequest{
			Identity:             &kutv1.AgentIdentity{DeviceId: ident.deviceID, AgentVersion: agentVersion, OsPlatform: runtime.GOOS},
			CurrentPolicyVersion: engine.Load().Version(),
		})
		if err == nil {
			for {
				b, rerr := stream.Recv()
				if rerr != nil {
					break
				}
				engine.Store(policy.New(policy.FromProto(b)))
				log.Printf("politika güncellendi (push): sürüm=%s, kural=%d", b.GetPolicyVersion(), len(b.GetRules()))
			}
		}
		// Kopma/hata: kısa bekleyip yeniden bağlan.
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// checkUpdate, sunucudan güncelleme manifestosu ister; imzayı doğrular, paketi
// indirir, SHA-256'yı doğrular ve staging'e yazar (gerçek swap watchdog'un işi).
// İmza/hash geçersizse güncellemeyi REDDEDER ve SECURITY/CRITICAL olayı üretir.
func checkUpdate(ctx context.Context, cli kutv1.AgentServiceClient, ident *identity, v *update.Verifier, dl update.Downloader, stageDir string, buf *collector.Buffer) {
	resp, err := cli.CheckUpdate(ctx, &kutv1.UpdateCheckRequest{
		Identity: &kutv1.AgentIdentity{DeviceId: ident.deviceID, AgentVersion: agentVersion, OsPlatform: runtime.GOOS},
	})
	if err != nil || !resp.GetUpdateAvailable() {
		return
	}
	// Bu sürüm zaten staging'de bekliyorsa tekrar indirme (watchdog swap'ini bekle);
	// aksi halde her heartbeat'te aynı paket boşuna yeniden indirilir.
	if data, rerr := os.ReadFile(filepath.Join(stageDir, "agent-staged.version")); rerr == nil &&
		strings.TrimSpace(string(data)) == resp.GetTargetVersion() {
		return
	}
	m := otawire.Manifest{
		TargetVersion: resp.GetTargetVersion(),
		SHA256Hex:     resp.GetSha256Hex(),
		DownloadURL:   resp.GetDownloadUrl(),
		Mandatory:     resp.GetMandatory(),
	}
	staged, err := update.Prepare(ctx, m, resp.GetSignature(), v, dl, stageDir)
	if err != nil {
		if err == update.ErrBadSignature || err == update.ErrHashMismatch {
			log.Printf("GÜNCELLEME REDDEDİLDİ (%v): sürüm=%s", err, resp.GetTargetVersion())
			buf.Add(collector.Event{
				Category: "SECURITY", Severity: "CRITICAL",
				Message:    "sahte/bozuk güncelleme reddedildi: " + resp.GetTargetVersion(),
				OccurredAt: time.Now(),
			})
			return
		}
		log.Printf("güncelleme hazırlanamadı: %v", err)
		return
	}
	log.Printf("güncelleme hazırlandı: sürüm=%s (staging: %s; swap watchdog tarafından)", staged.Version, staged.Path)
	buf.Add(collector.Event{
		Category: "AGENT_UPDATE", Severity: "INFO",
		Message:    "imzalı güncelleme doğrulandı ve staging'e alındı: " + staged.Version,
		OccurredAt: time.Now(),
	})
}

// handleCommands, sunucudan gelen anlık komutları uygular (karantina, imzalı
// script, adli dosya toplama).
func handleCommands(ctx context.Context, cmds []*kutv1.Command, quar *quarantine.Manager, sv *script.Verifier, buf *collector.Buffer, cli kutv1.AgentServiceClient, safeMode bool, clog *cmdlog.Log, dataDir string) {
	for _, c := range cmds {
		id := c.GetCommandId()
		// İDEMPOTENCY: komut daha önce yürütüldüyse (en-az-bir-kez teslimde yeniden
		// gelmiş olabilir) TEKRAR YÜRÜTME — ör. çift-WIPE/çift-LOCK önlenir. Yine de
		// onay kuyruğuna al: önceki ack sunucuya ulaşmadığı için yeniden teslim edilmiş
		// olabilir; yeniden onaylayalım ki sunucu teslimi durdursun.
		if clog != nil && clog.Executed(id) {
			clog.QueueAck(id)
			continue
		}
		switch c.GetType() {
		case kutv1.Command_COMMAND_TYPE_QUARANTINE:
			if err := quar.Apply(); err != nil {
				log.Printf("karantina uygulanamadı: %v", err)
				queueResult(clog, id, false, c.GetType(), err.Error()) // effective-state: uygulanamadı
			} else {
				log.Println("karantina uygulandı")
				queueResult(clog, id, true, c.GetType(), "") // effective-state: cihaz gerçekten izole
			}
		case kutv1.Command_COMMAND_TYPE_UNQUARANTINE:
			if err := quar.Release(); err != nil {
				log.Printf("karantina kaldırılamadı: %v", err)
				queueResult(clog, id, false, c.GetType(), err.Error())
			} else {
				log.Println("karantina kaldırıldı")
				queueResult(clog, id, true, c.GetType(), "")
			}
		case kutv1.Command_COMMAND_TYPE_RUN_SIGNED_SCRIPT:
			// Uzun sürebilir; heartbeat döngüsünü bloklamamak için arka planda.
			go runSignedScript(ctx, c, sv, buf)
		case kutv1.Command_COMMAND_TYPE_COLLECT_FILE:
			// Dosya okuma/yükleme bloklamasın; arka planda.
			go collectFile(ctx, c, buf, cli, dataDir)
		case kutv1.Command_COMMAND_TYPE_LOCK:
			doDeviceAction(buf, safeMode, "LOCK", "ekran kilitleme", deviceaction.Lock)
		case kutv1.Command_COMMAND_TYPE_RESTART:
			doDeviceAction(buf, safeMode, "RESTART", "yeniden başlatma", deviceaction.Restart)
		case kutv1.Command_COMMAND_TYPE_WIPE:
			// WIPE geri döndürülemez kripto-silme yapar. ÜÇÜNCÜ güvenlik katmanı:
			// gerçek silme yalnız ajan AÇIKÇA ARM'lıysa (KUT_ALLOW_WIPE=1) çağrılır;
			// aksi halde yalnız olay üretilir, VERİ SİLİNMEZ. (Diğer iki katman: sunucu
			// RBAC=ADMIN ve doDeviceAction'daki güvenli-mod denetimi.)
			doDeviceAction(buf, safeMode, "WIPE", "veri silme", selectWipeFn(deviceaction.WipeArmed()))
		default:
			// Diğer komut tipleri ileride (UNINSTALL, COLLECT_DIAGNOSTICS) ya da
			// UNSPECIFIED/tanınmayan: YÜRÜTÜLMEZ. Yalnız görünürlük için günlüğe yazılır;
			// ack/kayıt davranışı değişmez. Korumalılık sunucuyla aynı komut tablosundan.
			log.Printf("komut tipi %s bu ajan sürümünde yürütülmüyor (korumalı=%v)", c.GetType(), commandProtected(c.GetType()))
		}
		// Komut işlendi (senkron uygulandı ya da arka plana verildi): idempotency için
		// kaydet ve sunucuya onay kuyruğuna al (sonraki heartbeat'te bildirilir).
		if clog != nil {
			clog.Record(id)
			clog.QueueAck(id)
		}
	}
}

// queueResult, komut yürütme sonucunu güvenli kuyruğa alır (clog nil olabilir).
func queueResult(clog *cmdlog.Log, id string, ok bool, typ kutv1.Command_CommandType, detail string) {
	if clog != nil {
		clog.QueueResult(id, ok, int32(typ), detail)
	}
}

// toProtoResults, cmdlog sonuçlarını heartbeat için proto CommandResult'a çevirir.
func toProtoResults(rs []cmdlog.Result) []*kutv1.CommandResult {
	if len(rs) == 0 {
		return nil
	}
	out := make([]*kutv1.CommandResult, 0, len(rs))
	for _, r := range rs {
		st := kutv1.CommandStatus_COMMAND_STATUS_SUCCEEDED
		if !r.OK {
			st = kutv1.CommandStatus_COMMAND_STATUS_FAILED
		}
		out = append(out, &kutv1.CommandResult{
			CommandId:   r.ID,
			Status:      st,
			CommandType: kutv1.Command_CommandType(r.Type),
			Detail:      r.Detail,
		})
	}
	return out
}

// resultIDs, sonuç kimliklerini döner (ConfirmResults için).
func resultIDs(rs []cmdlog.Result) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

// selectWipeFn, WIPE için çalıştırılacak fonksiyonu ARM durumuna göre seçer.
// ARM'lı DEĞİLSE (güvenli varsayılan) gerçek yıkıcı Wipe YERİNE, hiçbir şey silmeyen
// ve ErrWipeNotArmed dönen bir güdük döner — kazara veri kaybını önler. ARM'lıysa
// gerçek kripto-silme (deviceaction.Wipe) döner.
func selectWipeFn(armed bool) func() error {
	if !armed {
		return func() error { return deviceaction.ErrWipeNotArmed }
	}
	return deviceaction.Wipe
}

// doDeviceAction, bir MDM uzak eylemini uygular ve sonucu olay olarak bildirir.
// Güvenli-mod AÇIKKEN gerçek OS eylemi ÇAĞRILMAZ (yalnız olay üretilir) — demo/
// test sırasında cihazın kilitlenmesi/yeniden başlaması önlenir.
func doDeviceAction(buf *collector.Buffer, safeMode bool, action, label string, fn func() error) {
	if safeMode {
		buf.Add(collector.Event{Category: "SYSTEM", Severity: "INFO",
			Message: "MDM " + label + " komutu alındı (GÜVENLİ MOD: gerçek eylem yok)", OccurredAt: time.Now(),
			Details: map[string]any{"action": action, "safe_mode": true}})
		log.Printf("MDM %s (güvenli mod: gerçek eylem yok)", action)
		return
	}
	err := fn()
	sev, msg := "INFO", "MDM "+label+" uygulandı"
	det := map[string]any{"action": action}
	if err != nil {
		sev, msg = "MEDIUM", "MDM "+label+" başarısız: "+err.Error()
		det["error"] = err.Error()
	}
	buf.Add(collector.Event{Category: "SYSTEM", Severity: sev, Message: msg, OccurredAt: time.Now(), Details: det})
	log.Printf("MDM %s: %v", action, err)
}

// maxCollectBytes, ajanın toplayıp yükleyeceği bir dosyanın üst sınırıdır (sunucu
// da ayrıca sınır uygular). Büyük dosyalar reddedilir.
const maxCollectBytes = 3 << 20 // 3 MiB

// collectFile, COLLECT_FILE komutunun hedef dosyasını (boyut-sınırlı) okur,
// SHA-256'sını hesaplar ve UploadArtifact ile sunucuya yükler. Başarı/başarısızlık
// bir SYSTEM olayı olarak da bildirilir (konsol görünürlüğü).
// protectedCollectPath, istenen yolun ajanın KENDİ veri dizini içinde olup olmadığını döner.
// O dizin ajanın mTLS özel anahtarını/sertifikasını ve iç durumunu barındırır; COLLECT_FILE
// ile toplanması, ele geçmiş/sahte bir C2'nin ajan kimliğini sızdırmasına yol açardı.
// Çözülemeyen yol güvenli tarafta reddedilir. Windows'ta karşılaştırma büyük/küçük harf
// duyarsızdır.
func protectedCollectPath(path, dataDir string) bool {
	ap, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return true // fail-closed
	}
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return false
	}
	ad, err := filepath.Abs(filepath.Clean(dataDir))
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		ap, ad = strings.ToLower(ap), strings.ToLower(ad)
	}
	return ap == ad || strings.HasPrefix(ap, ad+string(os.PathSeparator))
}

func collectFile(ctx context.Context, c *kutv1.Command, buf *collector.Buffer, cli kutv1.AgentServiceClient, dataDir string) {
	path := c.GetParams().GetFields()["path"].GetStringValue()
	if path == "" {
		return
	}
	if protectedCollectPath(path, dataDir) {
		buf.Add(collector.Event{Category: "SECURITY", Severity: "HIGH",
			Message: "dosya toplama REDDEDİLDİ (korumalı ajan veri dizini): " + path, OccurredAt: time.Now(),
			Details: map[string]any{"path": path, "error": "protected_path"}})
		return
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		buf.Add(collector.Event{Category: "SYSTEM", Severity: "LOW",
			Message: "dosya toplama başarısız (bulunamadı/dizin): " + path, OccurredAt: time.Now(),
			Details: map[string]any{"path": path, "error": "not_found_or_dir"}})
		return
	}
	if info.Size() > maxCollectBytes {
		buf.Add(collector.Event{Category: "SYSTEM", Severity: "LOW",
			Message: fmt.Sprintf("dosya toplama başarısız (çok büyük: %d B): %s", info.Size(), path), OccurredAt: time.Now(),
			Details: map[string]any{"path": path, "error": "too_large", "size": info.Size()}})
		return
	}
	content, err := os.ReadFile(path)
	if err != nil {
		buf.Add(collector.Event{Category: "SYSTEM", Severity: "LOW",
			Message: "dosya toplama başarısız (okunamadı): " + path, OccurredAt: time.Now(),
			Details: map[string]any{"path": path, "error": "read_failed"}})
		return
	}
	sum := sha256.Sum256(content)
	_, err = cli.UploadArtifact(ctx, &kutv1.UploadArtifactRequest{
		CommandId: c.GetCommandId(), Path: path, Sha256: hex.EncodeToString(sum[:]), Content: content,
	})
	if err != nil {
		log.Printf("artefakt yüklenemedi (%s): %v", path, err)
		return
	}
	buf.Add(collector.Event{Category: "SYSTEM", Severity: "INFO",
		Message: fmt.Sprintf("dosya toplandı ve yüklendi: %s (%d B)", path, len(content)), OccurredAt: time.Now(),
		Details: map[string]any{"path": path, "size": len(content), "sha256": hex.EncodeToString(sum[:])}})
}

// runSignedScript, komut parametrelerinden scripti çıkarır, İMZASINI gömülü
// public key ile doğrular ve YALNIZ geçerliyse sınırlı biçimde çalıştırır.
// İmza geçersizse SECURITY/CRITICAL olayı üretir ve çalıştırmaz.
func runSignedScript(ctx context.Context, c *kutv1.Command, sv *script.Verifier, buf *collector.Buffer) {
	if sv == nil {
		log.Println("imzalı script alındı ama script public key ayarlı değil; atlanıyor")
		return
	}
	f := c.GetParams().GetFields()
	s := scriptwire.Script{
		Interpreter: f["interpreter"].GetStringValue(),
		Body:        f["body"].GetStringValue(),
	}
	for _, v := range f["args"].GetListValue().GetValues() {
		s.Args = append(s.Args, v.GetStringValue())
	}
	sig, err := base64.StdEncoding.DecodeString(f["signature"].GetStringValue())
	if err != nil || sv.Verify(s, sig) != nil {
		log.Printf("SCRIPT REDDEDİLDİ (imza doğrulanamadı): komut=%s", c.GetCommandId())
		buf.Add(collector.Event{Category: "SECURITY", Severity: "CRITICAL",
			Message: "imzasız/sahte script reddedildi: " + c.GetCommandId(), OccurredAt: time.Now()})
		return
	}
	res, err := script.Run(ctx, s, 60*time.Second, 256*1024)
	if err != nil {
		log.Printf("script çalıştırılamadı: %v", err)
		return
	}
	log.Printf("imzalı script çalıştı: komut=%s çıkış=%d timeout=%v", c.GetCommandId(), res.ExitCode, res.TimedOut)
	buf.Add(collector.Event{Category: "SYSTEM", Severity: "INFO",
		Message:    fmt.Sprintf("imzalı script çalıştı (komut=%s, çıkış=%d)", c.GetCommandId(), res.ExitCode),
		OccurredAt: time.Now()})
}

// spawnDetached, verilen ikiliyi bağımsız bir süreç olarak başlatır (beklemez).
func spawnDetached(bin string) {
	cmd := exec.Command(bin)
	if err := cmd.Start(); err != nil {
		log.Printf("watchdog yeniden başlatılamadı: %v", err)
		return
	}
	log.Printf("watchdog yeniden başlatıldı (pid=%d)", cmd.Process.Pid)
	// Zombie bırakmamak için arka planda bekle.
	go func() { _ = cmd.Wait() }()
}

func filterEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// runCertRenewal, ajanın istemci sertifikasını süre dolmadan yeniler. Ömrün
// son üçte birine girildiğinde enroll endpoint'ine mTLS ile bağlanıp yeniler,
// yeni cert+key'i diske yazar ve holder'ı günceller (canlı bağlantı eski cert
// hâlâ geçerli olduğu için etkilenmez; sonraki bağlantılar yeniyi kullanır).
func runCertRenewal(ctx context.Context, cfg envConfig, holder *transport.CertHolder, ident *identity) {
	nb, na, err := certrenew.ParseValidity(ident.certPEM)
	if err != nil {
		log.Printf("sertifika süresi çözülemedi, yenileme kapalı: %v", err)
		return
	}
	check := time.NewTicker(6 * time.Hour)
	defer check.Stop()
	for {
		if certrenew.ShouldRenew(nb, na, time.Now(), 1.0/3.0) {
			rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			certPEM, keyPEM, newNA, rerr := transport.Renew(rctx, cfg.enrollAddr, holder, ident.caPEM, cfg.serverName)
			cancel()
			if rerr != nil {
				log.Printf("sertifika yenileme başarısız (yeniden denenecek): %v", rerr)
			} else {
				_ = os.WriteFile(filepath.Join(cfg.dataDir, "agent.crt"), certPEM, 0o644)
				_ = os.WriteFile(filepath.Join(cfg.dataDir, "agent.key"), keyPEM, 0o600)
				nb, na = time.Now(), newNA
				log.Printf("sertifika yenilendi, yeni bitiş: %s", na.Format(time.RFC3339))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-check.C:
		}
	}
}

// fimTracker, izlenen yolların bütünlüğünü izler (FIM); ekleme/değiştirme/silme
// değişikliklerini SECURITY olayı olarak yayınlar. İlk tarama taban çizgisidir.
type fimTracker struct {
	paths []string
	tr    fim.Tracker
}

func (f *fimTracker) report(buf *collector.Buffer) {
	for _, ch := range f.tr.Diff(fim.Scan(f.paths)) {
		sev := "MEDIUM"
		if ch.Type == fim.Deleted {
			sev = "HIGH" // kritik dosya silinmesi daha yüksek öncelik
		}
		det := map[string]any{"fim": true, "path": ch.Path, "change": string(ch.Type)}
		if ch.Hash != "" {
			det["sha256"] = ch.Hash
		}
		if ch.OldHash != "" {
			det["old_sha256"] = ch.OldHash
		}
		buf.Add(collector.Event{
			Category:   "SECURITY",
			Severity:   sev,
			Message:    "dosya bütünlüğü değişikliği (" + string(ch.Type) + "): " + ch.Path,
			OccurredAt: time.Now(),
			Details:    det,
		})
	}
}

// dlpScanner, yapılandırılmış yolları (ör. USB bağlama noktaları) hassas veri (PII)
// sinyalleri için tarar (DLP). Bir dosyada kredi kartı/TCKN/IBAN/e-posta bulunursa
// POLICY_VIOLATION olayı üretir. GİZLİLİK: yalnız TÜR + SAYI raporlanır (ham hassas
// değer ASLA olaya yazılmaz — KVKK veri-minimizasyonu). (yol|dosya) başına bir kez.
type dlpScanner struct {
	paths   []string
	maxSize int64
	seen    map[string]bool
}

func (d *dlpScanner) scan(buf *collector.Buffer) {
	if d.seen == nil {
		d.seen = map[string]bool{}
	}
	for _, root := range d.paths {
		filepath.WalkDir(root, func(path string, de os.DirEntry, err error) error {
			if err != nil || de.IsDir() {
				return nil
			}
			info, err := de.Info()
			if err != nil || info.Size() == 0 || info.Size() > d.maxSize {
				return nil
			}
			if d.seen[path] {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			sigs := dlp.Scan(string(data))
			if len(sigs) == 0 {
				return nil
			}
			d.seen[path] = true
			// Redakte edilmiş özet (tür→sayı); ham değer yok.
			kinds := make([]any, 0, len(sigs))
			total := 0
			for _, s := range sigs {
				kinds = append(kinds, map[string]any{"kind": s.Kind, "count": s.Count})
				total += s.Count
			}
			buf.Add(collector.Event{
				Category:   "POLICY_VIOLATION",
				Severity:   "HIGH",
				Message:    fmt.Sprintf("DLP: hassas veri tespit edildi (%d sinyal): %s", total, path),
				OccurredAt: time.Now(),
				Details:    map[string]any{"dlp": true, "path": path, "signals": kinds},
			})
			return nil
		})
	}
}

// dnsTracker, uç noktanın DNS önbelleğini periyodik tarar; YENİ alan adlarını
// NETWORK_DISCOVERY, DGA-şüphelileri SECURITY olayı olarak bildirir. İlk tarama
// taban çizgisidir (mevcut önbellek gürültü üretmez). Yalnız-yeni felsefesi.
type dnsTracker struct {
	sc   dnsmon.Scanner
	seen map[string]bool
}

func (d *dnsTracker) report(buf *collector.Buffer) {
	names := d.sc.Scan()
	if d.seen == nil {
		// İlk tarama: mevcut önbelleği taban çizgisi say (olay üretme).
		d.seen = make(map[string]bool, len(names))
		for _, n := range names {
			d.seen[n] = true
		}
		return
	}
	for _, n := range names {
		if d.seen[n] {
			continue
		}
		d.seen[n] = true
		score := dnsmon.ScoreDomain(n)
		if score.Suspicious {
			buf.Add(collector.Event{
				Category:   "SECURITY",
				Severity:   "HIGH",
				Message:    "DGA-şüpheli DNS sorgusu: " + n,
				OccurredAt: time.Now(),
				Details: map[string]any{
					"dns": true, "domain": n, "dga_suspicious": true,
					"entropy": score.Entropy, "vowel_ratio": score.VowelRatio,
					"digit_ratio": score.DigitRatio, "max_consonant_run": score.MaxConsonantRun,
				},
			})
		} else {
			buf.Add(collector.Event{
				Category:   "NETWORK_DISCOVERY",
				Severity:   "INFO",
				Message:    "yeni DNS sorgusu: " + n,
				OccurredAt: time.Now(),
				Details:    map[string]any{"dns": true, "domain": n},
			})
		}
	}
}

// contentScanner, yapılandırılmış yolları imzalı içerik-tarama (YARA-tarzı)
// kurallarına karşı tarar; eşleşen dosyalar SECURITY olayı olarak yayınlanır.
// İçerik-tarama I/O-ağır olduğundan periyodik (uyum) kadansında çalışır. Aynı
// (yol|kural) eşleşmesi süreç ömrü boyunca yalnız BİR kez bildirilir (gürültü
// azaltma; kalıcılık izleyicisiyle aynı "yalnız-yeni" felsefesi).
type contentScanner struct {
	paths   []string
	rules   contentscan.RuleSet
	maxSize int64
	seen    map[string]bool // "path|rule" → bildirildi
}

func (c *contentScanner) scan(buf *collector.Buffer) {
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	for _, root := range c.paths {
		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // erişilemeyen girdiyi atla (tarama sürsün)
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() == 0 || info.Size() > c.maxSize {
				return nil // boş ya da çok büyük dosyayı atla
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, m := range c.rules.Scan(data) {
				key := path + "|" + m.Rule
				if c.seen[key] {
					continue
				}
				c.seen[key] = true
				sev := m.Severity
				if sev == "" {
					sev = "MEDIUM"
				}
				buf.Add(collector.Event{
					Category:   "SECURITY",
					Severity:   sev,
					Message:    "içerik-tarama eşleşmesi (" + m.Rule + "): " + path,
					OccurredAt: time.Now(),
					Details: map[string]any{
						"content_scan": true, "rule": m.Rule, "path": path, "hits": m.Hits,
					},
				})
			}
			return nil
		})
	}
}

// persistenceTracker, kalıcılık (autostart) noktalarını izler; YENİ girdileri
// POLICY_VIOLATION olayı olarak yayınlar (MITRE TA0003). İlk tarama taban çizgisidir.
type persistenceTracker struct {
	tr persistence.Tracker
}

func (p *persistenceTracker) report(buf *collector.Buffer) {
	p.emit(buf, p.tr.Diff(persistence.Scan()))
}

// emit, verilen yeni kalıcılık girdilerini olay olarak yayınlar (test edilebilir).
func (p *persistenceTracker) emit(buf *collector.Buffer, added []persistence.Entry) {
	for _, e := range added {
		det := map[string]any{"persistence": true, "kind": string(e.Kind), "name": e.Name}
		if e.Value != "" {
			det["value"] = e.Value
		}
		buf.Add(collector.Event{
			Category:   "POLICY_VIOLATION",
			Severity:   "HIGH",
			Message:    "yeni kalıcılık girdisi (" + string(e.Kind) + "): " + e.Name,
			OccurredAt: time.Now(),
			Details:    det,
		})
	}
}

// scanNetwork, komşu tablosunu tarar ve yeni tespit edilen cihazları
// NETWORK_DISCOVERY olayı olarak tamponlar. Yetkisiz cihazlar MEDIUM olarak
// işaretlenir.
// complianceInterval, uyum durumunun periyodik yeniden-kontrol aralığıdır.
const complianceInterval = 6 * time.Hour

// reportCompliance, CIS-tarzı güvenlik-tabanı (baseline) değerlendirmesini bir
// olay olarak yayınlar. HIGH/MEDIUM önemli herhangi bir kontrol başarısızsa
// güvenlik-duruşu ihlali (SECURITY/MEDIUM); aksi halde bilgi amaçlı (SYSTEM/INFO).
// Details, tam kontrol listesini + uyum skorunu taşır (konsol detay paneli +
// sunucu event_logs). Ham sinyaller de geriye-uyumluluk için Details'te tutulur.
func reportCompliance(buf *collector.Buffer, chk compliance.Checker) {
	rep := compliance.Evaluate(chk)

	// Kontrolleri Details için serileştirilebilir dilimlere çevir. structpb.NewStruct
	// yalnız []any kabul eder ([]map[string]any DEĞİL) — aksi halde tüm Details sessizce
	// düşer; bu yüzden dilim tipi []any olmalıdır.
	checks := make([]any, 0, len(rep.Checks))
	for _, c := range rep.Checks {
		checks = append(checks, map[string]any{
			"id": c.ID, "title": c.Title, "severity": c.Severity,
			"status": string(c.Status), "detail": c.Detail,
		})
	}

	cat, sev := "SYSTEM", "INFO"
	msg := fmt.Sprintf("uyum tabanı: skor %%%d (%d geçti, %d kaldı, %d bilinmiyor)",
		rep.ScorePct(), rep.Passed, rep.Failed, rep.Unknown)
	if rep.HasFailure() {
		cat, sev = "SECURITY", "MEDIUM"
		msg = "uyum ihlali (skor %" + fmt.Sprint(rep.ScorePct()) + "): " +
			strings.Join(rep.FailedTitles(), ", ")
	}
	buf.Add(collector.Event{
		Category:   cat,
		Severity:   sev,
		Message:    msg,
		OccurredAt: time.Now(),
		Details: map[string]any{
			"compliance_score": rep.ScorePct(),
			"passed":           rep.Passed,
			"failed":           rep.Failed,
			"unknown":          rep.Unknown,
			"checks":           checks,
			// Geriye-uyumluluk: ham sinyaller (mevcut konsol/sorgular bunlara bakabilir).
			"disk_encryption": chkDetail(rep, "CIS-1.1"),
			"firewall":        chkDetail(rep, "CIS-9.1"),
		},
	})
}

// chkDetail, rapordaki verilen ID'li kontrolün ham sinyalini döner (yoksa "unknown").
func chkDetail(rep compliance.Report, id string) string {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c.Detail
		}
	}
	return "unknown"
}

// reportResource, uç noktanın kaynak kullanımı anlık görüntüsünü (bellek/disk
// kullanımı + uptime) bir olay olarak yayınlar (uç-nokta sağlığı görünürlüğü).
// Bellek veya disk kritik eşiğin üstündeyse SECURITY/MEDIUM (duruş uyarısı),
// aksi halde SYSTEM/INFO. Details yüzdeleri taşır. Veri alınamazsa olay üretmez.
func reportResource(buf *collector.Buffer) {
	s := resource.Collect()
	if !s.OK {
		return
	}
	cat, sev := "SYSTEM", "INFO"
	msg := fmt.Sprintf("kaynak: bellek %%%d, disk %%%d, uptime %dsa", s.MemUsedPct, s.DiskUsedPct, s.UptimeHours)
	if s.MemUsedPct >= 90 || s.DiskUsedPct >= 90 {
		cat, sev = "SECURITY", "MEDIUM"
		msg = fmt.Sprintf("kaynak baskısı: bellek %%%d, disk %%%d", s.MemUsedPct, s.DiskUsedPct)
	}
	buf.Add(collector.Event{
		Category:   cat,
		Severity:   sev,
		Message:    msg,
		OccurredAt: time.Now(),
		Details: map[string]any{
			"mem_used_pct": s.MemUsedPct, "mem_total_mb": s.MemTotalMB,
			"disk_used_pct": s.DiskUsedPct, "disk_total_gb": s.DiskTotalGB,
			"uptime_hours": s.UptimeHours,
		},
	})
}

// reportInventory, yüklü yazılım envanterini bir olay olarak yayınlar (MDM varlık
// görünürlüğü). Details, paket listesini (maxPackages'a kırpılmış) ve toplam
// benzersiz sayıyı taşır. Envanter alınamazsa (desteksiz OS/araç yok) olay üretmez.
func reportInventory(buf *collector.Buffer) {
	list, total := inventory.Collect()
	if total == 0 {
		return // envanter yok — gürültü üretme
	}
	anyList := make([]any, len(list))
	for i, s := range list {
		anyList[i] = s
	}
	buf.Add(collector.Event{
		Category:   "SYSTEM",
		Severity:   "INFO",
		Message:    fmt.Sprintf("yazılım envanteri: %d paket", total),
		OccurredAt: time.Now(),
		Details:    map[string]any{"software": anyList, "software_count": total},
	})
}

// connTracker, ajan-ömrü boyunca görülen giden bağlantıları izler; yalnız YENİ
// bağlantılar NETWORK_CONN olayı olarak yayınlanır. İlk tarama taban çizgisidir.
type connTracker struct {
	seen      map[string]bool
	baselined bool
}

// report, mevcut giden bağlantıları tarar ve dedup mantığına devreder. OS tarama
// (netconn.Scan) burada; saf dedup mantığı reportConns'ta (test edilebilir).
func (t *connTracker) report(buf *collector.Buffer) {
	t.reportConns(buf, netconn.Scan())
}

// reportConns, verilen bağlantı kümesinden önceki tura göre YENİ olanları
// NETWORK_CONN/INFO olayı olarak yayınlar. İlk çağrı taban çizgisidir (olay yok).
func (t *connTracker) reportConns(buf *collector.Buffer, conns []netconn.Conn) {
	live := make(map[string]bool, len(conns))
	for _, c := range conns {
		live[c.Key()] = true
	}
	if !t.baselined {
		t.seen = live
		t.baselined = true
		return
	}
	for _, c := range conns {
		if t.seen[c.Key()] {
			continue
		}
		det := map[string]any{"remote_ip": c.RemoteIP, "remote_port": c.RemotePort, "local_port": c.LocalPort}
		if c.PID > 0 {
			det["pid"] = c.PID
		}
		buf.Add(collector.Event{
			Category:   "NETWORK_CONN",
			Severity:   "INFO",
			Message:    fmt.Sprintf("giden bağlantı: %s:%d (pid=%d)", c.RemoteIP, c.RemotePort, c.PID),
			OccurredAt: time.Now(),
			Details:    det,
		})
	}
	t.seen = live
}

// usbTracker, çıkarılabilir medya takar-takmaz (yeni sürücü) olay üretir.
// policy "audit" ise SECURITY/MEDIUM denetim olayı; "block" ise HIGH ve
// (güvenli-mod KAPALIYSA) engelleme uygulanır. İlk tarama taban çizgisidir.
type usbTracker struct {
	seen      map[string]bool
	baselined bool
	policy    string // "audit" | "block"
}

// report, çıkarılabilir medyayı tarar ve dedup mantığına devreder. OS tarama
// (usbmon.Scan) burada; saf dedup+politika mantığı reportDrives'ta (test edilebilir).
func (t *usbTracker) report(buf *collector.Buffer, safeMode bool) {
	t.reportDrives(buf, safeMode, usbmon.Scan())
}

// reportDrives, verilen sürücü kümesinden önceki tura göre YENİ olanlara politika
// (audit/block) uygular ve olay üretir. İlk çağrı taban çizgisidir (olay yok).
func (t *usbTracker) reportDrives(buf *collector.Buffer, safeMode bool, drives []usbmon.Drive) {
	live := make(map[string]bool, len(drives))
	for _, d := range drives {
		live[d.Key()] = true
	}
	if !t.baselined {
		t.seen = live
		t.baselined = true
		return
	}
	for _, d := range drives {
		if t.seen[d.Key()] {
			continue
		}
		sev := "MEDIUM"
		msg := "çıkarılabilir medya algılandı: " + d.ID
		if d.Label != "" {
			msg += " (" + d.Label + ")"
		}
		det := map[string]any{"drive": d.ID, "label": d.Label, "policy": t.policy}
		if t.policy == "block" {
			sev = "HIGH"
			msg = "çıkarılabilir medya politika ihlali (engelle): " + d.ID
			// Gerçek engelleme HEDEFLİ + geri döndürülebilir (mountvol /p ya da eject).
			// Güvenli-mod AÇIKKEN gerçek eylem uygulanmaz (yalnız olay) — demo/test'te
			// kullanıcı medyasını kesintiye uğratmaz.
			if safeMode {
				det["blocked"] = false
				det["note"] = "güvenli mod: gerçek engelleme uygulanmadı"
			} else if err := usbmon.Block(d.ID); err != nil {
				det["blocked"] = false
				det["error"] = err.Error()
				msg += " — engelleme başarısız"
			} else {
				det["blocked"] = true
			}
			buf.Add(collector.Event{Category: "POLICY_VIOLATION", Severity: sev, Message: msg, OccurredAt: time.Now(), Details: det})
		} else {
			buf.Add(collector.Event{Category: "SECURITY", Severity: sev, Message: msg, OccurredAt: time.Now(), Details: det})
		}
	}
	t.seen = live
}

func scanNetwork(src discovery.NeighborSource, tr *discovery.Tracker, buf *collector.Buffer) {
	hosts, err := src.Neighbors()
	if err != nil {
		return // keşif bu platformda yoksa sessizce geç
	}
	for _, d := range tr.Observe(hosts, time.Now()) {
		severity, label := "INFO", "yetkili"
		if !d.Authorized {
			severity, label = "MEDIUM", "YETKİSİZ"
		}
		buf.Add(collector.Event{
			Category:   "NETWORK_DISCOVERY",
			Severity:   severity,
			Message:    fmt.Sprintf("yeni cihaz (%s): %s / %s", label, d.Host.IP, d.Host.MAC),
			OccurredAt: time.Now(),
			Details:    map[string]any{"ip": d.Host.IP, "mac": d.Host.MAC, "authorized": d.Authorized},
		})
	}
}

// agentVersion, sürüm etiketidir. Release derlemesinde ldflags ile damgalanır:
//
//	-ldflags "-X main.agentVersion=1.0.0"
var agentVersion = "0.1.0-dev"

func protoCategory(s string) kutv1.EventCategory {
	if v, ok := kutv1.EventCategory_value["EVENT_CATEGORY_"+s]; ok {
		return kutv1.EventCategory(v)
	}
	return kutv1.EventCategory_EVENT_CATEGORY_SYSTEM
}

func protoSeverity(s string) kutv1.Severity {
	if v, ok := kutv1.Severity_value["SEVERITY_"+s]; ok {
		return kutv1.Severity(v)
	}
	return kutv1.Severity_SEVERITY_INFO
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getdur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// primaryMAC, ilk loopback olmayan arayüzün MAC adresini döner.
//
//nolint:unused // enroll.go tarafından kullanılır
func primaryMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) == 0 {
			continue
		}
		return i.HardwareAddr.String()
	}
	return ""
}
