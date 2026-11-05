// Package metrics, sunucu için bağımlılıksız Prometheus metin-exposition üretir.
// Harici bir kütüphane (client_golang) KULLANMAZ — süreç-içi atomik sayaçlar ve
// depodan alınan anlık gauge'lar elle Prometheus 0.0.4 metin formatında yazılır.
// Böylece dağıtılan ikiliye ek bağımlılık girmez (temiz izin-verici lisans
// envanteri korunur).
package metrics

import (
	"fmt"
	"io"
	"runtime"
	"sort"
	"sync/atomic"
	"time"
)

// startTime, süreç başlangıcı (uptime metriği için).
var startTime = time.Now()

// Süreç ömrü boyunca artan sayaçlar (atomik).
var (
	loginSuccess   atomic.Int64
	loginFailure   atomic.Int64
	eventsIngested atomic.Int64
	detections     atomic.Int64
	alertsRaised   atomic.Int64
	autoQuarantine atomic.Int64
	iocHits        atomic.Int64
	alertsSuppress atomic.Int64 // korelasyonla bastırılan yinelenen alarmlar
	thresholdGated atomic.Int64 // tekrar-eşiği aşılmadığı için alarma dönüşmeyen tespitler
	bitsGated      atomic.Int64 // çok-aşama ön-koşulu (bit) sağlanmadığı için bekletilen tespitler
	// Yatay ölçekleme küme fan-out sayaçları: yayınlanan (NOTIFY), alınan
	// (LISTEN→yerel dağıtım) ve yerel-dağıtıma-düşülen (NOTIFY başarısız). Fallback
	// sayacının artması DB'ye NOTIFY erişiminde sorun olduğunu gösterir.
	clusterPublished atomic.Int64
	clusterReceived  atomic.Int64
	clusterFallback  atomic.Int64
	chainFired       atomic.Int64 // çok-sinyal yüksek-güvenli saldırı zinciri tetiklemeleri
	lastIngestUnix   atomic.Int64 // son olay-alımının Unix saniyesi (boru-hattı canlılığı)
	lateralMovement  atomic.Int64 // yanal-hareket (netconn fan-out) tespitleri
	dnsTunnel        atomic.Int64 // DNS tünelleme tespitleri
	bruteForce       atomic.Int64 // kaba-kuvvet / parola-püskürtme tespitleri
	bruteForceWin    atomic.Int64 // BAŞARILI kaba-kuvvet (hesap ele geçirme) tespitleri
	savedSearchHits  atomic.Int64 // zamanlanmış kayıtlı-arama eşleşmeleri
	loginLockouts    atomic.Int64 // kaba-kuvvet kilidi tetiklemeleri (admin girişi)
	scopeDenied      atomic.Int64 // scope/ROE tarafından ENGELLENEN yüksek-etkili op (§4)
	scopeWouldDeny   atomic.Int64 // enforce KAPALIYKEN engellenecekti (danışma/tuning)
	cmdWouldDeny     atomic.Int64 // komut düzlemi AUDIT modunda engellenecekti (danışma)
	auditWriteFail   atomic.Int64 // denetim izi (tamper-evident) yazımı BAŞARISIZ — non-repudiation uyarısı
	eventsDuplicate  atomic.Int64 // yineleme-tespitiyle düşürülen olaylar (§6)
	eventsDeferred   atomic.Int64 // yazılamayıp ölü-mektup kuyruğuna alınan olaylar (§6 DLQ)
	verifyVerified   atomic.Int64 // remediation-doğrulama: sinyal doğrulanabilir biçimde kalktı (VERIFIED)
	verifyRegressed  atomic.Int64 // remediation-doğrulama: sinyal hâlâ tetikliyor (REGRESSED)
	verifyInconcl    atomic.Int64 // remediation-doğrulama: değerlendirilemedi — telemetri yok (INCONCLUSIVE)

	// Sınırlı bellek-içi durum: ajan/ingest kaynaklı graf + sekans modeli
	// agentsec grafı SERT tavanlıdır; tavan yüzünden reddedilen (dropped) ve LRU/TTL ile
	// atılan (evicted/pruned) girdiler burada sayılır. Artış = bir kiracı/cihaz tavana dayandı.
	graphDropped      atomic.Int64 // entitygraph: tavan/uzunluk/çapraz-kiracı nedeniyle reddedilen gözlem
	graphDevDropped   atomic.Int64 // entitygraph: cihaz bütçesi dolduğu için düşen yeni kenar (graph_dropped alt kümesi)
	graphEvicted      atomic.Int64 // entitygraph: kiracı tavanı aşılınca LRU ile atılan kenar
	graphPruned       atomic.Int64 // entitygraph: TTL süpürmesiyle atılan kenar
	graphFeedDropped  atomic.Int64 // besleyici: aşırı uzun dizge / derin zincir nedeniyle grafa girmeyen gözlem
	graphEdges        atomic.Int64 // gauge: toplam kenar
	graphNodes        atomic.Int64 // gauge: toplam düğüm
	seqDropped        atomic.Int64 // sekans modeli: tavan/uzunluk nedeniyle öğrenilmeyen geçiş
	seqEvicted        atomic.Int64 // sekans modeli: LRU ile atılan kaynak token
	seqPruned         atomic.Int64 // sekans modeli: TTL süpürmesiyle atılan kaynak token
	seqSources        atomic.Int64 // gauge: toplam kaynak token
	agentSecDropped   atomic.Int64 // aisec: tavan/uzunluk nedeniyle reddedilen düğüm/kenar
	analyzerSkipped   atomic.Int64 // arka plan analizörü bulgusu: kiracı çözülemedi → atlandı (fail-closed)
	incidentCaseSkip  atomic.Int64 // otomatik vaka açılışı: kiracı çözülemedi → atlandı (fail-closed)
	incidentCaseError atomic.Int64 // otomatik vaka açılışı: depo hatası (sessizce yutulmaz)
)

// certExpiryDays, CA+sunucu sertifikalarının EN AZ kalan günü (gauge). Sentinel 9999
// = henüz ayarlanmadı (ops alarmını tetiklemez).
var certExpiryDays atomic.Int64

func init() { certExpiryDays.Store(9999) }

// buildVersion, kut_build_info etiketinde raporlanan sürümdür.
var buildVersion = "dev"

// SetBuildVersion, build bilgisini ayarlar (main tarafından bir kez).
func SetBuildVersion(v string) {
	if v != "" {
		buildVersion = v
	}
}

// Version, raporlanan build sürümünü döner (sağlık ucu vb.).
func Version() string { return buildVersion }

// Counters, süreç-içi sayaçların anlık değerlerini döner (konsol etkinlik kartı
// gibi kimlik-doğrulanmış görünümler için; /metrics ile aynı kaynak).
func Counters() map[string]int64 {
	return map[string]int64{
		"login_success":       loginSuccess.Load(),
		"login_failure":       loginFailure.Load(),
		"events_ingested":     eventsIngested.Load(),
		"detections":          detections.Load(),
		"alerts_raised":       alertsRaised.Load(),
		"auto_quarantine":     autoQuarantine.Load(),
		"ioc_hits":            iocHits.Load(),
		"alerts_suppressed":   alertsSuppress.Load(),
		"threshold_gated":     thresholdGated.Load(),
		"bits_gated":          bitsGated.Load(),
		"cluster_published":   clusterPublished.Load(),
		"cluster_received":    clusterReceived.Load(),
		"cluster_fallback":    clusterFallback.Load(),
		"chain_fired":         chainFired.Load(),
		"lateral_movement":    lateralMovement.Load(),
		"dns_tunnel":          dnsTunnel.Load(),
		"graph_dropped":       graphDropped.Load(),
		"graph_evicted":       graphEvicted.Load(),
		"seqmodel_dropped":    seqDropped.Load(),
		"analyzer_skipped":    analyzerSkipped.Load(),
		"brute_force":         bruteForce.Load(),
		"brute_force_win":     bruteForceWin.Load(),
		"saved_search_hits":   savedSearchHits.Load(),
		"login_lockouts":      loginLockouts.Load(),
		"scope_denied":        scopeDenied.Load(),
		"scope_would_deny":    scopeWouldDeny.Load(),
		"cmd_would_deny":      cmdWouldDeny.Load(),
		"audit_write_fail":    auditWriteFail.Load(),
		"events_duplicate":    eventsDuplicate.Load(),
		"events_deferred":     eventsDeferred.Load(),
		"verify_verified":     verifyVerified.Load(),
		"verify_regressed":    verifyRegressed.Load(),
		"verify_inconclusive": verifyInconcl.Load(),
	}
}

// IncVerifyVerified, bir doğrulama check'i VERIFIED sonuçlandığında artar.
func IncVerifyVerified() { verifyVerified.Add(1) }

// IncVerifyRegressed, bir doğrulama check'i REGRESSED sonuçlandığında artar.
func IncVerifyRegressed() { verifyRegressed.Add(1) }

// IncVerifyInconclusive, bir doğrulama check'i INCONCLUSIVE (telemetri yok →
// değerlendirilemedi, fail-closed) sonuçlandığında artar. Yüksek oran = telemetri boşluğu.
func IncVerifyInconclusive() { verifyInconcl.Add(1) }

// UptimeSeconds, süreç çalışma süresini saniye olarak döner.
func UptimeSeconds() int64 { return int64(time.Since(startTime).Seconds()) }

// IncLoginSuccess / IncLoginFailure, giriş sonucu sayaçlarını artırır.
func IncLoginSuccess() { loginSuccess.Add(1) }
func IncLoginFailure() { loginFailure.Add(1) }

// AddEventsIngested, kabul edilen telemetri olayı sayacını artırır ve son-alım
// zaman damgasını günceller (boru-hattı canlılık gauge'ı için).
func AddEventsIngested(n int) {
	if n > 0 {
		eventsIngested.Add(int64(n))
		lastIngestUnix.Store(time.Now().Unix())
	}
}

// IncChainFired, çok-sinyal yüksek-güvenli saldırı-zinciri tetikleme sayacını artırır.
func IncChainFired() { chainFired.Add(1) }

// IncLateralMovement, yanal-hareket (netconn fan-out) tespit sayacını artırır.
func IncLateralMovement() { lateralMovement.Add(1) }

// IncDNSTunnel, DNS tünelleme tespit sayacını artırır.
func IncDNSTunnel() { dnsTunnel.Add(1) }

// SetGraphStats, varlık grafının kümülatif sayaçlarını ve anlık boyutunu yayınlar (mutlak
// değerler; graf kendi sayaçlarını tutar, app periyodik eşitler).
func SetGraphStats(dropped, evicted, pruned, edges, nodes int64) {
	graphDropped.Store(dropped)
	graphEvicted.Store(evicted)
	graphPruned.Store(pruned)
	graphEdges.Store(edges)
	graphNodes.Store(nodes)
}

// SetGraphDeviceDropped, cihaz başına kenar bütçesi dolduğu için düşen yeni kenarların kümülatif
// sayısını yayınlar (mutlak değer; tek bir ajanın graf selinin göstergesi).
func SetGraphDeviceDropped(n int64) { graphDevDropped.Store(n) }

// SetSeqModelStats, sekans modelinin kümülatif sayaçlarını ve anlık boyutunu yayınlar.
func SetSeqModelStats(dropped, evicted, pruned, sources int64) {
	seqDropped.Store(dropped)
	seqEvicted.Store(evicted)
	seqPruned.Store(pruned)
	seqSources.Store(sources)
}

// AddGraphFeedDropped, graf besleyicisinin (uzunluk/derinlik tavanı nedeniyle) atladığı gözlemleri sayar.
func AddGraphFeedDropped(n int) { graphFeedDropped.Add(int64(n)) }

// AddAgentSecDropped, aisec grafının tavan nedeniyle reddettiği düğüm/kenar sayısını artırır.
func AddAgentSecDropped(n int) { agentSecDropped.Add(int64(n)) }

// IncAnalyzerSkipped, kiracısı çözülemediği için atlanan arka plan analizörü bulgusunu sayar.
func IncAnalyzerSkipped() { analyzerSkipped.Add(1) }

// IncIncidentCaseSkipped, kiracı çözülemediği için açılmayan otomatik vakayı sayar.
func IncIncidentCaseSkipped() { incidentCaseSkip.Add(1) }

// IncIncidentCaseError, otomatik vaka açılışındaki depo hatasını sayar.
func IncIncidentCaseError() { incidentCaseError.Add(1) }

// IncBruteForce, kaba-kuvvet / parola-püskürtme tespit sayacını artırır.
func IncBruteForce() { bruteForce.Add(1) }

// IncBruteForceSuccess, BAŞARILI kaba-kuvvet (olası hesap ele geçirme) sayacını artırır.
func IncBruteForceSuccess() { bruteForceWin.Add(1) }

// AddSavedSearchHits, zamanlanmış kayıtlı-arama eşleşme sayacını artırır.
func AddSavedSearchHits(n int) {
	if n > 0 {
		savedSearchHits.Add(int64(n))
	}
}

// IncLoginLockout, kaba-kuvvet kilidi (admin girişi) tetikleme sayacını artırır.
func IncLoginLockout() { loginLockouts.Add(1) }

// IncScopeDenied, scope/ROE tarafından ENGELLENEN yüksek-etkili operasyon sayacını
// artırır (§4 — enforce açık ve karar RED).
func IncScopeDenied() { scopeDenied.Add(1) }

// IncScopeWouldDeny, enforce KAPALIYKEN scope/ROE'nin engelleyeceği (ama izin verilen)
// operasyon sayacını artırır — operatörün politika ayarı (tuning) için danışma sinyali.
func IncScopeWouldDeny() { scopeWouldDeny.Add(1) }

// IncCommandPlaneWouldDeny, komut düzleminin AUDIT modunda (KUT_SCOPE_ENFORCE kapalı) scope/ROE
// kararının RED olacağı ama izin verilen komut sayacını artırır (danışma sinyali).
func IncCommandPlaneWouldDeny() { cmdWouldDeny.Add(1) }

// IncAuditWriteFailure, tamper-evident denetim izine bir kayıt YAZILAMADIĞINDA artırılır
// (non-repudiation açığı sinyali — güvenlik operasyonu audit kaydı olmadan gerçekleşti).
func IncAuditWriteFailure() { auditWriteFail.Add(1) }

// AddEventsDuplicate, yineleme-tespitiyle (§6) düşürülen olay sayacını artırır.
func AddEventsDuplicate(n int) {
	if n > 0 {
		eventsDuplicate.Add(int64(n))
	}
}

// AddEventsDeferred, yazılamayıp ölü-mektup kuyruğuna (§6 DLQ) alınan olay sayacını artırır.
func AddEventsDeferred(n int) {
	if n > 0 {
		eventsDeferred.Add(int64(n))
	}
}

// SetCertExpiryDays, CA+sunucu sertifikalarının EN AZ kalan gününü (gauge) ayarlar.
func SetCertExpiryDays(d int) { certExpiryDays.Store(int64(d)) }

// AddDetections, kural-eşleşmeli tespit sayacını artırır (sunucu-taraflı motor).
func AddDetections(n int) {
	if n > 0 {
		detections.Add(int64(n))
	}
}

// IncAlertRaised, üretilen (SOC'a gönderilmeye aday) uyarı sayacını artırır.
func IncAlertRaised() { alertsRaised.Add(1) }

// IncAutoQuarantine, otomatik karantina (SOAR) sayacını artırır.
func IncAutoQuarantine() { autoQuarantine.Add(1) }

// IncIocHit, tehdit istihbaratı (IoC) eşleşme sayacını artırır.
func IncIocHit() { iocHits.Add(1) }

// IncAlertSuppressed, korelasyonla bastırılan yinelenen alarm sayacını artırır.
func IncAlertSuppressed() { alertsSuppress.Add(1) }

// IncThresholdGated, tekrar-eşiği (threshold) aşılmadığı için henüz alarma
// dönüşmeyen tespit sayacını artırır (brute-force/tarama biriktirme görünürlüğü).
func IncThresholdGated() { thresholdGated.Add(1) }

// IncBitsGated, çok-aşama ön-koşulu (require bit) sağlanmadığı için bekletilen
// tespit sayacını artırır (aşamalı-saldırı kapılama görünürlüğü).
func IncBitsGated() { bitsGated.Add(1) }

// IncClusterPublished, kümeye NOTIFY ile yayınlanan bildirim sayacını artırır.
func IncClusterPublished() { clusterPublished.Add(1) }

// IncClusterReceived, LISTEN'den alınıp yerel dağıtılan bildirim sayacını artırır.
func IncClusterReceived() { clusterReceived.Add(1) }

// IncClusterFallback, NOTIFY başarısız olup yerel dağıtıma düşülen sayacını artırır.
func IncClusterFallback() { clusterFallback.Add(1) }

// Snapshot, /metrics çıktısını üretmek için depodan alınan anlık gauge'lardır.
// Sayaçlar (login/olay) paket içinden okunur; gauge'lar çağıran tarafından
// (özet + aktif SSE) doldurulur.
type Snapshot struct {
	DevicesTotal       int
	DevicesOnline      int
	DevicesOffline     int
	DevicesQuarantined int
	EventsBySeverity   map[string]int
	SSEConnections     int
}

// Write, verilen anlık görüntüyü Prometheus metin formatında w'ye yazar.
func Write(w io.Writer, s Snapshot) {
	fmt.Fprintf(w, "# HELP kut_build_info Sürüm bilgisi (etiket).\n")
	fmt.Fprintf(w, "# TYPE kut_build_info gauge\n")
	fmt.Fprintf(w, "kut_build_info{version=%q} 1\n", buildVersion)

	fmt.Fprintf(w, "# HELP kut_login_success_total Başarılı admin girişleri.\n")
	fmt.Fprintf(w, "# TYPE kut_login_success_total counter\n")
	fmt.Fprintf(w, "kut_login_success_total %d\n", loginSuccess.Load())

	fmt.Fprintf(w, "# HELP kut_login_failure_total Başarısız admin giriş denemeleri.\n")
	fmt.Fprintf(w, "# TYPE kut_login_failure_total counter\n")
	fmt.Fprintf(w, "kut_login_failure_total %d\n", loginFailure.Load())

	fmt.Fprintf(w, "# HELP kut_events_ingested_total Kabul edilen telemetri olayları.\n")
	fmt.Fprintf(w, "# TYPE kut_events_ingested_total counter\n")
	fmt.Fprintf(w, "kut_events_ingested_total %d\n", eventsIngested.Load())

	fmt.Fprintf(w, "# HELP kut_detections_total Kural-eşleşmeli sunucu-taraflı tespitler.\n")
	fmt.Fprintf(w, "# TYPE kut_detections_total counter\n")
	fmt.Fprintf(w, "kut_detections_total %d\n", detections.Load())

	fmt.Fprintf(w, "# HELP kut_alerts_raised_total Üretilen SOC uyarıları.\n")
	fmt.Fprintf(w, "# TYPE kut_alerts_raised_total counter\n")
	fmt.Fprintf(w, "kut_alerts_raised_total %d\n", alertsRaised.Load())

	fmt.Fprintf(w, "# HELP kut_auto_quarantine_total Otomatik karantina (SOAR) eylemleri.\n")
	fmt.Fprintf(w, "# TYPE kut_auto_quarantine_total counter\n")
	fmt.Fprintf(w, "kut_auto_quarantine_total %d\n", autoQuarantine.Load())

	fmt.Fprintf(w, "# HELP kut_ioc_hits_total Tehdit istihbaratı (IoC) eşleşmeleri.\n")
	fmt.Fprintf(w, "# TYPE kut_ioc_hits_total counter\n")
	fmt.Fprintf(w, "kut_ioc_hits_total %d\n", iocHits.Load())

	fmt.Fprintf(w, "# HELP kut_alerts_suppressed_total Korelasyonla bastırılan yinelenen alarmlar.\n")
	fmt.Fprintf(w, "# TYPE kut_alerts_suppressed_total counter\n")
	fmt.Fprintf(w, "kut_alerts_suppressed_total %d\n", alertsSuppress.Load())

	fmt.Fprintf(w, "# HELP kut_threshold_gated_total Tekrar-eşiği aşılmadığı için alarma dönüşmeyen tespitler.\n")
	fmt.Fprintf(w, "# TYPE kut_threshold_gated_total counter\n")
	fmt.Fprintf(w, "kut_threshold_gated_total %d\n", thresholdGated.Load())

	fmt.Fprintf(w, "# HELP kut_bits_gated_total Çok-aşama ön-koşulu sağlanmadığı için bekletilen tespitler.\n")
	fmt.Fprintf(w, "# TYPE kut_bits_gated_total counter\n")
	fmt.Fprintf(w, "kut_bits_gated_total %d\n", bitsGated.Load())

	fmt.Fprintf(w, "# HELP kut_cluster_notices_total Küme fan-out bildirimleri (yön etiketli, HA).\n")
	fmt.Fprintf(w, "# TYPE kut_cluster_notices_total counter\n")
	fmt.Fprintf(w, "kut_cluster_notices_total{direction=\"published\"} %d\n", clusterPublished.Load())
	fmt.Fprintf(w, "kut_cluster_notices_total{direction=\"received\"} %d\n", clusterReceived.Load())
	fmt.Fprintf(w, "kut_cluster_notices_total{direction=\"fallback\"} %d\n", clusterFallback.Load())

	fmt.Fprintf(w, "# HELP kut_chain_fired_total Çok-sinyal yüksek-güvenli saldırı zinciri tetiklemeleri.\n")
	fmt.Fprintf(w, "# TYPE kut_chain_fired_total counter\n")
	fmt.Fprintf(w, "kut_chain_fired_total %d\n", chainFired.Load())

	fmt.Fprintf(w, "# HELP kut_lateral_movement_total Yanal-hareket (netconn fan-out) tespitleri.\n")
	fmt.Fprintf(w, "# TYPE kut_lateral_movement_total counter\n")
	fmt.Fprintf(w, "kut_lateral_movement_total %d\n", lateralMovement.Load())

	fmt.Fprintf(w, "# HELP kut_dns_tunnel_total DNS tünelleme tespitleri.\n")
	fmt.Fprintf(w, "# TYPE kut_dns_tunnel_total counter\n")
	fmt.Fprintf(w, "kut_dns_tunnel_total %d\n", dnsTunnel.Load())

	fmt.Fprintf(w, "# HELP kut_graph_dropped_total Varlık grafı: tavan/uzunluk/çapraz-kiracı nedeniyle reddedilen gözlemler.\n")
	fmt.Fprintf(w, "# TYPE kut_graph_dropped_total counter\n")
	fmt.Fprintf(w, "kut_graph_dropped_total %d\n", graphDropped.Load())
	fmt.Fprintf(w, "# HELP kut_graph_device_dropped_total Varlık grafı: cihaz başına kenar bütçesi dolduğu için düşen yeni kenarlar (ajan sel göstergesi).\n")
	fmt.Fprintf(w, "# TYPE kut_graph_device_dropped_total counter\n")
	fmt.Fprintf(w, "kut_graph_device_dropped_total %d\n", graphDevDropped.Load())
	fmt.Fprintf(w, "# HELP kut_graph_feed_dropped_total Graf besleyicisi: aşırı uzun dizge / derin parent_chain nedeniyle atlanan gözlemler.\n")
	fmt.Fprintf(w, "# TYPE kut_graph_feed_dropped_total counter\n")
	fmt.Fprintf(w, "kut_graph_feed_dropped_total %d\n", graphFeedDropped.Load())
	fmt.Fprintf(w, "# HELP kut_graph_evicted_total Varlık grafı: kiracı tavanı aşılınca LRU ile atılan kenarlar.\n")
	fmt.Fprintf(w, "# TYPE kut_graph_evicted_total counter\n")
	fmt.Fprintf(w, "kut_graph_evicted_total %d\n", graphEvicted.Load())
	fmt.Fprintf(w, "# HELP kut_graph_pruned_total Varlık grafı: TTL süpürmesiyle atılan kenarlar.\n")
	fmt.Fprintf(w, "# TYPE kut_graph_pruned_total counter\n")
	fmt.Fprintf(w, "kut_graph_pruned_total %d\n", graphPruned.Load())
	fmt.Fprintf(w, "# HELP kut_graph_size Varlık grafı boyutu (kenar/düğüm).\n")
	fmt.Fprintf(w, "# TYPE kut_graph_size gauge\n")
	fmt.Fprintf(w, "kut_graph_size{kind=\"edges\"} %d\n", graphEdges.Load())
	fmt.Fprintf(w, "kut_graph_size{kind=\"nodes\"} %d\n", graphNodes.Load())
	fmt.Fprintf(w, "# HELP kut_seqmodel_dropped_total Sekans modeli: tavan/uzunluk nedeniyle öğrenilmeyen geçişler.\n")
	fmt.Fprintf(w, "# TYPE kut_seqmodel_dropped_total counter\n")
	fmt.Fprintf(w, "kut_seqmodel_dropped_total %d\n", seqDropped.Load())
	fmt.Fprintf(w, "# HELP kut_seqmodel_evicted_total Sekans modeli: LRU/TTL ile atılan kaynak tokenlar.\n")
	fmt.Fprintf(w, "# TYPE kut_seqmodel_evicted_total counter\n")
	fmt.Fprintf(w, "kut_seqmodel_evicted_total{reason=\"lru\"} %d\n", seqEvicted.Load())
	fmt.Fprintf(w, "kut_seqmodel_evicted_total{reason=\"ttl\"} %d\n", seqPruned.Load())
	fmt.Fprintf(w, "# HELP kut_seqmodel_sources Sekans modeli kaynak token sayısı.\n")
	fmt.Fprintf(w, "# TYPE kut_seqmodel_sources gauge\n")
	fmt.Fprintf(w, "kut_seqmodel_sources %d\n", seqSources.Load())
	fmt.Fprintf(w, "# HELP kut_agentsec_dropped_total Agent causality grafı: tavan/uzunluk nedeniyle reddedilen düğüm/kenar.\n")
	fmt.Fprintf(w, "# TYPE kut_agentsec_dropped_total counter\n")
	fmt.Fprintf(w, "kut_agentsec_dropped_total %d\n", agentSecDropped.Load())
	fmt.Fprintf(w, "# HELP kut_analyzer_skipped_total Kiracısı çözülemediği için atlanan arka plan analizörü bulguları (fail-closed).\n")
	fmt.Fprintf(w, "# TYPE kut_analyzer_skipped_total counter\n")
	fmt.Fprintf(w, "kut_analyzer_skipped_total %d\n", analyzerSkipped.Load())
	fmt.Fprintf(w, "# HELP kut_incident_case_total Otomatik vaka açılışı: atlanan (kiracı çözülemedi) ve hatalı.\n")
	fmt.Fprintf(w, "# TYPE kut_incident_case_total counter\n")
	fmt.Fprintf(w, "kut_incident_case_total{result=\"skipped\"} %d\n", incidentCaseSkip.Load())
	fmt.Fprintf(w, "kut_incident_case_total{result=\"error\"} %d\n", incidentCaseError.Load())

	fmt.Fprintf(w, "# HELP kut_brute_force_total Kaba-kuvvet / parola-püskürtme tespitleri.\n")
	fmt.Fprintf(w, "# TYPE kut_brute_force_total counter\n")
	fmt.Fprintf(w, "kut_brute_force_total %d\n", bruteForce.Load())

	fmt.Fprintf(w, "# HELP kut_brute_force_success_total Başarılı kaba-kuvvet (olası hesap ele geçirme) tespitleri.\n")
	fmt.Fprintf(w, "# TYPE kut_brute_force_success_total counter\n")
	fmt.Fprintf(w, "kut_brute_force_success_total %d\n", bruteForceWin.Load())

	fmt.Fprintf(w, "# HELP kut_saved_search_hits_total Zamanlanmış kayıtlı-arama eşleşmeleri.\n")
	fmt.Fprintf(w, "# TYPE kut_saved_search_hits_total counter\n")
	fmt.Fprintf(w, "kut_saved_search_hits_total %d\n", savedSearchHits.Load())

	fmt.Fprintf(w, "# HELP kut_scope_denied_total Scope/ROE tarafından engellenen yüksek-etkili operasyonlar (§4).\n")
	fmt.Fprintf(w, "# TYPE kut_scope_denied_total counter\n")
	fmt.Fprintf(w, "kut_scope_denied_total %d\n", scopeDenied.Load())

	fmt.Fprintf(w, "# HELP kut_scope_would_deny_total Enforce kapalıyken scope/ROE'nin engelleyeceği operasyonlar (danışma).\n")
	fmt.Fprintf(w, "# TYPE kut_scope_would_deny_total counter\n")
	fmt.Fprintf(w, "kut_scope_would_deny_total %d\n", scopeWouldDeny.Load())

	fmt.Fprintf(w, "# HELP kut_command_plane_would_deny_total Komut düzlemi audit modunda scope/ROE reddedecekti ama izin verilen komutlar (danışma).\n")
	fmt.Fprintf(w, "# TYPE kut_command_plane_would_deny_total counter\n")
	fmt.Fprintf(w, "kut_command_plane_would_deny_total %d\n", cmdWouldDeny.Load())

	fmt.Fprintf(w, "# HELP kut_audit_write_fail_total Tamper-evident denetim izi yazımı başarısızlıkları (non-repudiation uyarısı).\n")
	fmt.Fprintf(w, "# TYPE kut_audit_write_fail_total counter\n")
	fmt.Fprintf(w, "kut_audit_write_fail_total %d\n", auditWriteFail.Load())

	fmt.Fprintf(w, "# HELP kut_events_duplicate_total Yineleme-tespitiyle düşürülen olaylar (§6).\n")
	fmt.Fprintf(w, "# TYPE kut_events_duplicate_total counter\n")
	fmt.Fprintf(w, "kut_events_duplicate_total %d\n", eventsDuplicate.Load())

	fmt.Fprintf(w, "# HELP kut_events_deferred_total Yazılamayıp ölü-mektup kuyruğuna alınan olaylar (§6 DLQ).\n")
	fmt.Fprintf(w, "# TYPE kut_events_deferred_total counter\n")
	fmt.Fprintf(w, "kut_events_deferred_total %d\n", eventsDeferred.Load())

	fmt.Fprintf(w, "# HELP kut_verify_verified_total Remediation-doğrulama: sinyal doğrulanabilir biçimde kalktı.\n")
	fmt.Fprintf(w, "# TYPE kut_verify_verified_total counter\n")
	fmt.Fprintf(w, "kut_verify_verified_total %d\n", verifyVerified.Load())

	fmt.Fprintf(w, "# HELP kut_verify_regressed_total Remediation-doğrulama: sinyal hâlâ tetikliyor (düzelme yok).\n")
	fmt.Fprintf(w, "# TYPE kut_verify_regressed_total counter\n")
	fmt.Fprintf(w, "kut_verify_regressed_total %d\n", verifyRegressed.Load())

	fmt.Fprintf(w, "# HELP kut_verify_inconclusive_total Remediation-doğrulama: telemetri yok → değerlendirilemedi (fail-closed).\n")
	fmt.Fprintf(w, "# TYPE kut_verify_inconclusive_total counter\n")
	fmt.Fprintf(w, "kut_verify_inconclusive_total %d\n", verifyInconcl.Load())

	fmt.Fprintf(w, "# HELP kut_login_lockouts_total Kaba-kuvvet kilidi (admin girişi) tetiklemeleri.\n")
	fmt.Fprintf(w, "# TYPE kut_login_lockouts_total counter\n")
	fmt.Fprintf(w, "kut_login_lockouts_total %d\n", loginLockouts.Load())

	// Sertifika ömrü (gauge): CA+sunucu sertifikalarının EN AZ kalan günü. Prometheus
	// alarmı için ideal (ör. < 14 → uyarı). Negatif = süresi dolmuş.
	fmt.Fprintf(w, "# HELP kut_cert_expiry_days CA/sunucu sertifikalarının en az kalan günü.\n")
	fmt.Fprintf(w, "# TYPE kut_cert_expiry_days gauge\n")
	fmt.Fprintf(w, "kut_cert_expiry_days %d\n", certExpiryDays.Load())

	// Boru-hattı canlılığı: son olay-alımından bu yana geçen saniye. Uzun süre
	// artıyorsa ajan/alım yolu durmuş olabilir (ops alarmı için ideal gauge).
	fmt.Fprintf(w, "# HELP kut_seconds_since_last_ingest Son telemetri alımından bu yana saniye (-1 = hiç).\n")
	fmt.Fprintf(w, "# TYPE kut_seconds_since_last_ingest gauge\n")
	if li := lastIngestUnix.Load(); li > 0 {
		fmt.Fprintf(w, "kut_seconds_since_last_ingest %d\n", time.Now().Unix()-li)
	} else {
		fmt.Fprintf(w, "kut_seconds_since_last_ingest -1\n")
	}

	fmt.Fprintf(w, "# HELP kut_devices Cihaz sayıları (duruma göre).\n")
	fmt.Fprintf(w, "# TYPE kut_devices gauge\n")
	fmt.Fprintf(w, "kut_devices{state=\"total\"} %d\n", s.DevicesTotal)
	fmt.Fprintf(w, "kut_devices{state=\"online\"} %d\n", s.DevicesOnline)
	fmt.Fprintf(w, "kut_devices{state=\"offline\"} %d\n", s.DevicesOffline)
	fmt.Fprintf(w, "kut_devices{state=\"quarantined\"} %d\n", s.DevicesQuarantined)

	fmt.Fprintf(w, "# HELP kut_events_by_severity Son penceredeki olaylar (önem düzeyine göre).\n")
	fmt.Fprintf(w, "# TYPE kut_events_by_severity gauge\n")
	sevs := make([]string, 0, len(s.EventsBySeverity))
	for k := range s.EventsBySeverity {
		sevs = append(sevs, k)
	}
	sort.Strings(sevs) // deterministik çıktı (test edilebilirlik)
	for _, sev := range sevs {
		fmt.Fprintf(w, "kut_events_by_severity{severity=%q} %d\n", sev, s.EventsBySeverity[sev])
	}

	fmt.Fprintf(w, "# HELP kut_sse_connections Aktif konsol SSE akış bağlantıları.\n")
	fmt.Fprintf(w, "# TYPE kut_sse_connections gauge\n")
	fmt.Fprintf(w, "kut_sse_connections %d\n", s.SSEConnections)

	// Çalışma-zamanı (ops) — bağımlılıksız Go runtime metrikleri.
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Fprintf(w, "# HELP kut_uptime_seconds Süreç çalışma süresi (saniye).\n")
	fmt.Fprintf(w, "# TYPE kut_uptime_seconds gauge\n")
	fmt.Fprintf(w, "kut_uptime_seconds %d\n", int64(time.Since(startTime).Seconds()))
	fmt.Fprintf(w, "# HELP kut_goroutines Aktif goroutine sayısı.\n")
	fmt.Fprintf(w, "# TYPE kut_goroutines gauge\n")
	fmt.Fprintf(w, "kut_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "# HELP kut_memory_alloc_bytes Ayrılmış heap belleği (bayt).\n")
	fmt.Fprintf(w, "# TYPE kut_memory_alloc_bytes gauge\n")
	fmt.Fprintf(w, "kut_memory_alloc_bytes %d\n", ms.Alloc)
}
