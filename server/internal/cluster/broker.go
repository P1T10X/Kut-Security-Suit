// Package cluster, C2 sunucusunu yatay ölçeklenebilir (çok-düğümlü) kılar.
//
// Tek-düğüm modunda canlı konsol akışı (SSE) bellek-içi bir yayın-abone ile
// çalışır: bir ajanın olayı YALNIZCA o ajanın bağlı olduğu düğümdeki abonelere
// ulaşır. Yük dengeleyici arkasında birden çok C2 düğümü varsa, A düğümüne gelen
// olay B düğümündeki admin SSE akışına ulaşmaz.
//
// Broker bu boşluğu Postgres LISTEN/NOTIFY ile kapatır: her düğüm yayınlarını
// paylaşılan bir kanala NOTIFY eder ve aynı kanalı LISTEN ile dinleyip gelen
// bildirimleri KENDİ yerel abonelerine dağıtır. Böylece hangi düğüme bağlı olursa
// olsun tüm adminler tüm olayları görür. Yayıncı düğüm de kendi NOTIFY'ını geri
// alır; bu yüzden dağıtım için tek bir yol (LISTEN→Deliver) vardır ve çift teslim
// olmaz.
package cluster

import (
	"context"
	"encoding/json"
	"time"

	"kut.corp/suite/server/internal/eventbus"
)

// NotifyBus, Postgres LISTEN/NOTIFY ilkelini soyutlar (db.Store karşılar).
type NotifyBus interface {
	NotifyChannel(ctx context.Context, channel, payload string) error
	ListenChannel(ctx context.Context, channel string, onPayload func(string)) error
}

// LocalDeliverer, bir bildirimi bu düğümdeki yerel abonelere dağıtır
// (*eventbus.Bus.Deliver karşılar).
type LocalDeliverer interface {
	Deliver(eventbus.Notice)
}

// maxPayload, tek bir NOTIFY yükü için güvenli üst sınırdır. Postgres sınırı
// 8000 bayttır; mesajı buna göre kırparız.
const maxPayload = 7000

// Broker, eventbus'ı düğümler arasında köprüler.
type Broker struct {
	appCtx  context.Context
	bus     NotifyBus
	local   LocalDeliverer
	channel string
	log     func(string)
	// Gözlemlenebilirlik kancaları (varsayılan no-op; main metrics'e bağlar). Broker
	// birim testlerinin global sayaç durumuna dokunmaması için enjekte edilir.
	onPublished func()
	onReceived  func()
	onFallback  func()
}

// New oluşturur. channel boşsa "kut_notice" kullanılır; log nil ise sessizdir.
func New(appCtx context.Context, bus NotifyBus, local LocalDeliverer, channel string, log func(string)) *Broker {
	if channel == "" {
		channel = "kut_notice"
	}
	if log == nil {
		log = func(string) {}
	}
	noop := func() {}
	return &Broker{appCtx: appCtx, bus: bus, local: local, channel: channel, log: log,
		onPublished: noop, onReceived: noop, onFallback: noop}
}

// SetMetrics, fan-out gözlemlenebilirlik kancalarını bağlar. nil kanca no-op.
func (b *Broker) SetMetrics(onPublished, onReceived, onFallback func()) {
	set := func(dst *func(), fn func()) {
		if fn != nil {
			*dst = fn
		}
	}
	set(&b.onPublished, onPublished)
	set(&b.onReceived, onReceived)
	set(&b.onFallback, onFallback)
}

// Publish, eventbus.Bus'ın sink'i olarak takılır: bildirimi kümeye NOTIFY eder.
// NOTIFY başarısız olursa (DB geçici erişilemez) en azından bu düğümün adminleri
// akışı kaçırmasın diye yerel dağıtıma düşer.
func (b *Broker) Publish(n eventbus.Notice) {
	payload, err := json.Marshal(n)
	if err != nil {
		b.log("bildirim serileştirilemedi: " + err.Error())
		b.local.Deliver(n)
		return
	}
	if len(payload) > maxPayload && len(n.Message) > 0 {
		// Mesajı kırp ve yeniden serileştir (yalnızca mesaj büyük olabilir).
		over := len(payload) - maxPayload
		if over < len(n.Message) {
			n.Message = n.Message[:len(n.Message)-over-1] + "…"
			payload, _ = json.Marshal(n)
		}
	}
	ctx, cancel := context.WithTimeout(b.appCtx, 5*time.Second)
	defer cancel()
	if err := b.bus.NotifyChannel(ctx, b.channel, string(payload)); err != nil {
		b.log("küme NOTIFY başarısız, yerel dağıtıma düşülüyor: " + err.Error())
		b.onFallback()
		b.local.Deliver(n)
		return
	}
	b.onPublished()
}

// Run, LISTEN döngüsünü çalıştırır: gelen her bildirimi çözüp yerel abonelere
// dağıtır. Bağlantı düşerse (ctx iptal edilmedikçe) kısa bir bekleyişle yeniden
// bağlanır. ctx bitene dek BLOKLAR — çağıran ayrı goroutine'de çalıştırmalıdır.
func (b *Broker) Run(ctx context.Context) {
	for {
		err := b.bus.ListenChannel(ctx, b.channel, func(payload string) {
			var n eventbus.Notice
			if err := json.Unmarshal([]byte(payload), &n); err != nil {
				b.log("bozuk bildirim yükü atlandı: " + err.Error())
				return
			}
			b.onReceived()
			b.local.Deliver(n)
		})
		if ctx.Err() != nil {
			return // temiz kapanış
		}
		b.log("küme LISTEN kesildi, yeniden bağlanılıyor: " + errStr(err))
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func errStr(err error) string {
	if err == nil {
		return "bilinmeyen"
	}
	return err.Error()
}
