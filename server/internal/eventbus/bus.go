// Package eventbus, ajan-kaynaklı değişiklikleri (yeni olay, cihaz yaşam sinyali)
// admin konsoluna SSE ile iletmek için hafif bir yayın-abone (pub/sub) sağlar.
// Yavaş bir abone yayıncıyı BLOKLAMAZ: kanal doluysa bildirim atlanır (konsol
// zaten periyodik yenileme ile tutarlılığı yakalar).
package eventbus

import (
	"sync"
	"time"
)

// Notice, konsola iletilen hafif değişiklik bildirimidir.
type Notice struct {
	Type     string    `json:"type"` // "event" | "device"
	DeviceID string    `json:"device_id,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Message  string    `json:"message,omitempty"`
	At       time.Time `json:"at"`
	// TenantID (opsiyonel): olayı üreten kimlik-doğrulanmış cihazın kiracısı. SUNUCU-TARAFI
	// bağlanır (asla client'tan), çok-tenant veri-düzlemi izolasyonu için dayanıklı bus üzerinden
	// ingest'e taşınır. Boş → tek-tenant (ingest yapılandırılan KUT_TENANT'a düşer). Alan additive:
	// tüm DurableLog backend'leri JSON serileştirir → geriye-uyumlu; frozen DurableLog imzası değişmez.
	TenantID string `json:"tenant_id,omitempty"`
}

// Bus, abonelere bildirim yayınlar.
type Bus struct {
	mu   sync.Mutex
	subs map[int]chan Notice
	next int
	// sink, PublishEvent/PublishDevice'in bildirimi nereye ileteceğini belirler.
	// Varsayılan yerel fan-out (Deliver). HA modunda SetSink ile küme
	// yayıncısına (Postgres NOTIFY) yönlendirilir; yerel dağıtım o zaman LISTEN
	// dinleyicisinden gelen Deliver çağrılarıyla yapılır.
	sink func(Notice)
}

// New, boş bir bus oluşturur.
func New() *Bus {
	b := &Bus{subs: make(map[int]chan Notice)}
	b.sink = b.Deliver // tek düğüm: doğrudan yerel dağıtım
	return b
}

// SetSink, Publish* çağrılarının bildirimi ileteceği hedefi değiştirir (HA).
// Küme modunda yayıncı NOTIFY'a yazar; yerel abonelere dağıtım LISTEN tarafından
// çağrılan Deliver ile olur. nil verilmesi yerel dağıtıma geri döner.
func (b *Bus) SetSink(sink func(Notice)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if sink == nil {
		sink = b.Deliver
	}
	b.sink = sink
}

// Subscribe, tamponlu bir bildirim kanalı ve onu kapatan bir iptal fonksiyonu
// döner. İptal idempotenttir.
func (b *Bus) Subscribe() (<-chan Notice, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan Notice, 32)
	id := b.next
	b.next++
	b.subs[id] = ch
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if c, ok := b.subs[id]; ok {
				delete(b.subs, id)
				close(c)
			}
		})
	}
	return ch, cancel
}

// Deliver, bildirimi bu düğümdeki tüm YEREL abonelere bloklamadan iletir. Küme
// modunda LISTEN dinleyicisi uzak düğümlerden gelen bildirimleri buraya
// enjekte eder; tek-düğüm modunda Publish* doğrudan buraya gelir.
func (b *Bus) Deliver(n Notice) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- n:
		default: // dolu/yavaş abone: atla
		}
	}
}

// emit, bildirimi yapılandırılmış sink'e iletir (yerel Deliver ya da küme NOTIFY).
func (b *Bus) emit(n Notice) {
	b.mu.Lock()
	sink := b.sink
	b.mu.Unlock()
	sink(n)
}

// PublishEvent, yeni bir olay bildirir (grpc.AdminNotifier arayüzü). Kiracısız
// (tek-tenant) — tenant-farkındalı üreticiler PublishTenantEvent kullanmalı.
func (b *Bus) PublishEvent(deviceID, severity, message string) {
	b.PublishTenantEvent("", deviceID, severity, message)
}

// PublishDevice, bir cihazın yaşam sinyali/durum değişimini bildirir (kiracısız).
func (b *Bus) PublishDevice(deviceID string) {
	b.PublishTenantDevice("", deviceID)
}

// PublishTenantEvent, kiracı-atıflı bir olay bildirir. tenant SUNUCU-TARAFI belirlenmeli
// (kimlik-doğrulanmış cihazdan), client yükünden değil. Boş tenant → tek-tenant davranış.
func (b *Bus) PublishTenantEvent(tenant, deviceID, severity, message string) {
	b.emit(Notice{Type: "event", TenantID: tenant, DeviceID: deviceID, Severity: severity, Message: message, At: time.Now().UTC()})
}

// PublishTenantDevice, kiracı-atıflı bir cihaz durum değişimi bildirir.
func (b *Bus) PublishTenantDevice(tenant, deviceID string) {
	b.emit(Notice{Type: "device", TenantID: tenant, DeviceID: deviceID, At: time.Now().UTC()})
}

// SubscriberCount, aktif abone sayısını döner (test/gözlem için).
func (b *Bus) SubscriberCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}
