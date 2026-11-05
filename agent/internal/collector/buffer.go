// Package collector, olay toplama ve store-and-forward tamponunu sağlar.
//
// Ajan çevrimdışıyken olaylar burada birikir; bağlantı gelince toplu gönderilir.
// Sunucu, kabul ettiği son sıra numarasını (EventAck) döner ve tampon yalnız
// ONAYLANANLARI siler — böylece geçici bağlantı kaybında olay kaybolmaz.
// Tampon sınırlıdır: kapasite aşılırsa en eski olaylar düşürülür
// ve sayaçla raporlanır (uzun süreli çevrimdışılıkta kaçınılmaz veri kaybı).
package collector

import (
	"sync"
	"time"
)

// Event, tamponlanan bir olaydır (domain biçimi; proto'dan bağımsız).
type Event struct {
	Seq        uint64
	Category   string
	Severity   string
	Message    string
	Details    map[string]any
	OccurredAt time.Time
}

// Buffer, sıra-numaralı, sınırlı, eşzamanlı-güvenli bir olay tamponudur.
type Buffer struct {
	mu      sync.Mutex
	events  []Event
	nextSeq uint64
	cap     int
	dropped uint64
}

// NewBuffer, verilen kapasiteyle (en fazla saklanacak olay sayısı) tampon açar.
// capacity <= 0 ise makul bir varsayılan kullanılır.
func NewBuffer(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = 10000
	}
	return &Buffer{cap: capacity}
}

// Add, olaya monotonik bir sıra numarası atar, tampona ekler ve numarayı döner.
// Kapasite aşılırsa en eski olay düşürülür.
func (b *Buffer) Add(e Event) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextSeq++
	e.Seq = b.nextSeq
	b.events = append(b.events, e)
	if len(b.events) > b.cap {
		over := len(b.events) - b.cap
		b.events = b.events[over:]
		b.dropped += uint64(over)
	}
	return e.Seq
}

// Pending, gönderilmeyi bekleyen olayların (sıraya göre) bir kopyasını döner.
// max <= 0 ise tümü döner.
func (b *Buffer) Pending(max int) []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(b.events)
	if max > 0 && max < n {
		n = max
	}
	out := make([]Event, n)
	copy(out, b.events[:n])
	return out
}

// Ack, sıra numarası uptoSeq'e kadar (dahil) olan olayları siler ve silinen
// sayısını döner. Olaylar sıraya göre tutulduğundan bu, baştan kırpmadır.
func (b *Buffer) Ack(uptoSeq uint64) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	i := 0
	for i < len(b.events) && b.events[i].Seq <= uptoSeq {
		i++
	}
	if i > 0 {
		b.events = append(b.events[:0], b.events[i:]...)
	}
	return i
}

// Len, bekleyen olay sayısıdır.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

// Dropped, kapasite aşımı nedeniyle düşürülen toplam olay sayısıdır.
func (b *Buffer) Dropped() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}
