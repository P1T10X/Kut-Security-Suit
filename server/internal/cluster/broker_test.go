package cluster

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kut.corp/suite/server/internal/eventbus"
)

// fakeBus, tek süreçte NOTIFY→LISTEN döngüsünü taklit eder: NotifyChannel'a gelen
// her yük, kayıtlı dinleyicilere iletilir (Postgres self-notify davranışı gibi).
type fakeBus struct {
	mu        sync.Mutex
	listeners []func(string)
	failNext  bool // bir sonraki NotifyChannel hata dönsün (fallback testi)
}

func (f *fakeBus) NotifyChannel(_ context.Context, _, payload string) error {
	f.mu.Lock()
	if f.failNext {
		f.failNext = false
		f.mu.Unlock()
		return errFail
	}
	ls := append([]func(string){}, f.listeners...)
	f.mu.Unlock()
	for _, l := range ls {
		l(payload)
	}
	return nil
}

func (f *fakeBus) ListenChannel(ctx context.Context, _ string, onPayload func(string)) error {
	f.mu.Lock()
	f.listeners = append(f.listeners, onPayload)
	f.mu.Unlock()
	<-ctx.Done() // ctx bitene dek dinle
	return ctx.Err()
}

type stubErr struct{}

func (stubErr) Error() string { return "fake notify hatası" }

var errFail = stubErr{}

// collector, Deliver ile ulaşan bildirimleri toplar (yerel abone taklidi).
type collector struct {
	mu  sync.Mutex
	got []eventbus.Notice
}

func (c *collector) Deliver(n eventbus.Notice) {
	c.mu.Lock()
	c.got = append(c.got, n)
	c.mu.Unlock()
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

// Publish → NOTIFY → (self) LISTEN → Deliver zinciri çalışmalı; çift teslim olmamalı.
func TestBrokerFanoutRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := &fakeBus{}
	col := &collector{}
	b := New(ctx, bus, col, "", nil)
	var pub, recv, fb atomic.Int64
	b.SetMetrics(func() { pub.Add(1) }, func() { recv.Add(1) }, func() { fb.Add(1) })
	go b.Run(ctx)

	// Dinleyicinin kaydolması için kısa bekleyiş.
	waitFor(t, func() bool { bus.mu.Lock(); defer bus.mu.Unlock(); return len(bus.listeners) == 1 })

	b.Publish(eventbus.Notice{Type: "event", DeviceID: "dev-1", Severity: "HIGH", Message: "test"})
	waitFor(t, func() bool { return col.count() == 1 })
	if got := col.got[0]; got.DeviceID != "dev-1" || got.Severity != "HIGH" {
		t.Fatalf("bildirim bozuldu: %+v", got)
	}
	if col.count() != 1 {
		t.Fatalf("çift teslim olmamalı, teslim sayısı: %d", col.count())
	}
	// Metrik kancaları: 1 yayın + 1 alım, fallback yok.
	if pub.Load() != 1 || recv.Load() != 1 || fb.Load() != 0 {
		t.Fatalf("metrik kancaları beklenmedik: pub=%d recv=%d fb=%d", pub.Load(), recv.Load(), fb.Load())
	}
}

// HA modunun ASIL garantisi: A düğümünde yayınlanan bir olay, paylaşılan kanalı
// dinleyen B düğümündeki yerel abonelere de ulaşmalı (çok-düğüm fan-out).
// Aynı fakeBus (paylaşılan Postgres kanalı gibi) iki broker'ı köprüler.
func TestBrokerCrossNodeFanout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := &fakeBus{} // paylaşılan kanal (tek Postgres)

	colA, colB := &collector{}, &collector{}
	bA := New(ctx, bus, colA, "kut_notice", nil) // A düğümü
	bB := New(ctx, bus, colB, "kut_notice", nil) // B düğümü
	go bA.Run(ctx)
	go bB.Run(ctx)

	// Her iki düğümün LISTEN'i kaydolana dek bekle.
	waitFor(t, func() bool { bus.mu.Lock(); defer bus.mu.Unlock(); return len(bus.listeners) == 2 })

	// A düğümünde yayınla.
	bA.Publish(eventbus.Notice{Type: "event", DeviceID: "dev-9", Severity: "CRITICAL", Message: "cross"})

	// B düğümündeki abone de almalı (asıl HA garantisi) — ve A da (self).
	waitFor(t, func() bool { return colA.count() == 1 && colB.count() == 1 })
	if colB.got[0].DeviceID != "dev-9" || colB.got[0].Severity != "CRITICAL" {
		t.Fatalf("B düğümü olayı bozuk aldı: %+v", colB.got[0])
	}
	// Her düğüm tam olarak bir kez almalı (çift teslim yok).
	if colA.count() != 1 || colB.count() != 1 {
		t.Fatalf("düğüm başına tam 1 teslim beklendi: A=%d B=%d", colA.count(), colB.count())
	}
}

// NOTIFY hata dönerse yerel dağıtıma düşülmeli (bu düğüm akışı kaçırmasın).
func TestBrokerPublishFallsBackOnNotifyError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := &fakeBus{failNext: true}
	col := &collector{}
	b := New(ctx, bus, col, "chan", nil)
	// Run BAŞLATILMADI; NOTIFY hata döndüğü için Publish yerel Deliver'a düşmeli.
	b.Publish(eventbus.Notice{Type: "device", DeviceID: "dev-2"})
	if col.count() != 1 {
		t.Fatalf("NOTIFY hatasında yerel dağıtım beklendi, teslim: %d", col.count())
	}
}

// Büyük mesaj NOTIFY sınırının altına kırpılmalı.
func TestBrokerTruncatesLargePayload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var captured string
	bus := &captureBus{onNotify: func(p string) { captured = p }}
	b := New(ctx, bus, &collector{}, "", nil)
	b.Publish(eventbus.Notice{Type: "event", DeviceID: "d", Message: strings.Repeat("A", 9000)})
	if len(captured) == 0 {
		t.Fatal("yük yakalanamadı")
	}
	if len(captured) > maxPayload+200 {
		t.Fatalf("yük kırpılmalıydı, uzunluk: %d", len(captured))
	}
}

type captureBus struct{ onNotify func(string) }

func (c *captureBus) NotifyChannel(_ context.Context, _, payload string) error {
	c.onNotify(payload)
	return nil
}
func (c *captureBus) ListenChannel(ctx context.Context, _ string, _ func(string)) error {
	<-ctx.Done()
	return ctx.Err()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("koşul zaman aşımına uğradı")
}
