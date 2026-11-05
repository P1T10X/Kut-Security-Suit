// Package agentclock, sunucu-çıpalı bir saat sağlar.
//
// Politika zaman pencereleri yerel DUVAR saatine göre değerlendirilemez: SYSTEM
// yetkili bir kullanıcı saati değiştirerek mesai-dışı yasağını atlatabilir.
// Bunun yerine ajan, her heartbeat'te sunucudan gelen zamanı
// çıpa alır ve o çıpadan itibaren MONOTONİK geçen süreyle ilerler. Duvar saati
// değişse bile monotonik geçen süre etkilenmez.
package agentclock

import (
	"sync"
	"time"
)

// Clock, son sunucu çıpasından itibaren monotonik ilerleyen bir saattir.
type Clock struct {
	mu          sync.Mutex
	localNow    func() time.Time
	anchorSrv   time.Time
	anchorLocal time.Time
	synced      bool
}

// New, yerel zaman kaynağıyla bir saat oluşturur. Üretimde New(time.Now).
func New(localNow func() time.Time) *Clock {
	if localNow == nil {
		localNow = time.Now
	}
	return &Clock{localNow: localNow}
}

// Sync, sunucudan gelen zamanı çıpa olarak alır (her heartbeat yanıtında).
func (c *Clock) Sync(serverTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.anchorSrv = serverTime
	c.anchorLocal = c.localNow()
	c.synced = true
}

// Now, tahmini geçerli sunucu zamanını döner. İkinci dönüş değeri, en az bir kez
// senkronize edilip edilmediğini belirtir; false ise zaman-bazlı kurallar
// güvenle uygulanamaz (çağıran fail-safe davranmalıdır).
func (c *Clock) Now() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.synced {
		return time.Time{}, false
	}
	elapsed := c.localNow().Sub(c.anchorLocal)
	if elapsed < 0 {
		elapsed = 0 // monotonik olmayan kaynakta geri gitmeyi engelle
	}
	return c.anchorSrv.Add(elapsed), true
}

// SyncedWithin, son senkronizasyonun üzerinden en fazla max süre geçmişse true
// döner. Çıpa çok bayatsa (ajan uzun süre çevrimdışı) zaman tahmini kaymış olur.
func (c *Clock) SyncedWithin(max time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.synced {
		return false
	}
	return c.localNow().Sub(c.anchorLocal) <= max
}
