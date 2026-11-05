// Package policy, ajanın politika değerlendirme motorudur.
//
// Proto tiplerinden bilinçli olarak bağımsızdır: transport katmanı gelen
// PolicyBundle'ı buradaki domain tiplerine çevirir. Böylece motor, proto
// üretimi olmadan da derlenip test edilebilir. Zaman değerlendirmesi DAİMA
// dışarıdan verilen (sunucu-çıpalı) `now` ile yapılır; yerel duvar saatine
// güvenilmez.
package policy

import (
	"strings"
	"time"
)

// RuleType, bir kuralın türüdür.
type RuleType int

const (
	RuleUnspecified    RuleType = iota
	RuleAppTimeBlock            // belirli saat penceresinde uygulama yasağı
	RuleAppBlockAlways          // her zaman yasak
	RuleNetwork                 // ağ kuralı (bu fazda değerlendirilmez)
)

// TimeOfDay, gün içi bir anı dakika cinsinden (0..1439) temsil eder.
type TimeOfDay int

// ParseHHMM, "HH:MM" biçimini ayrıştırır.
func ParseHHMM(s string) (TimeOfDay, bool) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return TimeOfDay(t.Hour()*60 + t.Minute()), true
}

func minutesOf(t time.Time) TimeOfDay { return TimeOfDay(t.Hour()*60 + t.Minute()) }

// Rule, tek bir politika kuralıdır (domain biçimi).
type Rule struct {
	ID         string
	Type       RuleType
	Target     string    // uygulama adı / yol / hash (küçük harfe normalize edilir)
	Start, End TimeOfDay // yalnız RuleAppTimeBlock için
	ActiveDays [7]bool   // index = time.Weekday (Sunday=0)
}

// Bundle, sürümlü bir politika paketidir.
type Bundle struct {
	Version string
	Rules   []Rule
}

// Decision, bir değerlendirmenin sonucudur.
type Decision struct {
	Blocked bool
	RuleID  string
	Reason  string
}

// Engine, geçerli politika paketini tutar ve değerlendirir.
type Engine struct {
	bundle Bundle
}

// New, verilen paketle bir motor oluşturur.
func New(b Bundle) *Engine { return &Engine{bundle: b} }

// Version, yüklü paketin sürümüdür.
func (e *Engine) Version() string { return e.bundle.Version }

// EvaluateProcess, bir sürecin verilen (sunucu-çıpalı) anda yasak olup
// olmadığını değerlendirir. İlk eşleşen yasaklayıcı kural kazanır.
func (e *Engine) EvaluateProcess(processPathOrName string, now time.Time) Decision {
	for i := range e.bundle.Rules {
		r := &e.bundle.Rules[i]
		if !matchesTarget(processPathOrName, r.Target) {
			continue
		}
		switch r.Type {
		case RuleAppBlockAlways:
			return Decision{Blocked: true, RuleID: r.ID, Reason: "uygulama her zaman yasak"}
		case RuleAppTimeBlock:
			if inWindow(now, r.Start, r.End, r.ActiveDays) {
				return Decision{Blocked: true, RuleID: r.ID, Reason: "mesai-dışı uygulama yasağı"}
			}
		}
	}
	return Decision{Blocked: false}
}

// EvaluateAlways, yalnız "her zaman yasak" (RuleAppBlockAlways) kurallarını
// değerlendirir; zaman gerektirmez. Saat sunucuya senkronize DEĞİLKEN zaman
// pencereli kurallar güvenle uygulanamaz — enforcement bu duruma
// düştüğünde bu metoda başvurur, böylece her-zaman-yasak kuralları yine uygulanır.
func (e *Engine) EvaluateAlways(processPathOrName string) Decision {
	for i := range e.bundle.Rules {
		r := &e.bundle.Rules[i]
		if r.Type == RuleAppBlockAlways && matchesTarget(processPathOrName, r.Target) {
			return Decision{Blocked: true, RuleID: r.ID, Reason: "uygulama her zaman yasak"}
		}
	}
	return Decision{Blocked: false}
}

// matchesTarget, süreç adını/yolunu hedefle karşılaştırır (küçük harf; tam yol
// veya dosya adı eşleşmesi).
func matchesTarget(proc, target string) bool {
	if target == "" {
		return false
	}
	p := strings.ToLower(strings.TrimSpace(proc))
	t := strings.ToLower(strings.TrimSpace(target))
	if p == t {
		return true
	}
	return baseName(p) == baseName(t)
}

// baseName, bir yolun son bileşenini (dosya adı) döner. filepath.Base'in AKSİNE
// hem '/' hem '\' ayırıcısını ele alır (OS-bağımsız): politika motoru, ajanın
// çalıştığı platformdan bağımsız olarak Windows ('\') ve Unix ('/') yollarını
// tutarlı eşleştirmelidir — aksi halde Linux'ta 'D:\x\a.exe' bölünmez ve
// dosya-adı eşleşmesi kaçırılır.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// inWindow, verilen anın [start,end) penceresi ve aktif günler içinde olup
// olmadığını söyler. Gece-aşırı pencereleri (start > end, örn. 18:00–08:00)
// doğru şekilde ele alır: bu durumda pencere önceki güne taşar.
func inWindow(now time.Time, start, end TimeOfDay, days [7]bool) bool {
	if start == end {
		return false // boş/tanımsız pencere
	}
	t := minutesOf(now)
	wd := int(now.Weekday())
	prev := (wd + 6) % 7

	if start < end {
		// Aynı gün içi pencere.
		return days[wd] && t >= start && t < end
	}
	// Gece-aşırı pencere: [start, 24:00) bugünkü güne, [00:00, end) önceki güne ait.
	if days[wd] && t >= start {
		return true
	}
	if days[prev] && t < end {
		return true
	}
	return false
}
