package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"kut.corp/suite/agent/internal/collector"
	"kut.corp/suite/agent/internal/deviceaction"
	"kut.corp/suite/agent/internal/netconn"
	"kut.corp/suite/agent/internal/persistence"
	"kut.corp/suite/agent/internal/usbmon"
)

// Güvenli-mod AÇIKKEN yıkıcı MDM eylemi (LOCK/RESTART/WIPE) gerçek OS fonksiyonunu
// ASLA çağırmamalı — yalnız bir INFO olayı üretmeli. Bu, demo/test sırasında
// cihazın kilitlenmesini/yeniden başlamasını/silinmesini önleyen kritik güvenlik
// garantisidir; kırılırsa gerçek yıkıcı eylem tetiklenebilir.
func TestDoDeviceActionSafeModeDoesNotInvoke(t *testing.T) {
	buf := collector.NewBuffer(16)
	called := false
	doDeviceAction(buf, true /*safeMode*/, "WIPE", "veri silme", func() error {
		called = true // gerçek yıkıcı eylem — çağrılmamalı
		return nil
	})
	if called {
		t.Fatal("güvenli modda gerçek eylem fonksiyonu çağrıldı — YIKICI eylem tetiklenebilirdi")
	}
	evs := buf.Pending(10)
	if len(evs) != 1 {
		t.Fatalf("tam olarak 1 olay beklendi, bulunan: %d", len(evs))
	}
	e := evs[0]
	if e.Category != "SYSTEM" || e.Severity != "INFO" {
		t.Fatalf("güvenli-mod olayı SYSTEM/INFO olmalı, bulunan: %s/%s", e.Category, e.Severity)
	}
	if sm, _ := e.Details["safe_mode"].(bool); !sm {
		t.Fatalf("olay details.safe_mode=true taşımalı: %+v", e.Details)
	}
}

// Güvenli-mod KAPALIYKEN eylem fonksiyonu çağrılmalı; başarı INFO olay üretmeli.
func TestDoDeviceActionAppliesWhenNotSafeMode(t *testing.T) {
	buf := collector.NewBuffer(16)
	called := false
	doDeviceAction(buf, false, "LOCK", "ekran kilitleme", func() error {
		called = true
		return nil
	})
	if !called {
		t.Fatal("güvenli-mod kapalıyken eylem fonksiyonu çağrılmalıydı")
	}
	evs := buf.Pending(10)
	if len(evs) != 1 || evs[0].Severity != "INFO" {
		t.Fatalf("başarı için 1 INFO olay beklendi: %+v", evs)
	}
	if _, ok := evs[0].Details["error"]; ok {
		t.Fatalf("başarı olayı error detayı taşımamalı: %+v", evs[0].Details)
	}
}

// Eylem fonksiyonu hata dönerse MEDIUM olay + error detayı üretilmeli.
func TestDoDeviceActionReportsFailure(t *testing.T) {
	buf := collector.NewBuffer(16)
	doDeviceAction(buf, false, "RESTART", "yeniden başlatma", func() error {
		return errors.New("boom")
	})
	evs := buf.Pending(10)
	if len(evs) != 1 {
		t.Fatalf("1 olay beklendi: %d", len(evs))
	}
	if evs[0].Severity != "MEDIUM" {
		t.Fatalf("başarısızlık olayı MEDIUM olmalı, bulunan: %s", evs[0].Severity)
	}
	if es, _ := evs[0].Details["error"].(string); es != "boom" {
		t.Fatalf("olay details.error='boom' taşımalı: %+v", evs[0].Details)
	}
}

// connTracker: ilk tur taban çizgisidir (olay yok); sonraki turda yalnız YENİ
// bağlantılar NETWORK_CONN olayı üretir; tekrar görülen bağlantı olay üretmez.
func TestConnTrackerBaselineAndNewOnly(t *testing.T) {
	buf := collector.NewBuffer(32)
	tr := &connTracker{}
	base := []netconn.Conn{{RemoteIP: "10.0.0.1", RemotePort: 443, LocalPort: 51000, PID: 100}}
	tr.reportConns(buf, base) // taban çizgisi
	if n := len(buf.Pending(10)); n != 0 {
		t.Fatalf("ilk tur taban çizgisi olmalı (olay yok), üretilen: %d", n)
	}
	// Yeni bağlantı eklenir; eski korunur.
	next := append([]netconn.Conn{}, base...)
	next = append(next, netconn.Conn{RemoteIP: "8.8.8.8", RemotePort: 53, LocalPort: 51001, PID: 200})
	tr.reportConns(buf, next)
	evs := buf.Pending(10)
	if len(evs) != 1 {
		t.Fatalf("yalnız 1 YENİ bağlantı olayı beklendi: %d", len(evs))
	}
	if evs[0].Category != "NETWORK_CONN" || evs[0].Details["remote_ip"] != "8.8.8.8" {
		t.Fatalf("yeni bağlantı olayı beklenmedik: %+v", evs[0])
	}
	// Aynı küme tekrar: yeni yok.
	buf.Ack(evs[0].Seq)
	tr.reportConns(buf, next)
	if n := len(buf.Pending(10)); n != 0 {
		t.Fatalf("tekrar görülen bağlantılar olay üretmemeli: %d", n)
	}
}

// usbTracker: ilk tur taban çizgisi; yeni sürücü audit politikasında SECURITY/
// MEDIUM, block politikasında POLICY_VIOLATION/HIGH (engelleme güdük — blocked:false).
func TestUsbTrackerPolicyAndDedup(t *testing.T) {
	// audit politikası.
	buf := collector.NewBuffer(32)
	ta := &usbTracker{policy: "audit"}
	ta.reportDrives(buf, false, nil) // taban çizgisi (boş)
	ta.reportDrives(buf, false, []usbmon.Drive{{ID: "E:", Label: "KINGSTON"}})
	evs := buf.Pending(10)
	if len(evs) != 1 || evs[0].Category != "SECURITY" || evs[0].Severity != "MEDIUM" {
		t.Fatalf("audit: SECURITY/MEDIUM olay beklendi: %+v", evs)
	}

	// block politikası GÜVENLİ-MODDA: HIGH + POLICY_VIOLATION üretir ama gerçek
	// engelleme UYGULANMAZ (blocked:false + "güvenli mod" notu). GÜVENLİ MOD kullanılır
	// çünkü safeMode=false gerçek usbmon.Block'u (mountvol/eject) test host'unda çalıştırır.
	buf2 := collector.NewBuffer(32)
	tb := &usbTracker{policy: "block"}
	tb.reportDrives(buf2, true /*safeMode*/, nil) // taban çizgisi
	tb.reportDrives(buf2, true, []usbmon.Drive{{ID: "F:"}})
	evs2 := buf2.Pending(10)
	if len(evs2) != 1 || evs2[0].Category != "POLICY_VIOLATION" || evs2[0].Severity != "HIGH" {
		t.Fatalf("block: POLICY_VIOLATION/HIGH olay beklendi: %+v", evs2)
	}
	if b, _ := evs2[0].Details["blocked"].(bool); b {
		t.Fatalf("güvenli modda gerçek engelleme uygulanmamalı — blocked:false olmalı: %+v", evs2[0].Details)
	}
	if note, _ := evs2[0].Details["note"].(string); note == "" {
		t.Fatalf("güvenli-mod block olayı 'note' taşımalı: %+v", evs2[0].Details)
	}
	// Aynı sürücü tekrar: yeni olay yok.
	buf2.Ack(evs2[0].Seq)
	tb.reportDrives(buf2, true, []usbmon.Drive{{ID: "F:"}})
	if n := len(buf2.Pending(10)); n != 0 {
		t.Fatalf("tekrar görülen sürücü olay üretmemeli: %d", n)
	}
}

// selectWipeFn: ARM'lı DEĞİLKEN (güvenli varsayılan) gerçek yıkıcı Wipe SEÇİLMEMELİ —
// dönen güdük hiçbir şey silmeden ErrWipeNotArmed dönmeli. (ARM'lı dal gerçek silme
// yaptığından burada ÇAĞRILMAZ; yalnız derleme + kod incelemesiyle doğrulanır.)
func TestSelectWipeFnNotArmedIsSafe(t *testing.T) {
	fn := selectWipeFn(false)
	if err := fn(); err != deviceaction.ErrWipeNotArmed {
		t.Fatalf("ARM'sız WIPE güdüğü ErrWipeNotArmed dönmeli (silme YOK), dönen: %v", err)
	}
}

// fimTracker.report: ilk tur taban çizgisi (olay yok); izlenen dosya değişince
// SECURITY / FILE-INTEGRITY olayı (change=modified) üretilmeli (FIM).
func TestFimTrackerReportsChanges(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(fp, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	buf := collector.NewBuffer(16)
	ft := &fimTracker{paths: []string{dir}}
	ft.report(buf) // taban çizgisi
	if n := len(buf.Pending(10)); n != 0 {
		t.Fatalf("taban çizgisi olay üretmemeli: %d", n)
	}
	if err := os.WriteFile(fp, []byte("v2-değişti"), 0o600); err != nil {
		t.Fatal(err)
	}
	ft.report(buf)
	evs := buf.Pending(10)
	if len(evs) != 1 || evs[0].Category != "SECURITY" {
		t.Fatalf("değişiklik SECURITY olayı üretmeli: %+v", evs)
	}
	if ch, _ := evs[0].Details["change"].(string); ch != "modified" {
		t.Fatalf("change=modified beklendi: %+v", evs[0].Details)
	}
	if fimFlag, _ := evs[0].Details["fim"].(bool); !fimFlag {
		t.Fatalf("olay details.fim=true taşımalı: %+v", evs[0].Details)
	}
}

// persistenceTracker.emit: yeni autostart girdisi POLICY_VIOLATION/HIGH olayı
// üretmeli; Details kind/name taşımalı.
func TestPersistenceTrackerEmit(t *testing.T) {
	buf := collector.NewBuffer(16)
	p := &persistenceTracker{}
	p.emit(buf, []persistence.Entry{{Kind: persistence.RunKey, Name: "Evil", Value: `C:\Temp\evil.exe`}})
	evs := buf.Pending(10)
	if len(evs) != 1 || evs[0].Category != "POLICY_VIOLATION" || evs[0].Severity != "HIGH" {
		t.Fatalf("yeni kalıcılık girdisi POLICY_VIOLATION/HIGH üretmeli: %+v", evs)
	}
	if k, _ := evs[0].Details["kind"].(string); k != "run_key" {
		t.Fatalf("details.kind=run_key beklendi: %+v", evs[0].Details)
	}
	// Boş girdi listesi olay üretmemeli.
	buf.Ack(evs[0].Seq)
	p.emit(buf, nil)
	if n := len(buf.Pending(10)); n != 0 {
		t.Fatalf("boş girdi listesi olay üretmemeli: %d", n)
	}
}

// TestProtectedCollectPath, COLLECT_FILE'ın ajanın KENDİ veri dizinini (mTLS anahtarı/
// sertifikası) toplamayı reddettiğini doğrular — ele geçmiş C2'nin ajan kimliğini
// sızdırmasını engeller. Dizin dışı yollar toplanabilir.
func TestProtectedCollectPath(t *testing.T) {
	dataDir := t.TempDir()
	// Ajanın kendi anahtarı/sertifikası ve alt yolları → REDDET.
	for _, p := range []string{
		filepath.Join(dataDir, "agent.key"),
		filepath.Join(dataDir, "agent.crt"),
		filepath.Join(dataDir, "updates", "staged"),
		dataDir,
	} {
		if !protectedCollectPath(p, dataDir) {
			t.Errorf("korumalı yol reddedilmeliydi: %s", p)
		}
	}
	// Veri dizini dışındaki meşru forensic hedefler → izin.
	outside := filepath.Join(t.TempDir(), "evidence.log")
	if protectedCollectPath(outside, dataDir) {
		t.Errorf("dizin dışı yol toplanabilmeliydi: %s", outside)
	}
	// Boş dataDir → koruma yok (yapılandırılmamış), ama panik/yanlış-pozitif olmamalı.
	if protectedCollectPath(outside, "") {
		t.Error("boş dataDir'de dizin-dışı yol reddedilmemeli")
	}
}
