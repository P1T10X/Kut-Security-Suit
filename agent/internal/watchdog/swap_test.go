package watchdog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSwapperSwapAndRollback(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent")
	stageDir := filepath.Join(dir, "updates")
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("ESKI-SURUM"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "agent-staged"), []byte("YENI-SURUM"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "agent-staged.version"), []byte("2.0.0"), 0o644); err != nil {
		t.Fatal(err)
	}

	sw := NewFileSwapper(bin, stageDir)

	ver, _, ok := sw.PendingStaged()
	if !ok || ver != "2.0.0" {
		t.Fatalf("bekleyen staged güncelleme bulunmalıydı: ver=%q ok=%v", ver, ok)
	}

	// Swap: ikili yeni sürüm olmalı, yedek eski sürümü tutmalı.
	if err := sw.Swap(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(bin); string(b) != "YENI-SURUM" {
		t.Fatalf("swap sonrası ikili yeni sürüm olmalı: %q", b)
	}
	if b, _ := os.ReadFile(bin + ".bak"); string(b) != "ESKI-SURUM" {
		t.Fatalf("yedek eski sürümü tutmalı: %q", b)
	}
	// Staged tüketilmiş olmalı.
	if _, _, ok := sw.PendingStaged(); ok {
		t.Fatal("swap sonrası bekleyen staged kalmamalı")
	}

	// Rollback: ikili tekrar eski sürüm olmalı.
	if err := sw.Rollback(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(bin); string(b) != "ESKI-SURUM" {
		t.Fatalf("rollback sonrası ikili eski sürüm olmalı: %q", b)
	}
}

func TestFileSwapperNoPending(t *testing.T) {
	dir := t.TempDir()
	sw := NewFileSwapper(filepath.Join(dir, "agent"), filepath.Join(dir, "updates"))
	if _, _, ok := sw.PendingStaged(); ok {
		t.Fatal("staged yokken pending false olmalı")
	}
}

// TestFileSwapperVerifyHookRefusesSwap, swap-anı yeniden-doğrulama kancası hata
// dönerse swap'ın REDDEDİLDİĞİNİ ve kurcalanmış staged artefaktların temizlendiğini; kanca
// başarılı olursa swap'ın gerçekleştiğini doğrular.
func TestFileSwapperVerifyHookRefusesSwap(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent")
	stageDir := filepath.Join(dir, "updates")
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(bin, []byte("ESKI"), 0o755)
	staged := filepath.Join(stageDir, "agent-staged")
	_ = os.WriteFile(staged, []byte("KURCALANMIS"), 0o755)
	_ = os.WriteFile(staged+".version", []byte("9.9.9"), 0o644)
	_ = os.WriteFile(staged+".manifest", []byte("{}"), 0o644)
	_ = os.WriteFile(staged+".sig", []byte("bad"), 0o644)

	// (1) Kanca hata dönüyor → swap reddedilmeli, ikili değişmemeli, staged temizlenmeli.
	sw := NewFileSwapper(bin, stageDir)
	sw.SetVerify(func(string) error { return os.ErrInvalid })
	if err := sw.Swap(); err == nil {
		t.Fatal("doğrulama başarısızken swap reddedilmeliydi")
	}
	if b, _ := os.ReadFile(bin); string(b) != "ESKI" {
		t.Fatalf("reddedilen swap ikiliyi değiştirmemeli: %q", b)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatal("kurcalanmış staged ikili temizlenmeliydi")
	}

	// (2) Kanca başarılı → swap gerçekleşmeli.
	_ = os.WriteFile(staged, []byte("YENI"), 0o755)
	sw2 := NewFileSwapper(bin, stageDir)
	sw2.SetVerify(func(string) error { return nil })
	if err := sw2.Swap(); err != nil {
		t.Fatalf("doğrulama başarılıyken swap gerçekleşmeli: %v", err)
	}
	if b, _ := os.ReadFile(bin); string(b) != "YENI" {
		t.Fatalf("swap sonrası ikili yeni sürüm olmalı: %q", b)
	}
}
