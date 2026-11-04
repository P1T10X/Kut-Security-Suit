package aiassist

import (
	"context"
	"testing"
)

// TestLocalProviderMitreMapping, MITRE eşlemesinin deterministik ve doğru
// teknikleri ürettiğini doğrular.
func TestLocalProviderMitreMapping(t *testing.T) {
	p := NewLocalProvider()
	cases := []struct {
		name    string
		input   string
		wantIDs []string
		minConf float64
	}{
		{"powershell", "Suspicious PowerShell script executed", []string{"T1059"}, 0.5},
		{"credential_dump", "mimikatz accessed lsass memory", []string{"T1003"}, 0.5},
		{"ransomware", "files encrypt by ransom note", []string{"T1486"}, 0.5},
		{"multi", "powershell ran mimikatz then beacon", []string{"T1003", "T1059", "T1071"}, 0.6},
		{"none", "routine login by user jdoe", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := p.Analyze(context.Background(), Request{Task: TaskMitreMapping, Input: tc.input})
			if err != nil {
				t.Fatalf("beklenmeyen hata: %v", err)
			}
			if len(rec.Suggestions) != len(tc.wantIDs) {
				t.Fatalf("ID sayısı = %v, beklenen %v (got %v)", len(rec.Suggestions), len(tc.wantIDs), rec.Suggestions)
			}
			for i, id := range tc.wantIDs {
				if rec.Suggestions[i] != id {
					t.Errorf("ID[%d] = %q, beklenen %q", i, rec.Suggestions[i], id)
				}
			}
			if rec.Confidence < tc.minConf {
				t.Errorf("güven = %v, beklenen >= %v", rec.Confidence, tc.minConf)
			}
			if rec.Confidence < 0 || rec.Confidence > 1 {
				t.Errorf("güven aralık dışı: %v", rec.Confidence)
			}
		})
	}
}

// TestLocalProviderDeterministic, aynı girdi için aynı çıktının üretildiğini doğrular.
func TestLocalProviderDeterministic(t *testing.T) {
	p := NewLocalProvider()
	req := Request{Task: TaskMitreMapping, Input: "powershell mimikatz injection beacon encrypt"}
	r1, _ := p.Analyze(context.Background(), req)
	r2, _ := p.Analyze(context.Background(), req)
	if r1.Summary != r2.Summary {
		t.Errorf("özet deterministik değil:\n%q\n%q", r1.Summary, r2.Summary)
	}
	if len(r1.Actions) != len(r2.Actions) {
		t.Fatalf("eylem sayısı farklı: %d vs %d", len(r1.Actions), len(r2.Actions))
	}
	for i := range r1.Actions {
		if r1.Actions[i].Target != r2.Actions[i].Target {
			t.Errorf("eylem[%d] hedefi farklı: %q vs %q", i, r1.Actions[i].Target, r2.Actions[i].Target)
		}
	}
}

// TestLocalProviderFalsePositive, yanlış pozitif sezgilerini doğrular.
func TestLocalProviderFalsePositive(t *testing.T) {
	p := NewLocalProvider()
	cases := []struct {
		name     string
		input    string
		wantFP   bool // özette "yanlış pozitif" geçmeli mi
		wantKind string
	}{
		{"test_signal", "Alert triggered during QA test run in staging", true, "create_case"},
		{"benign", "marked as known good benign sample", true, "create_case"},
		{"real", "active exploitation observed on prod", false, "create_case"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := p.Analyze(context.Background(), Request{Task: TaskFalsePositiveAnalysis, Input: tc.input})
			if err != nil {
				t.Fatalf("beklenmeyen hata: %v", err)
			}
			gotFP := len(rec.Suggestions) > 0
			if gotFP != tc.wantFP {
				t.Errorf("FP tespiti = %v, beklenen %v (özet: %q)", gotFP, tc.wantFP, rec.Summary)
			}
			if len(rec.Actions) == 0 || rec.Actions[0].Kind != tc.wantKind {
				t.Errorf("eylem türü = %v, beklenen %q", rec.Actions, tc.wantKind)
			}
		})
	}
}

// TestLocalProviderEmptyInput, boş girdinin hata döndürdüğünü doğrular.
func TestLocalProviderEmptyInput(t *testing.T) {
	p := NewLocalProvider()
	if _, err := p.Analyze(context.Background(), Request{Task: TaskAlertSummary, Input: "   "}); err != ErrEmptyInput {
		t.Errorf("hata = %v, beklenen ErrEmptyInput", err)
	}
}

// TestLocalProviderSummary, genel özet görevinin anahtar kelime çıkardığını doğrular.
func TestLocalProviderSummary(t *testing.T) {
	p := NewLocalProvider()
	rec, err := p.Analyze(context.Background(), Request{
		Task:  TaskAlertSummary,
		Input: "Ransomware ransomware detected on finance finance server server",
	})
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if len(rec.Suggestions) == 0 {
		t.Fatal("anahtar kelime bekleniyordu")
	}
	// En sık geçen terim "ransomware" veya "finance"/"server" olmalı (hepsi 2 kez,
	// eşitlikte alfabetik): "finance" < "ransomware" < "server".
	if rec.Suggestions[0] != "finance" {
		t.Errorf("ilk anahtar kelime = %q, beklenen \"finance\"", rec.Suggestions[0])
	}
	// Özet görevleri eylem önermez.
	if len(rec.Actions) != 0 {
		t.Errorf("özet görevinde eylem beklenmiyordu: %v", rec.Actions)
	}
}

// TestLocalProviderRemediation, iyileştirme önerilerinin bağlamı kullandığını doğrular.
func TestLocalProviderRemediation(t *testing.T) {
	p := NewLocalProvider()
	rec, err := p.Analyze(context.Background(), Request{
		Task:    TaskRemediationSuggestion,
		Input:   "ransomware encrypt spreading",
		Context: map[string]string{"host": "WIN-01"},
	})
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	var isolate bool
	for _, a := range rec.Actions {
		if a.Kind == "isolate" && a.Target == "WIN-01" {
			isolate = true
		}
	}
	if !isolate {
		t.Errorf("izolasyon eylemi WIN-01 için bekleniyordu: %v", rec.Actions)
	}
}

// TestGateBlockedByPolicy, politika başarısızken kararın engellendiğini ve
// eylemlerin uygulanamaz olduğunu doğrular.
func TestGateBlockedByPolicy(t *testing.T) {
	g := NewGate()
	rec := Recommendation{Task: TaskRemediationSuggestion, Actions: []ProposedAction{{Kind: "isolate", Target: "h1"}}}
	d := g.Review(rec, false)
	if d.State != StateBlocked {
		t.Errorf("durum = %v, beklenen Blocked", d.State)
	}
	if d.Actionable() {
		t.Error("politika engelliyken uygulanabilir olmamalı")
	}
	if d.ActionableActions() != nil {
		t.Error("engellenmişken eylem sızdırılmamalı")
	}
	// Politika engelliyse onay girişimi başarısız olmalı.
	if err := d.Approve("analyst"); err != ErrNotPending {
		t.Errorf("onay hatası = %v, beklenen ErrNotPending", err)
	}
}

// TestGateNeedsApproval, politika geçse bile onay olmadan eylemin
// uygulanamayacağını doğrular.
func TestGateNeedsApproval(t *testing.T) {
	g := NewGate()
	rec := Recommendation{Task: TaskRemediationSuggestion, Actions: []ProposedAction{{Kind: "quarantine", Target: "f1"}}}
	d := g.Review(rec, true)
	if d.State != StatePendingApproval {
		t.Errorf("durum = %v, beklenen PendingApproval", d.State)
	}
	if d.Actionable() {
		t.Error("onay öncesi uygulanabilir olmamalı")
	}
	if d.ActionableActions() != nil {
		t.Error("onay öncesi eylem sızdırılmamalı")
	}
}

// TestGateApproveAllows, hem politika geçip hem insan onayladığında eylemlerin
// uygulanabilir olduğunu ve onaylayanın kaydedildiğini doğrular.
func TestGateApproveAllows(t *testing.T) {
	g := NewGate()
	acts := []ProposedAction{{Kind: "isolate", Target: "h1"}}
	rec := Recommendation{Task: TaskRemediationSuggestion, Actions: acts}
	d := g.Review(rec, true)
	if err := d.Approve("soc-lead"); err != nil {
		t.Fatalf("onay hatası: %v", err)
	}
	if d.State != StateApproved {
		t.Errorf("durum = %v, beklenen Approved", d.State)
	}
	if !d.Actionable() {
		t.Error("onay + politika sonrası uygulanabilir olmalı")
	}
	if got := d.ActionableActions(); len(got) != 1 || got[0].Kind != "isolate" {
		t.Errorf("uygulanabilir eylemler = %v", got)
	}
	if d.ApprovedBy != "soc-lead" {
		t.Errorf("onaylayan = %q, beklenen \"soc-lead\"", d.ApprovedBy)
	}
	if d.DecidedAt.IsZero() {
		t.Error("karar zamanı kaydedilmeliydi")
	}
	// Boş onaylayan reddedilmeli (ayrı bir karar üzerinde).
	d2 := g.Review(rec, true)
	if err := d2.Approve("  "); err == nil {
		t.Error("boş onaylayan kabul edilmemeli")
	}
}

// TestGateRejectPath, reddetme yolunu ve gerekçe kaydını doğrular.
func TestGateRejectPath(t *testing.T) {
	g := NewGate()
	rec := Recommendation{Task: TaskRemediationSuggestion, Actions: []ProposedAction{{Kind: "isolate", Target: "h1"}}}
	d := g.Review(rec, true)
	if err := d.Reject("analyst", "iş etkisi çok yüksek"); err != nil {
		t.Fatalf("reddetme hatası: %v", err)
	}
	if d.State != StateRejected {
		t.Errorf("durum = %v, beklenen Rejected", d.State)
	}
	if d.Actionable() {
		t.Error("reddedilmiş karar uygulanabilir olmamalı")
	}
	if d.RejectedBy != "analyst" || d.Reason != "iş etkisi çok yüksek" {
		t.Errorf("reddeden/gerekçe kaydı hatalı: %q / %q", d.RejectedBy, d.Reason)
	}
	// Reddedilmiş karar tekrar onaylanamaz.
	if err := d.Approve("x"); err != ErrNotPending {
		t.Errorf("hata = %v, beklenen ErrNotPending", err)
	}
}

// TestAssistantFlow, Assistant'ın öneri ürettiğini (PendingApproval) ve insan
// onayına kadar hiçbir eylemin uygulanabilir olmadığını doğrular.
func TestAssistantFlow(t *testing.T) {
	a := NewAssistant(NewLocalProvider(), nil)
	rec, err := a.Recommend(context.Background(), Request{
		Task:    TaskRemediationSuggestion,
		Input:   "malware trojan injection found",
		Context: map[string]string{"file": "evil.exe"},
	})
	if err != nil {
		t.Fatalf("öneri hatası: %v", err)
	}
	if len(rec.Actions) == 0 {
		t.Fatal("öneri eylemi bekleniyordu")
	}
	// Politika geçmeden önce.
	dBlocked := a.Review(rec, false)
	if dBlocked.Actionable() {
		t.Error("politika engelliyken uygulanabilir olmamalı")
	}
	// Politika geçer ama henüz onay yok.
	d := a.Review(rec, true)
	if d.State != StatePendingApproval {
		t.Errorf("durum = %v, beklenen PendingApproval", d.State)
	}
	if d.Actionable() {
		t.Error("onay öncesi uygulanabilir olmamalı")
	}
	// İnsan onayı sonrası.
	if err := d.Approve("analyst"); err != nil {
		t.Fatalf("onay hatası: %v", err)
	}
	if !d.Actionable() {
		t.Error("onay + politika sonrası uygulanabilir olmalı")
	}
}

// TestContextCancellation, iptal edilmiş bağlamda analizin hata döndürdüğünü doğrular.
func TestContextCancellation(t *testing.T) {
	p := NewLocalProvider()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Analyze(ctx, Request{Task: TaskAlertSummary, Input: "something happened"}); err == nil {
		t.Error("iptal edilmiş bağlamda hata bekleniyordu")
	}
}
