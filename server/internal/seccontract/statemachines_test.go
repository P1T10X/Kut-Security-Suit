package seccontract

import "testing"

func TestCommandTransitions(t *testing.T) {
	// Geçerli mutlu yol.
	if !CmdRunning.CanGoTo(CmdSucceeded) {
		t.Fatal("RUNNING→SUCCEEDED geçerli olmalı")
	}
	// ACK ≠ SUCCEEDED: ACKNOWLEDGED doğrudan SUCCEEDED olamaz (INV-026/007).
	if CmdAcknowledged.CanGoTo(CmdSucceeded) {
		t.Fatal("ACKNOWLEDGED→SUCCEEDED doğrudan YASAK (RUNNING gerek)")
	}
	// EXECUTION_UNKNOWN → QUEUED YASAK (INV-050).
	if CmdExecutionUnknown.CanGoTo(CmdQueued) {
		t.Fatal("EXECUTION_UNKNOWN→QUEUED yasak (INV-050)")
	}
	// EXECUTION_FAILED → QUEUED YASAK (INV-043); yalnız FAILED_FINAL.
	if CmdExecutionFailed.CanGoTo(CmdQueued) {
		t.Fatal("EXECUTION_FAILED→QUEUED yasak (INV-043)")
	}
	if !CmdExecutionFailed.CanGoTo(CmdFailedFinal) {
		t.Fatal("EXECUTION_FAILED→FAILED_FINAL geçerli olmalı")
	}
	// Delivery retry: DELIVERY_FAILED→QUEUED.
	if !CmdDeliveryFailed.CanGoTo(CmdQueued) {
		t.Fatal("DELIVERY_FAILED→QUEUED geçerli olmalı (delivery retry)")
	}
	// Terminal sınıflandırma: EXECUTION_UNKNOWN terminal DEĞİL.
	if CmdExecutionUnknown.Terminal() {
		t.Fatal("EXECUTION_UNKNOWN terminal olmamalı")
	}
	if !CmdSucceeded.Terminal() || !CmdFailedFinal.Terminal() {
		t.Fatal("SUCCEEDED/FAILED_FINAL terminal olmalı")
	}
}

func TestIntentTransitions(t *testing.T) {
	// CREATED→UNKNOWN (INV-051): delivery sınırı geçti, execution belirsiz.
	if !IntentCreated.CanGoTo(IntentUnknown) {
		t.Fatal("CREATED→UNKNOWN geçerli olmalı (INV-051)")
	}
	if !IntentExecuting.CanGoTo(IntentUnknown) {
		t.Fatal("EXECUTING→UNKNOWN geçerli olmalı")
	}
	if !IntentUnknown.CanGoTo(IntentReconciledDone) {
		t.Fatal("UNKNOWN→RECONCILED_DONE geçerli olmalı")
	}
	if IntentUnknown.CanGoTo(IntentDone) {
		t.Fatal("UNKNOWN doğrudan DONE olamaz (reconciliation gerek, INV-050)")
	}
}

func TestQuarantineTransitions(t *testing.T) {
	// Kısmi uygulama INACTIVE olamaz (INV-028): APPLYING→INACTIVE yok.
	if QApplying.CanGoTo(QInactive) {
		t.Fatal("APPLYING→INACTIVE yasak (partial=DEGRADED, INV-028)")
	}
	if !QApplying.CanGoTo(QDegraded) {
		t.Fatal("APPLYING→DEGRADED geçerli olmalı")
	}
	if !QDegraded.CanGoTo(QApplying) || !QDegraded.CanGoTo(QReleasing) {
		t.Fatal("DEGRADED çıkışları (→APPLYING/→RELEASING) olmalı")
	}
}

func TestEvidenceTransitions(t *testing.T) {
	if !EvReceived.CanGoTo(EvVerified) || !EvVerified.CanGoTo(EvSealed) {
		t.Fatal("RECEIVED→VERIFIED→SEALED geçerli olmalı")
	}
	// VERIFIED olmadan SEALED olamaz.
	if EvReceived.CanGoTo(EvSealed) {
		t.Fatal("RECEIVED→SEALED doğrudan yasak (önce VERIFIED)")
	}
}

func TestRecommendationTransitions(t *testing.T) {
	if !RecValidated.CanGoTo(RecAccepted) || !RecAccepted.CanGoTo(RecConsumed) {
		t.Fatal("VALIDATED→ACCEPTED→CONSUMED geçerli olmalı")
	}
	// Doğrulanmadan kabul edilemez.
	if RecIssued.CanGoTo(RecAccepted) {
		t.Fatal("ISSUED→ACCEPTED doğrudan yasak (önce VALIDATED)")
	}
	// 'APPROVED' diye bir recommendation durumu YOKTUR (authorization terminolojisi
	// AIRecommendation'da kullanılmaz). Bu, tip-seviyesinde garanti edilir — RecApproved
	// sabiti tanımlı değildir; buradaki test yalnız niyeti belgeler.
}
