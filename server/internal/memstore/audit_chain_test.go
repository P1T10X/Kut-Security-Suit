package memstore

import (
	"context"
	"testing"
)

// Denetim izi hash-zinciri bütünlüğü: normalde doğrulanır; bir kayıt kurcalanınca
// (silme/değiştirme) zincir kırılır ve VerifyAuditChain hata döner.
func TestAuditChainDetectsTampering(t *testing.T) {
	ctx := context.Background()
	s := New()
	for _, a := range []string{"LOGIN", "QUARANTINE_DEVICE", "CREATE_ADMIN", "DATA_ERASURE"} {
		if err := s.WriteAudit(ctx, "admin-x", a, "device", "dev-1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.VerifyAuditChain(ctx); err != nil {
		t.Fatalf("sağlam zincir doğrulanmalıydı: %v", err)
	}

	// Bir kaydın alanını değiştir (kurcalama) → zincir kırılmalı.
	s.audit[1].action = "DELETE_ALL_LOGS"
	if err := s.VerifyAuditChain(ctx); err == nil {
		t.Fatal("kurcalanmış kayıt için zincir kırılmalıydı")
	}

	// Değişikliği geri al → yine sağlam.
	s.audit[1].action = "QUARANTINE_DEVICE"
	if err := s.VerifyAuditChain(ctx); err != nil {
		t.Fatalf("geri alınınca zincir yine sağlam olmalıydı: %v", err)
	}

	// Bir kaydı sil (araya) → sonraki hash'ler artık uyumsuz.
	s.audit = append(s.audit[:1], s.audit[2:]...)
	if err := s.VerifyAuditChain(ctx); err == nil {
		t.Fatal("silinen kayıt sonrası zincir kırılmalıydı")
	}
}
