package db

// QueryEvents'in kayıtlı kiracıyı döndürmesi (arka plan analizörlerinin kiracı atfı için)
// — gerçek PostgreSQL'e karşı. KUT_DATABASE_URL yoksa ATLANIR.

import (
	"testing"
	"time"

	"kut.corp/suite/server/internal/adminread"
	"kut.corp/suite/server/internal/model"
)

func TestPGQueryEventsCarriesStoredTenant(t *testing.T) {
	s, ctx := pgStore(t)
	// Geçerli ay partition'ı yoksa oluştur (idempotent; CI şeması yalnız örnek aylar içerir).
	if ok, err := s.EventPartitionReady(ctx); err != nil {
		t.Fatal(err)
	} else if !ok {
		now := time.Now().UTC()
		if err := s.CreatePartition(ctx, time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
	}
	var dev string
	if err := s.pool.QueryRow(ctx, `SELECT uuid_generate_v4()::text`).Scan(&dev); err != nil {
		t.Fatal(err)
	}
	tn, other := uniq(t, "tn-"), uniq(t, "ot-")
	if _, err := s.SaveEvents(ctx, dev, []model.Event{{
		Category: "SECURITY", Severity: "HIGH", Message: "analyzer-tenant-probe",
		OccurredAt: time.Now(), TenantID: tn, Details: `{"probe":true}`,
	}}); err != nil {
		t.Fatalf("olay yazımı: %v", err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM event_logs WHERE device_id = $1::uuid`, dev) })

	// POZİTİF: kayıtlı kiracı satırla birlikte döner; kiracı-kapsamlı sorgu sahibine gösterir.
	rows, err := s.QueryEvents(ctx, adminread.EventFilter{DeviceID: dev, TenantID: tn, Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].TenantID != tn {
		t.Fatalf("satır kayıtlı kiracıyı taşımalı: %+v %v", rows, err)
	}
	// NEGATİF: başka kiracı kapsamı aynı satırı GÖRMEZ.
	rows, err = s.QueryEvents(ctx, adminread.EventFilter{DeviceID: dev, TenantID: other, Limit: 10})
	if err != nil || len(rows) != 0 {
		t.Fatalf("başka kiracı bu olayı görmemeli: %+v %v", rows, err)
	}
}
