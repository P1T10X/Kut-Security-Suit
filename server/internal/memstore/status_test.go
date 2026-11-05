package memstore

import (
	"context"
	"testing"
	"time"

	"kut.corp/suite/server/internal/enroll"
)

// enrollDevice, test için bir cihaz oluşturur ve id'sini döner.
func enrollDevice(t *testing.T, s *Store) string {
	t.Helper()
	id, err := s.UpsertEnrollingDevice(context.Background(), enroll.DeviceEnrollment{
		MACBlindIndex: []byte(t.Name()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestMarkStaleOfflineOnlyTouchesStaleActive(t *testing.T) {
	s := New()
	ctx := context.Background()
	id := enrollDevice(t, s)

	now := time.Now()
	// Cihaz taze görüldü: bayat değil, OFFLINE olmamalı.
	if _, err := s.TouchHeartbeat(ctx, id, "", "", now); err != nil {
		t.Fatal(err)
	}
	n, err := s.MarkStaleOffline(ctx, now.Add(-90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("taze cihaz OFFLINE işaretlenmemeli, dönen sayı: %d", n)
	}

	// Cihaz eskisi görüldü (eşiğin gerisinde): OFFLINE işaretlenmeli.
	if _, err := s.TouchHeartbeat(ctx, id, "", "", now.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	n, err = s.MarkStaleOffline(ctx, now.Add(-90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("bayat cihaz OFFLINE işaretlenmeliydi, dönen sayı: %d", n)
	}
	d, _, _ := s.DeviceByID(ctx, id)
	if d.Status != "OFFLINE" {
		t.Fatalf("durum OFFLINE olmalı, dönen: %q", d.Status)
	}

	// İkinci tarama idempotent: zaten OFFLINE olan tekrar sayılmaz.
	n, _ = s.MarkStaleOffline(ctx, now.Add(-90*time.Second))
	if n != 0 {
		t.Fatalf("zaten OFFLINE cihaz tekrar işaretlenmemeli, dönen: %d", n)
	}
}

func TestMarkStaleOfflinePreservesQuarantined(t *testing.T) {
	s := New()
	ctx := context.Background()
	id := enrollDevice(t, s)

	// Cihaz eski görüldü ama QUARANTINED: bayat görev buna dokunmamalı.
	if _, err := s.TouchHeartbeat(ctx, id, "", "", time.Now().Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDeviceStatus(ctx, id, "QUARANTINED"); err != nil {
		t.Fatal(err)
	}
	n, err := s.MarkStaleOffline(ctx, time.Now().Add(-90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("QUARANTINED cihaz OFFLINE'a düşmemeli, dönen: %d", n)
	}
	d, _, _ := s.DeviceByID(ctx, id)
	if d.Status != "QUARANTINED" {
		t.Fatalf("durum QUARANTINED korunmalı, dönen: %q", d.Status)
	}
}

func TestSetDeviceStatusUnknownDeviceNoError(t *testing.T) {
	s := New()
	if err := s.SetDeviceStatus(context.Background(), "yok", "ACTIVE"); err != nil {
		t.Fatalf("bilinmeyen cihaz sessizce geçilmeli: %v", err)
	}
}

func TestTouchHeartbeatStoresOSVersion(t *testing.T) {
	s := New()
	id, _ := s.UpsertEnrollingDevice(context.Background(), enroll.DeviceEnrollment{PreferredDeviceID: "d-os"})
	if _, err := s.TouchHeartbeat(context.Background(), id, "1.2.0", "Ubuntu 22.04", time.Now()); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ListDevices(context.Background(), 10, "")
	var found bool
	for _, r := range rows {
		if r.ID == id && r.OSVersion == "Ubuntu 22.04" && r.AgentVersion == "1.2.0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("os_version/agent_version saklanmalıydı: %+v", rows)
	}
}

// RecordAgentBinary (öz-tasdik): ilk kayıt kurcalama değil; sürüm değişmeden
// hash değişirse kurcalama; sürüm de değişirse (meşru güncelleme) kurcalama değil.
func TestRecordAgentBinaryTamperDetection(t *testing.T) {
	s := New()
	ctx := context.Background()
	id, _ := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{PreferredDeviceID: "d-att"})

	if tampered, _ := s.RecordAgentBinary(ctx, id, "1.0.0", "hashA"); tampered {
		t.Fatal("ilk kayıt kurcalama olmamalı")
	}
	// Aynı sürüm, farklı hash → KURCALAMA.
	if tampered, _ := s.RecordAgentBinary(ctx, id, "1.0.0", "hashB"); !tampered {
		t.Fatal("sürüm aynı + hash farklı → kurcalama beklenmeliydi")
	}
	// Meşru güncelleme: sürüm değişti + hash değişti → kurcalama DEĞİL.
	if tampered, _ := s.RecordAgentBinary(ctx, id, "1.1.0", "hashC"); tampered {
		t.Fatal("sürüm değişimiyle hash değişimi meşru (kurcalama değil)")
	}
}
