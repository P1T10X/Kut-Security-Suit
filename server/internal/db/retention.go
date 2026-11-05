package db

import (
	"context"
	"fmt"
	"time"

	"kut.corp/suite/server/internal/retention"
)

// Derleme-zamanı arayüz kontrolü.
var _ retention.Store = (*Store)(nil)

// ListPartitions, event_logs'un mevcut aylık partition'larını (ay başlangıcı
// olarak) döner. Adları event_logs_YYYY_MM'den ay çözülür.
func (s *Store) ListPartitions(ctx context.Context) ([]time.Time, error) {
	const q = `
		SELECT c.relname
		  FROM pg_inherits i
		  JOIN pg_class c      ON c.oid = i.inhrelid
		  JOIN pg_class parent ON parent.oid = i.inhparent
		 WHERE parent.relname = 'event_logs'`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("db: partition listesi: %w", err)
	}
	defer rows.Close()

	var out []time.Time
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		var y, m int
		if _, err := fmt.Sscanf(name, "event_logs_%04d_%02d", &y, &m); err != nil {
			continue // beklenmeyen adları atla
		}
		out = append(out, time.Date(y, time.Month(m), 1, 0, 0, 0, 0, time.UTC))
	}
	return out, rows.Err()
}

// EventPartitionReady, ŞU ANKİ ayın event_logs partition'ının mevcut olup
// olmadığını döner. false → gelen olay INSERT'leri başarısız olur (partition
// horizon bitmiş; retention işi aksamış). /readyz bunu kontrol ederek depo
// erişilebilir olsa bile hazır-değil (503) bildirebilir — sessiz INSERT hatası
// yerine erken uyarı (yük dengeleyici trafiği keser).
func (s *Store) EventPartitionReady(ctx context.Context) (bool, error) {
	parts, err := s.ListPartitions(ctx)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	cur := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	for _, p := range parts {
		if p.Equal(cur) {
			return true, nil
		}
	}
	return false, nil
}

// CreatePartition, verilen ay için event_logs partition'ını oluşturur (varsa dokunmaz).
func (s *Store) CreatePartition(ctx context.Context, monthStart time.Time) error {
	name := retention.PartitionName(monthStart)
	start := monthStart.UTC().Format("2006-01-02")
	end := monthStart.UTC().AddDate(0, 1, 0).Format("2006-01-02")
	// Not: tablo/aralık adları sabit biçimden türetilir (SQL injection yüzeyi yok).
	q := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s PARTITION OF event_logs FOR VALUES FROM ('%s') TO ('%s')`,
		name, start, end)
	if _, err := s.pool.Exec(ctx, q); err != nil {
		return fmt.Errorf("db: partition oluşturma (%s): %w", name, err)
	}
	return nil
}

// DropPartition, verilen ay partition'ını kalıcı olarak siler (saklama süresi doldu).
func (s *Store) DropPartition(ctx context.Context, monthStart time.Time) error {
	name := retention.PartitionName(monthStart)
	if _, err := s.pool.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, name)); err != nil {
		return fmt.Errorf("db: partition düşürme (%s): %w", name, err)
	}
	return nil
}

// PurgeArtifactsOlderThan, saklama penceresinden eski toplanan dosya
// artefaktlarını (adli/IR) siler ve silinen satır sayısını döner. artifacts
// tablosu partition'lanmadığından (dosya içeriği BYTEA) DELETE ile budanır.
func (s *Store) PurgeArtifactsOlderThan(ctx context.Context, cutoff time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM artifacts WHERE collected_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("db: artefakt budama: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
