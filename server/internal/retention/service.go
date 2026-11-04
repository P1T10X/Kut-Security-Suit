package retention

import (
	"context"
	"strconv"
	"time"
)

// Store, partition DDL işlemlerinin kalıcılık kaynağıdır.
type Store interface {
	ListPartitions(ctx context.Context) ([]time.Time, error)
	CreatePartition(ctx context.Context, monthStart time.Time) error
	DropPartition(ctx context.Context, monthStart time.Time) error
	// PurgeArtifactsOlderThan, verilen zamandan eski toplanan dosya artefaktlarını
	// (adli/IR) siler ve silinen sayısını döner. artifacts tablosu dosya
	// içeriğini (BYTEA) sakladığından partition'lanmaz; DELETE ile budanır.
	PurgeArtifactsOlderThan(ctx context.Context, cutoff time.Time) (int, error)
}

// Service, saklama planını hesaplayıp uygular.
type Service struct {
	store         Store
	retentionDays int
	aheadMonths   int
	log           func(string)
}

// NewService oluşturur. retentionDays <= 0 ise 90 (varsayılan) kullanılır.
func NewService(store Store, retentionDays, aheadMonths int, log func(string)) *Service {
	if retentionDays <= 0 {
		retentionDays = 90
	}
	if aheadMonths <= 0 {
		aheadMonths = 2
	}
	if log == nil {
		log = func(string) {}
	}
	return &Service{store: store, retentionDays: retentionDays, aheadMonths: aheadMonths, log: log}
}

// Run, mevcut partition'ları listeler, planı hesaplar ve uygular: önce gelecek
// partition'ları OLUŞTURUR (veri kaybı riski olmadan), sonra süresi dolanları DÜŞÜRÜR.
func (s *Service) Run(ctx context.Context, now time.Time) error {
	existing, err := s.store.ListPartitions(ctx)
	if err != nil {
		return err
	}
	create, drop := PlanPartitions(now, s.retentionDays, s.aheadMonths, existing)

	for _, m := range create {
		if err := s.store.CreatePartition(ctx, m); err != nil {
			return err
		}
		s.log("partition oluşturuldu: " + PartitionName(m))
	}
	for _, m := range drop {
		if err := s.store.DropPartition(ctx, m); err != nil {
			return err
		}
		s.log("saklama süresi doldu, partition düşürüldü: " + PartitionName(m))
	}

	// Toplanan dosya artefaktları (adli/IR) partition'lanmaz; saklama penceresinden
	// eski olanları DELETE ile buda (aksi halde BYTEA içerik sınırsız büyür).
	cutoff := now.AddDate(0, 0, -s.retentionDays)
	if n, err := s.store.PurgeArtifactsOlderThan(ctx, cutoff); err != nil {
		return err
	} else if n > 0 {
		s.log("saklama süresi dolan " + strconv.Itoa(n) + " artefakt silindi")
	}
	return nil
}
