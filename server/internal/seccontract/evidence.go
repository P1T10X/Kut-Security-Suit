package seccontract

import "time"

// Evidence, delil kaydı + gözetim zinciridir (CONTRACTS §9). Doğrulama TEK bir
// "verified" bayrağı değil, AYRI assurance boyutlarıdır: biri diğerini ima
// etmez. SEALED terminaldir ve değişmezdir.
type Evidence struct {
	EvidenceID     string
	CaseID         string
	IncidentID     string
	SourceDevice   string
	CollectorID    string
	SourcePathType string
	CollectedAt    time.Time
	HashAtSource   string // opsiyonel; yoksa SourceHashVerified=false
	HashAtReceipt  string
	StorageHash    string

	// Ayrı assurance boyutları — karıştırılmaz:
	TransportIntegrityVerified bool // nakil/depolama bütünlüğü (HashAtReceipt==HashAtStorage)
	SourceHashVerified         bool // kaynak-hash tutarlılığı (yalnız HashAtSource varsa; sahicilik DEĞİL)
	CollectorIdentityVerified  bool // toplayan kimlik (mTLS/imza)
	ProvenanceVerified         bool // kaynak cihaz/yol bağlamı

	State     EvidenceState
	AccessLog []string
	ExportLog []string
	Retention string
}

// CanSeal, delilin SEALED olabilmesi için zorunlu ön-koşulun sağlanıp sağlanmadığını
// döner: VERIFIED = TransportIntegrityVerified. Diğer boyutlar ayrı raporlanır;
// "SEALED" bütünsel-sahicilik iddiası taşımaz.
func (e Evidence) CanSeal() bool { return e.TransportIntegrityVerified && e.State == EvVerified }
