package seccontract

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"kut.corp/suite/server/internal/scope"
)

// ExecutionIntent, grant-consume ile ATOMİK yaratılan durable kayıttır (CONTRACTS §7).
// TÜM state-changing komutlar için oluşur; Destructive=true olanlar ek fail-closed
// gereksinimlere tabidir (DestructiveJournal). Command lifecycle ile belirsizlik
// semantiği uyumludur (INV-050/051).
type ExecutionIntent struct {
	IntentID    string
	CommandID   string // ExecutionIntent.CommandID == CommandEnvelope.CommandID (INV-046)
	GrantID     string
	TenantID    string
	Action      scope.Action
	Targets     []string
	Destructive bool
	State       IntentState
	CreatedAt   time.Time
	CompletedAt time.Time
}

// CommandEnvelope, sunucudan CİHAZA giden komuttur (CONTRACTS §5). Grant'ten AYRI
// güven nesnesi (§5.1): kendi imza/replay/expiry/device-binding'i vardır; GERÇEK
// GrantID TAŞIMAZ, yalnız opak AuthorizationCorrelationID.
type CommandEnvelope struct {
	CommandID                  string // stable execution/dedup kimliği (INV-042/046)
	AuthorizationCorrelationID string // opak; GrantID DEĞİL
	RequestID                  string // audit korelasyon
	TenantID                   string
	DeviceID                   string
	Action                     scope.Action
	ParametersHash             string
	IssuedAt                   time.Time
	ExpiresAt                  time.Time
	Nonce                      string // replay freshness
	Sequence                   uint64 // ordering
	Signature                  []byte // sunucu imzası (agent bağımsız doğrular)
}

// CorrelationID, bir GrantID'den OPAK, yetkilendirmeyen bir korelasyon kimliği türetir.
// Cihaza güvenle gönderilebilir; GrantID geri elde edilemez (tek-yön özet).
// Server audit CorrelationID↔GrantID↔RequestID eşlemesini ayrıca tutar.
func CorrelationID(grantID string) string {
	sum := sha256.Sum256([]byte("kut-corr\x1f" + grantID))
	return "corr_" + hex.EncodeToString(sum[:])[:24]
}
