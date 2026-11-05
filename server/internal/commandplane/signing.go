package commandplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"kut.corp/suite/cmdenvelope"
)

// SignedCommandEnvelope wraps an authorized command with a cryptographic signature,
// ensuring non-repudiation, integrity, and anti-replay.
type SignedCommandEnvelope struct {
	CommandID string         `json:"command_id"`
	DeviceID  string         `json:"device_id"`
	Type      CommandType    `json:"type"`
	IssuedBy  string         `json:"issued_by"`
	Params    map[string]any `json:"params,omitempty"`
	Nonce     string         `json:"nonce"`
	IssuedAt  time.Time      `json:"issued_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	Signature []byte         `json:"signature"` // Ed25519 signature
}

// CanonicalSigningBytes produces deterministic canonical bytes for signing or verification.
// Avoids non-deterministic JSON key serialization issues by computing
// a sorted SHA-256 hash of parameters and binding all fields with explicit unit separators.
//
// Kodlama, paylaşılan (internal OLMAYAN) cmdenvelope paketine DELEGE edilir; böylece ajan
// da (commandplane'i import edemeden) BİREBİR aynı baytları üretip imzayı doğrulayabilir.
// İmza, zaman alanlarını UnixNano int64 olarak bağlar.
func CanonicalSigningBytes(cmdID, deviceID string, cmdType CommandType, issuedBy string, params map[string]any, nonce string, issuedAt, expiresAt time.Time) []byte {
	return cmdenvelope.CanonicalBytes(cmdID, deviceID, string(cmdType), issuedBy, params, nonce, issuedAt.UnixNano(), expiresAt.UnixNano())
}

// CommandSigner signs command envelopes using an Ed25519 private key.
type CommandSigner struct {
	privKey ed25519.PrivateKey
	ttl     time.Duration
}

// NewCommandSigner creates a new CommandSigner.
func NewCommandSigner(privKey ed25519.PrivateKey, ttl time.Duration) *CommandSigner {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &CommandSigner{
		privKey: privKey,
		ttl:     ttl,
	}
}

// Sign crafts and signs an envelope for the given command request.
func (s *CommandSigner) Sign(cmdID string, req CommandRequest, now time.Time) (SignedCommandEnvelope, error) {
	if len(s.privKey) != ed25519.PrivateKeySize {
		return SignedCommandEnvelope{}, errors.New("invalid private key size")
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return SignedCommandEnvelope{}, fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	issuedAt := now.UTC()
	expiresAt := issuedAt.Add(s.ttl)

	signBytes := CanonicalSigningBytes(cmdID, req.DeviceID, req.Type, req.IssuedBy, req.Params, nonce, issuedAt, expiresAt)
	sig := ed25519.Sign(s.privKey, signBytes)

	return SignedCommandEnvelope{
		CommandID: cmdID,
		DeviceID:  req.DeviceID,
		Type:      req.Type,
		IssuedBy:  req.IssuedBy,
		Params:    req.Params,
		Nonce:     nonce,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		Signature: sig,
	}, nil
}

// CommandVerifier verifies signed command envelopes using an Ed25519 public key.
// Anti-replay: her başarıyla doğrulanan nonce TÜKETİLİR (kaydedilir);
// aynı nonce TTL penceresi içinde yeniden sunulursa reddedilir. Böylece yakalanan
// geçerli bir zarf süresi dolana dek tekrar oynatılamaz (önceki sürüm yalnız
// nonce'un boş-olmadığını kontrol ediyor, tüketmiyordu).
type CommandVerifier struct {
	pubKey ed25519.PublicKey
	mu     sync.Mutex
	seen   map[string]time.Time // nonce -> zarf son-geçerlilik; bu ana dek replay reddi
}

// NewCommandVerifier creates a new CommandVerifier.
func NewCommandVerifier(pubKey ed25519.PublicKey) *CommandVerifier {
	return &CommandVerifier{pubKey: pubKey, seen: make(map[string]time.Time)}
}

// consumeNonce, nonce'u anti-replay deposuna işler. Daha önce görülmüş ve henüz
// süresi dolmamışsa replay'dir (hata). Fırsatçı budama ile süresi geçmiş nonce'lar
// temizlenir (sınırsız bellek büyümesini önler).
func (v *CommandVerifier) consumeNonce(nonce string, expiresAt, now time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = make(map[string]time.Time)
	}
	if exp, ok := v.seen[nonce]; ok && now.Before(exp) {
		return errors.New("replay detected: nonce already consumed")
	}
	for n, exp := range v.seen { // budama
		if !now.Before(exp) {
			delete(v.seen, n)
		}
	}
	v.seen[nonce] = expiresAt
	return nil
}

// Verify validates that the envelope signature is authentic, targeting the expected device,
// and has not expired.
func (v *CommandVerifier) Verify(env SignedCommandEnvelope, expectedDeviceID string, now time.Time) error {
	if len(v.pubKey) != ed25519.PublicKeySize {
		return errors.New("invalid public key size")
	}

	if expectedDeviceID != "" && env.DeviceID != expectedDeviceID {
		return fmt.Errorf("device ID mismatch: expected %s, got %s", expectedDeviceID, env.DeviceID)
	}

	if now.After(env.ExpiresAt) {
		return fmt.Errorf("command envelope expired at %s", env.ExpiresAt.Format(time.RFC3339))
	}

	if env.Nonce == "" {
		return errors.New("missing cryptographic nonce")
	}

	signBytes := CanonicalSigningBytes(env.CommandID, env.DeviceID, env.Type, env.IssuedBy, env.Params, env.Nonce, env.IssuedAt, env.ExpiresAt)
	if !ed25519.Verify(v.pubKey, signBytes, env.Signature) {
		return errors.New("cryptographic signature verification failed")
	}

	// İmza geçerli → nonce'u tüket (anti-replay). Yalnız doğrulanmış zarflar
	// deposu kirletir; reddedilen imza replay-state'i etkilemez.
	if err := v.consumeNonce(env.Nonce, env.ExpiresAt, now); err != nil {
		return err
	}

	return nil
}
