package commandplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestCommandSigningAndVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 keypair: %v", err)
	}

	signer := NewCommandSigner(priv, 5*time.Minute)
	verifier := NewCommandVerifier(pub)

	now := time.Now()
	req := CommandRequest{
		DeviceID: "endpoint-corp-042",
		Type:     TypeQuarantine,
		IssuedBy: "secops-operator@corp",
		Params: map[string]any{
			"reason": "malware execution detected",
			"case":   "INC-9912",
		},
	}

	// 1. Sign
	env, err := signer.Sign("cmd-1001", req, now)
	if err != nil {
		t.Fatalf("failed to sign command: %v", err)
	}

	if env.CommandID != "cmd-1001" || env.Nonce == "" || len(env.Signature) == 0 {
		t.Fatalf("invalid envelope generated: %+v", env)
	}

	// 2. Verify Success
	if err := verifier.Verify(env, "endpoint-corp-042", now.Add(time.Minute)); err != nil {
		t.Fatalf("verification failed on authentic envelope: %v", err)
	}

	// 3. Verify Failure on Target Device Mismatch
	if err := verifier.Verify(env, "endpoint-corp-999", now.Add(time.Minute)); err == nil {
		t.Fatal("expected failure on device mismatch, got nil")
	}

	// 4. Verify Failure on Expiration
	if err := verifier.Verify(env, "endpoint-corp-042", now.Add(10*time.Minute)); err == nil {
		t.Fatal("expected failure on expired envelope, got nil")
	}

	// 5. Verify Failure on Tampering (Parameters modified)
	tamperedEnv := env
	tamperedEnv.Params = map[string]any{
		"reason": "forged parameter",
	}
	if err := verifier.Verify(tamperedEnv, "endpoint-corp-042", now.Add(time.Minute)); err == nil {
		t.Fatal("expected failure on tampered params, got nil")
	}

	// 6. Verify Failure on Type Tampering (Quarantine -> Wipe)
	tamperedTypeEnv := env
	tamperedTypeEnv.Type = TypeWipe
	if err := verifier.Verify(tamperedTypeEnv, "endpoint-corp-042", now.Add(time.Minute)); err == nil {
		t.Fatal("expected failure on tampered command type, got nil")
	}
}

// TestCommandReplayRejected, geçerli bir zarfın TTL penceresi içinde yeniden
// sunulduğunda (aynı nonce) reddedildiğini doğrular (anti-replay).
func TestCommandReplayRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer := NewCommandSigner(priv, 5*time.Minute)
	verifier := NewCommandVerifier(pub)
	now := time.Now()
	req := CommandRequest{DeviceID: "dev-1", Type: TypeQuarantine, IssuedBy: "op@corp"}

	env, err := signer.Sign("cmd-replay", req, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := verifier.Verify(env, "dev-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("ilk doğrulama başarılı olmalı: %v", err)
	}
	// Aynı zarf TTL içinde tekrar sunulur → replay reddi.
	if err := verifier.Verify(env, "dev-1", now.Add(2*time.Minute)); err == nil {
		t.Fatal("TTL içinde tekrar sunulan zarf (aynı nonce) reddedilmeliydi")
	}
}
