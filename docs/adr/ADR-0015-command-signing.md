# ADR 0015: Cryptographic Command Signing and Tamper Verification

## Status
Accepted

## Context
In enterprise endpoint security platforms, commands sent from the C2 server to endpoints (such as `LOCK`, `WIPE`, `QUARANTINE`, or `RUN_SIGNED_SCRIPT`) represent high-impact actions. Without end-to-end cryptographic integrity, an attacker performing a man-in-the-middle or compromising intermediate queues could forge, alter parameters, or replay administrative actions. 

Furthermore, naive JSON serialization is non-deterministic in Go without canonical ordering, risking false-positive signature verification failures.

## Decision
We implemented deterministic command signing and verification in `server/internal/commandplane`:

1. **Deterministic Canonical Signing Layout:**
   - `CanonicalSigningBytes` binds `CommandID`, `DeviceID`, `CommandType`, `IssuedBy`, sorted SHA-256 hash of parameters (`hashParams`), `Nonce`, `IssuedAt`, and `ExpiresAt` using unit separators (`0x1f`).
   - Eliminates JSON key-ordering discrepancies.

2. **Ed25519 Signature Envelope:**
   - `CommandSigner.Sign` generates a cryptographic nonce and signs canonical bytes with the server's Ed25519 private key.
   - Outputs a self-contained `SignedCommandEnvelope`.

3. **Strict Endpoint Verification:**
   - `CommandVerifier.Verify` checks:
     - Expected device ID matches target device ID (prevents cross-device command diversion).
     - Envelope has not expired.
     - Cryptographic nonce is present.
     - Ed25519 signature verifies against the server's public key.

## Consequences

### Positive
- Endpoint agents execute high-impact commands only if verified by the server's Ed25519 signature.
- Anti-replay and parameter integrity are guaranteed at the cryptographic level.
- Removes JSON key-ordering discrepancies.

### Negative
- Endpoints must have the server's Ed25519 public key pre-provisioned or distributed during enrollment.
