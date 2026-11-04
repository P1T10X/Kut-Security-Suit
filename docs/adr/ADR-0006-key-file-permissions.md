# ADR 0006: Private Key File Permissions

## Status
Accepted

## Context
Private key files (TLS server keys, CA keys) were being loaded directly without verifying their file permissions. In POSIX environments, if an administrator mistakenly extracts or copies a private key with world-readable permissions (e.g., `0644`), any local user could read the key and potentially compromise the system. The principle of fail-closed security requires that sensitive operations be restricted.

## Decision
We will enforce safe file permissions (`0600` or `0400`) on all loaded private key files (`CAKeyPath` and `ServerKeyPath`).
Consistent with the project's fail-closed ethos, this check is **enforced by default**: an insecure permission (e.g., `0644`) halts startup with an actionable error. An operator who knowingly accepts relaxed permissions can downgrade the check to warn-only by setting `KUT_ALLOW_INSECURE_KEY_PERMISSIONS=1` (not recommended).
On Windows environments, where POSIX-style permissions do not natively apply, this check is bypassed via a `runtime.GOOS` guard.
(Revised: the earlier default was warn-only — fail-open — which contradicted the fail-closed principle; the default is now strict with an explicit opt-out.)

## Consequences
- **Positive:** Reduces the risk of local key compromise by actively checking file permissions.
- **Positive:** Fail-closed by default — insecure key permissions cannot be shipped silently; an explicit opt-out (`KUT_ALLOW_INSECURE_KEY_PERMISSIONS=1`) keeps a documented escape hatch.
- **Negative:** Administrators on POSIX systems with previously relaxed permissions must tighten them to `0600`/`0400` (or set the opt-out) before the server will start.
