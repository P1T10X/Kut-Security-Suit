# ADR 0010: AI Context Sanitization and De-Tainting Guardrail

## Status
Accepted

## Context
In the KUT Agentic Security Plane (`server/internal/aisec`), trust levels propagate monotonically downwards: `Tainted < Untrusted < Trusted`. While this design strictly prevents untrusted or tainted inputs from being implicitly elevated, it left a gap: there was no mechanism to sanitize or cleanse legitimately validated inputs. Once a context became Tainted, it remained permanently Tainted, leading to operational deadlocks where valid downstream workflows were blocked from execution.

## Decision
We introduced a formal, capability-gated sanitization mechanism via `SanitizeContext` and `Sanitizer`:

1. **Elevation Ceiling:**
   - A `Tainted` context can only be elevated to `Untrusted` (never directly to `Trusted`).
   - This ensures sanitized inputs can be processed through human-in-the-loop workflows (`REQUIRE_HUMAN`) without triggering unconditional denies, while preserving the invariant that external data is never trusted blindly.

2. **Capability Guardrail:**
   - The caller/agent principal must possess the explicit capability `CapSanitize ("context.sanitize")`.
   - Principals without this capability cannot de-taint context.

3. **Validator Prerequisite:**
   - A valid `Sanitizer` implementation must successfully clean and validate the input (`ok == true`).
   - If validation fails, the context remains `Tainted`.

## Consequences

### Positive
- Resolves operational deadlocks for multi-turn agentic workflows.
- Maintains defense-in-depth: untrusted inputs still require verification before sensitive actions.
- Preserves invariant INV-AG-001: external inputs never achieve `Trusted` status.

### Negative
- Requires agents performing validation to be provisioned with the `context.sanitize` capability.
