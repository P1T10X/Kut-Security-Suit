# ADR 0008: AI Model Provider Abstraction and Model Router

## Status
Proposed

## Context
KUT Security Fabric requires AI integration for SOC summarization, triage recommendations, causality graph analysis, and autonomous security decisions. Currently, the platform connects to a single external HTTP endpoint (`services/ai/app.py` via `aibrain.HTTPProvider`) with no model diversity, no local LLM support, no data redaction, and no sensitivity-based routing.

Directly coupling to any single AI provider (OpenAI, Anthropic, Google) violates KUT's core principle of **sovereignty and provider-neutrality**. Furthermore, sending un-redacted security telemetry to external cloud LLMs violates data sovereignty and KVKK/GDPR requirements.

## Decision
We will introduce a dedicated `aiprovider` package (`server/internal/aiprovider`) that provides:

1. **`ModelProvider` Interface:**
   - Unified abstraction for text completion, structured output, and embeddings
   - Implementations: Local (Ollama/vLLM/llama.cpp), Cloud (OpenAI, Anthropic, Gemini), Fallback (deterministic safe-Go)
   - Streaming support via Go channels

2. **`ModelRouter`:**
   - Routes requests based on:
     - **Task type:** Summarization → Fast model, Triage → Reasoning model, Graph analysis → Specialized model
     - **Data sensitivity:** Public/Low → Cloud allowed, High/PII → Local-only, Sovereign/Airgap → Local-only
     - **Cost/Latency constraints:** SLA-based fallback

3. **`DataDLP` Pre-Flight Redaction:**
   - Intercepts all prompt payloads before provider dispatch
   - Redacts or masks: PII (emails, names), credentials (keys, tokens), internal network topology (private IPs, hostnames)
   - Reversible token replacement for post-response rehydration

4. **Integration with Existing `aibrain`:**
   - `aibrain.Provider` interface remains the high-level security contract
   - A new `aibrain.ModelBridge` adapts `aiprovider.ModelProvider` to fulfill `aibrain.Provider`
   - Existing `LocalProvider` remains the ultimate fail-safe fallback

## Consequences

### Positive
- **Sovereign by default:** Operates fully offline with Ollama/vLLM
- **Provider-neutral:** Switch providers with configuration changes, no code modification
- **Privacy-preserving:** Data DLP guarantees sensitive data never leaves boundary
- **Cost-effective:** Routes routine tasks to smaller/local models, reserves large models for complex reasoning
- **Backward-compatible:** Existing `aibrain` callers require zero changes

### Negative
- Additional latency introduced by DLP redaction and rehydration
- Increased operational complexity (managing multiple provider configurations)
- Token-mapping state must be maintained per-request for reversible redaction
