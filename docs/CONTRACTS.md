# KUT Security Contracts (TASLAK v3.2)

**Durum:** TASLAK v3.2.1. **Henüz FREEZE APPROVED değil, uygulanmadı, migrate edilmedi.**
**Kapsam:** güvenlik-duyarlı arayüzlerin şekli, durum makineleri, fail-closed davranışı, runtime sırası, crash atomikliği, retry taksonomisi, invariant'lar.

İsim-alanları: `KUT-SEC-*` · `INV-*`/`INV-AI-*` · `REV-*` · `KUT-ARCH-*`.

---

## 0. Uçtan uca RUNTIME sırası (dondurulmuş)

```text
ActionRequest            (RequestedImpact = hint)
     ▼
Gateway.Authorize()      EffectiveImpact = ImpactPolicy(Action,Targets,Context)  ← server-side
     ▼
AuthorizationDecision ── DENY ─────────────────────────────► stop (audit + reason codes)
     ├── NEED_APPROVAL ─► Approval (Requester≠Approver, request-bound)
     │        ▼
     │   FinalizeAuthorization(request, approval)
     │        │  approval State==APPROVED & !expired? · policy/tenant/scope/target/binding YENİDEN doğrula
     │        │  değilse → DENY (spesifik reason-code, §4)
     │        ▼
     │      ALLOW ─► atomically consume Approval (APPROVED→CONSUMED) + Grant mint
     └── ALLOW ─────────────────────────────────────────────┐
                                                             ▼
                                              AuthorizationGrant (ISSUED)
                                                             ▼
                          GuardedExecutor.Execute(request, grant)   ← ATOMİK SECURITY TRANSITION SAHİBİ
                          │  1) Validate Grant + binding RE-CHECK:
                          │        Grant.State==ISSUED · ExpiresAt>now · PolicyHash==effectivePolicyHash
                          │        · RequestHash==requestHash · TenantID==effectiveTenant · Action/Targets==request
                          │  2) Generate CommandID
                          │  3) BEGIN SECURITY TX { CAS Grant ISSUED→CONSUMED ; INSERT ExecutionIntent(CommandID) } COMMIT
                          │        ├─ CAS fail (concurrent/replay) ──────────► DENY
                          │        └─ ayrı boundary'de intent kurulamadı ────► GRANT_CONSUMED_BUT_INTENT_NOT_CREATED
                          │                                                     (terminal; re-auth; sessiz geri-alma yok)
                          ▼    [ destructive: intent/journal durable olmadan aşağı İNİLMEZ — fail-closed ]
                    Mint CommandEnvelope(CommandID)   (AuthorizationCorrelationID opak; GERÇEK GrantID YOK)
                          ▼
                    Persist Command
                          ▼
                    Deliver ──(mTLS)──► [ CİHAZ GÜVEN SINIRI ]
                          ▼
                    Agent idempotency check (cmdlog, anahtar = CommandID)
                          ▼
                    Execute → Result   (ACK ≠ SUCCEEDED)
                          ▼
                    ExecutionIntent / Command lifecycle update → Evidence / Audit
```

**GuardedExecutor sınırı (freeze):** `validate + generate CommandID + CAS grant + INSERT ExecutionIntent` tek **GuardedExecutor**'a aittir; harici kod `consumeGrant()`+`createIntent()`'i ayrı çağırıp bypass edemez (INV-047, §13 görünürlük kuralı).
AI yolu: `AI Context → Local AI → Output Validator → AIRecommendation(VALIDATED→ACCEPTED) → Tool/Capability Firewall → ActionRequest ⇒ AYNI zincir`.

---

## 0.1 Kesin hükümler
| Hüküm | Invariant |
|---|---|
| `ACK != SUCCEEDED` · `AUTHORIZED != EXECUTED` · `Recommendation != Authorization` · `Approval != Grant` | 026/007/AI-006/009 |
| Grant atomik tek-kullanım (ISSUED→CONSUMED CAS); concurrent'ta yalnız biri | 001..003 |
| Approval → FinalizeAuthorization (re-validate) → atomik consume → Grant; Approval tek başına grant-mint etmez | 040 |
| **GuardedExecutor = validate+CommandID+CAS-grant+intent atomik transition'ın SAHİBİ**; harici bypass yok | 047 |
| **CommandID intent persistence'tan ÖNCE üretilir; Intent.CommandID == Envelope.CommandID; delivery retry'da değişmez** | 046 |
| Grant validate ile CAS **tek authorization commit-point**; CAS anında binding'ler yeniden doğrulanır (TOCTOU yok) | 047 |
| Grant-consume + durable ExecutionIntent = tek atomik transaction (aynı boundary); ayrı boundary → recovery | 041/027 |
| ExecutionIntent = TÜM state-changing; DestructiveJournal = destructive ek gereksinim | 027 |
| `CommandID`=stable execution/dedup kimliği (tek başına exactly-once side-effect garantisi DEĞİL) · `Nonce`=replay · `Sequence`=ordering | 042,049 |
| Exactly-once side-effect yalnız dedup ile garanti edilemez; kanıtlanamayan destructive sonuç → `EXECUTION_UNKNOWN` + reconciliation (otomatik re-exec YOK) | 049,050,048 |
| DELIVERY_FAILED→QUEUED (aynı CommandID); EXECUTION_FAILED→FAILED_FINAL (destructive requeue yok) | 043 |
| **RUNNING destructive → EXPIRED OLAMAZ; sonuç bilinmiyorsa EXECUTION_UNKNOWN + reconciliation; otomatik replacement yok** | 048 |
| Quarantine partial=DEGRADED; sessiz reset yok | 028/029 |
| AI: no direct executor/WIPE-ERASE/shell-SQL/policy-audit-guardrail mutation | AI-001..005 |
| Cross-tenant implicit değil; **missing TenantID → DENY** | 006/012/044 |
| Background/AutoResponder/SOAR/AI → normal Gateway | 037 |
| `Grant` (server yetki) ≠ `CommandEnvelope` (cihaz komut sahiciliği) | KUT-SEC-006/007 |
| `EffectiveImpact` server-side; caller düşüremez | 006 |
| Evidence: TransportIntegrity ≠ SourceHash ≠ CollectorIdentity ≠ Provenance | 045 |

---

## 1. `ActionRequest v2`
Alanlar (freeze): `RequestID, TenantID, Principal{Type,ID}, Action, Targets[], RequestedImpact(hint), Confirmed, CreatedAt`.
Trust boundary: sunucu-içi. Fail-closed: geçersiz principal/bilinmeyen Action/boş yüksek-etki Target → DENY. Tenant: server-side; missing→DENY (INV-044). Integrity: `RequestHash` (kanonik, §17). Impact: RequestedImpact hint; `EffectiveImpact` server-side; destructive düşürülemez.
KUT-SEC 002,008 · INV 004,006,012,044 · Kesişen `authz.Request`→v2.
Kapsam: tip + RequestHash kanonik + EffectiveImpact türetme + testler.

## 2. `AuthorizationDecision` + `ReasonCode`
Alanlar (freeze): `Result∈{ALLOW,DENY,NEED_APPROVAL}, ReasonCodes[], RequiredApproval*, Grant*`(yalnız ALLOW).
**ReasonCode kümesi (freeze):** `RBAC_DENY, SCOPE_DENY, TENANT_MISMATCH, CRITICALITY_DENY, BLAST_RADIUS_EXCEEDED, RATE_LIMITED, DUAL_CONTROL_REQUIRED, APPROVAL_EXPIRED, APPROVAL_BINDING_MISMATCH, APPROVAL_ALREADY_CONSUMED, POLICY_CHANGED, SCOPE_CHANGED, TARGET_CHANGED, GRANT_MISSING, GRANT_EXPIRED, GRANT_REPLAYED, GRANT_MISMATCH, INTENT_NOT_CREATED`.
Allowed/forbidden: ALLOW→Grant; NEED_APPROVAL→Approval, Grant nil; DENY→son. Fail-closed: herhangi kontrol reddi→DENY+reason. Integrity: PolicyHash+PolicyVersion.
KUT-SEC 002,004,005 · INV 008..011.
Kapsam: enum + reason-code kümesi + "DENY/NEED_APPROVAL⇒Grant nil" testi.

## 3. `AuthorizationGrant`
Alanlar (freeze): `GrantID, RequestHash, PolicyHash, PolicyVersion, TenantID, Principal, Action, Targets[], Nonce, IssuedAt, ExpiresAt`.
Trust boundary: SUNUCU-İÇİ; cihaza gitmez (§5.1). State: `ISSUED → CONSUMED`(atomik CAS) | `EXPIRED`.
**Consume:** tüketim GuardedExecutor içinde; validate + binding re-check + CAS + ExecutionIntent INSERT **tek atomik security transaction** (aynı boundary). Validate ile CAS arasında ayrı bir pencere yoktur — **tek authorization commit-point** (INV-047). Ayrı persistence boundary → §7 recovery modeli.
**CAS predicate (freeze):** consume **yalnız ve yalnızca** şu koşullar aynı atomik adımda sağlanırsa başarılı olur (TOCTOU uygulayıcıya bırakılmaz):
```text
CONSUME succeeds IFF:
  Grant.State == ISSUED
  AND Grant.ExpiresAt > TrustedNow()
  AND Grant.TenantID   == effectiveTenant
  AND Grant.RequestHash == requestHash
  AND Grant.PolicyHash  == effectivePolicyHash
  AND Grant.Action      == request.Action
  AND Grant.TargetsHash == request.TargetsHash
aksi halde → DENY (spesifik reason-code)
```
Fail-closed: eksik/expired/replayed/mismatch→DENY. PolicyHash=enforce, PolicyVersion=audit.
KUT-SEC 001,006 · INV 001..007,041,047 · INV-AI 035 · Kesişen: yeni (authz)+security hash.
Kapsam: tip + replay-store + atomik CAS + binding-recheck + concurrent testleri.

## 4. `Approval` + `FinalizeAuthorization`
Amaç: dual-control onayı. Grant/grant-mint yetkisi DEĞİL.
Alanlar (freeze): `ApprovalID, TenantID, RequestID, RequestHash, Action, TargetsHash, PolicyHash, PolicyVersion, RequesterPrincipal, ApproverPrincipal, DecidedBy, DecidedAt, IssuedAt, ExpiresAt, State`.
State machine: `REQUESTED→APPROVED→CONSUMED`; `APPROVED→EXPIRED`; `REQUESTED→REJECTED`(terminal); `REQUESTED→EXPIRED`(terminal). CONSUMED yalnız APPROVED'dan.
State-authoritative: karar = State; ayrı mutable Decision yok.
**FinalizeAuthorization:** `AuthorizeWithApproval(request, approval)`: (1) State==APPROVED & !expired değilse DENY(`APPROVAL_EXPIRED`/`APPROVAL_ALREADY_CONSUMED`); (2) policy/tenant/scope/target + RequestHash/TargetsHash binding re-validate — uyumsuzluk spesifik reason-code (`POLICY_CHANGED`/`SCOPE_CHANGED`/`TARGET_CHANGED`/`TENANT_MISMATCH`/`APPROVAL_BINDING_MISMATCH`); (3) `RequesterPrincipal!=ApproverPrincipal`; (4) ALLOW → **atomik** `APPROVED→CONSUMED` + tek Grant (concurrent finalize → yalnız biri).
KUT-SEC 005 · INV 009,010,040.
Kapsam: state machine + Finalize re-validate + reason-code'lar + "requester≠approver / atomik tek-grant" testleri.

## 5. `CommandEnvelope`
Alanlar (freeze): `CommandID`(stable execution/dedup kimliği), `AuthorizationCorrelationID`(opak), `RequestID, TenantID, DeviceID/TargetID, Action, ParametersHash, IssuedAt, ExpiresAt, Nonce`(replay), `Sequence`(ordering), `Signature`.
**CommandID üretim anı (freeze):** CommandID **GuardedExecutor** tarafından, ExecutionIntent persistence'tan **ÖNCE** üretilir; `ExecutionIntent.CommandID == CommandEnvelope.CommandID`; delivery retry'larda **değişmez** (INV-046).
Kimlik ayrımı: CommandID = stable execution/deduplication kimliği (cmdlog anahtarı; **tek başına exactly-once side-effect kanıtı DEĞİL** — INV-049) · Nonce = replay freshness · Sequence = ordering.
Trust boundary: CİHAZ; agent imza+idempotency'yi bağımsız doğrular; grant görmez. Fail-closed: imza/expired/device-mismatch/replay→reddet+audit.
KUT-SEC 006,007,011 · INV 007,022,030..033,042,046.
Kapsam: alan şeması + "CommandID intent'ten önce + envelope==intent + GrantID taşımaz" testleri.

### 5.1 `AuthorizationGrant` ≠ `CommandEnvelope`
Grant = sunucu yetki capability'si (sunucuda tüketilir, cihaza gitmez). CommandEnvelope = cihaz komut sahiciliği (kendi imza/replay/expiry/device-binding'i). Bağ yalnız izlenebilirlik (`AuthorizationCorrelationID↔GrantID↔RequestID`). Birleşme yasak.

## 6. Command lifecycle
```text
CREATED → AUTHORIZED → QUEUED → DELIVERED → ACKNOWLEDGED → RUNNING → SUCCEEDED   (terminal)
                          │  │                                          │
                          │  └─ (envelope TTL, HİÇ delivered olmadı) → EXPIRED (terminal, pre-delivery)
                          ▼                                             ▼
                    DELIVERY_FAILED → QUEUED                       EXECUTION_FAILED → FAILED_FINAL (terminal)
   DELIVERED | ACKNOWLEDGED | RUNNING  + sunucu-timeout  →  EXECUTION_UNKNOWN (reconciliation gerekir)
   ek terminal: CANCELLED
```
**Süre aşımı (freeze):** `EXPIRED` yalnız **QUEUED**'da, komut hiç teslim edilmemişken envelope TTL geçerse. DELIVERED/ACKNOWLEDGED/RUNNING'de sunucu-timeout → **`EXECUTION_UNKNOWN`** (cihaz hâlâ yürütüyor olabilir). RUNNING destructive **EXPIRED olamaz** ve otomatik replacement üretemez; bilinmeyen sonuç **reconciliation** ister (INV-048). "Başarısız" (`EXECUTION_FAILED`) ≠ "sonuç bilinmiyor" (`EXECUTION_UNKNOWN`).
**Reconciliation durumu (freeze):** `EXECUTION_UNKNOWN` **terminal değildir**; yürütülemez bir **reconciliation** state'idir. Geçişleri: `EXECUTION_UNKNOWN → RECONCILED_SUCCEEDED | RECONCILED_FAILED | MANUAL_REVIEW_REQUIRED`. **`EXECUTION_UNKNOWN → QUEUED` YASAK** (otomatik yeniden-yürütme yok). Gerçek terminaller: SUCCEEDED, FAILED_FINAL, EXPIRED, CANCELLED, RECONCILED_*.
**Reconciliation kanıtı (freeze):** `EXECUTION_UNKNOWN` bir agent-raporuyla körü körüne kapatılamaz. Reconciliation, **authenticated ve policy-kabul edilmiş** kanıt gerektirir:
```text
ReconciliationEvidence { CommandID, AgentIdentity, DeviceID, ObservedState, EvidenceHash, ObservedAt, VerificationMethod }
```
Özellikle **destructive** için: tek, doğrulanmamış bir "SUCCEEDED" iddiası → `RECONCILED_SUCCEEDED` YAPAMAZ; kimlik-doğrulanmış + politika-kabul kanıt şarttır (INV-052). Kalan belirsizlik `MANUAL_REVIEW_REQUIRED`.
DELIVERY_FAILED→QUEUED (aynı CommandID); EXECUTION_FAILED→FAILED_FINAL; yeni execution → yeni auth+CommandID. Premature-ACK (INV-026): ACK≠SUCCEEDED. AUTHORIZED→QUEUED yalnız durable ExecutionIntent sonrası.
KUT-SEC 007 · INV 007,026,043,048 · Kesişen `db device_commands` (durum sütunu eklenecek).
Kapsam: state enum + geçişler + "RUNNING destructive→EXPIRED yasak / EXECUTION_UNKNOWN reconciliation / DELIVERY vs EXECUTION" testleri.

## 7. `ExecutionIntent` (+ Destructive Journal)
Kapsam: ExecutionIntent = TÜM state-changing komutlar; DestructiveJournal = destructive intent'in ek durable/audit/fail-closed gereksinimi.
Alanlar (freeze): `IntentID, CommandID, GrantID, TenantID, Action, Targets, Destructive bool, State, CreatedAt, CompletedAt`.
State:
```text
CREATED → EXECUTING → DONE | FAILED | UNKNOWN
CREATED → UNKNOWN                     (delivery cihaz sınırını geçti, execution başladı mı KANITLANAMIYOR — INV-051)
UNKNOWN → RECONCILED_DONE | RECONCILED_FAILED
```
**ExecutionIntent, karşılık gelen Command `EXECUTION_UNKNOWN` iken DONE/FAILED işaretlenemez** — reconciliation sonucu belirleyene kadar UNKNOWN kalır (INV-050). Command lifecycle (§6) ile belirsizlik semantiği **uyumlu** olmalıdır (INV-051): Command `EXECUTION_UNKNOWN` ⇔ Intent `EXECUTING`/`CREATED` değil, `UNKNOWN`.
Atomiklik: GuardedExecutor içinde grant-consume ile aynı transaction; CommandID intent'e persistence öncesi yazılır. Ayrı boundary → `GRANT_CONSUMED_BUT_INTENT_NOT_CREATED`.
Fail-closed: Destructive iken durable intent olmadan envelope mint/persist/deliver yok.
Idempotency: aynı CommandID'nin tekrar teslimi **bilinçli yeni execution BAŞLATMAZ**. Crash sonrası önceki side-effect sonucu **kanıtlanamıyorsa** komut **UNKNOWN/reconciliation**'a girer — otomatik yeniden-yürütme değil. ("İki kez yürütülemez" dağıtık garantisi İDDİA EDİLMEZ; sağlanan invariant "ikinci yürütme bilinçli başlatılamaz + belirsizlikte reconciliation"dır.)
KUT-SEC 007 · INV 027,041,046.
Kapsam: intent tipi + "tüm state-changing için / destructive journal yoksa DENY / CommandID intent==envelope" testleri.

## 8. Quarantine lifecycle
```text
INACTIVE → APPLYING → ACTIVE → RELEASING → INACTIVE
              │(partial)          │(partial)
              ▼                   ▼
           DEGRADED            DEGRADED   (+ ERROR)
              ├─►APPLYING          ├─►RELEASING
              └─►INACTIVE*         └─►INACTIVE*   (*yalnız doğrulanmış remediation/restore; sessiz reset yasak)
```
DEGRADED çıkışları tanımlı; partial=DEGRADED (INV-028); release önceki politikayı zayıflatmaz (INV-029). IPv4/IPv6/DNS/yönetim-C2/reboot test.
KUT-SEC 012 · INV 028,029 · Kesişen `quarantine.Manager`.
Kapsam: state enum + "partial=DEGRADED/sessiz reset yok" testleri.

## 9. Evidence lifecycle / CoC
```text
REQUESTED → COLLECTING → RECEIVED → VERIFIED → SEALED   (SEALED terminal, değişmez)
     │           │
     └─CANCELLED └─FAILED
```
Command bağı: `ActionRequest→Grant→GuardedExecutor→CommandEnvelope(COLLECT_*)→Agent→Evidence`. `COLLECT_* SUCCEEDED ≠ Evidence SEALED`.
**Doğrulama özellikleri (freeze — ayrı ve karıştırılmaz):**
- `TransportIntegrityVerified` = nakil/depolama bütünlüğü (HashAtReceipt==HashAtStorage). SEALED ön-koşulu.
- `SourceHashVerified` = kaynak-hash tutarlılığı (HashAtSource mevcut ve eşleşiyor). **Tek başına sahicilik kanıtı DEĞİL** — ele geçirilmiş collector doğru hash üretebilir.
- `CollectorIdentityVerified` = toplayan ajan/kimlik doğrulandı (mTLS/imza).
- `ProvenanceVerified` = kaynak cihaz/yol bağlamı doğrulandı.
`HashAtSource` yoksa `SourceHashVerified=false` açıkça. "SEALED" yanıltıcı bir bütünsel-sahicilik iddiası taşımaz; hangi özelliklerin doğrulandığı ayrı alanlarda görünür.
**VERIFIED tanımı (freeze):** `VERIFIED = (TransportIntegrityVerified == true) AND (zorunlu doğrulama politikası değerlendirildi)`. Diğer üç özellik (`SourceHashVerified`, `CollectorIdentityVerified`, `ProvenanceVerified`) **ayrı assurance boyutlarıdır**; `VERIFIED` kelimesi "her şey doğrulandı" anlamına kaymaz. SEALED ön-koşulu yalnız `VERIFIED`'dir.
Alanlar (freeze): `EvidenceID, CaseID/IncidentID, SourceDevice, CollectorIdentity, SourcePathType, CollectedAt, HashAtSource?, HashAtReceipt, StorageHash, TransportIntegrityVerified, SourceHashVerified, CollectorIdentityVerified, ProvenanceVerified, AccessLog, RetentionPolicy, ExportLog`.
Fail-closed: TransportIntegrityVerified değilse SEALED olmaz; append-only.
KUT-SEC 010 · INV 026,025,045.
Kapsam: state enum + 4-özellik ayrımı + "TransportIntegrity yoksa SEALED yok / HashAtSource yoksa SourceHashVerified=false" testleri.

## 10. Tenant binding (invariant)
Kural (freeze): her güvenlik nesnesi `TenantID`; server-side enjekte; **missing→DENY** (INV-044). Cross-tenant implicit değil. Tek-kiracılı uyum yalnız açıkça yapılandırılmış tenant ile.
Negatif testler: A→B incident/evidence/device/AI = DENY.
KUT-SEC 003 · INV 006,012,044 · Kesişen iam/casemgmt/scim/event_ack/tenant.

## 11. AI principal / capability
v1: `type=ai, id=local-ai`. İzinli: incident.read, evidence.metadata.read, hunt.read, recommend.action. Yasak: executor.direct, wipe, erase, shell/sql.execute, policy.write, audit.disable, guardrail.write, identity/credential.admin. Fail-closed: yasak capability→grant yok.
KUT-SEC 002,008 · INV-AI 001,004,005 · INV 035.

## 12. `AIRecommendation`
State: `ISSUED→VALIDATED→ACCEPTED→CONSUMED` | `REJECTED` | `EXPIRED`. **APPROVED yok.** ACCEPTED = analist kabulü (yetki değil); Gateway dual-control (Approval §4) ayrı.
Alanlar (freeze): `RecommendationID, IncidentID, PrincipalID, ModelID, PromptVersion, ContextHash, ResponseHash, Action, Targets[], EvidenceIDs[], IssuedAt, ExpiresAt`.
Fail-closed: geçersiz schema/evidence/enum→`AI_INVALID_OUTPUT`; değişen öneri→yeni ACCEPTED (INV-034).
KUT-SEC 002 · INV-AI 002..006 · INV 013..017,034,035.

## 13. Executor authorization boundary + `GuardedExecutor`
Kural (freeze): TEK merkezi sınır `GuardedExecutor.Execute(request, grant)` — **validate + binding re-check + Generate CommandID + [BEGIN TX: CAS grant + INSERT ExecutionIntent : COMMIT] + mint envelope** akışının SAHİBİ. Storage impl'leri authorization'ı yeniden uygulamaz; `consumeGrant()`/`createIntent()` gibi alt işlemler **dışarıya kapalıdır**; ham state-değiştiren yazım paket/arayüz görünürlüğüyle yapısal engellenir (mutasyon yalnız GuardedExecutor'a erişilebilir).
Ret koşulları: grant missing/expired/replayed/wrong-tenant/principal/action/target/request-hash/policy-mismatch/approval-unmet → DENY (spesifik reason-code).
Birleşik giriş: Admin/AutoResponder/SOAR/AI/scheduled → ActionRequest→Gateway→(Approval→Finalize)→Grant→GuardedExecutor. Alternatif yol YOK.
KUT-SEC 001,008 · INV 001..007,037,047 · INV-AI 001,006 · Kesişen `admin.Store.EnqueueCommand*`+`response.AutoQuarantiner`(BYPASS).
Kapsam: GuardedExecutor arayüzü + görünürlük + "grant yoksa DENY / consumeGrant dışarı kapalı / AutoResponder doğrudan yol yok / raw Store state-değiştiremez" testleri.

---

## 14. Contract Dependency Matrix (13 sözleşme — güvenlik bağımlılığı)
| Sözleşme | Bağımlı |
|---|---|
| 10 Tenant | — (taban) |
| 1 ActionRequest | 10, 11 |
| 2 Decision | 1, 10 |
| 4 Approval+Finalize | 2, 1, 10 |
| 3 Grant | 2 (ALLOW) veya 4 (Finalize), 1 |
| 13 GuardedExecutor | 3 |
| 7 ExecutionIntent | 13 (atomik consume ile), 3 |
| 5 CommandEnvelope | 13 (mint), 7 (CommandID+destructive intent) |
| 6 Command lifecycle | 5, 7 |
| 8 Quarantine | 5, 13 |
| 9 Evidence | 5(COLLECT_*), 13, 10 |
| 11 AI principal | 10 |
| 12 AIRecommendation | 11, 9 → çıkış 1 |
**Döngü YOK.** Tenant taban; tek yönlü; AI yalnız ActionRequest'e çıkış.

## 15. Runtime ordering (bağımlılıktan ayrı)
`Authorize→(Approval→Finalize)→Grant→GuardedExecutor{validate+CommandID+[atomik: CAS grant+ExecutionIntent]}→mint Envelope→persist→deliver→agent idempotency→execute→result→lifecycle/evidence/audit`.

## 16. Retry Taxonomy
| Tür | Yeni auth? | Aynı CommandID/envelope? | Agent execute? |
|---|---|---|---|
| Authorization Retry | EVET | hayır (yeni) | yeni intent'e göre |
| Delivery Retry | HAYIR | EVET (idempotent) | aynı CommandID 2. kez EXECUTE ETMEZ |
| Execution Retry | Action policy'ye bağlı; **destructive: otomatik YASAK** | intent'e göre | eski CommandID→FAILED_FINAL, yeni auth→yeni CommandID |
`EXECUTION_UNKNOWN` (§6) **retry sebebi değildir** — reconciliation ister; destructive'de asla otomatik replacement.

## 17. Failure Atomicity Matrix
| # | Crash noktası | Yeniden-auth? | Aynı CommandID? | Re-deliver? | Agent execute? | Server state | Audit |
|---|---|---|---|---|---|---|---|
| 1 | Grant consume ÖNCESİ | HAYIR — geçerli ISSUED grant tekrar sunulabilir (yalnız expired/revoked/policy-invalid → re-auth) | N/A | N/A | hayır | grant ISSUED; intent yok | auth attempt |
| 2 | validate↔intent arası | **aynı boundary'de bu pencere YOK** (tek atomik TX). Yalnız ayrı boundary: EVET | hayır | hayır | hayır | GRANT_CONSUMED_BUT_INTENT_NOT_CREATED | grant consumed + intent-fail |
| 3 | Intent SONRASI / envelope mint ÖNCESİ | HAYIR (intent+CommandID otoriter) | EVET | N/A | hayır | intent CREATED; envelope mint ile devam | intent created |
| 4 | Envelope persist SONRASI / delivery ÖNCESİ | HAYIR | EVET | EVET | hayır | QUEUED | persisted |
| 5 | Delivery SONRASI / ACK ÖNCESİ | HAYIR | EVET | EVET (aynı CommandID) | agent **durable dedup/recovery** kontrolü yapar; önceki sonuç kanıtlanamıyorsa **EXECUTION_UNKNOWN** (destructive: otomatik re-exec YOK) — mutlak çift-exec garantisi İDDİA EDİLMEZ (INV-049) | DELIVERED | delivered |
| 6 | ACK SONRASI / result ÖNCESİ | HAYIR | EVET | delivery retry OK; re-execute yok | devam/bitti | ACKNOWLEDGED/RUNNING | ack |
| 7 | Execution SONRASI / result persist ÖNCESİ | HAYIR | EVET | yeni execution YOK | **yalnız durable agent-side completion evidence varsa kesin** (COMPLETED→cached result re-report; FAILED→failure re-report); aksi halde sonuç **UNKNOWN** | durable kanıt varsa SUCCEEDED/FAILED_FINAL; yoksa **EXECUTION_UNKNOWN → reconciliation** (destructive: otomatik re-exec YOK) | execution outcome durable ise re-report; değilse unknown+reconcile |
| 8 | Result SONRASI / evidence verify ÖNCESİ | HAYIR | EVET | hayır | bitti | command SUCCEEDED; evidence RECEIVED | result + evidence pending |

## 18. DESIGN notları
- Command EXPIRED/CANCELLED/EXECUTION_UNKNOWN giriş durumları §6.
- AI principal per-task migrasyonu.
- Tenant missing→DENY (§10).
- Sözleşme-başına metrics.

## 19. Invariant eklemeleri
```text
INV-040 Approval doğrudan grant-mint edemez; Finalize (re-validate+atomik consume) şart.
INV-041 Grant-consume + durable ExecutionIntent aynı boundary'de tek atomik transaction.
INV-042 CommandID tek otoriter execution/deduplication kimliğidir; tek başına exactly-once side-effect garantisi DEĞİL. Nonce replay freshness, Sequence ordering içindir.
INV-043 EXECUTION_FAILED (özellikle destructive) aynı CommandID ile requeue edilemez.
INV-044 Missing TenantID → DENY.
INV-045 Evidence doğrulama özellikleri (TransportIntegrity/SourceHash/CollectorIdentity/Provenance) ayrıdır; biri diğerini ima etmez.
INV-046 CommandID, ExecutionIntent persistence'tan önce üretilir; Intent.CommandID==Envelope.CommandID; delivery retry'da değişmez.
INV-047 Grant validate + CAS-consume + ExecutionIntent tek GuardedExecutor commit-point'idir; alt işlemler dışarı kapalıdır (bypass yok); CAS anında binding re-check yapılır.
INV-048 RUNNING destructive komut EXPIRED'a geçemez ve otomatik replacement üretemez; bilinmeyen sonuç EXECUTION_UNKNOWN + reconciliation gerektirir.
INV-049 CommandID stabil execution/dedup kimliğidir; TEK BAŞINA exactly-once side-effect garantisi DEĞİL. Kurtarma sonrası sonucu kanıtlanamayan destructive komut EXECUTION_UNKNOWN'a geçer ve otomatik yeniden-yürütülemez.
INV-050 Command EXECUTION_UNKNOWN iken karşılık gelen ExecutionIntent, reconciliation sonucu belirleyene kadar DONE/FAILED işaretlenemez (UNKNOWN kalır); EXECUTION_UNKNOWN → QUEUED yasaktır.
INV-051 Delivery cihaz güven sınırını geçmiş ve sunucu execution'ın başlayıp başlamadığını kanıtlayamıyorsa ExecutionIntent CREATED→UNKNOWN geçebilir; Command EXECUTION_UNKNOWN ile Intent belirsizlik semantiği UYUMLU olmalıdır.
INV-052 Destructive bir EXECUTION_UNKNOWN, yalnız doğrulanmamış bir iddiadan reconcile EDİLEMEZ; reconciliation authenticated ve policy-kabul edilmiş ReconciliationEvidence gerektirir.
```

## 20. Kapsam sınırı
Kapsam **yalnız**: 13 sözleşmenin tip/enum iskeleti + durum-makinesi/invariant/atomiklik testleri + bu belge (freeze). **Migration/davranış YOK**; geri kalanı sonraki değişikliklere aittir.

## 21. Dörtlü mekanik tutarlılık çapraz-kontrolü (runtime ↔ state ↔ matrix ↔ invariant)
| Konu | Runtime (§0/§15) | State machine | Dependency (§14) | Invariant |
|---|---|---|---|---|
| Approval→Grant | Finalize→atomik consume→Grant | Approval REQUESTED→APPROVED→CONSUMED | 3←4 | 040 |
| Grant tüketimi | GuardedExecutor içinde CAS | Grant ISSUED→CONSUMED | 13←3, 7←13 | 001-003,047 |
| Grant+Intent atomik | tek BEGIN/COMMIT | Intent CREATED | 7←3/13 | 041,046,047 |
| CommandID | mint öncesi üretilir | (kimlik) | 5←7 | 042,046 |
| Destructive journal | delivery öncesi durable | Intent(Destructive) | 5←7 | 027 |
| Delivery vs Execution fail | ayrı yollar | DELIVERY_FAILED→QUEUED / EXECUTION_FAILED→FAILED_FINAL | 6←5 | 043 |
| RUNNING timeout | Command `EXECUTION_UNKNOWN` **↔ Intent `UNKNOWN`** (hizalı) | 6←5, 7 | 048,050 |
| Exactly-once / reconciliation | dedup ≠ garanti; UNKNOWN→reconcile (→QUEUED yasak) | 6/7 | 049,050 |
| Quarantine partial | — | APPLYING→DEGRADED | 8←5/13 | 028,029 |
| Evidence verify | COLLECT_* sonrası ayrı | RECEIVED→VERIFIED→SEALED | 9←5/13/10 | 026,045 |
| Tenant | server-side enjekte | — | tüm nesneler←10 | 006,012,044 |
| AI yolu | ActionRequest'e çıkış | AIRecommendation ISSUED→…→CONSUMED | 12→1 | AI-001..006 |
Dört görünüm birbiriyle **uyumludur**. Command `EXECUTION_UNKNOWN` ↔ ExecutionIntent belirsizlik hizası `UNKNOWN` ve `CREATED→UNKNOWN` (INV-051) geçişiyle tam kapatılmıştır — DELIVERED sonrası "execution başladı mı?" belirsizliği her iki state-machine'de temsil edilir. v3.2.1 itibarıyla çelişki tespit edilmedi.

---

## 22. Agentic Threat Defense Plane  (ayrı kontrat paketi)

**Kapsam notu:** Bu bölüm **§1-13 sözleşmelerine DAHİL DEĞİLDİR** ve §1-13 execution/authorization sözleşmelerinin freeze'ini geciktirmez. Ayrı bir kontrat paketi + namespace olarak **freeze sonrası** planlanır. Amaç: KUT'u yalnız "AI kullanan SOC" değil, **AI-agent saldırılarını gözlemleyen ve güven zincirini anlayan** platform yapmak. Enforcement yine **deterministik**; AI yalnız korelasyon/açıklama/sınıflandırma/öneri katmanında (§0'daki `AI → ActionRequest → Gateway → Grant → GuardedExecutor` zinciri aynen geçerli).

**Neden ayrı:** §1-13, KUT'un KENDİ AI'sını kontrol eder. Bu bölüm ise **saldırganın AI-agent'larını** ve karma (insan/yazılım/AI) principal davranışını modeller. Güncel tehdit çerçeveleriyle hizalı (OWASP LLM/Agentic: prompt injection, tool abuse, excessive agency, memory poisoning, exfiltration; MITRE ATLAS: tool/context poisoning, AI-agent C2, tool invocation; NIST: agent kimliği/authorization/audit/non-repudiation).

**Namespace: `KUT-AI-SEC-*`**
```text
KUT-AI-SEC-001 Agent Identity            KUT-AI-SEC-006 Trust/Taint Propagation
KUT-AI-SEC-002 Delegation Chain          KUT-AI-SEC-007 Agent Data Flow
KUT-AI-SEC-003 Context Provenance        KUT-AI-SEC-008 Agent Supply Chain
KUT-AI-SEC-004 Tool Invocation           KUT-AI-SEC-009 Agent C2 Detection
KUT-AI-SEC-005 Memory Integrity          KUT-AI-SEC-010 Agent Containment
```

**Agentic invariant'ları (`INV-AG-*`, freeze — bu paket geldiğinde):**
```text
INV-AG-001 Untrusted content principal ayrıcalığını ARTIRAMAZ.
INV-AG-002 AI çıktısı authorization'a DÖNÜŞEMEZ (yalnız §12 zinciriyle ActionRequest).
INV-AG-003 Delegation effective capability'yi ARTIRAMAZ:
           effective = intersection(human, agentA, agentB, tool, tenant policy).
INV-AG-004 Tainted context, privileged write/execute capability'ye SESSİZCE geçemez
           (tainted + credential.read + external.write → DENY / REQUIRE HUMAN).
INV-AG-005 Tool/MCP çıktısı DATA'dır; komut/talimat yetkisi taşımaz.
INV-AG-006 Memory write PROVENANCE gerektirir (kaynak-trust + author principal).
INV-AG-007 Agent identity model çıktısından ÇIKARSANMAZ (kriptografik kimlik).
INV-AG-008 Agent-üretimi kimlik-bilgisi tenant sınırını AŞAMAZ.
INV-AG-009 Bilinmeyen tool/MCP sunucusu privileged agent için deny-by-default.
INV-AG-010 Agent containment normal KUT authorization'ı BYPASS EDEMEZ.
INV-AG-011 Hiçbir AI (KUT'un kendi AI'sı dahil) bu invariant'ları DEĞİŞTİREMEZ.
```

**İlk iş (model DEĞİL, veri zemini):** Agent Identity + Delegation Graph + Context Provenance/Taint + Tool/Memory telemetrisi. Bunlar olmadan AI-agent saldırı zincirini (ör. `untrusted web → agent reads secret → external HTTP` = indirect prompt-injection → credential access → exfiltration) güvenilir tespit edecek **Agent Causality Graph** verisi oluşmaz.

**Telemetri/kimlik taslakları (planlama; freeze değil):** `AgentPrincipal{AgentID, InstanceID, ModelID, OwnerPrincipal, DelegatedBy, TenantID, Capabilities, TrustLevel, ExpiresAt}` · Memory olayları (`MemoryWrite/Read`, `SourceTrust`, `AuthorPrincipal`, `InfluenceChain`, `TTL`, `Hash`) · Provenance/taint etiketleri (`UNTRUSTED`/`TAINTED`) canonical event şemasına girer.

**Konum:** entity-graph üzerine oturan veri-zemini. GNN/model işleri en sonda, veri olgunlaşınca.
