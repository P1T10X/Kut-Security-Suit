package seccontract

// statemachines.go — CONTRACTS §5-9,§12 durum makinelerinin dondurulmuş geçiş
// tabloları. Her tablo yalnız GEÇERLİ geçişleri içerir; tabloda olmayan her geçiş
// fail-closed reddedilir. Bu bir iskelettir; mevcut impl'ler (device_commands,
// quarantine.Manager, evidence) sonraki değişikliklerde bu tablolara migrate edilir.

// ---- Command lifecycle (§6; INV-007/026/043/048/050) ----
type CommandState string

const (
	CmdCreated          CommandState = "CREATED"
	CmdAuthorized       CommandState = "AUTHORIZED"
	CmdQueued           CommandState = "QUEUED"
	CmdDelivered        CommandState = "DELIVERED"
	CmdAcknowledged     CommandState = "ACKNOWLEDGED"
	CmdRunning          CommandState = "RUNNING"
	CmdSucceeded        CommandState = "SUCCEEDED"         // terminal
	CmdDeliveryFailed   CommandState = "DELIVERY_FAILED"   // → QUEUED (aynı CommandID)
	CmdExecutionFailed  CommandState = "EXECUTION_FAILED"  // → FAILED_FINAL
	CmdFailedFinal      CommandState = "FAILED_FINAL"      // terminal
	CmdExpired          CommandState = "EXPIRED"           // terminal (yalnız pre-delivery)
	CmdCancelled        CommandState = "CANCELLED"         // terminal
	CmdExecutionUnknown CommandState = "EXECUTION_UNKNOWN" // non-terminal reconciliation
	CmdReconciledOK     CommandState = "RECONCILED_SUCCEEDED"
	CmdReconciledFail   CommandState = "RECONCILED_FAILED"
	CmdManualReview     CommandState = "MANUAL_REVIEW_REQUIRED"
)

var commandTransitions = map[CommandState]map[CommandState]bool{
	CmdCreated:          {CmdAuthorized: true, CmdCancelled: true},
	CmdAuthorized:       {CmdQueued: true, CmdCancelled: true},
	CmdQueued:           {CmdDelivered: true, CmdDeliveryFailed: true, CmdExpired: true, CmdCancelled: true},
	CmdDeliveryFailed:   {CmdQueued: true}, // delivery retry, aynı CommandID (§16)
	CmdDelivered:        {CmdAcknowledged: true, CmdExecutionUnknown: true, CmdCancelled: true},
	CmdAcknowledged:     {CmdRunning: true, CmdExecutionUnknown: true},
	CmdRunning:          {CmdSucceeded: true, CmdExecutionFailed: true, CmdExecutionUnknown: true},
	CmdExecutionFailed:  {CmdFailedFinal: true},                                                  // requeue YOK (INV-043)
	CmdExecutionUnknown: {CmdReconciledOK: true, CmdReconciledFail: true, CmdManualReview: true}, // →QUEUED YOK (INV-050)
}

// CanGoTo, komut durum geçişinin geçerli olup olmadığını döner (fail-closed).
func (s CommandState) CanGoTo(to CommandState) bool { return commandTransitions[s][to] }

// Terminal, komut durumunun terminal olup olmadığını döner. EXECUTION_UNKNOWN
// terminal DEĞİLDİR (reconciliation ister — INV-050).
func (s CommandState) Terminal() bool {
	switch s {
	case CmdSucceeded, CmdFailedFinal, CmdExpired, CmdCancelled, CmdReconciledOK, CmdReconciledFail:
		return true
	default:
		return false
	}
}

// ---- ExecutionIntent (§7; INV-050/051) ----
type IntentState string

const (
	IntentCreated        IntentState = "CREATED"
	IntentExecuting      IntentState = "EXECUTING"
	IntentDone           IntentState = "DONE"
	IntentFailed         IntentState = "FAILED"
	IntentUnknown        IntentState = "UNKNOWN"
	IntentReconciledDone IntentState = "RECONCILED_DONE"
	IntentReconciledFail IntentState = "RECONCILED_FAILED"
)

var intentTransitions = map[IntentState]map[IntentState]bool{
	IntentCreated:   {IntentExecuting: true, IntentUnknown: true}, // CREATED→UNKNOWN (INV-051)
	IntentExecuting: {IntentDone: true, IntentFailed: true, IntentUnknown: true},
	IntentUnknown:   {IntentReconciledDone: true, IntentReconciledFail: true},
}

func (s IntentState) CanGoTo(to IntentState) bool { return intentTransitions[s][to] }

// ---- Quarantine lifecycle (§8; INV-028/029) ----
type QuarantineState string

const (
	QInactive  QuarantineState = "INACTIVE"
	QApplying  QuarantineState = "APPLYING"
	QActive    QuarantineState = "ACTIVE"
	QReleasing QuarantineState = "RELEASING"
	QDegraded  QuarantineState = "DEGRADED"
	QError     QuarantineState = "ERROR"
)

// NOT: APPLYING→INACTIVE ve RELEASING→INACTIVE(doğrudan partial) YOK; kısmi uygulama
// DEGRADED'e gider (INV-028). DEGRADED→INACTIVE yalnız doğrulanmış remediation sonrası.
var quarantineTransitions = map[QuarantineState]map[QuarantineState]bool{
	QInactive:  {QApplying: true},
	QApplying:  {QActive: true, QDegraded: true, QError: true},
	QActive:    {QReleasing: true},
	QReleasing: {QInactive: true, QDegraded: true, QError: true},
	QDegraded:  {QApplying: true, QReleasing: true, QInactive: true}, // INACTIVE yalnız doğrulanmış restore ile (semantik kural)
}

func (s QuarantineState) CanGoTo(to QuarantineState) bool { return quarantineTransitions[s][to] }

// ---- Evidence lifecycle (§9; INV-026/045) ----
type EvidenceState string

const (
	EvRequested  EvidenceState = "REQUESTED"
	EvCollecting EvidenceState = "COLLECTING"
	EvReceived   EvidenceState = "RECEIVED"
	EvVerified   EvidenceState = "VERIFIED"
	EvSealed     EvidenceState = "SEALED" // terminal, değişmez
	EvFailed     EvidenceState = "FAILED"
	EvCancelled  EvidenceState = "CANCELLED"
)

var evidenceTransitions = map[EvidenceState]map[EvidenceState]bool{
	EvRequested:  {EvCollecting: true, EvCancelled: true},
	EvCollecting: {EvReceived: true, EvFailed: true, EvCancelled: true},
	EvReceived:   {EvVerified: true, EvFailed: true},
	EvVerified:   {EvSealed: true},
}

func (s EvidenceState) CanGoTo(to EvidenceState) bool { return evidenceTransitions[s][to] }

// ---- AIRecommendation lifecycle (§12; APPROVED YOK) ----
type RecommendationState string

const (
	RecIssued    RecommendationState = "ISSUED"
	RecValidated RecommendationState = "VALIDATED"
	RecAccepted  RecommendationState = "ACCEPTED" // analist kabulü (yetki DEĞİL)
	RecConsumed  RecommendationState = "CONSUMED"
	RecRejected  RecommendationState = "REJECTED"
	RecExpired   RecommendationState = "EXPIRED"
)

var recommendationTransitions = map[RecommendationState]map[RecommendationState]bool{
	RecIssued:    {RecValidated: true, RecRejected: true, RecExpired: true},
	RecValidated: {RecAccepted: true, RecRejected: true, RecExpired: true},
	RecAccepted:  {RecConsumed: true, RecExpired: true},
}

func (s RecommendationState) CanGoTo(to RecommendationState) bool {
	return recommendationTransitions[s][to]
}
