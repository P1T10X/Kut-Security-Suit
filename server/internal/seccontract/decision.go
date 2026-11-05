package seccontract

// DecisionResult, politika motorunun sonucudur (CONTRACTS §2).
type DecisionResult string

const (
	ResultAllow        DecisionResult = "ALLOW"
	ResultDeny         DecisionResult = "DENY"
	ResultNeedApproval DecisionResult = "NEED_APPROVAL"
)

// ReasonCode, karar/red gerekçesidir (CONTRACTS §2). SOC'ta "neden grant
// verilmedi?" sorusunun deterministik cevabıdır.
type ReasonCode string

const (
	ReasonRBACDeny                ReasonCode = "RBAC_DENY"
	ReasonScopeDeny               ReasonCode = "SCOPE_DENY"
	ReasonTenantMismatch          ReasonCode = "TENANT_MISMATCH"
	ReasonCriticalityDeny         ReasonCode = "CRITICALITY_DENY"
	ReasonBlastRadiusExceeded     ReasonCode = "BLAST_RADIUS_EXCEEDED"
	ReasonRateLimited             ReasonCode = "RATE_LIMITED"
	ReasonDualControlRequired     ReasonCode = "DUAL_CONTROL_REQUIRED"
	ReasonApprovalExpired         ReasonCode = "APPROVAL_EXPIRED"
	ReasonApprovalBindingMismatch ReasonCode = "APPROVAL_BINDING_MISMATCH"
	ReasonApprovalAlreadyConsumed ReasonCode = "APPROVAL_ALREADY_CONSUMED"
	ReasonPolicyChanged           ReasonCode = "POLICY_CHANGED"
	ReasonScopeChanged            ReasonCode = "SCOPE_CHANGED"
	ReasonTargetChanged           ReasonCode = "TARGET_CHANGED"
	ReasonGrantMissing            ReasonCode = "GRANT_MISSING"
	ReasonGrantExpired            ReasonCode = "GRANT_EXPIRED"
	ReasonGrantReplayed           ReasonCode = "GRANT_REPLAYED"
	ReasonGrantMismatch           ReasonCode = "GRANT_MISMATCH"
	ReasonIntentNotCreated        ReasonCode = "INTENT_NOT_CREATED"
)

// AuthorizationDecision, tek yetki-karar noktasının çıktısıdır (CONTRACTS §2).
// Grant YALNIZ ALLOW'da doludur; DENY/NEED_APPROVAL'da nil (yürütme yolu yok).
type AuthorizationDecision struct {
	Result      DecisionResult
	ReasonCodes []ReasonCode
	Grant       *AuthorizationGrant
}

// Deny, gerekçe kodlarıyla bir DENY kararı üretir (Grant nil).
func Deny(reasons ...ReasonCode) AuthorizationDecision {
	return AuthorizationDecision{Result: ResultDeny, ReasonCodes: reasons}
}

// NeedApproval, dual-control gerektiren bir karar üretir (Grant nil).
func NeedApproval(reasons ...ReasonCode) AuthorizationDecision {
	return AuthorizationDecision{Result: ResultNeedApproval, ReasonCodes: append([]ReasonCode{ReasonDualControlRequired}, reasons...)}
}

// Allow, verilen grant ile bir ALLOW kararı üretir.
func Allow(g *AuthorizationGrant) AuthorizationDecision {
	return AuthorizationDecision{Result: ResultAllow, Grant: g}
}

// Valid, invariant tutarlılığını doğrular: ALLOW ⇔ Grant!=nil; DENY/NEED_APPROVAL ⇔
// Grant==nil (CONTRACTS §2, INV-008..011).
func (d AuthorizationDecision) Valid() bool {
	switch d.Result {
	case ResultAllow:
		return d.Grant != nil
	case ResultDeny, ResultNeedApproval:
		return d.Grant == nil
	default:
		return false
	}
}
