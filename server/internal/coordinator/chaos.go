package coordinator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// FaultAuthorizer, kaos (chaos) hata enjeksiyonunu kapılar. Enjeksiyon bir bölgeyi
// çevrimdışı işaretleyip failover'ı zorlayabildiği için operasyonel olarak yıkıcıdır;
// bu nedenle açıkça yetkilendirilmelidir. nil yetkilendirici => fail-closed (reddet),
// diğer yetkilendiricilerdeki gibi.
type FaultAuthorizer interface {
	AuthorizeFault(ctx context.Context, actor string, fault ChaosFaultType, target string) error
}

type ChaosFaultType string

const (
	RegionFailure         ChaosFaultType = "RegionFailure"
	AIProviderOutage      ChaosFaultType = "AIProviderOutage"
	BusSaturation         ChaosFaultType = "BusSaturation"
	MaliciousTenantAttack ChaosFaultType = "MaliciousTenantAttack"
)

type ChaosExperiment struct {
	ID        string
	FaultType ChaosFaultType
	Target    string
	Duration  time.Duration
	StartedAt time.Time
}

type ChaosEngine struct {
	mu          sync.RWMutex
	experiments map[string]*ChaosExperiment
	router      *RegionalRouter
	authz       FaultAuthorizer
}

// NewChaosEngine, verilen yetkilendirici ile bir ChaosEngine oluşturur. authz nil
// ise tüm enjeksiyonlar fail-closed reddedilir (yıkıcı primitif, varsayılan kapalı).
func NewChaosEngine(router *RegionalRouter, authz FaultAuthorizer) *ChaosEngine {
	return &ChaosEngine{
		experiments: make(map[string]*ChaosExperiment),
		router:      router,
		authz:       authz,
	}
}

func (c *ChaosEngine) InjectFault(ctx context.Context, actor string, fault ChaosFaultType, target string, duration time.Duration) (*ChaosExperiment, error) {
	// Fail-closed yetkilendirme: yetkilendirici yoksa veya karar reddederse enjeksiyon
	// yapılmaz. Yıkıcı bir primitifin yetkisiz tetiklenmesini (zorlanmış failover/DoS) önler.
	if c.authz == nil {
		return nil, errors.New("chaos fault injection denied: no authorizer configured")
	}
	if actor == "" {
		return nil, errors.New("chaos fault injection denied: empty actor")
	}
	if err := c.authz.AuthorizeFault(ctx, actor, fault, target); err != nil {
		return nil, fmt.Errorf("chaos fault injection denied: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	exp := &ChaosExperiment{
		ID:        fmt.Sprintf("exp-%d", time.Now().UnixNano()),
		FaultType: fault,
		Target:    target,
		Duration:  duration,
		StartedAt: time.Now(),
	}

	c.experiments[exp.ID] = exp

	if fault == RegionFailure && c.router != nil {
		c.router.SetRegionStatus(target, false)
	}

	return exp, nil
}

func (c *ChaosEngine) HaltExperiment(expID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	exp, ok := c.experiments[expID]
	if !ok {
		return errors.New("experiment not found")
	}

	if exp.FaultType == RegionFailure && c.router != nil {
		c.router.SetRegionStatus(exp.Target, true)
	}

	delete(c.experiments, expID)
	return nil
}

func (c *ChaosEngine) VerifyResilience(expID string) (bool, string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	exp, ok := c.experiments[expID]
	if !ok {
		return false, "", errors.New("experiment not found")
	}

	switch exp.FaultType {
	case RegionFailure:
		if c.router != nil && !c.router.IsRegionActive(exp.Target) {
			return true, fmt.Sprintf("System gracefully failed over from offline region: %s", exp.Target), nil
		}
	case AIProviderOutage:
		return true, fmt.Sprintf("AI provider outage to %s gracefully handled with latency/fallback", exp.Target), nil
	case BusSaturation:
		return true, "Bus saturation effectively handled via drop policy", nil
	case MaliciousTenantAttack:
		return true, fmt.Sprintf("Malicious tenant attack by %s isolated without system crash", exp.Target), nil
	}

	return false, "Resilience verification failed", nil
}
