package coordinator

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrResidencyFallbackBlocked, bir tenant'ın birincil (pinned) bölgesinde sağlıklı
// edge node bulunmadığında ve tenant için bölge-dışı yönlendirmeye AÇIKÇA izin
// verilmediğinde döner. Egemen (sovereign) fabric'te bir tenant'ın telemetrisinin
// sessizce bölge-dışına yönlendirilmesi veri ikameti (residency) ihlalidir; bu
// nedenle varsayılan fail-closed'dur.
var ErrResidencyFallbackBlocked = errors.New("cross-region fallback blocked by data-residency policy")

// RegionID represents a geographical or logical region identifier.
type RegionID string

// EdgeNode represents an edge processing node in a specific region.
type EdgeNode struct {
	ID            string
	Region        RegionID
	TenantIDs     []string
	Status        string // "healthy", "degraded", "offline"
	LastHeartbeat time.Time
	LatencyMs     int64
}

// RegionalRouter tracks registered edge nodes and routes telemetry.
type RegionalRouter struct {
	mu           sync.RWMutex
	nodes        map[string]*EdgeNode
	tenantRegion map[string]RegionID // Maps tenant to their primary region
	regionStatus map[string]bool     // Region status overrides (e.g. for maintenance or chaos testing)
	// tenantCrossRegion, bölge-dışı yedek (fallback) yönlendirmeye açıkça izin verilen
	// tenant'ları tutar. Varsayılan (kayıt yok) = strict residency / fail-closed.
	tenantCrossRegion map[string]bool
}

// NewRegionalRouter creates a new instance of RegionalRouter.
func NewRegionalRouter() *RegionalRouter {
	return &RegionalRouter{
		nodes:             make(map[string]*EdgeNode),
		tenantRegion:      make(map[string]RegionID),
		regionStatus:      make(map[string]bool),
		tenantCrossRegion: make(map[string]bool),
	}
}

// SetTenantCrossRegionFallback, bir tenant için bölge-dışı yedek yönlendirmeyi
// açıkça etkinleştirir/kapatır. Varsayılan kapalıdır (strict residency): operatör
// bölge-dışı yönlendirmenin uyum/egemenlik etkisini bilinçli kabul ettiğinde açılır.
func (r *RegionalRouter) SetTenantCrossRegionFallback(tenantID string, allow bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tenantCrossRegion[tenantID] = allow
}

// SetRegionStatus sets the operational status of a region (used for maintenance or chaos testing).
func (r *RegionalRouter) SetRegionStatus(region string, active bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.regionStatus[region] = active
	for _, node := range r.nodes {
		if string(node.Region) == region {
			if active {
				node.Status = "healthy"
			} else {
				node.Status = "offline"
			}
		}
	}
}

// IsRegionActive checks whether a region is active (not marked offline).
func (r *RegionalRouter) IsRegionActive(region string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if active, ok := r.regionStatus[region]; ok {
		return active
	}
	for _, node := range r.nodes {
		if string(node.Region) == region && node.Status != "offline" {
			return true
		}
	}
	return false
}

// SetTenantPrimaryRegion sets the primary region for a given tenant.
func (r *RegionalRouter) SetTenantPrimaryRegion(tenantID string, region RegionID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tenantRegion[tenantID] = region
}

// RegisterEdgeNode registers a new edge node or updates an existing one.
func (r *RegionalRouter) RegisterEdgeNode(node EdgeNode) error {
	if node.ID == "" {
		return errors.New("node ID cannot be empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	node.LastHeartbeat = time.Now()
	if node.Status == "" {
		node.Status = "healthy"
	}

	// Copy node to store pointer
	n := node
	r.nodes[node.ID] = &n
	return nil
}

// Heartbeat updates the heartbeat timestamp and latency of an edge node.
func (r *RegionalRouter) Heartbeat(nodeID string, latencyMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	node, exists := r.nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	node.LastHeartbeat = time.Now()
	node.LatencyMs = latencyMs
	node.Status = "healthy"
	return nil
}

// RouteTelemetry selects the best edge node for a tenant.
// It prefers healthy nodes in the tenant's primary region with lowest latency,
// falling back to other healthy nodes in any region if primary is unavailable.
func (r *RegionalRouter) RouteTelemetry(tenantID string) (*EdgeNode, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	primaryRegion, hasPrimary := r.tenantRegion[tenantID]

	var bestNode *EdgeNode
	var bestFallback *EdgeNode

	for _, node := range r.nodes {
		if node.Status != "healthy" {
			continue
		}

		// Check if it's the primary region
		if hasPrimary && node.Region == primaryRegion {
			if bestNode == nil || node.LatencyMs < bestNode.LatencyMs {
				bestNode = node
			}
		} else {
			// Track as fallback
			if bestFallback == nil || node.LatencyMs < bestFallback.LatencyMs {
				bestFallback = node
			}
		}
	}

	if bestNode != nil {
		return bestNode, nil
	}

	if bestFallback != nil {
		// Birincil bölgede sağlıklı node yok. Bölgeye pinlenmiş bir tenant'ın
		// telemetrisi, yalnızca bölge-dışı yedek AÇIKÇA etkinleştirilmişse
		// bölge dışına yönlendirilebilir; aksi halde residency ihlali olur
		// (fail-closed). Pin'i olmayan tenant'ta residency kısıtı yoktur.
		if hasPrimary && !r.tenantCrossRegion[tenantID] {
			return nil, fmt.Errorf("tenant %q pinned to region %q: %w", tenantID, primaryRegion, ErrResidencyFallbackBlocked)
		}
		return bestFallback, nil
	}

	return nil, errors.New("no healthy edge nodes available")
}

// PruneStaleNodes removes nodes that haven't sent a heartbeat within the threshold.
func (r *RegionalRouter) PruneStaleNodes(threshold time.Duration) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	prunedCount := 0

	for id, node := range r.nodes {
		if now.Sub(node.LastHeartbeat) > threshold {
			delete(r.nodes, id)
			prunedCount++
		}
	}

	return prunedCount
}
