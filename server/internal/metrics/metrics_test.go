package metrics

import (
	"strings"
	"testing"
)

func TestWriteExposition(t *testing.T) {
	SetBuildVersion("1.2.3")
	IncLoginSuccess()
	IncLoginFailure()
	IncLoginFailure()
	AddEventsIngested(5)
	AddDetections(3)
	IncAlertRaised()
	IncAutoQuarantine()
	IncIocHit()
	IncClusterPublished()
	IncClusterPublished()
	IncClusterReceived()
	IncClusterFallback()
	IncThresholdGated()
	IncThresholdGated()
	IncBitsGated()

	var sb strings.Builder
	Write(&sb, Snapshot{
		DevicesTotal:       10,
		DevicesOnline:      7,
		DevicesOffline:     3,
		DevicesQuarantined: 1,
		EventsBySeverity:   map[string]int{"HIGH": 4, "INFO": 20},
		SSEConnections:     2,
	})
	out := sb.String()

	wants := []string{
		`kut_build_info{version="1.2.3"} 1`,
		"kut_login_success_total 1",
		"kut_login_failure_total 2",
		"kut_events_ingested_total 5",
		"kut_detections_total 3",
		"kut_alerts_raised_total 1",
		"kut_auto_quarantine_total 1",
		"kut_ioc_hits_total 1",
		`kut_cluster_notices_total{direction="published"} 2`,
		`kut_cluster_notices_total{direction="received"} 1`,
		`kut_cluster_notices_total{direction="fallback"} 1`,
		`kut_devices{state="total"} 10`,
		`kut_devices{state="online"} 7`,
		`kut_devices{state="quarantined"} 1`,
		`kut_events_by_severity{severity="HIGH"} 4`,
		`kut_events_by_severity{severity="INFO"} 20`,
		"kut_threshold_gated_total 2",
		"kut_bits_gated_total 1",
		"kut_sse_connections 2",
		"kut_uptime_seconds ",
		"kut_goroutines ",
		"kut_memory_alloc_bytes ",
		"# TYPE kut_login_failure_total counter",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("exposition %q satırını içermeliydi.\n---\n%s", w, out)
		}
	}
	// Önem düzeyi satırları deterministik (alfabetik) sırada olmalı: HIGH < INFO.
	if strings.Index(out, `severity="HIGH"`) > strings.Index(out, `severity="INFO"`) {
		t.Error("önem düzeyi satırları alfabetik sıralı değil")
	}
}

// Kiracı izolasyonu: sınırlı bellek-içi durumun düşen/atılan/boyut metrikleri /metrics'te görünür.
func TestWriteBoundedStateMetrics(t *testing.T) {
	SetGraphStats(7, 5, 3, 120, 90)
	SetSeqModelStats(11, 2, 4, 33)
	AddAgentSecDropped(6)
	IncAnalyzerSkipped()
	IncIncidentCaseSkipped()
	IncIncidentCaseError()

	var sb strings.Builder
	Write(&sb, Snapshot{})
	out := sb.String()
	for _, want := range []string{
		"kut_graph_dropped_total 7",
		"kut_graph_evicted_total 5",
		"kut_graph_pruned_total 3",
		`kut_graph_size{kind="edges"} 120`,
		`kut_graph_size{kind="nodes"} 90`,
		"kut_seqmodel_dropped_total 11",
		`kut_seqmodel_evicted_total{reason="lru"} 2`,
		`kut_seqmodel_evicted_total{reason="ttl"} 4`,
		"kut_seqmodel_sources 33",
		"kut_agentsec_dropped_total ",
		"kut_analyzer_skipped_total ",
		`kut_incident_case_total{result="skipped"} `,
		`kut_incident_case_total{result="error"} `,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics çıktısında %q yok", want)
		}
	}
}
