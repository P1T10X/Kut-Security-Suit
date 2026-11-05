// Package notify, yüksek önem düzeyli güvenlik olaylarında SOC'a gerçek-zamanlı
// dış uyarı (webhook) gönderir. Slack/Teams/genel webhook uçlarıyla uyumlu basit
// JSON POST. Bağımlılıksız (yalnız net/http). Gönderim asenkron ve best-effort'tur:
// kuyruk dolarsa uyarı düşürülür (olay-alım yolu ASLA bloke olmaz).
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"time"
)

// sevRank, önem düzeyini karşılaştırılabilir bir sayıya çevirir.
func sevRank(s string) int {
	switch s {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

// Alert, dışa gönderilen uyarının içeriğidir.
type Alert struct {
	DeviceID   string    `json:"device_id"`
	Category   string    `json:"category"`
	Severity   string    `json:"severity"`
	Message    string    `json:"message"`
	OccurredAt time.Time `json:"occurred_at"`
	// MITRE ATT&CK bağlamı (varsa; eşleşme yoksa boş bırakılır — omitempty).
	TechniqueID   string `json:"mitre_technique_id,omitempty"`
	TechniqueName string `json:"mitre_technique,omitempty"`
	Tactic        string `json:"mitre_tactic,omitempty"`
	// Tenant, uyarıyı üreten dağıtımın kiracı kimliğidir (çok-kiracılı ortak
	// downstream — SIEM/analitik — kiracıya göre ayrıştırabilsin). "default" ise boş bırakılır.
	Tenant string `json:"tenant,omitempty"`
}

// Notifier, bir uyarıyı (best-effort) iletir.
type Notifier interface {
	Notify(a Alert)
}

// WebhookNotifier, uyarıları yapılandırılmış bir HTTPS webhook'una POST eder.
type WebhookNotifier struct {
	url    string
	minSev int
	format string // "json" (varsayılan) veya "slack" (Slack/Teams incoming webhook)
	secret []byte // ayarlıysa gövde HMAC-SHA256 ile imzalanır (X-KUT-Signature)
	client *http.Client
	ch     chan Alert
}

// SetHMACSecret, giden webhook gövdesini HMAC-SHA256 ile imzalamayı etkinleştirir.
// Alıcı, paylaşılan sırla imzayı doğrulayarak uyarının GERÇEKTEN KUT'ten geldiğini
// (sahte uyarı enjeksiyonu değil) doğrular. Boş sır → imzalama kapalı.
func (n *WebhookNotifier) SetHMACSecret(secret string) {
	n.secret = []byte(secret)
}

// Option sabitleri.
const (
	queueSize   = 256
	httpTimeout = 10 * time.Second
)

// NewWebhookNotifier, verilen HTTPS URL'e uyarı gönderen bir notifier kurar ve
// arka plan gönderim işçisini başlatır. minSeverity altındaki uyarılar yok sayılır
// (ör. "HIGH" → yalnız HIGH ve CRITICAL). URL https değilse hata döner (uyarı içeriği
// güven sınırını düz-metin geçmemeli).
func NewWebhookNotifier(url, minSeverity, format string) (*WebhookNotifier, error) {
	u, err := neturl.Parse(url)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("notify: webhook URL https olmalı: %q", url)
	}
	if format != "slack" {
		format = "json"
	}
	n := &WebhookNotifier{
		url:    url,
		minSev: sevRank(minSeverity),
		format: format,
		client: &http.Client{Timeout: httpTimeout},
		ch:     make(chan Alert, queueSize),
	}
	if n.minSev == 0 {
		n.minSev = sevRank("HIGH") // varsayılan eşik
	}
	go n.worker()
	return n, nil
}

// Notify, uyarıyı eşik üstündeyse kuyruğa alır. Kuyruk doluysa DÜŞÜRÜR (bloke
// olmaz) — olay-alım yolunun gecikmemesi kritik.
func (n *WebhookNotifier) Notify(a Alert) {
	if sevRank(a.Severity) < n.minSev {
		return
	}
	select {
	case n.ch <- a:
	default:
		log.Printf("notify: uyarı kuyruğu dolu, düşürüldü (device=%s sev=%s)", a.DeviceID, a.Severity)
	}
}

// worker, kuyruğu tüketip her uyarıyı POST eder.
func (n *WebhookNotifier) worker() {
	for a := range n.ch {
		n.post(a)
	}
}

// sevEmoji, önem düzeyi için Slack emoji'si.
func sevEmoji(sev string) string {
	switch sev {
	case "CRITICAL":
		return ":rotating_light:"
	case "HIGH":
		return ":red_circle:"
	case "MEDIUM":
		return ":large_orange_diamond:"
	default:
		return ":large_blue_circle:"
	}
}

// slackText, uyarıyı Slack/Teams incoming webhook için okunabilir metne çevirir.
func slackText(a Alert) string {
	s := sevEmoji(a.Severity) + " *[" + a.Severity + "]* " + a.Message
	s += "\n• Cihaz: `" + a.DeviceID + "`"
	if a.Category != "" {
		s += " • Kategori: " + a.Category
	}
	if a.TechniqueID != "" {
		s += " • ATT&CK: " + a.TechniqueID + " " + a.TechniqueName + " (" + a.Tactic + ")"
	}
	return s
}

// payloadBytes, yapılandırılmış biçime göre HTTP gövdesini üretir.
func (n *WebhookNotifier) payloadBytes(a Alert) ([]byte, error) {
	if n.format == "slack" {
		return json.Marshal(map[string]string{"text": slackText(a)})
	}
	return json.Marshal(a)
}

func (n *WebhookNotifier) post(a Alert) {
	body, err := n.payloadBytes(a)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// İmzalama etkinse: gövdenin HMAC-SHA256'sını başlığa ekle (alıcı doğrular).
	if len(n.secret) > 0 {
		mac := hmac.New(sha256.New, n.secret)
		mac.Write(body)
		req.Header.Set("X-KUT-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("notify: webhook POST başarısız: %v", err)
		return
	}
	// Gövdeyi EOF'a kadar boşalt (sınırlı) → transport bağlantıyı havuza iade eder
	// (keep-alive). Aksi halde alarm-fırtınasında her POST yeni TCP+TLS el sıkışması yapar.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}
