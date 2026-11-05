package update

import (
	"context"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"time"
)

// HTTPDownloader, güncelleme paketini HTTP(S) ile indirir. Boyut sınırı,
// bellek/disk tükenme saldırılarına karşı korur.
type HTTPDownloader struct {
	client   *http.Client
	maxBytes int64
}

// NewHTTPDownloader oluşturur. maxBytes <= 0 ise makul bir varsayılan kullanılır.
func NewHTTPDownloader(maxBytes int64) *HTTPDownloader {
	if maxBytes <= 0 {
		maxBytes = 256 << 20 // 256 MiB
	}
	return &HTTPDownloader{
		client: &http.Client{
			Timeout: 5 * time.Minute,
			// yönlendirmeler de https olmalı + sınırlı (http'ye düşürme yok).
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("update: çok fazla yönlendirme")
				}
				if req.URL.Scheme != "https" {
					return fmt.Errorf("update: yönlendirme https olmalı, %q", req.URL.Scheme)
				}
				return nil
			},
		},
		maxBytes: maxBytes,
	}
}

// Download, verilen URL'den paketi indirir (en fazla maxBytes). Yalnız
// https kabul edilir (imzalı manifest + SHA-256'ya ek aktarım güvenliği).
func (d *HTTPDownloader) Download(ctx context.Context, rawURL string) ([]byte, error) {
	if u, err := neturl.Parse(rawURL); err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("update: indirme URL'i https olmalı")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update: indirme: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: indirme durumu %d", resp.StatusCode)
	}
	// maxBytes+1 oku; fazlaysa reddet.
	data, err := io.ReadAll(io.LimitReader(resp.Body, d.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("update: gövde okuma: %w", err)
	}
	if int64(len(data)) > d.maxBytes {
		return nil, fmt.Errorf("update: paket boyut sınırını aştı (%d bayt)", d.maxBytes)
	}
	return data, nil
}
