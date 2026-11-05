package adminapi

// Bu dosya, temel kiracı izolasyonu kapsamındaki saf (test edilebilir) yardımcıları içerir:
// kiracı sunucu-tarafı oturumdan çözülür, istemci gövdesinden ASLA güvenilmez.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"kut.corp/suite/server/internal/admin"
	"kut.corp/suite/server/internal/tenant"
)

// resolveTokenTenant, enrollment token'ın mühürleneceği kiracıyı çözer.
//
//   - Kiracıya bağlı çağıran (callerTenant != ""): HER ZAMAN kendi kiracısı. Gövdedeki
//     değer boşsa "kendi kiracım"dır (asla dağıtım varsayılanı değil); kendi kiracısıyla
//     (normalize edilmiş) AYNI değilse admin.ErrForbidden — başka kiracıya cihaz sokma yok.
//   - Platform admini (callerTenant == ""): gövde boşsa dağıtım varsayılanı; doluysa
//     tenant.Normalize ile doğrulanmış kiracı (geçersiz → admin.ErrInvalidInput).
func resolveTokenTenant(callerTenant, requested, deploymentDefault string) (string, error) {
	requested = strings.TrimSpace(requested)
	if callerTenant != "" {
		if requested != "" {
			n, err := tenant.Normalize(requested)
			if requested != callerTenant && (err != nil || string(n) != callerTenant) {
				return "", admin.ErrForbidden
			}
		}
		return callerTenant, nil
	}
	if requested == "" {
		return deploymentDefault, nil
	}
	n, err := tenant.Normalize(requested)
	if err != nil {
		return "", admin.ErrInvalidInput
	}
	return string(n), nil
}

// decodeOptional, İSTEĞE BAĞLI JSON gövdesini (boş gövde tolere edilir) boyut sınırıyla
// çözer. Bozuk JSON / aşırı büyük gövde için hata yanıtı yazar ve false döner.
func decodeOptional(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil {
		return true
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "istek gövdesi çok büyük")
			return false
		}
		writeErr(w, http.StatusBadRequest, "geçersiz JSON")
		return false
	}
	return true
}

// normalizeTenantInput, istekten gelen BOŞ OLMAYAN bir kiracı değerini sınırda doğrular ve
// normalleştirir (tenant.Normalize: kırp + küçük harf + [a-z0-9-], 1-63). Geçersizse hata döner;
// çağıran 400 yazar. Boş girdi çağıranın sorumluluğundadır (Normalize boşu "default"a çevirir,
// oysa burada boş "belirtilmedi" demektir).
func normalizeTenantInput(raw string) (string, error) {
	n, err := tenant.Normalize(raw)
	if err != nil {
		return "", err
	}
	return string(n), nil
}

// resolveReadScope, kiracı-bölümlü bir kaynağı (agentsec grafı, AI av grafı) OKUYAN/YAZAN bir
// isteğin kiracı kapsamını SUNUCU-TARAFI çözer:
//
//   - Kiracıya bağlı çağıran (callerTenant != ""): HER ZAMAN kendi kiracısı; istekteki değer
//     (query/gövde) YOK SAYILIR — başka kiracıyı seçme yolu yoktur.
//   - Platform admini (callerTenant == ""): requested doluysa tenant.Normalize ile
//     doğrulanmış AÇIK kiracı filtresi (geçersiz → admin.ErrInvalidInput); boşsa all=true
//     (tüm kiracılar; yazma yollarında çağıran bunu platform bölümüne çevirir).
func resolveReadScope(callerTenant, requested string) (tenantID string, all bool, err error) {
	if callerTenant != "" {
		return callerTenant, false, nil
	}
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return "", true, nil
	}
	n, nerr := normalizeTenantInput(requested)
	if nerr != nil {
		return "", false, admin.ErrInvalidInput
	}
	return n, false, nil
}

// readScope, resolveReadScope'u oturumdaki yöneticiye uygular (AdminTenant hatası yayılır:
// bilinmeyen/pasif yönetici fail-closed 403).
func (s *Server) readScope(ctx context.Context, adminID, requested string) (string, bool, error) {
	ct, err := s.callerTenant(ctx, adminID)
	if err != nil {
		return "", false, err
	}
	return resolveReadScope(ct, requested)
}
