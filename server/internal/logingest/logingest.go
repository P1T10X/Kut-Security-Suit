// Package logingest, HARİCİ kaynaklardan (güvenlik duvarı, bulut, kimlik sağlayıcı,
// başka SIEM) gelen logları KUT'in ortak olay modeline (model.Event) normalize
// eder. Böylece KUT yalnız uç-nokta ajan telemetrisini değil, harici logları da
// tek bir korelasyon/tespit/hunt yüzeyinde toplayabilir (SIEM alım yolu).
//
// İki giriş biçimi desteklenir: yapılandırılmış JSON ve CEF (ArcSight). Tanınmayan
// kategori/önem güvenli varsayılana (SYSTEM/INFO) düşürülür. Her harici kaynak,
// adından türetilen KARARLI bir cihaz kimliğine (UUIDv5) eşlenir — böylece aynı
// kaynak her zaman aynı "cihaz" altında toplanır.
package logingest

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/tenant"
)

// Record, normalize edilmiş tek bir alım kaydıdır (hedef cihaz + olay).
type Record struct {
	DeviceID string
	Event    model.Event
}

var validCategory = map[string]bool{
	"SYSTEM": true, "SECURITY": true, "NETWORK_DISCOVERY": true,
	"POLICY_VIOLATION": true, "AGENT_UPDATE": true, "PROCESS": true, "NETWORK_CONN": true,
}

var validSeverity = map[string]bool{
	"INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
}

func normCategory(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if validCategory[s] {
		return s
	}
	return "SYSTEM"
}

func normSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if validSeverity[s] {
		return s
	}
	return "INFO"
}

// ingestNamespace, kaynak-adı → UUIDv5 türetmesi için sabit ad alanıdır.
var ingestNamespace = [16]byte{
	0x1e, 0x4b, 0x7a, 0x90, 0x3c, 0x5d, 0x4f, 0x21,
	0xa8, 0x0b, 0x9c, 0x77, 0x2d, 0x6e, 0x11, 0x33,
}

// SourceUUID, bir harici kaynak adından KARARLI bir UUIDv5 üretir (aynı ad →
// aynı cihaz kimliği). DB device_id UUID kolonuyla uyumludur.
func SourceUUID(source string) string {
	h := sha1.New()
	h.Write(ingestNamespace[:])
	h.Write([]byte(source))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // sürüm 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC4122 varyantı
	hexs := hex.EncodeToString(u[:])
	return hexs[0:8] + "-" + hexs[8:12] + "-" + hexs[12:16] + "-" + hexs[16:20] + "-" + hexs[20:32]
}

// tenantNamespace, kiracıya-özgü cihaz kimliği türetmesi için ayrı ad alanıdır
// (ingestNamespace'ten FARKLI → kiracı-ad-alanlı kimlikler eski kimliklerle çakışamaz).
var tenantNamespace = [16]byte{
	0x7d, 0x21, 0xc4, 0x5e, 0x88, 0x0a, 0x4b, 0x6f,
	0x9e, 0x13, 0x52, 0xa7, 0xd0, 0x3b, 0x64, 0x19,
}

// TenantDeviceID, bir harici kaynağın (SourceUUID ile türetilmiş) cihaz kimliğini KİRACIYA
// göre ad-alanlar: iki kiracı aynı kaynak adını ("fw1") kullansa da kimlikleri AYRIDIR →
// eşik/bit/korelatör/zincir durumu ve cihaz listesi kiracılar arasında ÇÖKMEZ.
// Kiracı SUNUCU-TARAFI bilinendir (ingest token'ının bağlı kiracısı / connector yapılandırması),
// ASLA istemci verisi değildir. Varsayılan kiracı (ve boş = legacy) kimliği DEĞİŞTİRMEZ →
// mevcut tek-kiracılı kurulumların kaynak kimlikleri sürekliliğini korur; diğer kiracılar
// ayrı bir ad alanından türetilir (eski kimliklerle çakışma imkânsız).
func TenantDeviceID(tenantID, deviceID string) string {
	if tenant.Canonical(tenantID) == string(tenant.Default) {
		return deviceID
	}
	h := sha1.New()
	h.Write(tenantNamespace[:])
	h.Write([]byte(tenantID))
	h.Write([]byte{0x1f})
	h.Write([]byte(deviceID))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	hexs := hex.EncodeToString(u[:])
	return hexs[0:8] + "-" + hexs[8:12] + "-" + hexs[12:16] + "-" + hexs[16:20] + "-" + hexs[20:32]
}

// SourceIDTenant, bir kaynağın cihaz kimliğinin hangi kiracıya göre AD-ALANLANACAĞINI döner
// (TenantDeviceID'ye verilecek değer). Ad-alanlama YALNIZ kaynak AÇIKÇA bir kiracıya
// bağlıysa (ingest token'ının ya da bağlayıcının kiracısı dolu) VE bu kiracı dağıtımın
// varsayılan kiracısından farklıysa uygulanır. Kiracısız (legacy/statik token, kiracısız
// bağlayıcı) kaynaklar dağıtım kiracısıyla DAMGALANIR ama kimlikleri kiracı damgalama öncesiyle AYNI
// kalır ("" döner → TenantDeviceID kimliği değiştirmez): KUT_TENANT_ID=acme dağıtımında
// mevcut kaynakların geçmişi/eşik/korelatör durumu bölünmez.
func SourceIDTenant(explicit, deployTenant string) string {
	e := strings.ToLower(strings.TrimSpace(explicit))
	if e == "" {
		return ""
	}
	if tenant.Canonical(e) == tenant.Canonical(strings.ToLower(strings.TrimSpace(deployTenant))) {
		return ""
	}
	return e
}

// logJSON, harici JSON log kaydının şemasıdır.
type logJSON struct {
	Source     string          `json:"source"`
	Category   string          `json:"category"`
	Severity   string          `json:"severity"`
	Message    string          `json:"message"`
	OccurredAt string          `json:"occurred_at"` // RFC3339, opsiyonel
	Details    json.RawMessage `json:"details"`     // opsiyonel nesne
}

// NormalizeJSON, bir JSON dizisini (veya tek nesneyi) normalize edilmiş kayıtlara
// çevirir. source ve message zorunludur; geçersiz kayıtlar hata döndürür.
// stampCanonical, kanonik olay alanlarını (§5) bir olaya ekler: source (ve varsa
// event_type) hem ilk-sınıf model alanlarına hem de Details JSON'una yazılır. Details'e
// yazmak, DB round-trip'inde (event_logs yalnız details JSONB taşır) alanların korunmasını
// sağlar; böylece /api/events tüketicisi source/event_type'ı ilk-sınıf görür. Details bir
// JSON NESNESİ değilse (ya da boşsa yeni nesne) yalnız model alanları set edilir, mevcut
// details ezilmez (güvenli birleştirme).
func stampCanonical(ev *model.Event, source, eventType string) {
	ev.Source, ev.EventType = source, eventType
	m := map[string]any{}
	if ev.Details != "" {
		if err := json.Unmarshal([]byte(ev.Details), &m); err != nil {
			return // nesne değil → mevcut details'i ezme
		}
	}
	if source != "" {
		m["source"] = source
	}
	if eventType != "" {
		m["event_type"] = eventType
	}
	if b, err := json.Marshal(m); err == nil {
		ev.Details = string(b)
	}
}

func NormalizeJSON(data []byte, now time.Time) ([]Record, error) {
	trimmed := strings.TrimSpace(string(data))
	var raws []logJSON
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &raws); err != nil {
			return nil, fmt.Errorf("logingest: JSON dizi çözülemedi: %w", err)
		}
	} else {
		var one logJSON
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, fmt.Errorf("logingest: JSON çözülemedi: %w", err)
		}
		raws = []logJSON{one}
	}
	out := make([]Record, 0, len(raws))
	for i, r := range raws {
		if strings.TrimSpace(r.Source) == "" {
			return nil, fmt.Errorf("logingest: kayıt #%d source zorunlu", i)
		}
		if strings.TrimSpace(r.Message) == "" {
			return nil, fmt.Errorf("logingest: kayıt #%d message zorunlu", i)
		}
		occurred := now
		if r.OccurredAt != "" {
			if t, err := time.Parse(time.RFC3339, r.OccurredAt); err == nil {
				occurred = t
			}
		}
		details := ""
		if len(r.Details) > 0 && string(r.Details) != "null" {
			details = string(r.Details)
		}
		rec := Record{
			DeviceID: SourceUUID(r.Source),
			Event: model.Event{
				Category:   normCategory(r.Category),
				Severity:   normSeverity(r.Severity),
				Message:    "[" + r.Source + "] " + r.Message,
				OccurredAt: occurred,
				Details:    details,
			},
		}
		stampCanonical(&rec.Event, r.Source, "")
		out = append(out, rec)
	}
	return out, nil
}

// NormalizeCEF, tek bir CEF satırını normalize eder:
//
//	CEF:Version|Vendor|Product|Ver|SigID|Name|Severity|Extensions
//
// Kaynak "Vendor/Product", mesaj "Name", önem CEF 0-10 → INFO..CRITICAL.
func NormalizeCEF(line string, now time.Time) (Record, error) {
	idx := strings.Index(line, "CEF:")
	if idx < 0 {
		return Record{}, fmt.Errorf("logingest: CEF öneki yok")
	}
	body := line[idx+4:]
	parts := strings.SplitN(body, "|", 8)
	if len(parts) < 7 {
		return Record{}, fmt.Errorf("logingest: CEF alanları eksik (%d)", len(parts))
	}
	vendor, product, name, sev := parts[1], parts[2], parts[5], parts[6]
	source := strings.TrimSpace(vendor + "/" + product)
	details := ""
	if len(parts) == 8 {
		details = strings.TrimSpace(parts[7])
	}
	rec := Record{
		DeviceID: SourceUUID(source),
		Event: model.Event{
			Category:   "SECURITY",
			Severity:   cefSeverity(sev),
			Message:    "[" + source + "] " + strings.TrimSpace(name),
			OccurredAt: parseFlexTime(cefExtField(details, "rt"), now), // CEF rt (olay zamanı)
		},
	}
	if details != "" {
		// Ham CEF uzantısını yapılandırılmış Details'e sar (arama/görünürlük).
		b, _ := json.Marshal(map[string]string{"cef_extension": details})
		rec.Event.Details = string(b)
	}
	stampCanonical(&rec.Event, source, "")
	return rec, nil
}

// cefExtField, CEF uzantı dizesinden (boşlukla ayrılmış key=value) bir anahtarın
// değerini döner. CEF değerleri boşluk içerebildiğinden yalnız boşluksuz değerler
// (rt gibi zaman damgaları tipik olarak öyledir) güvenilir çıkarılır.
func cefExtField(ext, key string) string {
	for _, tok := range strings.Fields(ext) {
		if k, v, ok := strings.Cut(tok, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// parseFlexTime, esnek zaman damgalarını (CEF rt / LEEF devTime) çözer: epoch
// (>1e11 → ms, aksi halde sn), RFC3339/Nano ya da yaygın CEF/LEEF tarih düzenleri.
// Çözülemezse fallback döner.
func parseFlexTime(s string, fallback time.Time) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n > 1e11 { // epoch millis
			return time.UnixMilli(n).UTC()
		}
		return time.Unix(n, 0).UTC() // epoch saniye
	}
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339,
		"Jan 02 2006 15:04:05.000", "Jan 02 2006 15:04:05",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return fallback
}

// NormalizeLEEF, bir LEEF (QRadar) satırını olay kaydına çevirir. Biçim:
//
//	LEEF:Sürüm|Vendor|Product|Ver|EventID|<öznitelikler>
//
// Öznitelikler varsayılan SEKME (tab) ile ayrılmış key=value çiftleridir; LEEF 2.0
// isteğe bağlı bir ayraç alanı taşıyabilir (EventID'den sonra). sev/msg/cat gibi
// standart öznitelikler tanınır; kalanlar Details'e yazılır. SIEM alım simetrisi
// (giden SIEM zaten LEEF üretir).
func NormalizeLEEF(line string, now time.Time) (Record, error) {
	idx := strings.Index(line, "LEEF:")
	if idx < 0 {
		return Record{}, fmt.Errorf("logingest: LEEF öneki yok")
	}
	parts := strings.Split(line[idx+5:], "|")
	if len(parts) < 6 {
		return Record{}, fmt.Errorf("logingest: LEEF alanları eksik (%d)", len(parts))
	}
	version, vendor, product, eventID := parts[0], parts[1], parts[2], parts[4]
	attrs, delim := parts[5], "\t"
	// LEEF 2.0 opsiyonel ayraç alanı: EventID'den sonraki alan kv değilse ayraçtır.
	if strings.HasPrefix(version, "2.0") && len(parts) >= 7 && !strings.Contains(parts[5], "=") {
		delim = decodeLEEFDelim(parts[5])
		attrs = parts[6]
	}
	kv := parseLEEFAttrs(attrs, delim)
	source := strings.TrimSpace(vendor + "/" + product)
	name := kv["msg"]
	if name == "" {
		name = strings.TrimSpace(eventID)
	}
	sev := kv["sev"]
	if sev == "" {
		sev = kv["severity"]
	}
	rec := Record{
		DeviceID: SourceUUID(source),
		Event: model.Event{
			Category:   "SECURITY",
			Severity:   cefSeverity(sev), // LEEF sev de sayısal (CEF gibi) ya da metinsel olabilir
			Message:    "[" + source + "] " + strings.TrimSpace(name),
			OccurredAt: parseFlexTime(leefDevTime(kv), now), // LEEF devTime (olay zamanı)
		},
	}
	if len(kv) > 0 {
		b, _ := json.Marshal(kv)
		rec.Event.Details = string(b)
	}
	stampCanonical(&rec.Event, source, "")
	return rec, nil
}

// leefDevTime, LEEF özniteliklerinden olay zaman damgasını (devTime) döner
// (büyük/küçük harf toleranslı: devTime / devtime).
func leefDevTime(kv map[string]string) string {
	if v := kv["devTime"]; v != "" {
		return v
	}
	return kv["devtime"]
}

// parseLEEFAttrs, ayraçla ayrılmış key=value öznitelik dizesini haritaya çevirir.
func parseLEEFAttrs(attrs, delim string) map[string]string {
	kv := map[string]string{}
	for _, tok := range strings.Split(attrs, delim) {
		if k, v, ok := strings.Cut(strings.TrimSpace(tok), "="); ok {
			k = strings.TrimSpace(k)
			if k != "" {
				kv[k] = strings.TrimSpace(v)
			}
		}
	}
	return kv
}

// decodeLEEFDelim, LEEF 2.0 ayraç alanını çözer: "xHH" (hex bayt) ya da literal karakter.
func decodeLEEFDelim(f string) string {
	if len(f) == 3 && (f[0] == 'x' || f[0] == 'X') {
		if n, err := strconv.ParseUint(f[1:], 16, 8); err == nil {
			return string([]byte{byte(n)})
		}
	}
	if f == "" {
		return "\t"
	}
	return f
}

// NormalizeSyslog, bir düz syslog satırını (RFC5424 veya RFC3164) olay kaydına
// çevirir. Log-shipper'lar (rsyslog omhttp, fluent-bit http) syslog'u HTTP üzerinden
// iletebildiğinden bu, CEF/LEEF dışı kaynakları da kapsar. PRAGMATİK ayrıştırma:
// <PRI>'dan önem çıkarılır; RFC5424'te hostname/app-name kaynak olur; kalan MSG'dir.
//
//	RFC5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
//	RFC3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG
func NormalizeSyslog(line string, now time.Time) (Record, error) {
	line = strings.TrimSpace(line)
	if len(line) < 3 || line[0] != '<' {
		return Record{}, fmt.Errorf("logingest: syslog <PRI> öneki yok")
	}
	end := strings.IndexByte(line, '>')
	if end < 2 || end > 4 { // <PRI> en fazla 3 basamak
		return Record{}, fmt.Errorf("logingest: syslog <PRI> geçersiz")
	}
	pri, err := strconv.Atoi(line[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return Record{}, fmt.Errorf("logingest: syslog PRI geçersiz")
	}
	rest := line[end+1:]
	sev := syslogSeverity(pri % 8)

	source, msg := "syslog", strings.TrimSpace(rest)
	occurred := now
	fields := strings.Fields(rest)
	// RFC5424: ilk alan sürüm ("1"); TIMESTAMP=fields[1], HOSTNAME=fields[2], APP-NAME=fields[3].
	if len(fields) >= 5 && fields[0] == "1" {
		host := deNil(fields[2])
		app := deNil(fields[3])
		if host != "" {
			source = host
		} else if app != "" {
			source = app
		}
		// TIMESTAMP (RFC3339): olayın gerçek zamanı — zaman çizelgesi doğruluğu.
		if ts := deNil(fields[1]); ts != "" {
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
				if t, err := time.Parse(layout, ts); err == nil {
					occurred = t
					break
				}
			}
		}
		// MSG: MSGID(+SD) sonrası; SD karmaşık olabilir → pragmatik: 6. alandan sonrası.
		if i := nthFieldIndex(rest, 6); i >= 0 {
			msg = strings.TrimSpace(rest[i:])
		}
	} else if len(fields) >= 5 {
		// RFC3164: "Mon DD HH:MM:SS HOST TAG: MSG" — HOST 4. alan (fields[3]).
		if h := fields[3]; h != "" {
			source = h
		}
	}
	if msg == "" {
		msg = "(boş syslog mesajı)"
	}
	rec := Record{
		DeviceID: SourceUUID(source),
		Event: model.Event{
			Category:   "SECURITY",
			Severity:   sev,
			Message:    "[" + source + "] " + msg,
			OccurredAt: occurred,
		},
	}
	stampCanonical(&rec.Event, source, "")
	return rec, nil
}

// syslogSeverity, syslog önem kodunu (0-7) KUT önem düzeyine eşler.
func syslogSeverity(s int) string {
	switch {
	case s <= 2: // emerg/alert/crit
		return "CRITICAL"
	case s == 3: // err
		return "HIGH"
	case s == 4: // warning
		return "MEDIUM"
	case s == 5: // notice
		return "LOW"
	default: // info/debug
		return "INFO"
	}
}

// deNil, syslog "-" (yok) değerini boş string'e çevirir.
func deNil(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// nthFieldIndex, boşlukla ayrılmış n. alanın (0-tabanlı) `s` içindeki başlangıç
// bayt indeksini döner; yoksa -1.
func nthFieldIndex(s string, n int) int {
	field, inField := 0, false
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '\t' {
			if !inField {
				if field == n {
					return i
				}
				field++
				inField = true
			}
		} else {
			inField = false
		}
	}
	return -1
}

// winClass, tek bir Windows olay kimliğinin sınıflandırmasıdır.
type winClass struct {
	cat, sev, name string
}

// winCatalog, İYİ-BİLİNEN Windows güvenlik/sistem/Sysmon/PowerShell olay
// kimliklerini KUT kategori+önem + insan-okur ada eşler. EDR görünürlüğü:
// winlogbeat/nxlog gibi standart log-shipper'lar bu olayları HTTP ile iletir.
// Adlar İngilizce anahtar kelime taşır (aşağı-akış MITRE/tespit kuralları için).
var winCatalog = map[int]winClass{
	// --- Security kanalı ---
	1102: {"SECURITY", "CRITICAL", "denetim günlüğü temizlendi (audit log cleared)"},
	4624: {"SECURITY", "INFO", "başarılı oturum açma (logon)"},
	4625: {"SECURITY", "MEDIUM", "oturum açma başarısız (failed logon)"},
	4634: {"SECURITY", "INFO", "oturum kapatma (logoff)"},
	4648: {"SECURITY", "MEDIUM", "açık kimlik bilgisiyle oturum (explicit credentials logon)"},
	4672: {"SECURITY", "MEDIUM", "özel ayrıcalıklar atandı (special privileges assigned)"},
	4688: {"PROCESS", "INFO", "yeni süreç oluşturuldu (process creation)"},
	4697: {"SECURITY", "HIGH", "hizmet kuruldu (service installed persistence)"},
	4698: {"SECURITY", "HIGH", "zamanlanmış görev oluşturuldu (scheduled task created persistence)"},
	4699: {"SECURITY", "MEDIUM", "zamanlanmış görev silindi (scheduled task deleted)"},
	4700: {"SECURITY", "LOW", "zamanlanmış görev etkinleştirildi (scheduled task enabled)"},
	4701: {"SECURITY", "LOW", "zamanlanmış görev devre dışı (scheduled task disabled)"},
	4702: {"SECURITY", "LOW", "zamanlanmış görev güncellendi (scheduled task updated)"},
	4719: {"SECURITY", "HIGH", "sistem denetim politikası değişti (audit policy changed defense evasion)"},
	4720: {"SECURITY", "HIGH", "kullanıcı hesabı oluşturuldu (user account created)"},
	4722: {"SECURITY", "MEDIUM", "kullanıcı hesabı etkinleştirildi (account enabled)"},
	4723: {"SECURITY", "MEDIUM", "parola değiştirme girişimi (password change attempt)"},
	4724: {"SECURITY", "MEDIUM", "parola sıfırlama girişimi (password reset attempt)"},
	4725: {"SECURITY", "LOW", "kullanıcı hesabı devre dışı (account disabled)"},
	4726: {"SECURITY", "MEDIUM", "kullanıcı hesabı silindi (account deleted)"},
	4728: {"SECURITY", "HIGH", "güvenlik-etkin global gruba üye eklendi (privilege escalation)"},
	4732: {"SECURITY", "HIGH", "güvenlik-etkin yerel gruba üye eklendi (privilege escalation)"},
	4756: {"SECURITY", "HIGH", "güvenlik-etkin evrensel gruba üye eklendi (privilege escalation)"},
	4738: {"SECURITY", "LOW", "kullanıcı hesabı değişti (account changed)"},
	4740: {"SECURITY", "MEDIUM", "kullanıcı hesabı kilitlendi (account locked out)"},
	4767: {"SECURITY", "LOW", "kullanıcı hesabı kilidi açıldı (account unlocked)"},
	4768: {"SECURITY", "INFO", "Kerberos TGT istendi (authentication ticket requested)"},
	4769: {"SECURITY", "INFO", "Kerberos hizmet bileti istendi (service ticket requested)"},
	4771: {"SECURITY", "MEDIUM", "Kerberos ön-kimlik doğrulama başarısız (pre-authentication failed)"},
	4776: {"SECURITY", "INFO", "kimlik bilgisi doğrulama (credential validation)"},
	4798: {"SECURITY", "LOW", "kullanıcı yerel grup üyeliği sıralandı (group enumeration recon)"},
	4799: {"SECURITY", "LOW", "güvenlik-etkin yerel grup sıralandı (group enumeration recon)"},
	4964: {"SECURITY", "MEDIUM", "özel gruba atanmış oturum açma (special groups logon)"},
	5140: {"NETWORK_CONN", "INFO", "ağ paylaşımına erişildi (network share accessed)"},
	5145: {"SECURITY", "LOW", "paylaşım nesnesi erişim denetimi (share object checked)"},
	// --- System kanalı ---
	104:  {"SECURITY", "CRITICAL", "olay günlüğü temizlendi (event log cleared defense evasion)"},
	6005: {"SYSTEM", "INFO", "olay günlüğü hizmeti başlatıldı (event log started)"},
	6006: {"SYSTEM", "INFO", "olay günlüğü hizmeti durduruldu (event log stopped)"},
	7036: {"SYSTEM", "INFO", "hizmet durumu değişti (service state changed)"},
	7040: {"SECURITY", "MEDIUM", "hizmet başlangıç türü değişti (service start type changed)"},
	7045: {"SECURITY", "HIGH", "yeni hizmet kuruldu (service installed persistence)"},
	// --- Sysmon (Microsoft-Windows-Sysmon/Operational) ---
	// NOT: Sysmon ID'leri Security ile çakışır → kanal Sysmon ise winSysmon kullanılır.
	// --- PowerShell (Microsoft-Windows-PowerShell/Operational) ---
	// NOT: 4103/4104 kanal PowerShell ise winPowerShell kullanılır.
	// --- WMI-Activity ---
	5861: {"SECURITY", "HIGH", "WMI kalıcı olay tüketicisi (permanent event consumer persistence)"},
}

// winSysmon, Sysmon kanalı olay kimlikleri (Security kanalıyla çakıştığından ayrı).
var winSysmon = map[int]winClass{
	1:  {"PROCESS", "INFO", "süreç oluşturma (Sysmon process create)"},
	2:  {"SECURITY", "MEDIUM", "dosya oluşturma zamanı değiştirildi (timestomp defense evasion)"},
	3:  {"NETWORK_CONN", "INFO", "ağ bağlantısı (Sysmon network connection)"},
	5:  {"PROCESS", "INFO", "süreç sonlandı (Sysmon process terminated)"},
	7:  {"SECURITY", "LOW", "imaj yüklendi (Sysmon image loaded)"},
	8:  {"SECURITY", "HIGH", "CreateRemoteThread (Sysmon process injection)"},
	10: {"SECURITY", "MEDIUM", "süreç erişimi (Sysmon process access)"},
	11: {"SYSTEM", "INFO", "dosya oluşturuldu (Sysmon file create)"},
	12: {"SECURITY", "LOW", "kayıt defteri nesnesi eklendi/silindi (Sysmon registry)"},
	13: {"SECURITY", "LOW", "kayıt defteri değeri ayarlandı (Sysmon registry set)"},
	14: {"SECURITY", "LOW", "kayıt defteri anahtarı yeniden adlandırıldı (Sysmon registry)"},
	22: {"NETWORK_CONN", "INFO", "DNS sorgusu (Sysmon DNS query)"},
	23: {"SECURITY", "LOW", "dosya silindi (Sysmon file delete)"},
}

// winPowerShell, PowerShell operasyonel kanalı olay kimlikleri.
var winPowerShell = map[int]winClass{
	4103: {"PROCESS", "LOW", "PowerShell işlem hattı yürütmesi (pipeline execution)"},
	4104: {"PROCESS", "MEDIUM", "PowerShell betik bloğu günlüğü (script block logging)"},
}

// winDefender, Microsoft Defender operasyonel kanalı olay kimlikleri. Defender'ın
// KENDİ telemetrisi birincil bir EDR kaynağıdır: kötü amaçlı yazılım tespitleri ve
// (kritik) korumanın devre dışı bırakılması. ID'ler Security kanalıyla çakışabildiği
// için kanal Defender ise bu harita kullanılır.
var winDefender = map[int]winClass{
	1006: {"SECURITY", "HIGH", "kötü amaçlı yazılım tespit edildi (Defender malware detected)"},
	1015: {"SECURITY", "MEDIUM", "şüpheli davranış tespit edildi (Defender suspicious behavior)"},
	1116: {"SECURITY", "HIGH", "kötü amaçlı yazılım tespit edildi (Defender malware detected)"},
	1117: {"SECURITY", "MEDIUM", "tehdide karşı eylem alındı (Defender action taken)"},
	5001: {"SECURITY", "HIGH", "gerçek-zamanlı koruma devre dışı (Defender realtime protection disabled)"},
	5004: {"SECURITY", "MEDIUM", "gerçek-zamanlı koruma yapılandırması değişti (Defender realtime config changed)"},
	5007: {"SECURITY", "MEDIUM", "Defender yapılandırması değişti (config changed)"},
	5010: {"SECURITY", "HIGH", "kötü amaçlı yazılım taraması devre dışı (Defender antimalware scanning disabled)"},
	5012: {"SECURITY", "HIGH", "virüs taraması devre dışı (Defender antivirus scanning disabled)"},
}

// WinEventClass, bir Windows olay kimliği + kanaldan KUT kategori, önem ve
// insan-okur ad döner. Bilinmeyen kimlikler kanala göre güvenli varsayılana düşer
// (known=false). SAF fonksiyon (test edilebilir).
func WinEventClass(eventID int, channel string) (cat, sev, name string, known bool) {
	ch := strings.ToLower(channel)
	switch {
	case strings.Contains(ch, "sysmon"):
		if c, ok := winSysmon[eventID]; ok {
			return c.cat, c.sev, c.name, true
		}
	case strings.Contains(ch, "powershell"):
		if c, ok := winPowerShell[eventID]; ok {
			return c.cat, c.sev, c.name, true
		}
	case strings.Contains(ch, "defender"):
		if c, ok := winDefender[eventID]; ok {
			return c.cat, c.sev, c.name, true
		}
	}
	if c, ok := winCatalog[eventID]; ok {
		return c.cat, c.sev, c.name, true
	}
	// Bilinmeyen: kanala göre güvenli varsayılan.
	switch {
	case strings.Contains(ch, "security"):
		return "SECURITY", "INFO", "", false
	case strings.Contains(ch, "sysmon"):
		return "SECURITY", "INFO", "", false
	case strings.Contains(ch, "powershell"):
		return "PROCESS", "INFO", "", false
	case strings.Contains(ch, "defender"):
		return "SECURITY", "MEDIUM", "", false // Defender kanalı güvenlik-ilgili
	default:
		return "SYSTEM", "INFO", "", false
	}
}

// NormalizeWinEvent, Windows olay günlüğü JSON'unu (winlogbeat iç içe "winlog",
// nxlog düz, ya da render-edilmiş XML "Event.System" şekilleri) olay kayıtlarına
// çevirir. Olay kimliği + kanala göre kategori/önem sınıflandırılır (WinEventClass).
// EDR görünürlüğü: standart Windows log-shipper'ları /api/ingest'e JSON iletir.
func NormalizeWinEvent(data []byte, now time.Time) ([]Record, error) {
	trimmed := strings.TrimSpace(string(data))
	var objs []map[string]any
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &objs); err != nil {
			return nil, fmt.Errorf("logingest: winlog JSON dizi çözülemedi: %w", err)
		}
	} else {
		var one map[string]any
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, fmt.Errorf("logingest: winlog JSON çözülemedi: %w", err)
		}
		objs = []map[string]any{one}
	}
	out := make([]Record, 0, len(objs))
	for i, m := range objs {
		flat := map[string]any{}
		winFlatten(m, flat, 0)
		id := winInt(flat, "event_id", "eventid", "eventidentifier")
		if id == 0 {
			return nil, fmt.Errorf("logingest: winlog kaydı #%d event_id yok", i)
		}
		channel := winStr(flat, "channel")
		cat, sev, name, _ := WinEventClass(id, channel)
		computer := winStr(flat, "computer_name", "computer", "hostname", "host")
		provider := winStr(flat, "provider_name", "sourcename", "provider")
		source := strings.TrimSpace(computer)
		if source == "" {
			source = "winlog"
		}
		orig := winStr(flat, "message", "rendered_message", "renderingmessage")
		if len(orig) > 500 { // çok uzun render mesajlarını kırp
			orig = orig[:500] + "…"
		}
		orig = strings.TrimSpace(strings.ReplaceAll(orig, "\n", " "))
		label := name
		if label == "" {
			label = "Windows olayı"
		}
		msg := fmt.Sprintf("[%s] EventID %d %s", source, id, label)
		if orig != "" {
			msg += ": " + orig
		}
		detail := map[string]any{
			"event_id": id, "channel": channel, "provider": provider, "computer": computer,
		}
		// EventData zenginleştirme: triyaj için en yararlı alanları Details'e taşı
		// (hedef hesap, kaynak IP, oturum türü, hizmet/süreç). winFlatten bunları
		// winlogbeat "event_data", nxlog düz ve render-XML Data[] şekillerinden çıkarır.
		for out, keys := range winEnrichKeys {
			if v := winStr(flat, keys...); v != "" {
				detail[out] = v
			}
		}
		det, _ := json.Marshal(detail)
		rec := Record{
			DeviceID: SourceUUID(source),
			Event: model.Event{
				Category:   cat,
				Severity:   sev,
				Message:    msg,
				OccurredAt: winTime(flat, now), // olayın GERÇEK zamanı (varsa); yoksa alım zamanı
				Details:    string(det),
			},
		}
		// Windows olayları için spesifik event_type (kanonik), ör. "winevent_4625".
		stampCanonical(&rec.Event, source, fmt.Sprintf("winevent_%d", id))
		out = append(out, rec)
	}
	return out, nil
}

// winEnrichKeys, Details'e taşınacak EventData alanlarını (çıktı adı → aday kaynak
// anahtarlar) tanımlar. Anahtarlar küçük harf (winFlatten küçük-harfe indirir).
var winEnrichKeys = map[string][]string{
	"target_user":  {"targetusername", "target_user_name"},
	"subject_user": {"subjectusername", "subject_user_name"},
	"src_ip":       {"ipaddress", "ip_address", "source_network_address"},
	"workstation":  {"workstationname", "workstation_name"},
	"logon_type":   {"logontype", "logon_type"},
	"service_name": {"servicename", "service_name"},
	"process_name": {"processname", "process_name", "newprocessname"},
	"command_line": {"commandline", "command_line"},
}

// maxWinDepth, winFlatten özyineleme derinliği üst sınırıdır (ağ-yüzeyli girdiye karşı
// savunma-derinliği: aşırı iç içe JSON'da yığın taşmasını önler). Gerçek Windows olay
// şekilleri birkaç seviye derindir; 64 fazlasıyla yeterlidir.
const maxWinDepth = 64

// winFlatten, iç içe Windows JSON şekillerini (winlog, Event, System, EventData)
// tek düzey haritaya düzleştirir; anahtarlar küçük harfe indirilir (son-yazan kazanır).
// Render-XML EventData Data[] dizisi ({@Name,#text} çiftleri) de düzleştirilir.
// depth, özyineleme derinliğidir; maxWinDepth aşılırsa daha derine inilmez.
func winFlatten(m map[string]any, out map[string]any, depth int) {
	if depth >= maxWinDepth {
		return
	}
	for k, v := range m {
		lk := strings.ToLower(strings.TrimSpace(k))
		switch child := v.(type) {
		case map[string]any:
			// #text / @Name gibi öznitelik-sarmalı skalerler: değeri anahtara ata.
			if t, ok := child["#text"]; ok {
				out[lk] = t
			}
			if nm, ok := child["@Name"]; ok && lk == "provider" {
				out["provider_name"] = nm
			}
			winFlatten(child, out, depth+1) // iç içe alanları da yukarı taşı
		case []any:
			// Render-XML EventData: [{"@Name":"TargetUserName","#text":"bob"}, ...].
			for _, el := range child {
				em, ok := el.(map[string]any)
				if !ok {
					continue
				}
				if nm, ok := em["@Name"].(string); ok {
					if t, ok := em["#text"]; ok {
						out[strings.ToLower(strings.TrimSpace(nm))] = t
					}
				} else {
					winFlatten(em, out, depth+1)
				}
			}
		default:
			if _, exists := out[lk]; !exists || out[lk] == nil {
				out[lk] = v
			}
		}
	}
}

// winTime, Windows olayının GERÇEK oluşma zamanını düzleştirilmiş haritadan çıkarır
// (winlogbeat "@timestamp", ECS "event.created", render-XML TimeCreated "@systemtime").
// RFC3339/RFC3339Nano denenir; çözülemezse alım zamanı (fallback) döner. Bu, saldırı
// hikâyesi ve olay zaman çizelgesinin alım gecikmesinden değil gerçek olay saatinden
// sıralanmasını sağlar.
func winTime(flat map[string]any, fallback time.Time) time.Time {
	s := winStr(flat, "@timestamp", "@systemtime", "systemtime", "timecreated", "event_created", "eventtime")
	if s == "" {
		return fallback
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000000Z", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return fallback
}

// winStr, düzleştirilmiş haritada aday anahtarların ilk boş-olmayan string değerini döner.
func winStr(flat map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := flat[k]; ok {
			if s := fmt.Sprintf("%v", v); s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

// winInt, düzleştirilmiş haritada aday anahtarların ilk çözülebilir tamsayısını döner.
func winInt(flat map[string]any, keys ...string) int {
	for _, k := range keys {
		v, ok := flat[k]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			return int(n)
		case json.Number:
			if x, err := n.Int64(); err == nil {
				return int(x)
			}
		case string:
			if x, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
				return x
			}
		}
	}
	return 0
}

// cefSeverity, CEF 0-10 önem ölçeğini KUT önem düzeyine eşler.
func cefSeverity(s string) string {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return normSeverity(s) // metinsel önem (Low/High...) olabilir
	}
	switch {
	case n >= 9:
		return "CRITICAL"
	case n >= 7:
		return "HIGH"
	case n >= 4:
		return "MEDIUM"
	case n >= 1:
		return "LOW"
	default:
		return "INFO"
	}
}
