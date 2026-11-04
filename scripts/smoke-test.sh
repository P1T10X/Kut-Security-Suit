#!/usr/bin/env bash
# smoke-test.sh — uçtan uca kabul testi: gerçek c2 + gerçek agent'ı ayağa
# kaldırır, kayıt → heartbeat → olay → admin eylem → SSE zincirini iddialarla
# doğrular. Bellek-içi demo modu (harici bağımlılık yok). CI'da da çalışır.
#
# Çıkış kodu 0 = tüm iddialar geçti.
set -uo pipefail
cd "$(dirname "$0")/.."

EXT=""; [ "${OS:-}" = "Windows_NT" ] && EXT=".exe"
WORK="$(mktemp -d 2>/dev/null || echo "./_smoke")"; mkdir -p "$WORK"
AGENT_PORT=18443; ENROLL_PORT=18444; ADMIN_PORT=18445
B="https://127.0.0.1:${ADMIN_PORT}"
PIDS=()
FAILED=0

log(){ printf '  %s\n' "$*"; }
pass(){ printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail(){ printf '  \033[31m✗ %s\033[0m\n' "$*"; FAILED=1; }
cleanup(){
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT

echo "[1/6] İkilileri derle"
go build -o "$WORK/c2$EXT" ./server/cmd/c2 || { echo "c2 derlenemedi"; exit 1; }
go build -o "$WORK/agent$EXT" ./agent/cmd/agent || { echo "agent derlenemedi"; exit 1; }
go build -o "$WORK/gencerts$EXT" ./tools/gencerts || { echo "gencerts derlenemedi"; exit 1; }
pass "c2, agent, gencerts derlendi"

# Depo modu: KUT_DATABASE_URL verilirse PostgreSQL (şema yükle + admin tohumla),
# aksi halde bellek-içi demo. Diğer tüm adımlar/iddialar aynıdır.
MODE="bellek-içi"
if [ -n "${KUT_DATABASE_URL:-}" ]; then
  MODE="PostgreSQL"
  # PSQL komutu dışarıdan verilebilir (ör. CI'da postgres servis konteynerindeki
  # psql'i kullanmak için "docker exec -i <cid> psql"); varsayılan host psql'i.
  PSQL="${PSQL:-psql}"
  if [ "$PSQL" = "psql" ]; then
    command -v psql >/dev/null 2>&1 || { echo "psql gerekli (DB modu)"; exit 1; }
  fi
  echo "[2/6] PostgreSQL: migrasyonları uygula + admin tohumla"
  # Şema, gömülü goose migrasyonlarıyla kurulur (yeniden çalıştırmak zararsızdır).
  # psql yalnız yönetici tohumlaması için gerekir (stdin ile; docker-exec ile de çalışır).
  go run ./server/cmd/kutctl migrate up \
    && pass "migrasyonlar uygulandı (db/postgres/migrations)" || { fail "migrasyonlar uygulanamadı"; exit 1; }
  go run ./tools/adminseed -email admin@local -password smoke1234 -role ADMIN -name Smoke \
    | tail -n +2 | $PSQL "$KUT_DATABASE_URL" -v ON_ERROR_STOP=1 -q \
    && pass "yönetici tohumlandı (Argon2id)" || fail "admin tohumlanamadı"
fi

echo "[2/6] PKI + sunucuyu başlat ($MODE)"
"$WORK/gencerts$EXT" -out "$WORK/pki" -name kut-c2 >/dev/null
MASTER_KEY="$(openssl rand -base64 32 2>/dev/null || head -c32 /dev/urandom | base64)"
# base64 çıktısındaki olası satır-sonu/boşlukları temizle (bazı platformlarda base64
# 76 sütunda kırar / CRLF ekler → config base64-çözme hatası). Güvenli tek-satır anahtar.
MASTER_KEY="$(printf '%s' "$MASTER_KEY" | tr -d '[:space:]')"
# XDR connector: bir CEF kaynak dosyası + connector yapılandırması. c2
# başlarken bunu yükleyip 1sn aralıkla yoklamalı ve olayı depolamalı. Kaynak yolu,
# JSON içeriğinde yer aldığından ve native binary tarafından açılacağından, Windows'ta
# cygpath -m ile ileri-eğik-çizgili karma yola çevrilir (Linux'ta POSIX yol kullanılır).
printf 'CEF:0|SmokeConn|FW|1.0|100|baglanti engellendi|5|src=9.9.9.9\n' > "$WORK/conn-src.cef"
CONN_SRC="$(cygpath -m "$WORK/conn-src.cef" 2>/dev/null || echo "$WORK/conn-src.cef")"
printf '[{"name":"smoke-cef","format":"cef","source":"%s","interval_sec":1}]\n' "$CONN_SRC" > "$WORK/connectors.json"
# ABAC: subject.role=admin ise izin veren tek politika.
printf '[{"id":"p-admin","effect":"allow","match":[{"key":"subject.role","op":"eq","value":"admin"}]}]\n' > "$WORK/abac.json"
COMMON_ENV=(
  "KUT_MASTER_KEY=$MASTER_KEY"
  "KUT_CONNECTORS_FILE=$WORK/connectors.json"
  "KUT_ABAC_FILE=$WORK/abac.json"
  "KUT_CA_CERT=$WORK/pki/ca.crt" "KUT_CA_KEY=$WORK/pki/ca.key"
  "KUT_SERVER_CERT=$WORK/pki/server.crt" "KUT_SERVER_KEY=$WORK/pki/server.key"
  "KUT_LISTEN_AGENT=:$AGENT_PORT" "KUT_LISTEN_ENROLL=:$ENROLL_PORT" "KUT_LISTEN_ADMIN=:$ADMIN_PORT"
  "KUT_VULN_FILE=deploy/vuln-sample.json"
  "KUT_INGEST_TOKEN=smoke-ingest-token"
)
if [ -n "${KUT_DATABASE_URL:-}" ]; then
  # DB modunda yatay-ölçekleme fan-out'unu aç (#10): SSE iddiası gerçek Postgres
  # LISTEN/NOTIFY round-trip'ini doğrular (tek düğüm de NOTIFY'ı kendine geri alır).
  env "${COMMON_ENV[@]}" "KUT_DATABASE_URL=$KUT_DATABASE_URL" "KUT_CLUSTER=1" "$WORK/c2$EXT" > "$WORK/c2.log" 2>&1 &
else
  env "${COMMON_ENV[@]}" "KUT_DEMO=1" "KUT_DEMO_ADMIN_PASSWORD=smoke1234" "$WORK/c2$EXT" > "$WORK/c2.log" 2>&1 &
fi
PIDS+=($!)

# Admin API hazır olana dek bekle (maks ~10 sn)
ready=0
for _ in $(seq 1 50); do
  if curl -sk "$B/" -o /dev/null 2>/dev/null; then ready=1; break; fi
  sleep 0.2
done
[ "$ready" = 1 ] && pass "C2 dinliyor (:$ADMIN_PORT)" || { fail "C2 başlamadı"; cat "$WORK/c2.log"; exit 1; }
# Konsol yeni istihbarat panelini (Risk & Uyum) içeriyor mu (delivered-but-invisible önlemi).
# NOT: konsol ~155KB; grep -q boruyu erken kapatıp curl'e SIGPIPE verir ve pipefail
# ile boru başarısız görünür — bu yüzden gövde önce değişkene alınır.
console_html="$(curl -sk "$B/")"
case "$console_html" in *'id="risk-summary"'*) pass "konsol Risk & Uyum panelini sunuyor";; *) fail "konsolda risk paneli yok";; esac

echo "[3/6] Giriş + enrollment token"
TOK="$(curl -sk "$B/api/login" -X POST -H 'Content-Type: application/json' \
  -d '{"email":"admin@local","password":"smoke1234"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')"
[ -n "$TOK" ] && [ "$TOK" != "$(printf '{')" ] && pass "yönetici girişi başarılı" || fail "giriş başarısız"
ETOK="$(curl -sk "$B/api/enrollment-tokens" -X POST -H "Authorization: Bearer $TOK" -d '{}' \
  | sed -E 's/.*"enrollment_token":"([^"]+)".*/\1/')"
[ ${#ETOK} -ge 16 ] && pass "enrollment token üretildi" || fail "token üretilemedi"

echo "[4/6] Ajanı kaydet + olay akışını doğrula"
KUT_ENROLL_ADDR="127.0.0.1:$ENROLL_PORT" KUT_AGENT_ADDR="127.0.0.1:$AGENT_PORT" \
KUT_SERVER_NAME="kut-c2" KUT_CA_PEM="$WORK/pki/ca.crt" KUT_ENROLL_TOKEN="$ETOK" \
KUT_AGENT_DATA="$WORK/agent-data" KUT_HEARTBEAT_INTERVAL="2s" KUT_SAFE_MODE="1" \
  "$WORK/agent$EXT" > "$WORK/agent.log" 2>&1 &
PIDS+=($!)

# Cihaz görünene dek bekle
dev=0
for _ in $(seq 1 40); do
  n="$(curl -sk "$B/api/devices" -H "Authorization: Bearer $TOK" | grep -o '"id"' | wc -l)"
  if [ "$n" -ge 1 ]; then dev=1; break; fi
  sleep 0.25
done
[ "$dev" = 1 ] && pass "ajan kaydoldu (cihaz listede)" || fail "cihaz kaydı görünmedi"

# "kimlik hazır" log satırı, cihaz sunucuda göründükten SONRA yazılır (ajan
# ensureEnrolled → sunucuya kayıt → log). Tek-atışta yarışa girmemek için poll et.
idok=0
for _ in $(seq 1 40); do
  if grep -q "kimlik hazır" "$WORK/agent.log"; then idok=1; break; fi
  sleep 0.25
done
[ "$idok" = 1 ] && pass "ajan kimliği üretildi (CSR imzalandı)" || fail "ajan kimliği yok"

# Olaylar ilk heartbeat/toplama döngüsünden SONRA gelir (interval 2s). Tek-atış
# yerine yayılım için poll et (en çok ~15 sn).
evc=0
for _ in $(seq 1 60); do
  evc="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -o '"id"' | wc -l)"
  if [ "$evc" -ge 1 ]; then break; fi
  sleep 0.25
done
[ "$evc" -ge 1 ] && pass "olaylar alındı ($evc olay)" || fail "olay yok"
# Olay cihaz-atfı: her olay device_id taşımalı (filo-geneli triyaj/gruplama).
curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -q '"device_id"' \
  && pass "olaylar cihaz-atfı (device_id) taşıyor" || fail "olaylarda device_id yok"
# Uyum olayı: disk şifreleme + güvenlik duvarı durumu (poll — uyum kontrolü exec-ağır).
comp=""
for _ in $(seq 1 40); do
  comp="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -oE '"firewall":"[^"]+"' | head -1)"
  [ -n "$comp" ] && break
  sleep 0.25
done
[ -n "$comp" ] && pass "uyum olayı güvenlik duvarı durumu taşıyor ($comp)" || fail "uyum olayında firewall yok"
# Yazılım envanteri: ajan yüklü yazılım listesini raporlamalı (MDM varlık).
inv=""
for _ in $(seq 1 40); do
  inv="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -oE '"software_count":[0-9]+' | head -1)"
  [ -n "$inv" ] && break
  sleep 0.25
done
[ -n "$inv" ] && pass "yazılım envanteri raporlandı ($inv)" || fail "yazılım envanteri yok"
# Zafiyet eşleştirme: envanter × CVE veri kümesi (örnek set 7-Zip/Adobe içerir).
vln=""
for _ in $(seq 1 40); do
  vln="$(curl -sk "$B/api/vulnerabilities" -H "Authorization: Bearer $TOK" | grep -oE '"vulnerable_devices":[0-9]+' | head -1)"
  echo "$vln" | grep -qE ':[1-9]' && break
  sleep 0.25
done
echo "$vln" | grep -qE ':[1-9]' && pass "zafiyet eşleştirme çalıştı ($vln)" || fail "zafiyet eşleşmesi yok"
# Kaynak telemetrisi: ajan bellek/disk/uptime raporlamalı (uç-nokta sağlığı).
rsc=""
for _ in $(seq 1 40); do
  rsc="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -oE '"mem_used_pct":[0-9]+' | head -1)"
  [ -n "$rsc" ] && break
  sleep 0.25
done
[ -n "$rsc" ] && pass "kaynak telemetrisi raporlandı ($rsc)" || fail "kaynak telemetrisi yok"
# Filo yazılım araması: envanterdeki bir paketi ara, cihaz eşleşmeli.
pkg="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -oE '"software":\["[^"]+"' | head -1 | sed -E 's/.*\["([^"]+)".*/\1/' | cut -c1-6)"
if [ -n "$pkg" ]; then
  curl -sk "$B/api/software?q=$(printf %s "$pkg" | sed 's/ /%20/g')" -H "Authorization: Bearer $TOK" | grep -q '"device_count":[1-9]' \
    && pass "filo yazılım araması eşleşti ($pkg)" || fail "yazılım araması başarısız"
else
  fail "arama için paket adı bulunamadı"
fi

echo "[5/6] Admin eylemleri + okuma uçları"
DID="$(curl -sk "$B/api/devices" -H "Authorization: Bearer $TOK" | sed -E 's/.*"id":"([^"]+)".*/\1/')"
curl -sk "$B/api/devices/collect-diagnostics" -X POST -H "Authorization: Bearer $TOK" \
  -d "{\"device_id\":\"$DID\"}" -o /dev/null
sleep 0.3
curl -sk "$B/api/audit?limit=20" -H "Authorization: Bearer $TOK" | grep -q "COLLECT_DIAGNOSTICS" \
  && pass "tanılama komutu kuyruğa alındı + denetlendi" || fail "tanılama denetim izinde yok"
# Delil + gözetim-zinciri: cihaz artefaktları doğrulanmış delil kaydı olarak döner.
curl -sk "$B/api/devices/$DID/evidence" -H "Authorization: Bearer $TOK" | grep -q '"evidence"' \
  && pass "/api/devices/{id}/evidence delil+gözetim-zinciri ucu döndü" || fail "/api/devices/{id}/evidence başarısız"
# Gözetim ekleme ucu bağlı: olmayan artefakta ACCESSED → 404 (uç + hata eşleme çalışıyor).
cust_code="$(curl -sk -o /dev/null -w '%{http_code}' "$B/api/devices/$DID/evidence/yok-artefakt/custody" \
  -X POST -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"action":"ACCESSED"}')"
[ "$cust_code" = "404" ] \
  && pass "/api/devices/{id}/evidence/{art}/custody ekleme ucu bağlı (yolu)" || fail "custody ucu başarısız ($cust_code)"
# Vaka yönetimi (#9): bir olaya sorumlu+not ata, listede geri oku (db SetEventCase/EventAcks).
EVID="$(curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | sed -E 's/.*"id":"([^"]+)".*/\1/')"
curl -sk "$B/api/events/$EVID/case" -X POST -H "Authorization: Bearer $TOK" \
  -d '{"assignee":"soc@corp","note":"otomatik smoke vaka"}' -o /dev/null
curl -sk "$B/api/events?limit=50" -H "Authorization: Bearer $TOK" | grep -q '"ack_assignee":"soc@corp"' \
  && pass "olay vaka ataması (assignee) kalıcı + okundu" || fail "olay vaka ataması görünmedi"
# SOC vaka yaşam döngüsü (casemgmt, kalıcı DB): oluştur → listede (write-through DB) →
# geçerli durum geçişi. Oluşturma/geçiş DB'ye upsert eder; şema/SQL hatası 500'e düşer.
CID="$(curl -sk "$B/api/cases" -X POST -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"title":"smoke SOC vaka","severity":"HIGH"}' \
  | sed -E 's/.*"id":"([^"]+)".*/\1/')"
{ [ -n "$CID" ] && curl -sk "$B/api/cases" -H "Authorization: Bearer $TOK" | grep -q "$CID" ; } \
  && pass "SOC vakası oluşturuldu + kalıcı ($CID)" || fail "SOC vaka oluşturma/kalıcılık başarısız"
curl -sk "$B/api/cases/$CID/transition" -X POST -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"to":"INVESTIGATING","note":"smoke triyaj"}' \
  | grep -q '"status":"INVESTIGATING"' \
  && pass "SOC vaka geçişi OPEN→INVESTIGATING (fail-closed durum makinesi)" || fail "SOC vaka geçişi başarısız"
curl -sk "$B/api/audit?limit=20" -H "Authorization: Bearer $TOK" | grep -q "EVENT_CASE" \
  && pass "vaka ataması denetim izine yazıldı" || fail "vaka denetim izinde yok"
# Remediation Doğrulama (verify, kalıcı DB yolu): check aç → listede (write-through DB) →
# çalıştır (DB Resolve). Açma/çalıştırma DB'ye upsert/update eder; şema/SQL hatası 500'e düşer.
VID="$(curl -sk "$B/api/verify/open" -X POST -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d "{\"device_id\":\"$DID\",\"rule_id\":\"smoke-rule\",\"kind\":\"detection\"}" \
  | sed -E 's/.*"id":"([^"]+)".*/\1/')"
{ [ -n "$VID" ] && curl -sk "$B/api/verify" -H "Authorization: Bearer $TOK" | grep -q "$VID" ; } \
  && pass "doğrulama check açıldı + kalıcı ($VID)" || fail "doğrulama check açma/kalıcılık başarısız"
curl -sk "$B/api/verify/$VID/run" -X POST -H "Authorization: Bearer $TOK" \
  | grep -qE '"outcome":"(VERIFIED|REGRESSED|INCONCLUSIVE)"' \
  && pass "doğrulama check çalıştı + çözüldü (DB Resolve)" || fail "doğrulama run/resolve başarısız"
# Kurcalama-kanıtlı denetim dışa aktarımı (#16): hash-zincirli JSONL üretilir.
exp="$(curl -sk "$B/api/audit/export" -H "Authorization: Bearer $TOK")"
echo "$exp" | grep -q '"hash"' \
  && pass "/api/audit/export hash-zinciri üretti" || fail "/api/audit/export başarısız"
curl -sk "$B/api/summary" -H "Authorization: Bearer $TOK" | grep -q "devices_total" \
  && pass "özet uç yanıt verdi" || fail "özet uç başarısız"
curl -sk "$B/api/policies" -H "Authorization: Bearer $TOK" | grep -q "policies" \
  && pass "politika listeleme uç yanıt verdi" || fail "politika uç başarısız"
# Tehdit etkinliği sayaçları (kimlik doğrulanmış) — yeni /api/activity ucu.
curl -sk "$B/api/activity" -H "Authorization: Bearer $TOK" | grep -q "detections" \
  && pass "/api/activity sayaçları döndü" || fail "/api/activity başarısız"
# Bastırma-nedeni sayaçları API üzerinden erişilebilir olmalı (threshold/bits kapılama görünürlüğü).
curl -sk "$B/api/activity" -H "Authorization: Bearer $TOK" | grep -q "threshold_gated" \
  && curl -sk "$B/api/activity" -H "Authorization: Bearer $TOK" | grep -q "bits_gated" \
  && pass "/api/activity threshold_gated + bits_gated sayaçlarını sundu" || fail "/api/activity bastırma-nedeni sayaçları eksik"
# Tespit kural kataloğu ucu.
curl -sk "$B/api/detections/rules" -H "Authorization: Bearer $TOK" | grep -q "KUT-0001" \
  && pass "/api/detections/rules kataloğu döndü" || fail "/api/detections/rules başarısız"
# Tespit kuralı test aracı (dry-run): örnek olay → eşleşen kural.
curl -sk "$B/api/detections/test" -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"category":"SECURITY","message":"ajan kurcalama girisimi"}' \
  | grep -q "KUT-0001" \
  && pass "/api/detections/test kuralı eşleştirdi" || fail "/api/detections/test başarısız"
# Retro-hunt (#1): mevcut kuralları geçmiş olaylara uygula (QueryEvents + değerlendirme).
curl -sk "$B/api/hunt" -X POST -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"mode":"rules","limit":500}' \
  | grep -q '"scanned"' \
  && pass "/api/hunt retro-hunt çalıştı (geçmiş olaylar tarandı)" || fail "/api/hunt başarısız"
# Event Replay (§19): aday kuralı geçmiş olaylara uygula → etki raporu (by_rule).
curl -sk "$B/api/detections/replay" -X POST -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"rules":[{"id":"CAND-1","name":"aday","severity":"HIGH","contains":["a"]}],"limit":500}' \
  | grep -q '"by_rule"' \
  && pass "/api/detections/replay aday kuralı geçmişe uyguladı" || fail "/api/detections/replay başarısız"
# AI SOC asistanı: öneri-yalnız analiz (hiçbir eylem yürütülmez).
curl -sk "$B/api/ai/analyze" -X POST -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"task":"mitre_mapping","input":"powershell encoded komut ve mimikatz"}' \
  | grep -q '"recommendation"' \
  && pass "/api/ai/analyze öneri üretti (yürütmesiz)" || fail "/api/ai/analyze başarısız"
# Kayıtlı aramalar (#22 SIEM): bir hunt sorgusu kaydet + listede gör.
curl -sk "$B/api/hunt/saved" -X POST -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Kritik olaylar","filter":{"mode":"query","severity":"CRITICAL"}}' >/dev/null
curl -sk "$B/api/hunt/saved" -H "Authorization: Bearer $TOK" | grep -q "Kritik olaylar" \
  && pass "/api/hunt/saved kayıtlı arama kalıcılaştı" || fail "/api/hunt/saved başarısız"
# Olay korelasyonu (#2): incident listeleme ucu yanıt versin.
curl -sk "$B/api/incidents" -H "Authorization: Bearer $TOK" | grep -q '"incidents"' \
  && pass "/api/incidents korelasyon ucu döndü" || fail "/api/incidents başarısız"
curl -sk "$B/api/incidents/does-not-exist/timeline" -H "Authorization: Bearer $TOK" | grep -q "bulunamadı" \
  && pass "/api/incidents/{id}/timeline ucu bağlı (404 yolu)" || fail "/api/incidents/{id}/timeline başarısız"
curl -sk "$B/api/ueba/admins" -H "Authorization: Bearer $TOK" | grep -q "profiles" \
  && pass "/api/ueba/admins yönetici davranış analitiği döndü" || fail "/api/ueba/admins başarısız"
# Zamanlanmış/dışa aktarılabilir rapor (#7): duruş raporu HTML üretimi.
curl -sk "$B/api/report" -H "Authorization: Bearer $TOK" | grep -q "KUT Security Suite" \
  && pass "/api/report duruş raporu üretti" || fail "/api/report başarısız"
curl -sk "$B/api/report?format=json" -H "Authorization: Bearer $TOK" | grep -q '"devices_total"' \
  && pass "/api/report?format=json makine-okunur rapor üretti" || fail "/api/report json başarısız"
# Gelişmiş rapor: yönetici Markdown raporu.
curl -sk "$B/api/report?format=md&kind=executive" -H "Authorization: Bearer $TOK" | grep -q '# Yönetici Güvenlik Özeti' \
  && pass "/api/report?format=md yönetici Markdown raporu üretti" || fail "/api/report md başarısız"
curl -sk "$B/api/coverage" -H "Authorization: Bearer $TOK" | grep -q "coverage_pct" \
  && pass "/api/coverage filo kapsamı döndü" || fail "/api/coverage başarısız"
curl -sk "$B/api/risk" -H "Authorization: Bearer $TOK" | grep -q "fleet_score" \
  && pass "/api/risk çok-faktörlü risk skoru döndü" || fail "/api/risk başarısız"
curl -sk "$B/api/compliance/frameworks" -H "Authorization: Bearer $TOK" | grep -q "score_pct" \
  && pass "/api/compliance/frameworks çerçeve uyumu döndü" || fail "/api/compliance/frameworks başarısız"
curl -sk "$B/api/features" -H "Authorization: Bearer $TOK" | grep -q '"tenant_id"' \
  && pass "/api/features kiracı kimliği (tenant_id) taşıyor" || fail "/api/features tenant_id yok"
ASDID="$(curl -sk "$B/api/devices" -H "Authorization: Bearer $TOK" | sed -E 's/.*"id":"([^"]+)".*/\1/')"
curl -sk "$B/api/devices/$ASDID/attack-story" -H "Authorization: Bearer $TOK" | grep -q '"steps"' \
  && pass "/api/devices/{id}/attack-story saldırı hikâyesi döndü" || fail "/api/attack-story başarısız"
curl -sk "$B/api/devices/$ASDID/graph" -H "Authorization: Bearer $TOK" | grep -q '"nodes"' \
  && pass "/api/devices/{id}/graph varlık grafiği döndü" || fail "/api/graph başarısız"
curl -sk "$B/api/metrics/trends?days=7" -H "Authorization: Bearer $TOK" | grep -q "mttd_seconds" \
  && pass "/api/metrics/trends MTTD/MTTR trendi döndü" || fail "/api/metrics/trends başarısız"
curl -sk "$B/api/maintenance" -H "Authorization: Bearer $TOK" | grep -q "windows" \
  && pass "/api/maintenance bakım pencereleri ucu döndü" || fail "/api/maintenance başarısız"
# Harici log alımı (#21 SIEM): JSON log gönder, normalize edilip yazılmalı.
curl -sk "$B/api/ingest" -X POST -H "Authorization: Bearer smoke-ingest-token" \
  -H "Content-Type: application/json" \
  -d '[{"source":"fw-test","category":"NETWORK_CONN","severity":"high","message":"smoke ingest"}]' \
  | grep -q '"accepted":1' \
  && pass "/api/ingest harici log alımı çalıştı" || fail "/api/ingest başarısız"
# Yineleme-tespiti (§6): AYNI olayı (sabit occurred_at) iki kez gönder — ikincisi düşmeli.
DUP='[{"source":"fw-dup","category":"NETWORK_CONN","severity":"high","message":"dup olay","occurred_at":"2026-09-01T10:00:00Z"}]'
curl -sk "$B/api/ingest" -X POST -H "Authorization: Bearer smoke-ingest-token" \
  -H "Content-Type: application/json" -d "$DUP" >/dev/null
curl -sk "$B/api/ingest" -X POST -H "Authorization: Bearer smoke-ingest-token" \
  -H "Content-Type: application/json" -d "$DUP" \
  | grep -q '"duplicate":1' \
  && pass "/api/ingest yineleme-tespiti kopyayı düşürdü (§6)" || fail "/api/ingest dedup başarısız"
# Log-ingest TESPİT hattı: ingest edilen olay da sunucu-taraflı tespit motorundan
# geçmeli (yalnız kaydedilmemeli). Kural-eşleşen bir olay gönder ve detections
# sayacının ARTTIĞINI doğrula (sayaç monoton; ajan da artırabilir → delta >= 1).
det_before="$(curl -sk "$B/api/activity" -H "Authorization: Bearer $TOK" | grep -oE '"detections":[0-9]+' | grep -oE '[0-9]+' | head -1)"
curl -sk "$B/api/ingest" -X POST -H "Authorization: Bearer smoke-ingest-token" \
  -H "Content-Type: application/json" \
  -d '[{"source":"fw-det","category":"SECURITY","severity":"high","message":"ajan kurcalama girisimi (log-ingest tespit)"}]' >/dev/null
det_after="$(curl -sk "$B/api/activity" -H "Authorization: Bearer $TOK" | grep -oE '"detections":[0-9]+' | grep -oE '[0-9]+' | head -1)"
if [ -n "$det_before" ] && [ -n "$det_after" ] && [ "$det_after" -gt "$det_before" ]; then
  pass "/api/ingest olayları tespit hattından geçti (detections $det_before→$det_after)"
else
  fail "/api/ingest tespit hattını tetiklemedi (detections $det_before→$det_after)"
fi
# Zengin telemetri: cihaz OS sürümü (ilk heartbeat'ten sonra dolar) — poll et.
osv=""
for _ in $(seq 1 40); do
  osv="$(curl -sk "$B/api/devices" -H "Authorization: Bearer $TOK" | grep -oE '"os_version":"[^"]+"' | head -1)"
  [ -n "$osv" ] && break
  sleep 0.25
done
[ -n "$osv" ] && pass "cihaz OS sürümü raporlandı ($osv)" || fail "os_version boş kaldı"
# Sağlık uçları (kimlik doğrulama YOK) — /healthz sürüm + uptime içerir.
curl -sk "$B/healthz" | grep -q "uptime_seconds" \
  && pass "/healthz sürüm + uptime içeriyor" || fail "/healthz zenginleştirme yok"
[ "$(curl -sk -o /dev/null -w '%{http_code}' "$B/healthz")" = "200" ] \
  && pass "/healthz 200 (liveness)" || fail "/healthz başarısız"
[ "$(curl -sk -o /dev/null -w '%{http_code}' "$B/readyz")" = "200" ] \
  && pass "/readyz 200 (readiness)" || fail "/readyz başarısız"

# XDR connector: CEF kaynağından çekilen olay depolanmış olmalı (kısa poll).
conn_ok=""
for _ in 1 2 3 4 5 6; do
  if curl -sk "$B/api/events?limit=200" -H "Authorization: Bearer $TOK" | grep -q "SmokeConn"; then conn_ok=1; break; fi
  sleep 0.5
done
[ -n "$conn_ok" ] && pass "connector CEF kaynağından olay çekip depoladı" || fail "connector olayı depolanmadı"

# ABAC: subject.role=admin → allow (eşleşen politika p-admin).
curl -sk "$B/api/iam/abac/evaluate" -X POST -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"subject":{"role":"admin"},"resource":{"tenant":"t1"},"action":"read"}' \
  | grep -q '"allowed":true' \
  && pass "/api/iam/abac/evaluate ABAC kararı verdi" || fail "/api/iam/abac/evaluate başarısız"
# SCIM 2.0: kullanıcı sağla → getir → devre dışı bırak (soft-delete).
SCIM_ID="$(curl -sk "$B/scim/v2/Users" -X POST -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"userName":"jdoe@corp","name":{"givenName":"J","familyName":"Doe"},"active":true}' \
  | sed -E 's/.*"id":"([^"]+)".*/\1/')"
curl -sk "$B/scim/v2/Users/$SCIM_ID" -H "Authorization: Bearer $TOK" | grep -q '"userName":"jdoe@corp"' \
  && pass "SCIM kullanıcı sağlandı + getirildi" || fail "SCIM create/get başarısız"
curl -sk "$B/scim/v2/Users/$SCIM_ID" -X DELETE -H "Authorization: Bearer $TOK" | grep -q '"active":false' \
  && pass "SCIM kullanıcı devre dışı (soft-delete)" || fail "SCIM deactivate başarısız"
# MSP: müşteri ekle → listele → devre dışı bırak.
MSP_ID="$(curl -sk "$B/api/msp/customers" -X POST -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"name":"Acme A.Ş.","tenant_id":"acme"}' \
  | sed -E 's/.*"id":"([^"]+)".*/\1/')"
curl -sk "$B/api/msp/customers" -H "Authorization: Bearer $TOK" | grep -q '"tenant_id":"acme"' \
  && pass "MSP müşteri eklendi + listelendi" || fail "MSP create/list başarısız"
curl -sk "$B/api/msp/customers/$MSP_ID" -X DELETE -H "Authorization: Bearer $TOK" | grep -q '"deactivated":true' \
  && pass "MSP müşteri devre dışı (soft-delete)" || fail "MSP deactivate başarısız"

echo "[6/6] SSE canlı akış"
SSE="$(curl -sk -N --max-time 5 "$B/api/stream" -H "Authorization: Bearer $TOK" 2>/dev/null)"
echo "$SSE" | grep -q '"type":"' && pass "SSE bildirim iletti" || fail "SSE bildirim gelmedi"

echo
if [ "$FAILED" = 0 ]; then
  echo -e "\033[32mSMOKE TEST GEÇTİ — uçtan uca zincir sağlıklı.\033[0m"; exit 0
else
  echo -e "\033[31mSMOKE TEST BAŞARISIZ.\033[0m"; echo "--- c2.log ---"; tail -20 "$WORK/c2.log"; exit 1
fi
