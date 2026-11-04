# Multi-Tenancy — KUT Kiracı İzolasyon Modeli

KUT, **tek dağıtımda birden çok kiracıyı (müşteriyi)** güvenle barındıran paylaşımlı
bir SaaS modelini uygular. Kiracı ayrımı ayrı süreç/veritabanı ile DEĞİL, her varlığın
`tenant_id` taşıması ve her okuma/yazmanın çağıranın kiracısıyla daraltılmasıyla sağlanır.
(MSP, her müşteriyi ayrı dağıtıma değil; aynı dağıtımdaki bir `tenant_id`'ye eşler —
bkz. `msp_customers`.)

## Temel ilke — kiracı SUNUCU-TARAFI çözülür, istekten DEĞİL

Kiracı hiçbir zaman istemciden (header/gövde/parametre) alınmaz. Her zaman kimlik-
doğrulanmış bağlamdan türetilir:

| Yol | Kaynak |
|---|---|
| Ajan (yazma) | mTLS ile kimliklenen `device_id` → `devices.tenant_id` |
| Yönetici (okuma/aksiyon) | oturum admini `adminID` → `admins.tenant_id` |
| Olay triyajı | `event_id` → `event_logs.tenant_id` |

**Platform admini** = `admins.tenant_id` boş → TÜM kiracıları görür/yönetir (operatör/süper-
admin). **Kiracıya bağlı admin** = boş-olmayan `tenant_id` → yalnız kendi kiracısı.
Uyumsuzluk **fail-closed**: `ErrForbidden` ya da "bulunamadı" (varlık sızmaz).

## Yazma yolu (write path)

1. **Enrollment**: kayıt token'ı bir kiracı taşır (`enrollment_tokens.tenant_id`);
   cihaz kayıtta bu kiracıyı devralır (`devices.tenant_id`).
2. **Olay alımı**: handler cihazın kiracısını `TenantForDevice(device_id)` ile çözer ve
   her olayı sunucu-tarafı damgalar (`event_logs.tenant_id`) — istemcinin gönderdiği
   değere GÜVENİLMEZ.
3. **Zorlama**: `KUT_TENANT_ENFORCE=1` iken kiracıya bağlı OLMAYAN bir cihazın olayları
   `FailedPrecondition` ile reddedilir (INV-044: eksik kiracı → DENY). Varsayılan kapalı
   (geriye-uyumlu).

## Cihaz aksiyonları (yazma) ve olay triyajı

Yüksek-etkili/yıkıcı aksiyonlar rol + Scope/ROE'ye ek olarak **kiracı kapısından** geçer
(`enforceDeviceTenant`): lock, restart, quarantine, release, collect-diagnostics, wipe,
wipe-approve, wipe-cancel, collect-file, erase, revoke, assign-policy. Kiracıya bağlı bir
admin başka kiracının `device_id`'siyle aksiyon çalıştıramaz. Aynı biçimde olay triyaj
yazmaları (ack/resolve, sorumlu/not) `enforceEventTenant` ile olayın kiracısına bağlanır.

## Okuma yolu (read path)

Her yönetici okuma ucu çağıranın kiracısını çözüp sonucu daraltır. Kapsam:

- Olay listesi + retro-hunt + detection-replay (`EventFilter.TenantID`)
- Cihaz listesi + cihaz detayı (çapraz-kiracı cihaz "bulunamadı")
- Özet/KPI agregatları (durum/önem/kategori sayımları, uyum)
- Coverage, framework-compliance, fleet-risk
- Incident'ler + incident zaman çizelgesi (device→tenant join)
- Yazılım envanteri + zafiyet görünümü
- Artefaktlar + delil + gözetim-zinciri + artefakt indirme (device→tenant)
- Denetim izi + kayıtlı aramalar (admin→tenant join)
- SOC vakaları (list/get/transition/attach) + varlık grafı pivot/anomaly
- Enrollment token listesi + bekleyen WIPE listesi
- Cihaz-kapsamlı olay okumaları (attack-story, entity-graph, export)

Platform admini boş kiracıyla TÜMÜNÜ görür (gerekli yerde `ListAll`/`GetAny`/`*Any`
kiracı-agnostik yollar).

## Ayrıcalık-yükseltme koruması

`CreateAdmin`: istemcinin verdiği `tenant_id` yalnızca ÖNERİDİR. Oluşturan yöneticinin
kendi kiracısı sunucu-tarafı çözülür; kiracıya bağlı bir admin BAŞKA kiracıya admin
ekleyemez (fail-closed), boş istek kendi kiracısına sabitlenir. Platform admini herhangi
bir kiracıya ekleyebilir.

## Bilinçli kiracı-üstü (fleet-geneli) yüzeyler

Bazı uçlar tasarım gereği kiracılar-üstüdür ve bu bir sızıntı değildir:

- `GET /metrics` — operatör/Prometheus, statik token ile; dağıtım-geneli.
- Periyodik güvenlik-duruş raporu — dağıtımın `KUT_TENANT_ID`'siyle etiketlenir.
- Zamanlanmış kayıtlı-arama koşucusu + yönetici-davranışı (UEBA) — sistem analitiği.

## Altyapı-seviyesi izolasyon (dağıtım konfigü)

Uygulama katmanı her satır/anahtar/vakayı `tenant_id`-atıflı yapar. Derinlemesine-savunma
için altyapı katmanı da yapılandırılabilir (kod değil, dağıtım): ClickHouse tablo/row-
policy/quota, nesne-depolama (S3) kiracı-önekli anahtarlar, dayanıklı-bus partition/ACL.

## Sonradan kapsanan izolasyon seti (kiracı duvarı kapanışı)

Aşağıdaki yüzeyler de kiracı duvarına ve rol kapısına bağlanmıştır:

- **Enrollment token**: kiracı token'a sunucu tarafında mühürlenir (kiracıya bağlı admin
  başka kiracı veremez; gövdedeki `tenant_id` yalnız platform admini için geçerlidir) ve
  iptal (revoke) kiracı + OPERATOR kapısındandır; yabancı/yok token fail-closed reddedilir.
- **Cihaz yeniden-taşıma yok**: enroll sırasında mevcut cihaz başka kiracıya taşınamaz
  (MAC yolunda başka kiracının aynı MAC'i o satıra dokunmaz ve kendi cihazını alır; token'a bağlı cihaz yolunda `ErrTenantMismatch`); cihazın güvenlik durumu (karantina vb.)
  yeniden kayıtta korunur.
  Kiracı öncesi (legacy) cihazların boş kiracısı örtük `default` kiracıyla eşdeğer sayılır:
  `default` token'ıyla yeniden kayıt reddedilmez ve kiracı `default`'a normalleştirilir
  (gerçek hiçbir kiracıya taşıma yine yok).
- **Yönetici yönetimi**: oluşturma/rol/pasifleştirme/listeleme kiracı kapsamlıdır ve
  kapsam dışına rol (ADMIN dahil) veremez; kapsamın SON etkin ADMIN'i kendini düşüremez
  veya pasifleştiremez (403, kilitlenme koruması; platform kapsamı için de geçerlidir).
- **Yönetilen API token'ları** (metrics/ingest; oluştur/listele/iptal): yalnız platform
  admini; kiracıya bağlı admin 403 alır.
- **Cihaz etiketleri**: OPERATOR+ ve cihazın kiracısı ile sınırlı.
- **MFA yeniden kayıt**: MFA zaten etkinse `POST /api/mfa/enroll` mevcut TOTP kodunu
  (`{"code":"…"}`) ister; kodsuz/yanlış/tekrar kullanılmış kod 403 + denetim kaydıdır.
  Yeni sır BEKLEYEN olarak ayrı saklanır: yeni sırdan gelen geçerli kodla etkinleşene dek
  eski sır ve `mfa_enrolled` aynen kalır (giriş MFA'yı zorunlu kılar, kapatma eski sırdan
  kod ister); etkinleşmede takas atomiktir ve eski sır geçersizleşir.
- **Adli (forensics) uçları** OPERATOR+ gerektirir (VIEWER 403): artefakt indirme,
  emanet-zinciri (custody) kaydı, tespit yeniden-oynatma (replay) ve artefakt/delil
  LİSTELEME (`GET /api/devices/{id}/artifacts`, `/evidence`).
- **İptal edilmiş sertifikalar**, devam ettirilen (resumed) TLS oturumlarında da
  `VerifyConnection` ile zorlanır; iptal listesi başlangıçta yüklenir.

Konsol bu kapılarla uyumludur: VIEWER oturumunda artefakt indirme denetimi gizlenir
(kilit simgesi), 403'ler mesajla ele alınır; MFA yeniden kayıt/kapatma mevcut kodu sorar;
enrollment token isteği kiracı göndermez (kiracı sunucuda çözülür).

## Kiracı izolasyonu: veri ve yönetim katmanı

- **MAC tekilliği kiracı başınadır**: `devices.mac_address_bidx` artık küresel UNIQUE
  değildir; tekillik anahtarı `uq_devices_tenant_mac` = (kanonik kiracı, MAC). Kanonik kiracı
  `COALESCE(NULLIF(tenant_id,''),'default')`'tır: kiracı öncesi boş kiracı, `default` ile
  AYNI kiracıdır (`tenant.Canonical`), böylece `''` ve `default` aynı MAC için iki satır
  üretemez. Bir kiracı başkasının MAC'ini önceden kaydederek onu engelleyemez (MAC-squat DoS);
  aynı MAC başka kiracıda ayrı satır olur ve mevcut satıra DOKUNULMAZ (re-home yok).
- **Yazma yollarında SQL kiracı predicate'i**: enrollment-token iptali, yönetici
  rol/pasifleştirme ve cihaz etiketi `UPDATE`'leri çağıranın kiracısını `AND tenant_id = $n`
  ile taşır. Platform çağıran boş kiracı verir (süzme yok). Kiracıya bağlı çağıran için eşleşen
  satır yoksa `ErrForbidden` (403): servis katmanındaki bir hata kiracı sınırını aşamaz.
- **Bilinmeyen/pasif yönetici platform değildir **: `AdminTenant` bilinmeyen,
  bozuk-id'li veya pasif yönetici için `""` döndürmez; `ErrUnknownAdmin` (`ErrForbidden`'ı sarar,
  HTTP 403) döner. Tüm çağıranlar (servis kapıları, okuma kapsamı, platform-yalnız kontroller)
  hatayı yayar; boş kiracı yalnız ETKİN bir platform adminini ifade eder.
- **Politikalar kiracı sahibi taşır**: `policies.tenant_id` (varsayılan `''` =
  platform/paylaşımlı; mevcut tüm politikalar böyle kalır). Kiracıya bağlı admin yalnız KENDİ
  kiracısının politikalarını listeler/oluşturur/değiştirir (kural ekleme); paylaşımlı politikalar
  onlar için salt-okunur ve atanabilirdir; başka kiracının politikasına erişim yoktur (listede
  görünmez, kural listesi/kural ekleme/atama 403). Sahip SUNUCU-TARAFI çözülür; yalnız platform
  admini (doğrulanmış `tenant.Normalize`) kiracı seçebilir. Atama bütünlüğü: politika paylaşımlı
  ya da cihazın kiracısına ait olmalı — platform admini dahil herkes için ve SQL'de ayrıca;
  kural itmesi yalnız politikanın kiracısındaki cihazlara ulaşır; ajan politika çekimi eski
  çapraz-kiracı atamayı atlar.
- **Triyaj ve incident'lerde gerçek kiracı**: `event_ack.tenant_id` olayın kiracısıyla
  (ack ve vaka yolları), `incidents.tenant_id` cihazın kiracısıyla yazılır; kiracı daima
  sunucu-tarafı olaydan/cihazdan okunur. Boş (legacy) kiracı `tenant.Canonical` ile `default`
  olarak saklanır. Okuma yolları bilinçli olarak DEĞİŞMEDİ (backfill yapılmadığı için
  `event_ack.tenant_id` ile süzmek mevcut satırları gizlerdi).
- **Sınırda kiracı doğrulaması**: istekten gelen kiracı değerleri `tenant.Normalize`
  ile (kırp + küçük harf + `[a-z0-9-]`, 1-63) doğrulanır: yönetici oluşturma, MSP müşterisi,
  politika oluşturma, enrollment token ve yalnız-platform `?tenant=` filtresi (geçersiz → 400).
  Yönetici oluşturmada boş kiracı boş KALIR (platform admini).
- **Adli kayıt**: artefakt/delil listeleme OPERATOR+ (dosya yolları + gözetim zinciri aktörleri
  içerir); başarılı gözetim yazımı yönetici denetim izine `CUSTODY_<EYLEM>` olarak da düşer.

### Mevcut kurulumlar için yükseltme (veri ve yönetim katmanı)

1. Şema bloğunu uygulayın (idempotent, yeniden çalıştırılabilir; taze kurulumda no-op):
   `sed -n '/^-- BEGIN TENANT-MAC-UPGRADE/,/^-- END TENANT-MAC-UPGRADE/p' db/schema.sql | psql "$KUT_DATABASE_URL"`.
   Blok önce yeni `uq_devices_tenant_mac` indeksini oluşturur, SONRA eski küresel
   `devices_mac_address_bidx_key` kısıtını düşürür; `policies.tenant_id` sütununu ekler.
   **Kilit**: indeks `CONCURRENTLY` DEĞİL kurulur;
   build boyunca `devices` üzerinde SHARE kilidi tutulur ve cihaz yazmaları (enroll, heartbeat,
   etiket) bekler. Bakım penceresinde uygulayın. Ardından aşağıdaki "Yükseltme sonrası doğrulama"
   sorgusunu çalıştırın (kısıt farklı adlıysa DROP sessizce no-op olur).
2. Yeni ikiliyi AYNI bakım penceresinde dağıtın: eski ikili `ON CONFLICT (mac_address_bidx)`
   kullandığından kısıt düşünce cihaz kaydı (enroll) çalışmaz; yeni ikili ise `policies.tenant_id`
   sütununu bekler. **İkili/şema uyumsuzluğu** (yeni ikili + eski şema ya da eski ikili + yeni şema)
   yalnız enroll/politika YÖNETİM uçlarını değil, AJANIN politika çekimini de bozar (akış
   `Internal` döner). İki adım arasını mümkün olduğunca kısa tutun.
3. Geri alma: `ALTER TABLE devices ADD CONSTRAINT devices_mac_address_bidx_key UNIQUE
   (mac_address_bidx)` yalnız farklı kiracılarda aynı MAC'li satır YOKSA başarılır; önce mükerrerleri
   çözün. **Geri alma fiilen tek yönlüdür**: yükseltmeden sonra bir kiracı başka kiracıyla aynı MAC'i
   kaydettiyse geri alma bu cihaz satırlarından birinin SİLİNMESİNİ gerektirir. `uq_devices_tenant_mac`
   indeksi geri almada bırakılabilir (zararsız, daha zayıf).
4. İsteğe bağlı, tek seferlik backfill (geçmiş satırları yeni temsile çevirir; tekrar çalıştırılabilir,
   bir transaction içinde uygulayın). Yeni yazımlar zaten doğru kiracıyı taşır; bu yalnız eski
   satırlar içindir:

```sql
BEGIN;
-- event_ack: olayın kiracısından (boş = 'default'). Eski hata: her satır 'default' idi.
UPDATE event_ack ea
   SET tenant_id = COALESCE(NULLIF(el.tenant_id, ''), 'default')
  FROM event_logs el
 WHERE el.id::text = ea.event_id
   AND ea.tenant_id <> COALESCE(NULLIF(el.tenant_id, ''), 'default');

-- incidents: cihazın kiracısından; cihazsız incident 'default'.
UPDATE incidents i
   SET tenant_id = COALESCE(NULLIF(d.tenant_id, ''), 'default')
  FROM devices d
 WHERE d.id = i.device_id
   AND i.tenant_id <> COALESCE(NULLIF(d.tenant_id, ''), 'default');
UPDATE incidents SET tenant_id = 'default' WHERE device_id IS NULL AND tenant_id = '';
COMMIT;
```

   Politikalar: mevcut politikalar paylaşımlı (`tenant_id = ''`) kalır. Bir politikayı bir kiracıya
   sahiplendirmek için `UPDATE policies SET tenant_id = '<kiracı>' WHERE id = '<uuid>'`. Yükseltmeden
   ÖNCE oluşmuş çapraz-kiracı atamaları bulmak için:

```sql
SELECT dp.device_id, dp.policy_id, d.tenant_id AS cihaz_kiracisi, p.tenant_id AS politika_kiracisi
  FROM device_policies dp
  JOIN devices  d ON d.id = dp.device_id
  JOIN policies p ON p.id = dp.policy_id
 WHERE p.tenant_id <> ''
   AND p.tenant_id <> COALESCE(NULLIF(d.tenant_id, ''), 'default');
```

   Bu atamalar ajana ZATEN itilmez (politika çekimi kiracı eşleşmesi arar); satırları temizlemek
   için `DELETE FROM device_policies` ile ilgili çiftleri silin.

## Kiracı izolasyonu: telemetri, analizörler, AI ve graf

- **HTTP `/api/ingest` kiracıya bağlıdır**: yönetilen ingest token'ları
  OLUŞTURULURKEN bir kiracıya bağlanır (`POST /api/tokens {"scope":"ingest","tenant":"acme"}`;
  yalnız platform admini; kiracı `tenant.Normalize` ile doğrulanır; yalnız `ingest` kapsamı
  kiracıya bağlanabilir, `metrics` bağlanamaz). Olaylar `EventID` türetmesi, yineleme tespiti ve
  `SaveEvents`'ten ÖNCE token'ın kiracısıyla damgalanır; istek başlığı/gövdesi/query'si kiracı
  SEÇEMEZ. Kaynak "cihaz" kimliği, kaynak AÇIKÇA bir kiracıya bağlıysa ve bu kiracı dağıtımın
  varsayılan kiracısından (`KUT_TENANT_ID`, boşsa `default`) FARKLIYSA kiracıya ad-alanlanır
  (`logingest.SourceIDTenant` → `logingest.TenantDeviceID`): iki kiracı aynı kaynak adını (`fw1`)
  kullansa da AYRI cihaz/eşik/korelatör durumuna sahiptir.
  - **Kimlik sürekliliği kararı**: kiracısız (legacy/statik) token ve kiracısız connector olayları
    dağıtım kiracısıyla DAMGALANIR ama cihaz kimlikleri kiracı damgalama öncesiyle AYNI kalır (ad-alanlanmaz).
    Böylece `KUT_TENANT_ID=acme` olan mevcut bir dağıtımda yükseltme sonrası kaynakların cihaz
    kaydı, eşik, korelatör durumu ve geçmişi BÖLÜNMEZ. Dağıtım kiracısına açıkça bağlı token da
    aynı (eski) kimliği paylaşır. Ad-alanlama yalnız dağıtım kiracısından farklı, açıkça bağlı
    token/connector için uygulanır; geçmişi taşınacak bir kaynağı bir kiracıya BAĞLARSANIZ kimliği
    (ve dolayısıyla cihaz geçmişi) değişir — bu bilinçli bir taşıma adımıdır.
  - `KUT_TENANT_ENFORCE=1` iken kiracıya bağlı OLMAYAN token (statik `KUT_INGEST_TOKEN` dahil)
    `403` alır ve kiracısız ingest token'ı üretilemez (INV-044: eksik kiracı → DENY).
  - **Legacy**: zorlama KAPALIYKEN kiracısız token'lar (statik env token ve kiracı damgalama öncesi üretilmiş
    yönetilen token'lar) olayları dağıtımın varsayılan kiracısıyla (`KUT_TENANT_ID`, boşsa `default`)
    damgalar. Çok-kiracılı kurulumda bu token'ları kiracıya bağlı yenileriyle değiştirin.
- **Connector olayları** her connector'ın yapılandırılmış kiracısıyla (`"tenant"` alanı;
  boşsa dağıtım varsayılanı) kaydetmeden önce damgalanır; geçersiz kiracı başlangıçta hata verir.
  Cihaz kimliği ad-alanı HTTP ingest ile aynı kuralı izler (yukarıdaki kimlik sürekliliği kararı).
  **`KUT_TENANT_ENFORCE=1` iken `"tenant"` alanı OLMAYAN connector REDDEDİLİR** (INV-044; HTTP
  ingest'in kiracısız token'ı `403` ile reddetmesiyle aynı fail-closed): başlangıçta
  `connector "<ad>" atlandı (ÇALIŞTIRILMIYOR): ... kiracı zorunlu` günlüğü yazılır, connector
  başlatılmaz (diğerleri etkilenmez) ve `N connector kaynağı ETKİN, M atlandı` özeti verilir.
  Zorlama KAPALIYKEN davranış değişmez (dağıtım kiracısına düşer). Zorlamayı açmadan önce her
  connector'a açık `"tenant"` ekleyin.
  Connector olayları henüz paylaşılan tespit hattından GEÇMEZ (ayrı bir değişikliğin işi).
- **Sunucu-taraflı analizörler** (beacon, yanal hareket, DNS tüneli, kaba-kuvvet, zincir) bulguyu
  CİHAZIN kiracısıyla yazar: önce cihaz kaydı, kayıtsız ingest kaynakları için cihazın kendi
  olaylarındaki sunucu-damgalı kiracı, son olarak (yalnız zorlama kapalıyken) dağıtım varsayılanı.
  Çözülemezse bulgu atlanır (`kut_analyzer_skipped_total`). `Details` her zaman geçerli JSON'dur
  (`encoding/json`); "uyarıldı" bayrağı yalnız BAŞARILI kayıttan sonra set edilir. Bilinen sınır:
  analizörler okuma başına 1000 satırlık pencereyle çalışır.
- **SSE bildirimleri**: heartbeat / oto-karantina cihaz bildirimleri cihazın kiracısına atfedilir;
  kiracı çözülemezse (zorlama açıkken) yayınlanmaz.
- **agentsec grafı kiracı başına bölümlüdür**: `/api/agentsec/{findings,
  canonical,events}` ve imzalı telemetri sunucu-tarafı çözülmüş kiracının bölümünü okur/yazar.
  Kiracılı çağıran yalnız kendi bölümüne erişir (`?tenant=` yok sayılır); platform admini tüm
  bölümleri (bulgular `tenant` etiketli) ya da doğrulanmış `?tenant=` ile tek bölümü okur; yazımı
  platform bölümüne (`""`) ya da açık kiracıya yapar. Bölüm başına düğüm/kenar tavanı, 256 bayt
  kimlik sınırı, istek başına 1000 düğüm / 2000 kenar sınırı.
- **AI avı kiracı-kapsamlıdır**: `/api/ai/hunt` yalnız çağıranın kiracısının graf
  düğümlerini tarar (`HuntScope`); platform admini tümünü ya da gövdede `tenant` ile tek kiracıyı
  görür. `entitygraph.NodesByKindFor` tam kiracı eşleşmesidir (boş kiracı "hepsi" DEĞİLDİR).
- **Raporlar**: süreç-geneli sayaçlar (tespit/alarm/bastırılan/IoC) kiracıya bağlı raporlarda
  ve kiracılı `GET /api/activity` yanıtında YOKTUR (`counters_omitted: true`); yalnız platform
  görür. Zamanlanmış raporda zorlama açıkken de çıkarılır.
- **Sınırlı bellek**: ajan-kontrollü dizgelerden beslenen varlık grafı kiracı
  başına tavanlıdır (`KUT_GRAPH_MAX_EDGES`, `KUT_GRAPH_MAX_NODES`; varsayılan 100k) ve tavan aşılınca
  YALNIZ ihlal eden kiracının en eski-gözlenen kenarı atılır (LRU). Ek olarak **cihaz başına kenar
  bütçesi** vardır (`KUT_GRAPH_MAX_EDGES_PER_DEVICE`, varsayılan 10k benzersiz kenar): ele
  geçirilmiş tek bir ajan benzersiz alan adı/IP/süreç adı seliyle kiracı tavanını dolduramaz,
  diğer cihazların kenarlarını ya da kendi ESKİ (ör. C2) kenarlarını tahliye ettiremez. Bütçesi
  dolan cihazın YENİ kenarları tahliye YAPILMADAN düşürülür ve `kut_graph_device_dropped_total`
  ile sayılır (artış = ajan seli göstergesi); mevcut kenarlar TTL penceresi (`KUT_GRAPH_TTL`)
  boyunca korunur, süpürmeyle bütçe geri verilir. `KUT_GRAPH_TTL=0` süpürmeyi KAPATIR (kenarlar
  yalnız tavanla atılır; bütçe geri verilmez). Besleyici 256 bayttan uzun
  dizgeleri atar ve en çok 32 `parent_chain` girdisi işler. Sekans modeli kiracı BAŞINA ayrı ve
  sınırlıdır (`KUT_SEQMODEL_MAX_SOURCES`). Bakım döngüsü `KUT_GRAPH_TTL` (varsayılan 720h) kadar
  gözlenmeyen kenar/kaynakları atar (`KUT_GRAPH_SWEEP_INTERVAL`, varsayılan 10dk). `/metrics`:
  `kut_graph_{dropped,feed_dropped,evicted,pruned}_total`, `kut_graph_size{kind}`,
  `kut_seqmodel_{dropped,evicted}_total`, `kut_seqmodel_sources`, `kut_agentsec_dropped_total`.
  Sekans skoru uçları (`/api/hunt/sequence-score`, `/api/ai/risk`) çağıranın kiracı taban
  çizgisini kullanır; platform admini `?tenant=` seçer, yoksa dağıtım kiracısı.
- **Otomatik vaka**: cihaz kiracısı çözülemezse vaka AÇILMAZ (incident yine açılır;
  `kut_incident_case_total{result}`); `default` kovasına düşülmez. Boş kiracı kanonik `default`
  kiracısıdır, zorlama açıkken atlanır.

### Mevcut kurulumlar için yükseltme (telemetri, analizörler, AI ve graf)

1. Şema bloğunu uygulayın (idempotent; taze kurulumda no-op):
   `sed -n '/^-- BEGIN INGEST-TOKEN-TENANT-UPGRADE/,/^-- END INGEST-TOKEN-TENANT-UPGRADE/p' db/schema.sql | psql "$KUT_DATABASE_URL"`.
   Blok yalnız `tokens.tenant_id` sütununu ekler (tablo kilidi çok kısa; mevcut token'lar `''` =
   kiracısız/legacy kalır).
2. Yeni ikiliyi dağıtın. Yeni ikili `tokens.tenant_id` bekler: şemadan ÖNCE dağıtılırsa yönetilen
   token doğrulaması (`/api/ingest`, `/metrics`) başarısız olur; şema yeni sütunu eklediğinden eski
   ikili çalışmaya devam eder (geri uyumlu) — bu yüzden ÖNCE şema, SONRA ikili.
3. Kiracı başına ingest token'ı üretin ve kaynakları ona taşıyın; bittiğinde `KUT_TENANT_ENFORCE=1`
   ile kiracısız token'ları kapatın (connector'lara da açık `"tenant"` ekleyin). Kiracısız token
   ve connector'ların cihaz kimlikleri değişmez (bkz. kimlik sürekliliği kararı).

#### Geri alma (telemetri katmanı) — önce kiracıya bağlı ingest token'larını iptal edin

Geri alma "ikiliyi eskisiyle değiştirmek"ten ibaret DEĞİLDİR. ESKİ ikili `tokens.tenant_id`
sütununu yok sayar: kiracıya bağlı bir ingest token'ını geçerli kabul eder ve o token'ın olayları
sessizce **varsayılan kiracıya** düşer (kiracı bağı kaybolur; karışık sürümlü rolling deploy'da da
aynıdır). Bu yüzden geri almadan (ve rolling deploy'da eski örnekler trafik alırken) ÖNCE
kiracıya bağlı ingest token'larını iptal edin ve kaynakları kiracısız/legacy token'a döndürün:

```sql
-- 1) Kiracıya bağlı, etkin ingest token'larını listele
SELECT id, tenant_id, created_at, expires_at, last_used_at
  FROM tokens
 WHERE scope = 'ingest' AND tenant_id <> '' AND revoked_at IS NULL
 ORDER BY tenant_id, created_at;

-- 2) Hepsini iptal et (idempotent)
UPDATE tokens SET revoked_at = now()
 WHERE scope = 'ingest' AND tenant_id <> '' AND revoked_at IS NULL;
```

Aynı işlem API ile (platform admini): `GET /api/tokens?scope=ingest` yanıtında `tenant` alanı dolu
ve `revoked_at` boş olanları bulun, her biri için `POST /api/tokens/{id}/revoke` çağırın.
Doğrulama: ilk sorgu 0 satır dönmeli. Geri alma sonrası şema sütunu zararsız kalır (eski ikili
yok sayar); ikiliyi ancak bundan sonra eskisiyle değiştirin. Eski ikilide kiracı izolasyonunun ingest
kiracı bağı (token kiracısı, kiracısız token reddi, connector kiracısı) YOKTUR; çok-kiracılı bir
kurulumda geri alma bu yalıtımı kaybeder — mümkünse geri alma yerine ileri-düzeltme tercih edin.



## Yükseltme sonrası doğrulama (küresel MAC kısıtı)

`DROP CONSTRAINT IF EXISTS devices_mac_address_bidx_key` kısıt FARKLI bir adla varsa sessizce hiçbir
şey yapmaz; küresel tekillik bu durumda sinyalsiz sürerdi. Yükseltmeden sonra adı ne olursa olsun
`mac_address_bidx` üzerindeki tek-sütunlu UNIQUE kısıt/indeks sayısının **0** olduğunu doğrulayın:

```sql
SELECT (SELECT count(*) FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
          JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY (c.conkey)
         WHERE t.relname = 'devices' AND c.contype = 'u'
           AND array_length(c.conkey, 1) = 1 AND a.attname = 'mac_address_bidx')
     + (SELECT count(*) FROM pg_index i
          JOIN pg_class t ON t.oid = i.indrelid
          JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = i.indkey[0]
         WHERE t.relname = 'devices' AND i.indisunique AND i.indnatts = 1
           AND a.attname = 'mac_address_bidx') AS kalan_kuresel_tekillik;
-- beklenen: 0
```

Sonuç 0 değilse kalan kısıtı `\d devices` ile bulup düşürün (`ALTER TABLE devices DROP CONSTRAINT <ad>`),
aksi halde per-kiracı MAC yalnız yarım etkilidir.

## Değişmezler

- INV-044: kiracı çözülemiyorsa (zorlama açıkken) DENY.
- Kiracı istemci girdisinden ASLA alınmaz.
- Fail-closed: uyumsuz kiracı → reddet ya da "bulunamadı"; varlık sızdırılmaz.
