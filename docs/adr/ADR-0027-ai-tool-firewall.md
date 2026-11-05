# ADR-0027: AI Agent Tool Firewall Guardrail

## Durum
Kabul Edildi

## Bağlam
Otonom AI güvenlik ajanları (araştırmacı, avcı, müdahale ajanı) çeşitli araçları (tool calling) kullanarak sorgulama ve komut yürütme yetkisine sahiptir. Prompt enjeksiyonu veya mantık sapması yaşayan bir ajanın yetki yükseltmesi (privilege escalation) yaparak doğrudan yıkıcı sistem araçlarını çalıştırması veya komut parametrelerine enjeksiyon (SQLi, command injection) yapması platformun en kritik AI güvenlik riskidir (OWASP Top 10 for LLM: Insecure Tool Use).

## Karar
`server/internal/aisec` paketi altında `ToolFirewall` devreye alındı:
1. **Rol Bazlı En Az Yetki Prensibi (`AuthorizeToolCall`)**:
   - Her AI rolü (`investigator`, `hunter`, `response`) yalnız izinli araç kümesini (`AllowedTools`) çağırabilir.
   - Salt-okunur araştırmacı ajanların yıkıcı araçları (`quarantine_endpoint`, komut gönderme) çağırması kesin olarak bloklanır.
2. **Çift Kimlik Doğrulama / Onay Kontrolü (`RequiresDualAuth`)**:
   - Yüksek etkili araçlar için çift yetkilendirme politikası zorunlu tutulur.
3. **Parametre Enjeksiyon Koruması (`BlockedParameters`)**:
   - Parametre değerleri içindeki SQL ve komut enjeksiyonu kalıpları (`drop table`, `1=1`, `exec(`, vb.) taranarak fail-closed kuralıyla engellenir.
4. **Kiracı Sınırı Denetimi**:
   - Boş veya geçersiz kiracı çağrıları doğrudan reddedilir.

## Sonuçlar
- AI ajanlarının araç çağırma döngüsü tam güvenlik ve yetki duvarı arkasına alınarak saldırı vektörü olmaktan çıkarıldı.
