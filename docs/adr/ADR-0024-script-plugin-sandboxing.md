# ADR-0024: Script & Plugin Sandboxing Guardrail Engine

## Durum
Kabul Edildi

## Bağlam
XDR platformlarında uzaktan betik (script) çalıştırma ve eklenti yürütme (Live Response, remediation actions) en yüksek riskli operasyonlardır. Hatalı veya kötü niyetli komutlar (örn: `rm -rf`, disk formatlama, gölge kopyaların silinmesi `vssadmin delete shadows`, Mimikatz yürütülmesi) platformun kendisinin bir fidye yazılımı veya yıkım vektörüne dönüşmesine yol açabilir.

## Karar
`server/internal/scope` paketinde `SandboxGuardrail` ve `SandboxPolicy` motoru devreye alındı:
1. **Politika Tanımı (`SandboxPolicy`)**:
   - `MaxExecutionTime`: Betik çalışma süresi sınırı (varsayılan 30s).
   - `MaxMemoryBytes`: Bellek tüketim sınırı.
   - `DisallowedPatterns`: Yıkıcı ve saldırı amaçlı komut kalıpları (`rm -rf`, `format-volume`, `vssadmin delete shadows`, `invoke-mimikatz`, `set-executionpolicy bypass`, vb.).
   - `AllowedRuntimes`: İzin verilen güvenli çalışma ortamları (`powershell`, `bash`, `python`, `sh`).
2. **Fail-Closed Doğrulama (`ValidateScript`)**:
   - Desteklenmeyen veya tanımlanmamış çalışma zamanları anında reddedilir.
   - Boş betikler veya yasaklı kalıpları içeren kod blokları (büyük/küçük harf duyarsız kontrol ile) engellenir.
   - Herhangi bir ihlal oluştuğunda ayrıntılı ihlal listesi dönülerek komut gönderme düzleminde (`commandplane`) bloklanır.

## Sonuçlar
- Yıkıcı ve yetkisiz operasyonlar komut düzlemine ulaşmadan statik guardrail aşamasında engellenir.
