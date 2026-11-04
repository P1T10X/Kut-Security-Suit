// Package security, C2 sunucusunun kriptografik ilkelerini sağlar:
// blind index (aranabilir HMAC), alan-bazlı şifreleme (AES-256-GCM) ve
// istemci sertifikası imzalama (CA).
package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"strings"
)

// BlindIndexer, hassas bir değerden aranabilir ama tersine çevrilemez bir
// indeks üretir. Düz SHA-256 yerine keyed HMAC kullanılır: MAC adres uzayı
// ~48 bit olduğundan düz hash offline brute-force'a açıktır.
type BlindIndexer struct {
	key []byte
}

// NewBlindIndexer, verilen gizli anahtarla bir indeksleyici oluşturur.
// key sunucunun ana anahtarından türetilmeli ve en az 32 bayt olmalıdır.
func NewBlindIndexer(key []byte) *BlindIndexer {
	// Anahtarı kopyala; çağıranın slice'ını mutasyona karşı yalıt.
	k := make([]byte, len(key))
	copy(k, key)
	return &BlindIndexer{key: k}
}

// Compute, değerin HMAC-SHA256 blind index'ini döner (32 bayt).
func (b *BlindIndexer) Compute(value string) []byte {
	m := hmac.New(sha256.New, b.key)
	m.Write([]byte(value))
	return m.Sum(nil)
}

// Equal, iki blind index'i sabit-zamanlı karşılaştırır.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// NormalizeMAC, bir MAC adresini kanonik biçime getirir: yalnızca hex
// karakterler, küçük harf, iki nokta ayraçlı ("aa:bb:cc:dd:ee:ff").
// Blind index HESAPLANMADAN ÖNCE her zaman uygulanmalıdır ki farklı biçimde
// yazılmış aynı adres aynı indeksi üretsin.
func NormalizeMAC(mac string) string {
	var hex strings.Builder
	for _, r := range mac {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex.WriteRune(r)
		case r >= 'A' && r <= 'F':
			hex.WriteRune(r + ('a' - 'A'))
		default:
			// ayraçları (":", "-", ".", boşluk) atla
		}
	}
	h := hex.String()
	if len(h) != 12 {
		// Beklenen 48-bit MAC değilse dokunmadan, küçük harfe çevirerek dön;
		// çağıran doğrulamayı üst katmanda yapar.
		return strings.ToLower(strings.TrimSpace(mac))
	}
	var out strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(h[i : i+2])
	}
	return out.String()
}
