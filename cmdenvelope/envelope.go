// Package cmdenvelope, bir cihaz komut zarfının imzalanacak KANONİK bayt biçimini
// tanımlar. Sunucu (komut düzlemi = imzalayan) ve ajan (doğrulayan) TAM OLARAK aynı
// baytları üretmek zorunda olduğundan bu kodlama tek bir paylaşılan yerde (internal
// OLMAYAN) durur ve her iki tarafça kullanılır — ajan `server/internal/commandplane`'i
// import EDEMEZ (Go internal kuralı). otawire ile aynı desen (CONTRACTS §5 CommandEnvelope).
package cmdenvelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalBytes, bir komut zarfının imza/doğrulama için deterministik kanonik
// baytlarını üretir: alanlar 0x1f birim-ayracıyla bağlanır, parametreler
// sıralı SHA-256 ile özetlenir (JSON anahtar sırası belirsizliğinden kaçınır).
// Zaman alanları UnixNano int64 olarak yazılır (Postgres TIMESTAMPTZ µs yuvarlaması
// imzayı sessizce kırardı — bu yüzden ns-tamsayı taşınır ve saklanır).
func CanonicalBytes(cmdID, deviceID, cmdType, issuedBy string, params map[string]any, nonce string, issuedAtUnixNano, expiresAtUnixNano int64) []byte {
	var b bytes.Buffer
	sep := byte(0x1f)

	b.WriteString(cmdID)
	b.WriteByte(sep)
	b.WriteString(deviceID)
	b.WriteByte(sep)
	b.WriteString(cmdType)
	b.WriteByte(sep)
	b.WriteString(issuedBy)
	b.WriteByte(sep)

	paramsHash := hashParams(params)
	b.Write(paramsHash)
	b.WriteByte(sep)

	b.WriteString(nonce)
	b.WriteByte(sep)
	b.WriteString(fmt.Sprintf("%d", issuedAtUnixNano))
	b.WriteByte(sep)
	b.WriteString(fmt.Sprintf("%d", expiresAtUnixNano))

	return b.Bytes()
}

func hashParams(params map[string]any) []byte {
	if len(params) == 0 {
		return []byte("empty")
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte("="))
		valBytes, _ := json.Marshal(params[k])
		h.Write(valBytes)
		h.Write([]byte(";"))
	}
	return h.Sum(nil)
}

// VerifySignature, Ed25519 imzasını kanonik baytlar üzerinde doğrular. Saf/durumsuzdur
// (anti-replay nonce tüketimi çağırana aittir: sunucuda commandplane.CommandVerifier,
// ajanda kalıcı nonce deposu). Geçersiz anahtar boyutu → false (fail-closed).
func VerifySignature(pub ed25519.PublicKey, canonical, signature []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, canonical, signature)
}
