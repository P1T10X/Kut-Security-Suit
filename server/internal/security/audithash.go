package security

import (
	"crypto/sha256"
	"encoding/binary"
)

// unitSep, alan sınırı ayracıdır (birleştirme belirsizliğini önler).
const unitSep = 0x1f

// AuditChainHash, bir denetim kaydının zincir hash'ini hesaplar:
// SHA-256(prevHash || kanonik(alanlar)). Her kayıt bir öncekinin hash'ini
// içerdiğinden, herhangi bir kaydın (silme/değiştirme) sonrası zincir kırılır —
// kurcalama-kanıtı bir denetim izi sağlar. İlk kayıt için prev nil'dir.
// Not: id hash'e dahil DEĞİLDİR (DB'de id insert'te atanır); sıra/bütünlük
// prev-hash bağı + alanlar + zaman damgasıyla korunur.
// Çapraz-kiracı log naklini (transplant) önlemek için tenant_id de zincire dahil edilir.
// GERİYE UYUMLULUK: tenant_id YALNIZ boş-değilken zincire yazılır. Tek-tenant
// (tenant_id="") kurulumlarda bu, tenant alanı hiç olmayan eski (tenant-öncesi)
// hash biçimiyle BİREBİR aynı baytları üretir → mevcut denetim zincirleri migrasyon
// (ADD COLUMN DEFAULT ”) sonrası re-hash GEREKMEDEN doğrulanmaya devam eder.
// Çok-tenant satırlarda (tenant_id dolu) tenant zincire katılır → transplant koruması.
func AuditChainHash(prev []byte, tenantID, adminRef, action, targetType, targetID string, atUnixNano int64) []byte {
	h := sha256.New()
	h.Write(prev)
	if tenantID != "" {
		writeField(h, tenantID)
	}
	writeField(h, adminRef)
	writeField(h, action)
	writeField(h, targetType)
	writeField(h, targetID)
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], uint64(atUnixNano))
	h.Write(num[:])
	return h.Sum(nil)
}

func writeField(h interface{ Write([]byte) (int, error) }, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{unitSep})
}
