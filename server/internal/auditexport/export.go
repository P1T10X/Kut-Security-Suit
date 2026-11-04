// Package auditexport, denetim izinin (audit log) HARİCİ, taşınabilir ve
// KURCALAMA-KANITLI bir dışa aktarımını üretir ve doğrular.
//
// Amaç: Dahili denetim zinciri veritabanında tamper-evident tutulur;
// ancak uzun-süreli/bağımsız arşiv (WORM depolama, harici SIEM, denetçi) için
// izin C2'DEN BAĞIMSIZ doğrulanabilmesi gerekir. Bu paket her kaydı bir hash
// zincirine bağlar (bir kaydı değiştirmek sonraki tüm hash'leri bozar) ve
// opsiyonel olarak zincir başını (head) Ed25519 ile imzalar (köken kanıtı).
// Böylece dışa aktarılan dosya, C2 ele geçse bile off-box doğrulanabilir.
//
// Biçim: JSON Lines (JSONL). Her satır bir Record; imza varsa son satır bir
// Manifest'tir ({"manifest":true,...}). Zincir hash'i, dahili denetim ziniriyle
// AYNI fonksiyonu (security.AuditChainHash) kullanır — tutarlı ve yeniden
// hesaplanabilir.
package auditexport

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"kut.corp/suite/server/internal/security"
)

// Entry, dışa aktarılacak tek bir denetim kaydının ham alanlarıdır (depo-bağımsız).
type Entry struct {
	TenantID   string
	Admin      string
	Action     string
	TargetType string
	TargetID   string
	CreatedAt  time.Time
}

// Record, dışa aktarım satırıdır: kaydın alanları + zincir hash'leri (hex).
type Record struct {
	Seq        int64  `json:"seq"`
	TenantID   string `json:"tenant_id,omitempty"`
	Admin      string `json:"admin"`
	Action     string `json:"action"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	CreatedAt  int64  `json:"created_at_unixnano"`
	PrevHash   string `json:"prev_hash"`
	Hash       string `json:"hash"`
}

// Manifest, opsiyonel son satırdır: zincir başı (son hash) + Ed25519 imzası.
type Manifest struct {
	IsManifest bool   `json:"manifest"`
	Count      int64  `json:"count"`
	HeadHash   string `json:"head_hash"`
	Signature  string `json:"signature,omitempty"`  // base64; head_hash baytları üzerine
	PublicKey  string `json:"public_key,omitempty"` // base64; kolaylık için (güven ANKORU değil)
}

// hashFor, bir kaydın zincir hash'ini önceki hash'ten hesaplar (dahili zincirle
// aynı fonksiyon).
func hashFor(prev []byte, e Entry) []byte {
	return security.AuditChainHash(prev, e.TenantID, e.Admin, e.Action, e.TargetType, e.TargetID, e.CreatedAt.UnixNano())
}

// BuildChain, verilen kayıtları (KRONOLOJİK sırada olmalı) bir hash zincirine
// bağlar ve Record dilimini döner.
func BuildChain(entries []Entry) []Record {
	var prev []byte
	out := make([]Record, 0, len(entries))
	for i, e := range entries {
		h := hashFor(prev, e)
		out = append(out, Record{
			Seq: int64(i), TenantID: e.TenantID, Admin: e.Admin, Action: e.Action,
			TargetType: e.TargetType, TargetID: e.TargetID,
			CreatedAt: e.CreatedAt.UnixNano(),
			PrevHash:  hex.EncodeToString(prev), Hash: hex.EncodeToString(h),
		})
		prev = h
	}
	return out
}

// MarshalJSONL, kayıtları JSONL olarak serileştirir. priv verilirse (nil değil)
// son satıra imzalı bir Manifest eklenir.
func MarshalJSONL(records []Record, priv ed25519.PrivateKey) ([]byte, error) {
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		w.Write(b)
		w.WriteByte('\n')
	}
	var head string
	if n := len(records); n > 0 {
		head = records[n-1].Hash
	}
	if len(priv) == ed25519.PrivateKeySize {
		headBytes, _ := hex.DecodeString(head)
		m := Manifest{
			IsManifest: true, Count: int64(len(records)), HeadHash: head,
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, headBytes)),
			PublicKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		}
		b, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		w.Write(b)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Errors.
var (
	ErrEmpty     = errors.New("auditexport: boş dışa aktarım")
	ErrChain     = errors.New("auditexport: hash zinciri kırık (kurcalama)")
	ErrHeadMatch = errors.New("auditexport: manifest head_hash zincirle uyuşmuyor")
	ErrSignature = errors.New("auditexport: manifest imzası geçersiz")
)

// Verify, bir JSONL dışa aktarımını C2'DEN BAĞIMSIZ doğrular: her kaydın hash'ini
// yeniden hesaplayıp zincire bağlar; manifest varsa head + (pub verildiyse) imza
// kontrol edilir. pub nil ise imza doğrulaması atlanır (yalnız zincir bütünlüğü).
func Verify(data []byte, pub ed25519.PublicKey) error {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var prev []byte
	var count int64
	var manifest *Manifest
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		// Manifest satırı mı?
		if bytes.Contains(line, []byte(`"manifest"`)) {
			var m Manifest
			if err := json.Unmarshal(line, &m); err == nil && m.IsManifest {
				manifest = &m
				continue
			}
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return fmt.Errorf("auditexport: satır çözülemedi: %w", err)
		}
		// prev_hash beyan edileni zincirle karşılaştır.
		if r.PrevHash != hex.EncodeToString(prev) {
			return ErrChain
		}
		want := security.AuditChainHash(prev, r.TenantID, r.Admin, r.Action, r.TargetType, r.TargetID, r.CreatedAt)
		if r.Hash != hex.EncodeToString(want) {
			return ErrChain
		}
		prev = want
		count++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if count == 0 {
		return ErrEmpty
	}
	if manifest != nil {
		if manifest.HeadHash != hex.EncodeToString(prev) || manifest.Count != count {
			return ErrHeadMatch
		}
		if pub != nil {
			sig, err := base64.StdEncoding.DecodeString(manifest.Signature)
			if err != nil {
				return ErrSignature
			}
			if !ed25519.Verify(pub, prev, sig) {
				return ErrSignature
			}
		}
	}
	return nil
}
