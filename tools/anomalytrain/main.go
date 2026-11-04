// Command anomalytrain, etiketli öznitelik verisinden (CSV) ajan için bir
// lojistik anomali modeli eğitir ve anomaly.ModelScorer'ın yüklediği JSON
// formatına yazar. Böylece "eğit → JSON → ajan (KUT_ANOMALY_MODEL)" hattı
// tamamlanır.
//
// CSV: her satır  f1,f2,...,fn,label   (label 0=normal, 1=anomali). İlk satır
// sayısal değilse başlık kabul edilip atlanır.
//
// Örnek:
//
//	anomalytrain -in samples.csv -out model.json -epochs 500 -lr 0.5
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
)

func main() {
	in := flag.String("in", "", "etiketli CSV girdisi (f1..fn,label)")
	out := flag.String("out", "model.json", "çıktı model JSON yolu")
	epochs := flag.Int("epochs", 500, "eğitim epoch sayısı")
	lr := flag.Float64("lr", 0.5, "öğrenme oranı")
	signKey := flag.String("sign-key", "", "Ed25519 özel anahtar dosyası (base64) — verilirse <out>.sig imzası yazılır")
	genkey := flag.Bool("genkey", false, "yeni Ed25519 anahtar çifti üret (-out özel anahtar dosyası), public key'i bas")
	flag.Parse()

	if *genkey {
		doGenkey(*out)
		return
	}
	if *in == "" {
		fmt.Fprintln(os.Stderr, "anomalytrain: -in zorunlu (veya -genkey)")
		os.Exit(1)
	}
	samples, err := readCSV(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anomalytrain: %v\n", err)
		os.Exit(1)
	}
	if len(samples) == 0 {
		fmt.Fprintln(os.Stderr, "anomalytrain: örnek yok")
		os.Exit(1)
	}

	mean, std, w, b := trainLogistic(samples, *epochs, *lr)
	acc := accuracy(samples, mean, std, w, b)
	model := buildModel(mean, std, w, b)

	data, _ := json.MarshalIndent(model, "", "  ")
	data = append(data, '\n')
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "anomalytrain: yazma: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("model yazıldı: %s (%d örnek, %d öznitelik, eğitim doğruluğu %.1f%%)\n",
		*out, len(samples), len(samples[0].features), acc*100)

	// İmzalama: ajan yalnız imzalı modeli yükler.
	if *signKey != "" {
		if err := signModel(*out, data, *signKey); err != nil {
			fmt.Fprintf(os.Stderr, "anomalytrain: imzalama: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("imza yazıldı: %s.sig (ajanda KUT_ANOMALY_PUBKEY ile doğrulanır)\n", *out)
	}
}

// doGenkey, otasign ile aynı formatta bir Ed25519 anahtar çifti üretir: özel
// anahtar (64 bayt seed+pub) base64 olarak dosyaya (0600), public key stdout'a.
func doGenkey(keyPath string) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anomalytrain: anahtar üretimi: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "anomalytrain: özel anahtar yazma: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("özel anahtar: %s (gizli tut)\n", keyPath)
	fmt.Printf("Ajanlara verilecek public key:\n  KUT_ANOMALY_PUBKEY=%s\n", base64.StdEncoding.EncodeToString(pub))
}

// signModel, model baytlarını Ed25519 ile imzalar ve <out>.sig'e base64 yazar.
func signModel(out string, data []byte, keyPath string) error {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("özel anahtar okunamadı: %w", err)
	}
	priv, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return fmt.Errorf("özel anahtar base64 çözülemedi: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("özel anahtar boyutu %d, beklenen %d", len(priv), ed25519.PrivateKeySize)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), data)
	return os.WriteFile(out+".sig", []byte(base64.StdEncoding.EncodeToString(sig)), 0o644)
}

// readCSV, CSV'yi örneklere çevirir. Son sütun etikettir. Başlık (ilk satır
// sayısal değilse) atlanır.
func readCSV(path string) ([]sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	var samples []sample
	for i, row := range rows {
		if len(row) < 2 {
			continue
		}
		if i == 0 {
			if _, err := strconv.ParseFloat(row[0], 64); err != nil {
				continue // başlık satırı
			}
		}
		vals := make([]float64, len(row))
		ok := true
		for j, c := range row {
			v, err := strconv.ParseFloat(c, 64)
			if err != nil {
				ok = false
				break
			}
			vals[j] = v
		}
		if !ok {
			continue
		}
		samples = append(samples, sample{features: vals[:len(vals)-1], label: vals[len(vals)-1]})
	}
	return samples, nil
}
