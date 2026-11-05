# ONNX Model Entegrasyonu

# ONNX Model Integration

**Türkçe** · [English](#english)

KUT anomali motoru, çevrimdışı eğitilmiş küçük bir ileri-beslemeli ağı (MLP/lojistik)
**saf-Go** ile çalıştırır (`agent/internal/anomaly`). Bu belge, harici bir **ONNX**
modelinin bu motora nasıl taşınacağını ve gerçek `onnxruntime`'ın neden **varsayılan
olarak kapsam dışı** tutulduğunu açıklar.

## Neden doğrudan onnxruntime değil?

`onnxruntime` Go bağlaması (ör. `github.com/yalue/onnxruntime_go`) **CGo** gerektirir
ve platform başına yerel bir paylaşımlı kütüphane (`onnxruntime.{so,dll,dylib}`) ister.
Bu, projenin temel kısıtlarını bozar:

- **`CGO_ENABLED=0` cross-compile** (windows/linux/darwin) — sürüm derlemesi bununla yapılır.
- **Saf-Go CI** — yerelde gcc yok; CGo tüm derlemeyi/CI'ı kırar.
- **SBOM/govulncheck yüzeyi** — çalışan ikiliye asla girmeyecek ağır bir bağımlılık eklenir.

Bu nedenle varsayılan yol **çevrimdışı dönüştürme**dir (aşağıda). Gerçek onnxruntime,
yalnız *keyfi* ONNX grafikleri gerektiğinde, **opt-in** derleme etiketi arkasında eklenir
(bkz. "İleri: gerçek onnxruntime").

## Önerilen yol: çevrimdışı ONNX → JSON dönüştürme (`tools/onnx2json`)

Eğitilmiş modeli (sıralı MLP: `Gemm`/`MatMul` + `Relu`/`Sigmoid`) motorun taşınabilir
JSON ağırlık formatına çevirin. Çalışan ikiliye, `go.mod`'a, CGo duruşuna ya da CI'a
**hiçbir etkisi yoktur** — dönüştürme tamamen çevrimdışıdır.

```bash
# 1) Modeli çevir + imzala (öznitelik ölçekleme eğitimden gelir; -sign-key ile
#    <out>.sig fail-closed Ed25519 imzası yazılır — imzasız model YÜKLENMEZ).
go run ./tools/onnx2json -in model.onnx -out anomaly-model.json \
    -mean 0,12,0,3 -std 1,6,4,2 -sign-key ./anomaly-keys/priv
#    → anomaly-model.json + anomaly-model.json.sig üretir
#    (anahtar çifti: go run ./tools/anomalytrain -genkey -out ./anomaly-keys/priv)

# 2) Ajana ver
export KUT_ANOMALY_MODEL=/path/anomaly-model.json
export KUT_ANOMALY_PUBKEY=<base64-ed25519-pub>
```

Öznitelik vektörü sabit 4 boyutludur: `[novelty, hour, connections, pathDepth]`
(`agent/internal/anomaly/detector.go`). Modeliniz bu 4 özniteliği girdi almalı ve **tek**
bir anomali skoru (`[0,1]`) üretmelidir. Desteklenen op'lar: `Gemm` (transB dahil),
`MatMul`, `Relu`, `Sigmoid`; desteklenmeyen op → **gürültülü hata** (sessiz yanlış model
üretilmez).

## İleri: gerçek onnxruntime (opt-in, varsayılan derlemede YOK)

Keyfi ONNX grafikleri için, `Scorer` arayüzü (`Score(Features) float64`) arkasına derleme
etiketiyle ayrılmış bir backend eklenebilir — **varsayılan derlemeyi saf-Go tutarak**:

- `agent/internal/anomaly/onnx_stub.go` (`//go:build !onnx`): `NewONNXScorer(...)` "ONNX
  bu derlemede yok" hatası döndürür (dış bağımlılık yok → varsayılan derleme saf-Go).
- `agent/internal/anomaly/onnx_backend.go` (`//go:build onnx`): `onnxruntime_go` import
  eder, aynı imzayı uygular ve **yüklemeden önce Ed25519 imzasını doğrular**
  (fail-closed korunur).

Kurallar: CGo import'u YALNIZ `//go:build onnx` dosyasında olmalı; `-tags onnx` ne
`go test ./...`'e ne de sürüm scriptine eklenmeli; ayrı, cross-compile edilmeyen bir CI
şeridinde (gcc + onnxruntime kurulu) `go build -tags onnx ./...` çalıştırılmalı. Risk:
ORTA-YÜKSEK (yerel kütüphane dağıtımı) — yalnız gerçek ihtiyaç halinde.

---

<a name="english"></a>

# ONNX Model Integration (English)

The KUT anomaly engine runs a small offline-trained feed-forward network (MLP/logistic)
in **pure Go** (`agent/internal/anomaly`). This document explains how to bring an external
**ONNX** model into that engine and why real `onnxruntime` is **out of scope by default**.

## Why not onnxruntime directly?

The `onnxruntime` Go binding requires **CGo** and a per-platform native shared library,
which breaks the project's core constraints: `CGO_ENABLED=0` cross-compile (the release
build), the pure-Go CI (no local gcc), and the SBOM/govulncheck surface (a heavy dependency
that never ships in the binary). So the default path is **offline conversion**; real
onnxruntime is added only when *arbitrary* ONNX graphs are required, behind an **opt-in**
build tag.

## Recommended: offline ONNX → JSON conversion (`tools/onnx2json`)

Convert the trained model (sequential MLP: `Gemm`/`MatMul` + `Relu`/`Sigmoid`) to the
engine's portable JSON weight format — **zero** impact on the shipped binary, `go.mod`, CGo
posture, or CI.

```bash
# convert + sign (fail-closed Ed25519; unsigned models are refused)
go run ./tools/onnx2json -in model.onnx -out anomaly-model.json \
    -mean 0,12,0,3 -std 1,6,4,2 -sign-key ./anomaly-keys/priv
export KUT_ANOMALY_MODEL=/path/anomaly-model.json
export KUT_ANOMALY_PUBKEY=<base64-ed25519-pub>
```

The feature vector is fixed at 4 dims — `[novelty, hour, connections, pathDepth]` — and the
model must produce a single `[0,1]` anomaly score. Supported ops: `Gemm` (incl. transB),
`MatMul`, `Relu`, `Sigmoid`; unsupported ops fail loudly (never a silently-wrong model).

## Advanced: real onnxruntime (opt-in, NOT in the default build)

For arbitrary ONNX graphs, add a build-tag-split backend behind the `Scorer` interface
(`Score(Features) float64`), keeping the default build pure-Go: an `//go:build !onnx` stub
(`NewONNXScorer` returns "not compiled in", no external dep) plus an `//go:build onnx` file
importing `onnxruntime_go` that **verifies the Ed25519 signature before loading** (preserves
the fail-closed rule). The CGo import must live only in the tagged file; never add
`-tags onnx` to `go test ./...` or the release script; build the tagged artifact in a
separate, non-cross-compiled CI lane. Risk: MEDIUM-HIGH (native library distribution) —
only when genuinely needed.
