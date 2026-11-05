// Command watchdog, ajanı canlı tutan gözetmen süreçtir.
//
// Sorumluluk: ajanı bir alt süreç olarak çalıştırır, çökerse backoff'lu yeniden
// başlatır ve OTA staged güncellemesini (update.Prepare'in staging'e yazdığı)
// çalıştırmalar arasında swap eder; yeni sürüm deneme penceresinde çökerse
// rollback eder.
//
// NOT: Bu, kaza sonucu sonlanmalara karşı ilk savunmadır; SYSTEM
// yetkili müdahaleye karşı gerçek koruma ayrı bir katmandır (sürücü + PPL/ELAM).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"kut.corp/suite/agent/internal/liveness"
	"kut.corp/suite/agent/internal/standdown"
	"kut.corp/suite/agent/internal/update"
	"kut.corp/suite/agent/internal/watchdog"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[watchdog] ")

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	agentBin := getenv("KUT_AGENT_BIN", defaultAgentBin())
	dataDir := getenv("KUT_AGENT_DATA", "./agent-data")
	stageDir := filepath.Join(dataDir, "updates")

	// Kendi canlılık beacon'unu yaz (ajanın PeerGuard'ı bunu izler; watchdog
	// ölürse ajan onu yeniden başlatır — karşılıklı gözetim).
	wdBeacon := liveness.NewBeacon(filepath.Join(dataDir, "watchdog.beacon"))
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			_ = wdBeacon.Write(time.Now())
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	runner := watchdog.NewExecRunner(agentBin)
	swapper := watchdog.NewFileSwapper(agentBin, stageDir)
	// OTA imza anahtarı yapılandırılmışsa, swap-anı YENİDEN doğrulama kancasını kur: staged
	// ikili, swap'tan hemen önce imza + SHA-256 ile yeniden doğrulanır (ayrı SYSTEM
	// süreci kurcalanmış/forge bir ikiliyi çalıştırmaz). KUT_UPDATE_PUBKEY ajanla aynı env.
	if raw := strings.TrimSpace(os.Getenv("KUT_UPDATE_PUBKEY")); raw != "" {
		var pubs []ed25519.PublicKey
		for _, k := range strings.Split(raw, ",") {
			if k = strings.TrimSpace(k); k == "" {
				continue
			}
			if b, err := base64.StdEncoding.DecodeString(k); err == nil && len(b) == ed25519.PublicKeySize {
				pubs = append(pubs, ed25519.PublicKey(b))
			}
		}
		if v, err := update.NewVerifierMulti(pubs...); err == nil {
			swapper.SetVerify(func(stagedPath string) error { return update.VerifyStaged(stagedPath, v) })
			log.Println("OTA swap-anı yeniden-doğrulama ETKİN (imza + SHA-256)")
		} else {
			log.Printf("OTA public key ayrıştırılamadı, swap-anı yeniden-doğrulama DEVRE DIŞI: %v", err)
		}
	}
	sup := watchdog.NewSupervisor(runner, swapper, watchdog.Options{
		BaseBackoff: time.Second,
		MaxBackoff:  30 * time.Second,
		TrialWindow: 15 * time.Second,
		// İmzalı çevrimdışı offboard: ajan geçerli jetonu doğrulayıp stand-down
		// işaretini bıraktıysa gözetimi bırak (yeniden başlatma).
		StandDown: func() bool { return standdown.Exists(dataDir) },
		Log:       func(m string) { log.Println(m) },
	})

	log.Printf("ajan gözetleniyor: %s", agentBin)
	if err := sup.Run(ctx); err != nil && err != context.Canceled {
		log.Printf("gözetim durdu: %v", err)
	}
	log.Println("watchdog kapandı.")
}

func defaultAgentBin() string {
	if runtime.GOOS == "windows" {
		return "./agent.exe"
	}
	return "./agent"
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
