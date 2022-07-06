package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	listen                = flag.String("l", ":8080", "listen address")
	metricsListen         = flag.String("m", ":8081", "listen address")
	tokenValidityDuration = flag.Int("t", 60, "token validity duration in minutes")
	tokenValidationWait   = flag.Int("w", 60, "how long to wait for a token to be validated before deleting it in seconds")
	verbose               = flag.Bool("v", false, "enable verbose logging")
)

var (
	metricIssuedTokens = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "httpgate_issued_tokens",
		Help: "Issued HTTPGate tokens",
	})
	metricValidatedTokens = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "httpgate_validated_tokens",
		Help: "Validated HTTPGate tokens",
	})
)

type cacheEntry struct {
	created   time.Time // Time of creation
	validated bool      // Has this hash been validated by a client?
}

var cache = make(map[string]*cacheEntry) // server hash to expiration timestamp

const hexLetters = "0123456789abcdef"

// randomString returns a securely generated random string of specified length
func randomString(length int) (string, error) {
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(hexLetters))))
		if err != nil {
			return "", err
		}
		ret[i] = hexLetters[num.Int64()]
	}

	return string(ret), nil
}

// validate checks that a client provided token matches the given server hash
func validate(token, hash string) bool {
	entry, found := cache[hash]
	if !found {
		return false
	}
	entry.validated = true

	// Check if server hash is expired
	if time.Now().After(entry.created.Add(time.Duration(*tokenValidityDuration) * time.Minute)) {
		log.Debugf("Server hash %s expired, removing from cache", hash)
		delete(cache, hash)
		return false
	}

	return strings.HasSuffix(sha256hash(hash+token), "000")
}

func sha256hash(s string) string {
	fullHash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(fullHash[:])
}

func main() {
	flag.Parse()
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	// Purge cache of unvalidated entries
	purgeTicker := time.NewTicker(time.Second * time.Duration(*tokenValidationWait/2))
	go func() {
		for range purgeTicker.C {
			for hash, entry := range cache {
				if !entry.validated && time.Now().After(entry.created.Add(time.Duration(*tokenValidationWait)*time.Second)) {
					log.Debugf("Purging expired server hash %s", hash)
					delete(cache, hash)
				}
			}
		}
	}()

	metricUpdateTicker := time.NewTicker(1 * time.Second)
	go func() {
		for range metricUpdateTicker.C {
			metricIssuedTokens.Set(float64(len(cache)))
			validated := 0
			for _, token := range cache {
				if token.validated {
					validated++
				}
			}
			metricValidatedTokens.Set(float64(validated))
		}
	}()

	// /validate?hash=<hash>&token=<token> to validate a token
	http.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")
		token := r.URL.Query().Get("token")

		w.Header().Set("Content-Type", "text/plain")
		if validate(token, hash) {
			log.Debugf("Valid token %s for hash %s", token, hash)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		} else {
			log.Debugf("Invalid token %s for hash %s", token, hash)
			w.WriteHeader(http.StatusUnauthorized)
		}
	})

	// /new to request a new token
	http.HandleFunc("/new", func(w http.ResponseWriter, r *http.Request) {
		newHash, err := randomString(32)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Error"))
			return
		}
		cache[newHash] = &cacheEntry{
			created:   time.Now(),
			validated: false,
		}
		log.Debugf("Generated new hash %s", newHash)
		_, _ = w.Write([]byte(newHash))
	})

	http.HandleFunc("/invalidate", func(w http.ResponseWriter, r *http.Request) {
		log.Debug("Invalidating all hashes")
		cache = make(map[string]*cacheEntry)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Metrics server
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	log.Infof("Starting metrics exporter on http://%s/metrics", *metricsListen)
	go func() {
		log.Fatal(http.ListenAndServe(*metricsListen, metricsMux))
	}()

	log.Printf("Starting httpgate token broker on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
