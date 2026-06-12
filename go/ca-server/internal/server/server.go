// Package server implements the V4.0 HTTPS + mTLS API server.
package server

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cert-operator/ca-server/v2/internal/cert"
	"github.com/cert-operator/ca-server/v2/internal/config"
	"github.com/cert-operator/ca-server/v2/internal/ratelimit"
	"github.com/cert-operator/ca-server/v2/internal/rules"
	"github.com/cert-operator/ca-server/v2/internal/totp"
)

const Version = "4.0.0-dev"

type Server struct {
	ConfigPath string
	NoMTLS     bool

	// Paths for TLS material (set before Serve).
	HTTPSCertPath string
	HTTPSKeyPath  string
	ClientCertPath string // mTLS CA cert

	limiter *ratelimit.Limiter

	// TOTP replay protection
	totpMu    sync.Mutex
	usedTOTPs map[string]time.Time

	// Target watchers (long-polling)
	watcher *TargetWatcher
}

// ---- Serve ----------------------------------------------------------------

func (s *Server) Serve() error {
	s.limiter = ratelimit.New()
	s.usedTOTPs = make(map[string]time.Time)
	s.watcher = NewTargetWatcher()

	cfg, err := config.LoadRoot(s.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if !s.NoMTLS {
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		pool := x509.NewCertPool()
		mtlsCACert, err := os.ReadFile(s.ClientCertPath)
		if err != nil {
			return fmt.Errorf("read mTLS CA cert: %w", err)
		}
		if !pool.AppendCertsFromPEM(mtlsCACert) {
			return fmt.Errorf("parse mTLS CA cert")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no client certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse client cert: %w", err)
			}
			// Check against clients.json
			ok, cErr := checkClientRevocation(s.ConfigPath, cert.SerialNumber)
			if cErr != nil {
				return fmt.Errorf("revocation check: %w", cErr)
			}
			if !ok {
				return fmt.Errorf("client certificate revoked / expired (serial %d)", cert.SerialNumber)
			}
			return nil
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/get-cert", s.handleGetCert)
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/version", s.handleVersion)
	mux.HandleFunc("/api/v1/targets", s.handleTargets)
	mux.HandleFunc("/api/v1/schedule/", s.handleSchedule)
	mux.HandleFunc("/api/v1/", s.handleNotFound)

	srv := &http.Server{
		Addr:      fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	log.Printf("🚀 cert-operator v%s — serving on https://%s:%d", Version, cfg.Server.Host, cfg.Server.Port)
	if !s.NoMTLS {
		log.Println("   mTLS enabled (client cert required)")
	}

	return srv.ListenAndServeTLS(s.HTTPSCertPath, s.HTTPSKeyPath)
}

// ---- handlers -------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"version":  Version,
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version": Version,
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "not found"})
}

// ---- get-cert handler -----------------------------------------------------

type getCertRequest struct {
	TOTP     string `json:"totp"`
	Target   string `json:"target"`
	Group    string `json:"group"`
	User     string `json:"user"`
	ClientCN string `json:"-"` // extracted from mTLS cert
}

func (s *Server) handleGetCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}

	cfg, err := config.LoadRoot(s.ConfigPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "load config"})
		return
	}

	var body getCertRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON"})
		return
	}
	body.ClientCN = clientCertCN(r)

	if body.Target == "" {
		body.Target = "default"
	}
	if body.Group == "" {
		body.Group = "default"
	}

	// Check issue rules for this client+time
	now := time.Now().UTC()
	result, err := rules.CheckIssue(cfg.DataDir(), body.Target, body.Group, body.ClientCN, now)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}

	if result == nil || result.Mode == "" || result.Deny {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "当前时段无可用规则或已被禁止签发证书",
		})
		return
	}

	totpCode := strings.TrimSpace(body.TOTP)
	passwordlessMode := false

	switch result.Mode {
	case rules.ModePasswordless:
		passwordlessMode = true
	case rules.ModeTOTP:
		if totpCode == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"error":   "当前时段需要 TOTP 验证码",
			})
			return
		}
	default:
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   "当前时段禁止签发",
		})
		return
	}

	// Rate limit
	clientAddr := r.RemoteAddr
	if idx := strings.LastIndex(clientAddr, ":"); idx > 0 {
		clientAddr = clientAddr[:idx]
	}
	if !s.limiter.Check(clientAddr, 5, 300*time.Second) {
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{"error": "请求过于频繁"})
		return
	}

	// TOTP verification + replay protection (skipped in passwordless mode)
	if !passwordlessMode {
		if !isDigits(totpCode) || len(totpCode) != 6 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "TOTP 码格式错误"})
			return
		}
		gcfg, gErr := config.LoadGroupConfig(cfg.DataDir(), body.Target, body.Group)
		if gErr != nil || gcfg.TOTPSecret == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"error": "组 TOTP secret 未配置",
			})
			return
		}
		if !totp.Verify(gcfg.TOTPSecret, totpCode, 1) {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"success": false,
				"error":   "TOTP 验证失败",
			})
			return
		}
		// TOTP replay protection: sha256(secret|code) + step-indexed key
		replayHash := sha256hex(gcfg.TOTPSecret + "|" + totpCode)
		replayStep := time.Now().Unix() / 30
		s.totpMu.Lock()
		replayKey := replayHash + ":" + strconv.FormatInt(replayStep, 10)
		if _, exists := s.usedTOTPs[replayKey]; exists {
			s.totpMu.Unlock()
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"success": false,
				"error":   "TOTP 码已被使用，请等待新码",
			})
			return
		}
		s.usedTOTPs[replayKey] = time.Now().Add(90 * time.Second)
		s.totpMu.Unlock()
	}

	// Issue SSH cert
	targetDir := filepath.Join(cfg.DataDir(), "targets", body.Target)
	groupDir := filepath.Join(targetDir, "groups", body.Group)
	caKey := filepath.Join(groupDir, "ca_key")
	serialFile := filepath.Join(groupDir, "serial.txt")

	allowedUsers := body.User
	if allowedUsers == "" {
		allowedUsers = os.Getenv("USER")
		if allowedUsers == "" {
			allowedUsers = "root"
		}
	}

	// Check judge rules for sudo permission
	sudoAllowed, jErr := rules.CheckJudge(cfg.DataDir(), body.Target, body.Group, body.ClientCN, now)
	if jErr != nil {
		log.Printf("judge check error: %v", jErr)
	}
	extensions := make(map[string]string)
	if sudoAllowed {
		extensions["sudo"] = "true"
	}

	validity := fmt.Sprintf("+%dm", cfg.Defaults.ValidityMinutes)
	signer := cert.NewSigner(caKey, "ed25519", serialFile)

	privateKey, certPEM, serial, err := signer.SignWithValidity(allowedUsers, validity, extensions)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": fmt.Sprintf("签发失败: %v", err),
		})
		return
	}

	expiresAt := time.Now().UTC().Add(time.Duration(cfg.Defaults.ValidityMinutes) * time.Minute).Format(time.RFC3339)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"ssh_private_key": privateKey,
		"ssh_cert":        certPEM,
		"serial":          serial,
		"expires_at":      expiresAt,
		"mode":            string(result.Mode),
		"rule_id":         result.RuleID,
	})
}

// ---- helpers --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func clientCertCN(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return ""
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ---- mTLS revocation check -----------------------------------------------

// checkClientRevocation reads clients.json and checks if the given serial
// is present and not frozen/expired.
func checkClientRevocation(configPath string, serial *big.Int) (bool, error) {
	dataDir := filepath.Join(filepath.Dir(configPath), "data")
	cPath := filepath.Join(dataDir, "mtls", "clients.json")
	data, err := os.ReadFile(cPath)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil // No clients.json → legacy mode, allow all
		}
		return false, err
	}
	var db struct {
		Clients map[string]struct {
			Serial    int64  `json:"serial"`
			ExpiresAt string `json:"expires_at"`
			Frozen    bool   `json:"frozen"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(data, &db); err != nil {
		return false, fmt.Errorf("parse clients.json: %w", err)
	}
	for _, r := range db.Clients {
		if r.Serial == serial.Int64() {
			if r.Frozen {
				return false, nil
			}
			expires, eErr := time.Parse(time.RFC3339, r.ExpiresAt)
			if eErr != nil || time.Now().UTC().After(expires) {
				return false, nil
			}
			return true, nil
		}
	}
	return false, nil
}

// ---- TargetWatcher (long-polling) ----------------------------------------

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

type TargetWatcher struct {
	mu      sync.Mutex
	chs     map[string][]chan struct{}
	versions map[string]int
}

func NewTargetWatcher() *TargetWatcher {
	return &TargetWatcher{
		chs:      make(map[string][]chan struct{}),
		versions: make(map[string]int),
	}
}

func (tw *TargetWatcher) Notify(target string) {
	tw.mu.Lock()
	tw.versions[target]++
	for _, ch := range tw.chs[target] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	tw.mu.Unlock()
}

func (tw *TargetWatcher) Register(target string) chan struct{} {
	ch := make(chan struct{}, 1)
	tw.mu.Lock()
	tw.chs[target] = append(tw.chs[target], ch)
	tw.mu.Unlock()
	return ch
}

func (tw *TargetWatcher) Unregister(target string, ch chan struct{}) {
	tw.mu.Lock()
	var updated []chan struct{}
	for _, c := range tw.chs[target] {
		if c != ch {
			updated = append(updated, c)
		}
	}
	tw.chs[target] = updated
	close(ch)
	tw.mu.Unlock()
}

// ---- targets handler ------------------------------------------------------

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error":"method not allowed"})
		return
	}
	cfg, err := config.LoadRoot(s.ConfigPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error":"load config"})
		return
	}
	dir := filepath.Join(cfg.DataDir(), "targets")
	entries, _ := os.ReadDir(dir)
	var targets []string
	for _, e := range entries {
		if e.IsDir() { targets = append(targets, e.Name()) }
	}
	if targets == nil { targets = []string{} }
	writeJSON(w, http.StatusOK, map[string]interface{}{"targets": targets})
}

// ---- schedule handler ----------------------------------------------------

func (s *Server) handleSchedule(w http.ResponseWriter, r *http.Request) {
	cfg, _ := config.LoadRoot(s.ConfigPath)
	clientCN := clientCertCN(r)

	switch {
	case r.URL.Path == "/api/v1/schedule/request":
		if r.Method == http.MethodPost {
			var body struct {
				Target    string     `json:"target"`
				Group     string     `json:"group"`
				GrantedTo string     `json:"granted_to"`
				Rule      rules.Rule `json:"rule"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.Target == "" { body.Target = "default" }
			if body.Group == ""  { body.Group = "default" }
			if body.GrantedTo == "" && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				if ou := r.TLS.PeerCertificates[0].Subject.OrganizationalUnit; len(ou) > 0 {
					body.GrantedTo = ou[0]
				}
			}
			if err := rules.ValidateRule(body.Rule); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error":err.Error()})
				return
			}
			if err := rules.SubmitRequest(cfg.DataDir(), body.Target, body.Group, clientCN, body.GrantedTo, body.Rule); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error":err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"success":true,"message":"已提交"})
		} else { writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{}) }

	case r.URL.Path == "/api/v1/schedule/requests":
		if r.Method == http.MethodGet {
			reqs, err := rules.GetAllRequests(cfg.DataDir(), "", "", clientCN)
			if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error":err.Error()}); return }
			if reqs == nil { reqs = []rules.ScheduleRequest{} }
			writeJSON(w, http.StatusOK, map[string]interface{}{"requests":reqs})
		} else { writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{}) }

	case r.URL.Path == "/api/v1/schedule/replace":
		if r.Method == http.MethodPut {
			var body struct {
				Target    string     `json:"target"`
				Group     string     `json:"group"`
				GrantedTo string     `json:"granted_to"`
				Rule      rules.Rule `json:"rule"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.Target == "" { body.Target = "default" }
			if body.Group == ""  { body.Group = "default" }
			grantedTo := body.GrantedTo
			if grantedTo == "" && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				if ou := r.TLS.PeerCertificates[0].Subject.OrganizationalUnit; len(ou) > 0 {
					grantedTo = ou[0]
				}
			}
			if err := rules.ValidateRule(body.Rule); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error":err.Error()}); return
			}
			if err := rules.SubmitRequest(cfg.DataDir(), body.Target, body.Group, clientCN, grantedTo, body.Rule); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error":err.Error()}); return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"success":true,"message":"已覆盖"})
		} else { writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{}) }

	case r.URL.Path == "/api/v1/schedule/approved":
		sBody := struct {
			Target string `json:"target"`
			Group  string `json:"group"`
		}{"default", "default"}
		if r.Method == http.MethodGet || r.Method == http.MethodDelete {
			json.NewDecoder(r.Body).Decode(&sBody)
			if sBody.Target == "" { sBody.Target = "default" }
			if sBody.Group == ""  { sBody.Group = "default" }
		}
		switch r.Method {
		case http.MethodGet:
			cs, _ := rules.GetApprovedRules(cfg.DataDir(), sBody.Target, sBody.Group, clientCN)
			if cs == nil {
				writeJSON(w, http.StatusOK, map[string]interface{}{"rules":nil})
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"rules":cs})
		case http.MethodDelete:
			rules.RevokeApproved(cfg.DataDir(), sBody.Target, sBody.Group, clientCN)
			writeJSON(w, http.StatusOK, map[string]interface{}{"success":true})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{})
		}

	default:
		writeJSON(w, http.StatusNotFound, map[string]interface{}{})
	}
}
