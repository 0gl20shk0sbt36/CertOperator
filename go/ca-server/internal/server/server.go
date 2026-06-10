// Package server provides the HTTPS + mTLS API server for cert-operator v2.
//
// Routes:
//
//	POST /api/get-cert   — TOTP + group auth, returns signed SSH cert
//	GET  /api/health     — {"status":"ok","ca_ready":bool}
//	GET  /api/info       — group info (?level=basic|full)
//	GET  /api/version    — {"version":"2.0.0","name":"cert-operator"}
//
// mTLS is enabled by default (CERT_REQUIRED); pass --no-mtls to disable.
// Rate limiting is checked before TOTP verification.
// Configuration is reloaded from config.yaml on every request.
package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cert-operator/ca-server/v2/internal/cert"
	"github.com/cert-operator/ca-server/v2/internal/config"
	"github.com/cert-operator/ca-server/v2/internal/ratelimit"
	"github.com/cert-operator/ca-server/v2/internal/totp"
)

const (
	// Version embedded at build time; overridden by ldflags or main.go's VERSION.
	BuiltVersion = "3.0.0"
	name         = "cert-operator"
)

// Version returns the server version string.
func Version() string { return BuiltVersion }

// Server is the HTTPS + mTLS API server.
type Server struct {
	ConfigPath string
	NoMTLS     bool

	// Paths for TLS material (set before Serve).
	CAKeyPath     string
	CAKeyPubPath  string
	HTTPSCertPath string
	HTTPSKeyPath  string
	ClientCertPath string

	limiter *ratelimit.Limiter
}

// Serve starts the HTTPS server and blocks until the server exits.
func (s *Server) Serve() error {
	cfg, err := config.Load(s.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	s.limiter = ratelimit.New()

	// Background cleanup of stale rate-limit entries every 5 minutes.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.limiter.Clean(10 * time.Minute)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/get-cert", s.handleGetCert)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/info", s.handleInfo)
	mux.HandleFunc("/api/version", s.handleVersion)

	host := cfg.Server.Host
	if host == "" {
		host = "0.0.0.0"
	}
	port := cfg.Server.Port
	if port == 0 {
		port = 8443
	}
	addr := fmt.Sprintf("%s:%d", host, port)

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if !s.NoMTLS {
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		pool := x509.NewCertPool()
		clientCert, err := os.ReadFile(s.ClientCertPath)
		if err != nil {
			return fmt.Errorf("failed to read client CA cert: %w", err)
		}
		if !pool.AppendCertsFromPEM(clientCert) {
			return fmt.Errorf("failed to parse client CA cert")
		}
		tlsCfg.ClientCAs = pool
	}

	srv := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	rl := cfg.RateLimit
	log.Printf("cert-operator v%s — serving on https://%s", Version(), addr)
	log.Printf("  CA ready: %v", s.caReady())
	log.Printf("  rate limit: %d/%ds", rl.MaxAttempts, rl.WindowSeconds)
	if s.NoMTLS {
		log.Printf("  mTLS: disabled")
	} else {
		log.Printf("  mTLS: enabled")
	}

	return srv.ListenAndServeTLS(s.HTTPSCertPath, s.HTTPSKeyPath)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) handleGetCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{
			"success": false,
			"error":   "method not allowed",
		})
		return
	}

	cfg, err := config.Load(s.ConfigPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   "failed to load configuration",
		})
		return
	}

	// Parse body
	var body struct {
		TOTP  string `json:"totp"`
		Group string `json:"group"`
		User  string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "invalid JSON body",
		})
		return
	}

	totpCode := strings.TrimSpace(body.TOTP)
	if totpCode == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "缺少 totp 字段",
		})
		return
	}
	groupName := strings.TrimSpace(body.Group)
	reqUser := strings.TrimSpace(body.User)

	// Resolve group config
	gcfg := cfg.ResolveGroup(groupName)
	if gcfg == nil {
		name := groupName
		if name == "" {
			name = "default"
		}
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("组不存在: %s", name),
		})
		return
	}

	// Check frozen
	if gcfg.IsFrozen() {
		name := groupName
		if name == "" {
			name = "default"
		}
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("组 %s 已被冻结", name),
		})
		return
	}

	// Check allowed_users
	if strings.TrimSpace(gcfg.AllowedUsers) == "" {
		hint := "users add"
		if groupName != "" {
			hint = fmt.Sprintf("groups users %s add", groupName)
		}
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("未配置允许用户，请运行 %s", hint),
		})
		return
	}

	// User match
	allowedUsers := gcfg.AllowedUsers
	if reqUser != "" {
		userList := splitUsers(gcfg.AllowedUsers)
		found := false
		for _, u := range userList {
			if u == reqUser {
				found = true
				break
			}
		}
		if !found {
			writeJSON(w, http.StatusForbidden, map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("用户 %s 不在允许列表中", reqUser),
			})
			return
		}
		allowedUsers = reqUser
	}

	// Check TOTP secret
	if gcfg.TOTPSecret == "" {
		hint := "totp"
		if groupName != "" {
			hint = fmt.Sprintf("groups totp %s set", groupName)
		}
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("未配置 TOTP，请运行 %s", hint),
		})
		return
	}

	// Rate limit
	clientAddr := r.RemoteAddr
	if idx := strings.LastIndex(clientAddr, ":"); idx != -1 {
		clientAddr = clientAddr[:idx]
	}
	rl := cfg.RateLimit
	maxAttempts := rl.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	windowSec := rl.WindowSeconds
	if windowSec <= 0 {
		windowSec = 300
	}
	if !s.limiter.Check(clientAddr, maxAttempts, time.Duration(windowSec)*time.Second) {
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"success": false,
			"error":   "请求过于频繁，请等待后重试",
		})
		return
	}

	// TOTP format check
	if !isDigits(totpCode) || len(totpCode) != 6 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   "TOTP 码格式错误",
		})
		return
	}

	// Verify TOTP
	if !totp.Verify(gcfg.TOTPSecret, totpCode, 1) {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"error":   "TOTP 验证失败",
		})
		return
	}

	// Issue cert
	validityMinutes := gcfg.ValidityMinutes
	if validityMinutes <= 0 {
		validityMinutes = cfg.CA.ValidityMinutes
		if validityMinutes <= 0 {
			validityMinutes = 60
		}
	}
	keyType := cfg.CA.KeyType
	if keyType == "" {
		keyType = "ed25519"
	}

	extensions := gcfg.Extensions
	if extensions == nil {
		extensions = map[string]string{}
	}

	result, err := s.issueCert(keyType, allowedUsers, validityMinutes, extensions)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("签发失败：%v", err),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"ssh_private_key": result["ssh_private_key"],
		"ssh_cert":       result["ssh_cert"],
		"serial":         result["serial"],
		"expires_at":     result["expires_at"],
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{
			"error": "method not allowed",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"ca_ready": s.caReady(),
	})
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{
			"error": "method not allowed",
		})
		return
	}

	cfg, err := config.Load(s.ConfigPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "failed to load configuration",
		})
		return
	}

	level := r.URL.Query().Get("level")
	if level == "" {
		level = "basic"
	}

	caKeyType := cfg.CA.KeyType
	if caKeyType == "" {
		caKeyType = "ed25519"
	}
	defaultValidity := cfg.CA.ValidityMinutes
	if defaultValidity <= 0 {
		defaultValidity = 60
	}

	groupsInfo := make(map[string]interface{})
	for gname, gcfg := range cfg.Groups {
		resolved := cfg.ResolveGroup(gname)
		if resolved == nil {
			resolved = &gcfg
		}
		hasTOTP := resolved.TOTPSecret != ""
		users := resolved.AllowedUsers
		frozen := resolved.IsFrozen()
		ready := hasTOTP && strings.TrimSpace(users) != "" && !frozen

		if level == "full" {
			parent := gcfg.Parent
			exts := resolved.Extensions
			if exts == nil {
				exts = map[string]string{}
			}
			groupsInfo[gname] = map[string]interface{}{
				"allowed_users":    users,
				"validity_minutes": resolved.ValidityMinutes,
				"totp_configured":  hasTOTP,
				"frozen":           frozen,
				"parent":           parent,
				"extensions":       exts,
			}
		} else if ready {
			exts := resolved.Extensions
			sudo := false
			if exts != nil {
				if v, ok := exts["sudo"]; ok && v != "" {
					sudo = true
				}
			}
			groupsInfo[gname] = map[string]interface{}{
				"allowed_users": users,
				"sudo":          sudo,
			}
		}
	}

	caPub := ""
	if s.CAKeyPubPath != "" {
		if data, err := os.ReadFile(s.CAKeyPubPath); err == nil {
			caPub = strings.TrimSpace(string(data))
		}
	}

	result := map[string]interface{}{
		"ca_key_type":    caKeyType,
		"ca_public_key":  caPub,
	}
	if level == "full" {
		result["validity_minutes"] = defaultValidity
		dg := cfg.ResolveGroup("default")
		if dg != nil {
			result["allowed_users"] = dg.AllowedUsers
		} else {
			result["allowed_users"] = ""
		}
	}
	result["groups"] = groupsInfo

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{
			"error": "method not allowed",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version": Version(),
		"name":    name,
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (s *Server) caReady() bool {
	if s.CAKeyPath == "" || s.CAKeyPubPath == "" {
		return false
	}
	_, errKey := os.Stat(s.CAKeyPath)
	_, errPub := os.Stat(s.CAKeyPubPath)
	return errKey == nil && errPub == nil
}

// issueCert uses the cert.Signer to generate a temporary key pair, sign it
// with the CA key, and return the results.
func (s *Server) issueCert(keyType, allowedUsers string, validityMinutes int, extensions map[string]string) (map[string]string, error) {
	dataDir := filepath.Dir(s.CAKeyPath)
	serialFile := filepath.Join(dataDir, "serial.txt")
	signer := cert.NewSigner(s.CAKeyPath, keyType, serialFile)

	privKey, certPEM, serial, expiresAt, err := signer.Sign(allowedUsers, validityMinutes, extensions)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"ssh_private_key": privKey,
		"ssh_cert":        certPEM,
		"serial":          fmt.Sprintf("%d", serial),
		"expires_at":      expiresAt,
	}, nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func isDigits(s string) bool {
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func splitUsers(s string) []string {
	if s == "" {
		return nil
	}
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}
