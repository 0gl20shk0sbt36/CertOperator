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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cert-operator/ca-server/v2/internal/ca"
	"github.com/cert-operator/ca-server/v2/internal/cert"
	"github.com/cert-operator/ca-server/v2/internal/config"
	"github.com/cert-operator/ca-server/v2/internal/ratelimit"
	"github.com/cert-operator/ca-server/v2/internal/schedule"
	"github.com/cert-operator/ca-server/v2/internal/totp"
)

const (
	// Version embedded at build time; overridden by ldflags or main.go's VERSION.
	BuiltVersion = "3.2.0"
	name         = "cert-operator"
)

// Version returns the server version string.
func Version() string { return BuiltVersion }

// Server is the HTTPS + mTLS API server.
type Server struct {
	ConfigPath string
	NoMTLS     bool

	// Paths for TLS material (set before Serve).  ClientCertPath points to the mTLS CA cert.
	CAKeyPath      string
	CAKeyPubPath   string
	HTTPSCertPath  string
	HTTPSKeyPath   string
	ClientCertPath string

	limiter *ratelimit.Limiter

	// TOTP replay protection: sha256(secret|code) → expiry
	totpMu     sync.Mutex
	usedTOTPs  map[string]time.Time

	// Audit log rotation
	auditMu          sync.Mutex
	auditLogMaxBytes int64
}

// Serve starts the HTTPS server and blocks until the server exits.
func (s *Server) Serve() error {
	cfg, err := config.Load(s.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	s.limiter = ratelimit.New()
	s.usedTOTPs = make(map[string]time.Time)
	s.auditLogMaxBytes = int64(cfg.Server.AuditLogMaxMB) * 1024 * 1024

	// Background cleanup every 5 minutes: stale rate-limit + expired TOTP hashes.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.limiter.Clean(10 * time.Minute)
			s.totpMu.Lock()
			now := time.Now()
			for k, expiry := range s.usedTOTPs {
				if now.After(expiry) {
					delete(s.usedTOTPs, k)
				}
			}
			s.totpMu.Unlock()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/get-cert", s.handleGetCert)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/info", s.handleInfo)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/schedule/request", s.handleScheduleRequest)
	mux.HandleFunc("/api/schedule/requests", s.handleScheduleRequests)
	mux.HandleFunc("/api/schedule/replace", s.handleScheduleReplace)
	mux.HandleFunc("/api/schedule/approved", s.handleScheduleApproved)
	mux.HandleFunc("/api/get-scheduled-cert", s.handleGetScheduledCert)

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
		mtlsCACert, err := os.ReadFile(s.ClientCertPath)
		if err != nil {
			return fmt.Errorf("failed to read mTLS CA cert: %w", err)
		}
		if !pool.AppendCertsFromPEM(mtlsCACert) {
			return fmt.Errorf("failed to parse mTLS CA cert")
		}
		tlsCfg.ClientCAs = pool

		// VerifyPeerCertificate: after standard CA-chain verification,
		// check that the client certificate is present in clients.json
		// (not revoked) and not expired.
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no client certificate provided")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse client cert: %w", err)
			}
			cfg, cfgErr := config.Load(s.ConfigPath)
			if cfgErr != nil {
				return fmt.Errorf("load config: %w", cfgErr)
			}
			ok, err := ca.IsClientAuthorized(cfg, cert.SerialNumber)
			if err != nil {
				return fmt.Errorf("check authorization: %w", err)
			}
			if !ok {
				return fmt.Errorf("client certificate revoked or expired (serial %d)", cert.SerialNumber)
			}
			return nil
		}
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
	passwordlessMode := false
	var scheduleGroup string
	var scheduleCS *schedule.ClientSchedules
	var scheduleIdx int

	// When TOTP is empty, try passwordless-schedule mode.
	if totpCode == "" {
		clientName := clientCertCN(r)
		if clientName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"error":   "passwordless requires mTLS client certificate",
			})
			return
		}
		rule, cs, idx, matchErr := schedule.MatchClient(s.dataDir(), clientName, time.Now().UTC())
		if matchErr != nil || rule == nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"error":   "无免密规则匹配当前时段，或次数已用尽",
			})
			return
		}
		passwordlessMode = true
		scheduleGroup = rule.Group
		scheduleCS = cs
		scheduleIdx = idx
		// Set totpCode to a dummy value to pass format validation
		totpCode = "000000"
	}
	groupName := strings.TrimSpace(body.Group)
	reqUser := strings.TrimSpace(body.User)

	// In passwordless mode, the group comes from the schedule rule.
	if passwordlessMode {
		if groupName == "" {
			groupName = scheduleGroup
		}
	}

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
	if !passwordlessMode {
		if !isDigits(totpCode) || len(totpCode) != 6 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"error":   "TOTP 码格式错误",
			})
			return
		}
	}

	// Verify TOTP (skipped in passwordless mode)
	if !passwordlessMode {
		if !totp.Verify(gcfg.TOTPSecret, totpCode, 1) {
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"success": false,
				"error":   "TOTP 验证失败",
			})
			return
		}

		// TOTP replay protection: key = hash(secret|code) + 30s step.
		h := sha256.Sum256([]byte(gcfg.TOTPSecret + "|" + totpCode))
		hash := hex.EncodeToString(h[:])
		step := time.Now().Unix() / 30
		s.totpMu.Lock()
		for i := int64(-1); i <= 1; i++ {
			stepKey := hash + ":" + strconv.FormatInt(step+i, 10)
			if _, exists := s.usedTOTPs[stepKey]; exists {
				s.totpMu.Unlock()
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
					"success": false,
					"error":   "TOTP 码已被使用，请等待新码",
				})
				return
			}
		}
		for i := int64(-1); i <= 1; i++ {
			stepKey := hash + ":" + strconv.FormatInt(step+i, 10)
			s.usedTOTPs[stepKey] = time.Now().Add(90 * time.Second)
		}
		s.totpMu.Unlock()
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

	// Bump schedule counter in passwordless mode.
	if passwordlessMode && scheduleCS != nil {
		if incErr := schedule.IncrementUsed(s.dataDir(), scheduleCS, scheduleIdx); incErr != nil {
			log.Printf("schedule increment error: %v", incErr)
		}
	}

	// Audit log: who requested what and when
	// Extract applicant info from mTLS client certificate.
	applicantName := "unknown"
	applicantGrantedTo := "unknown"
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		subj := r.TLS.PeerCertificates[0].Subject
		applicantName = subj.CommonName
		if len(subj.OrganizationalUnit) > 0 {
			applicantGrantedTo = subj.OrganizationalUnit[0]
		}
	}
	if err := s.writeAuditLog(map[string]interface{}{
		"time":         time.Now().UTC().Format(time.RFC3339),
		"client_ip":    clientAddr,
		"applicant":    applicantName,
		"granted_to":   applicantGrantedTo,
		"group":        groupName,
		"user":         allowedUsers,
		"serial":       result["serial"],
		"expires_at":   result["expires_at"],
	}); err != nil {
		log.Printf("audit log write error: %v", err)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"ssh_private_key": result["ssh_private_key"],
		"ssh_cert":       result["ssh_cert"],
		"serial":         result["serial"],
		"expires_at":     result["expires_at"],
	})
}

// auditLogPath returns the path to the certificate issuance audit log.
func (s *Server) auditLogPath() string {
	dataDir := filepath.Dir(s.ConfigPath)
	return filepath.Join(dataDir, "data", "cert-audit.log")
}

// writeAuditLog appends a JSON line to the audit log file with size-based
// rotation.  Thread-safe (mutex-protected rotate + append).
func (s *Server) writeAuditLog(fields map[string]interface{}) error {
	data, err := json.Marshal(fields)
	if err != nil {
		return err
	}

	s.auditMu.Lock()
	defer s.auditMu.Unlock()

	path := s.auditLogPath()

	// Rotate if current file exceeds the configured limit.
	if s.auditLogMaxBytes > 0 {
		if fi, err := os.Stat(path); err == nil && fi.Size() > s.auditLogMaxBytes {
			os.Rename(path, path+".1")
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(append(data, '\n'))
	return err
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

// dataDir returns the data directory relative to the config file.
func (s *Server) dataDir() string {
	return filepath.Join(filepath.Dir(s.ConfigPath), "data")
}

// clientCertCN extracts the Common Name from the mTLS client certificate.
func clientCertCN(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return ""
}

// ---------------------------------------------------------------------------
// Schedule API handlers
// ---------------------------------------------------------------------------

func (s *Server) handleScheduleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}

	clientName := clientCertCN(r)
	if clientName == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "mTLS client certificate required"})
		return
	}

	var body struct {
		GrantedTo string          `json:"granted_to"`
		Rule      schedule.Rule   `json:"rule"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON"})
		return
	}

	grantedTo := body.GrantedTo
	if grantedTo == "" {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			ou := r.TLS.PeerCertificates[0].Subject.OrganizationalUnit
			if len(ou) > 0 {
				grantedTo = ou[0]
			}
		}
	}

	if err := schedule.ValidateRule(body.Rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}

	if err := schedule.SubmitRequest(s.dataDir(), clientName, grantedTo, body.Rule); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "申请已提交，等待审批"})
}

func (s *Server) handleScheduleRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}

	clientName := clientCertCN(r)
	if clientName == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "mTLS client certificate required"})
		return
	}

	// Clients can see all their own requests.
	reqs, err := schedule.GetAllRequests(s.dataDir(), clientName)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	if len(reqs) == 0 {
		writeJSON(w, http.StatusOK, map[string]interface{}{"requests": nil, "message": "无申请记录"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"requests": reqs})
}

// handleScheduleReplace - PUT replaces the client's existing request.
func (s *Server) handleScheduleReplace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}

	clientName := clientCertCN(r)
	if clientName == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "mTLS client certificate required"})
		return
	}

	var body struct {
		GrantedTo string          `json:"granted_to"`
		Rule      schedule.Rule   `json:"rule"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON"})
		return
	}

	grantedTo := body.GrantedTo
	if grantedTo == "" {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			ou := r.TLS.PeerCertificates[0].Subject.OrganizationalUnit
			if len(ou) > 0 {
				grantedTo = ou[0]
			}
		}
	}

	if err := schedule.ValidateRule(body.Rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}

	// Check if there's an existing pending request with the same rule name.
	existing, err := schedule.GetRequestByRule(s.dataDir(), clientName, body.Rule.Name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	if existing != nil && existing.Status == "pending" {
		if err := schedule.SubmitRequest(s.dataDir(), clientName, grantedTo, body.Rule); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "申请已覆盖，等待审批"})
		return
	}

	writeJSON(w, http.StatusConflict, map[string]interface{}{"error": "无待审批的申请可覆盖。（审批通过后可直接提交新申请）"})
}

// handleScheduleApproved — GET = view own approved rules; DELETE = revoke own rules.
func (s *Server) handleScheduleApproved(w http.ResponseWriter, r *http.Request) {
	clientName := clientCertCN(r)
	if clientName == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "mTLS client certificate required"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		cs, err := schedule.GetApprovedRules(s.dataDir(), clientName)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
			return
		}
		if cs == nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{"rules": nil, "message": "无生效规则"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"rules": cs.Rules})

	case http.MethodDelete:
		if err := schedule.RevokeApproved(s.dataDir(), clientName); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "规则已撤回"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
	}
}

// ---------------------------------------------------------------------------
// get-scheduled-cert — time-window-locked SSH cert with caching
// ---------------------------------------------------------------------------

type scheduledCertCache struct {
	PrivateKey string `json:"private_key"`
	Cert       string `json:"cert"`
	Serial     int    `json:"serial"`
	ExpiresAt  string `json:"expires_at"`
}

func (s *Server) scheduledCertDir() string {
	return filepath.Join(s.dataDir(), "scheduled-certs")
}

func (s *Server) handleGetScheduledCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}

	clientName := clientCertCN(r)
	if clientName == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "mTLS client certificate required"})
		return
	}

	cfg, err := config.Load(s.ConfigPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "load config"})
		return
	}

	var body struct {
		Name      string `json:"name"`       // rule name (from approved schedule)
		User      string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON"})
		return
	}

	if body.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "name is required (rule name from approved schedule)"})
		return
	}

	// Look up approved rule by name.
	rule, _, rErr := schedule.GetApprovedRuleByName(s.dataDir(), clientName, body.Name)
	if rErr != nil || rule == nil {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": fmt.Sprintf("没有名称为 %q 的已审批规则", body.Name)})
		return
	}

	groupName := rule.Group
	if groupName == "" {
		groupName = "default"
	}

	gcfg := cfg.ResolveGroup(groupName)
	if gcfg == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": fmt.Sprintf("组不存在: %s", groupName)})
		return
	}
	if gcfg.IsFrozen() {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"error": fmt.Sprintf("组 %s 已被冻结", groupName)})
		return
	}

	allowedUsers := gcfg.AllowedUsers
	if body.User != "" {
		allowedUsers = body.User
	}

	// Compute next occurrence from the rule's time window.
	nextStart, nextEnd := nextOccurrence(rule.Days, rule.StartTime, rule.EndTime)
	validityStr := fmt.Sprintf("%s:%s", nextStart.Format("20060102150405"), nextEnd.Format("20060102150405"))

	// Cache key = hash of rule name + client name
	cacheKey := sha256hex(clientName + ":" + rule.Name)
	cacheDir := s.scheduledCertDir()
	os.MkdirAll(cacheDir, 0700)
	cachePath := filepath.Join(cacheDir, cacheKey+".json")

	// Try cache first
	if cached, cerr := loadScheduledCertCache(cachePath); cerr == nil && cached != nil {
		if time.Now().UTC().Before(nextEnd) {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"success":        true,
				"cached":         true,
				"ssh_private_key": cached.PrivateKey,
				"ssh_cert":       cached.Cert,
				"serial":         cached.Serial,
				"expires_at":     cached.ExpiresAt,
				"valid_from":     nextStart.Format(time.RFC3339),
				"valid_until":    nextEnd.Format(time.RFC3339),
			})
			return
		}
		// Cached cert expired → remove and re-issue
		os.Remove(cachePath)
	}

	// Issue new cert with exact time window
	dataDir := filepath.Dir(s.CAKeyPath)
	serialFile := filepath.Join(dataDir, "serial.txt")
	keyType := cfg.CA.KeyType
	if keyType == "" {
		keyType = "ed25519"
	}
	signer := cert.NewSigner(s.CAKeyPath, keyType, serialFile)

	privKey, certPEM, serial, err := signer.SignWithValidity(allowedUsers, validityStr, gcfg.Extensions)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": fmt.Sprintf("签发失败: %v", err)})
		return
	}

	cache := scheduledCertCache{
		PrivateKey: privKey,
		Cert:       certPEM,
		Serial:     serial,
		ExpiresAt:  nextEnd.Format(time.RFC3339),
	}
	saveScheduledCertCache(cachePath, &cache)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"cached":         false,
		"ssh_private_key": privKey,
		"ssh_cert":       certPEM,
		"serial":         serial,
		"expires_at":     cache.ExpiresAt,
		"valid_from":     nextStart.Format(time.RFC3339),
		"valid_until":    nextEnd.Format(time.RFC3339),
	})
}

// ---- helpers ---------------------------------------------------------------

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func loadScheduledCertCache(path string) (*scheduledCertCache, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var c scheduledCertCache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func saveScheduledCertCache(path string, c *scheduledCertCache) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// nextOccurrence computes the next absolute [start, end] time window matching
// the given days-of-week and HH:MM times.
func nextOccurrence(days []int, startTime, endTime string) (time.Time, time.Time) {
	now := time.Now().UTC()
	today := now.Truncate(24 * time.Hour)

	for offset := 0; offset <= 7; offset++ {
		candidate := today.AddDate(0, 0, offset)
		wd := int(candidate.Weekday())
		// Check if day matches (empty days = every day)
		if len(days) > 0 {
			found := false
			for _, d := range days {
				if wd == d {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		sH, sM := parseHHMM(startTime)
		eH, eM := parseHHMM(endTime)
		start := candidate.Add(time.Duration(sH)*time.Hour + time.Duration(sM)*time.Minute)
		end := candidate.Add(time.Duration(eH)*time.Hour + time.Duration(eM)*time.Minute)

		if offset == 0 && now.After(end) {
			continue // today's window already passed
		}
		return start, end
	}

	// Fallback: tomorrow at start_time
	sH, sM := parseHHMM(startTime)
	eH, eM := parseHHMM(endTime)
	tomorrow := today.AddDate(0, 0, 1)
	return tomorrow.Add(time.Duration(sH)*time.Hour + time.Duration(sM)*time.Minute),
		tomorrow.Add(time.Duration(eH)*time.Hour + time.Duration(eM)*time.Minute)
}

func parseHHMM(s string) (int, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0
	}
	h := 0
	m := 0
	fmt.Sscanf(parts[0], "%d", &h)
	fmt.Sscanf(parts[1], "%d", &m)
	return h, m
}
