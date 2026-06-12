// Package ca — mTLS CA management (client certificate lifecycle).
//
// Replaces the old shared self-signed client.cert model with per-client
// certificates issued by a dedicated mTLS CA.  The server maintains a
// clients.json roster and only accepts certificates whose serial is present
// and unexpired.
package ca

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cert-operator/ca-server/v2/internal/config"
)

// ---- paths -----------------------------------------------------------------

func mtlsCAKeyPath(cfg *config.Config) string {
	return filepath.Join(dataDir(cfg), "mtls_ca_key.pem")
}

func mtlsCACertPath(cfg *config.Config) string {
	return filepath.Join(dataDir(cfg), "mtls_ca_cert.pem")
}

func clientsDBPath(cfg *config.Config) string {
	return filepath.Join(dataDir(cfg), "clients.json")
}

func clientPackDir(cfg *config.Config) string {
	return filepath.Join(dataDir(cfg), "clients")
}

// ---- data model ------------------------------------------------------------

// ClientRecord describes one issued mTLS client certificate.
type ClientRecord struct {
	Name      string `json:"name"`       // 证书标识名（如 laptop-alice）
	GrantedTo string `json:"granted_to"` // 授予者（如 alice@example.com）
	Serial    int64  `json:"serial"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	SAN       string `json:"san,omitempty"` // DNS:x,IP:y 格式，空表示无 SAN
	User      string `json:"user,omitempty"` // 关联的 SSH 用户名
	CertFile  string `json:"cert_file"`      // 证书 PEM 文件路径（相对 dataDir）
}

// ClientsDB is the on-disk roster of issued mTLS certificates.
type ClientsDB struct {
	Clients map[string]ClientRecord `json:"clients"`
}

// loadClientsDB reads clients.json from disk.  Returns an empty DB when the
// file does not exist.
func loadClientsDB(cfg *config.Config) (*ClientsDB, error) {
	path := clientsDBPath(cfg)
	db := &ClientsDB{Clients: make(map[string]ClientRecord)}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return db, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, db); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if db.Clients == nil {
		db.Clients = make(map[string]ClientRecord)
	}
	return db, nil
}

// saveClientsDB writes the DB back to disk.
func saveClientsDB(cfg *config.Config, db *ClientsDB) error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(clientsDBPath(cfg), append(data, '\n'), 0644)
}

// nextMTLSSerial returns the next available serial number for mTLS client
// certificates (separate from the SSH certificate serial counter).
func nextMTLSSerial(cfg *config.Config) (int64, error) {
	db, err := loadClientsDB(cfg)
	if err != nil {
		return 0, err
	}
	var maxSerial int64
	for _, r := range db.Clients {
		if r.Serial > maxSerial {
			maxSerial = r.Serial
		}
	}
	return maxSerial + 1, nil
}

// IsClientAuthorized checks whether a client certificate serial is present and
// unexpired in the roster.  Called from the TLS VerifyPeerCertificate callback.
func IsClientAuthorized(cfg *config.Config, serial *big.Int) (bool, error) {
	db, err := loadClientsDB(cfg)
	if err != nil {
		return false, err
	}
	for _, r := range db.Clients {
		if r.Serial == serial.Int64() {
			expires, eErr := time.Parse(time.RFC3339, r.ExpiresAt)
			if eErr != nil {
				return false, nil // malformed expiry → deny
			}
			return time.Now().UTC().Before(expires), nil
		}
	}
	return false, nil
}

// ---- mTLS CA generation ----------------------------------------------------

// GenerateMTLSCA creates an ed25519 CA key pair and a self-signed root
// certificate used to sign client mTLS certificates.
func GenerateMTLSCA(cfg *config.Config) error {
	keyPath := mtlsCAKeyPath(cfg)
	certPath := mtlsCACertPath(cfg)

	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("mTLS CA key already exists at %s", keyPath)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "CertOperator mTLS CA",
			Organization:       []string{"CertOperator"},
			Country:            []string{"CN"},
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	// Write private key
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshalED25519Private(priv)})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write mTLS CA key: %w", err)
	}

	// Write certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write mTLS CA cert: %w", err)
	}

	fmt.Printf("   ✅ mTLS CA key:  %s\n", keyPath)
	fmt.Printf("   ✅ mTLS CA cert: %s\n", certPath)
	return nil
}

// MTLSCACertPath returns the path to the mTLS CA certificate (PEM).
func MTLSCACertPath(cfg *config.Config) string {
	return mtlsCACertPath(cfg)
}

// ---- issue client certificate -----------------------------------------------

// IssueClientCert creates a per-client mTLS key + CA-signed cert, records it
// in clients.json, and packs the deployable artifacts into a tar.gz.
//
// Parameters:
//   - name:       certificate identifier (e.g. "laptop-alice")
//   - grantedTo:  grantee (stored in OU field + JSON roster)
//   - validityDays: validity period (default 365)
//   - san:        optional Subject Alternative Name (e.g. "DNS:laptop.local,IP:10.0.0.5")
//   - user:       optional associated SSH user name
//
// Returns the path to the generated tar.gz package.
func IssueClientCert(cfg *config.Config, name, grantedTo string, validityDays int, san, user string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if grantedTo == "" {
		return "", fmt.Errorf("granted-to is required")
	}
	// Validate name (same rules as cert_name in cert-operator CLI)
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return "", fmt.Errorf("name contains illegal characters")
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return "", fmt.Errorf("name can only contain alphanumeric and -_.")
		}
	}

	if validityDays <= 0 {
		validityDays = 365
	}

	caKeyPath := mtlsCAKeyPath(cfg)
	caCertPath := mtlsCACertPath(cfg)

	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		return "", fmt.Errorf("mTLS CA not initialized — run init first")
	}

	// Load CA
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return "", fmt.Errorf("read mTLS CA cert: %w", err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return "", fmt.Errorf("decode mTLS CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse mTLS CA cert: %w", err)
	}

	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return "", fmt.Errorf("read mTLS CA key: %w", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return "", fmt.Errorf("decode mTLS CA key PEM")
	}
	caPriv, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse mTLS CA key: %w", err)
	}

	// Generate client key pair
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate client key: %w", err)
	}

	serial, err := nextMTLSSerial(cfg)
	if err != nil {
		return "", err
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(0, 0, validityDays)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:         name,
			OrganizationalUnit: []string{grantedTo},
			Organization:       []string{"CertOperator"},
			Country:            []string{"CN"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	// Parse optional SAN
	if strings.TrimSpace(san) != "" {
		for _, entry := range strings.Split(san, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			switch {
			case strings.HasPrefix(entry, "DNS:"):
				template.DNSNames = append(template.DNSNames, strings.TrimPrefix(entry, "DNS:"))
			case strings.HasPrefix(entry, "IP:"):
				ip := net.ParseIP(strings.TrimPrefix(entry, "IP:"))
				if ip != nil {
					template.IPAddresses = append(template.IPAddresses, ip)
				}
			case strings.HasPrefix(entry, "EMAIL:"):
				template.EmailAddresses = append(template.EmailAddresses, strings.TrimPrefix(entry, "EMAIL:"))
			default:
				// Try as IP
				if ip := net.ParseIP(entry); ip != nil {
					template.IPAddresses = append(template.IPAddresses, ip)
				} else {
					template.DNSNames = append(template.DNSNames, entry)
				}
			}
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, clientPub, caPriv)
	if err != nil {
		return "", fmt.Errorf("sign client cert: %w", err)
	}

	// Ensure output directories
	packDir := clientPackDir(cfg)
	if err := os.MkdirAll(packDir, 0755); err != nil {
		return "", err
	}

	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshalED25519Private(clientPriv)})
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Save cert PEM for server-side reference
	certFileName := name + ".cert"
	certFilePath := filepath.Join(packDir, certFileName)
	if err := os.WriteFile(certFilePath, clientCertPEM, 0644); err != nil {
		return "", fmt.Errorf("save cert: %w", err)
	}

	// Record in DB
	db, err := loadClientsDB(cfg)
	if err != nil {
		return "", err
	}
	db.Clients[name] = ClientRecord{
		Name:      name,
		GrantedTo: grantedTo,
		Serial:    serial,
		IssuedAt:  notBefore.Format(time.RFC3339),
		ExpiresAt: notAfter.Format(time.RFC3339),
		SAN:       san,
		User:      user,
		CertFile:  filepath.Join("clients", certFileName),
	}
	if err := saveClientsDB(cfg, db); err != nil {
		return "", fmt.Errorf("save clients db: %w", err)
	}

	// Build tar.gz package
	tarPath := filepath.Join(packDir, name+".tar.gz")
	if err := buildClientPack(cfg, tarPath, name, clientKeyPEM, clientCertPEM); err != nil {
		return "", fmt.Errorf("build pack: %w", err)
	}

	fmt.Printf("   ✅ Client cert issued:  %s\n", name)
	fmt.Printf("   📦 Package:            %s\n", tarPath)
	fmt.Printf("   🔑 Serial:             %d\n", serial)
	fmt.Printf("   📅 Expires:            %s\n", notAfter.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("   👤 Granted to:         %s\n", grantedTo)
	if san != "" {
		fmt.Printf("   🌐 SAN:                %s\n", san)
	}

	return tarPath, nil
}

// buildClientPack creates a tar.gz containing:
//   ca-https-cert.pem   — server HTTPS certificate (for client-side verification)
//   <name>.key          — client private key
//   <name>.cert         — client certificate
func buildClientPack(cfg *config.Config, tarPath, name string, keyPEM, certPEM []byte) error {
	httpsCertPath := filepath.Join(dataDir(cfg), "https_cert.pem")
	httpsCert, err := os.ReadFile(httpsCertPath)
	if err != nil {
		return fmt.Errorf("read HTTPS cert: %w", err)
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	files := []struct {
		Name    string
		Data    []byte
		Mode    int64
	}{
		{"ca-https-cert.pem", httpsCert, 0644},
		{name + ".key", keyPEM, 0600},
		{name + ".cert", certPEM, 0644},
	}

	for _, f := range files {
		hdr := &tar.Header{
			Name: f.Name,
			Size: int64(len(f.Data)),
			Mode: f.Mode,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return err
	}
	if err := gw.Close(); err != nil {
		return err
	}

	return os.WriteFile(tarPath, buf.Bytes(), 0644)
}

// ---- revoke -----------------------------------------------------------------

// RevokeClientCert removes a client certificate from the roster.  The
// certificate itself is kept on disk (can be re-issued later), but the server
// will reject it at TLS handshake time.
func RevokeClientCert(cfg *config.Config, name string) error {
	db, err := loadClientsDB(cfg)
	if err != nil {
		return err
	}
	if _, ok := db.Clients[name]; !ok {
		return fmt.Errorf("client %q not found", name)
	}
	delete(db.Clients, name)
	if err := saveClientsDB(cfg, db); err != nil {
		return err
	}
	fmt.Printf("   ❌ Revoked: %s\n", name)
	return nil
}

// ---- list -------------------------------------------------------------------

// ListClientCerts returns the roster sorted by name.
func ListClientCerts(cfg *config.Config) ([]ClientRecord, error) {
	db, err := loadClientsDB(cfg)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(db.Clients))
	for n := range db.Clients {
		names = append(names, n)
	}
	sort.Strings(names)
	records := make([]ClientRecord, 0, len(names))
	for _, n := range names {
		records = append(records, db.Clients[n])
	}
	return records, nil
}

// GetClientCert returns a single client record by name.
func GetClientCert(cfg *config.Config, name string) (*ClientRecord, error) {
	db, err := loadClientsDB(cfg)
	if err != nil {
		return nil, err
	}
	r, ok := db.Clients[name]
	if !ok {
		return nil, fmt.Errorf("client %q not found", name)
	}
	return &r, nil
}

// ClientPackDir returns the directory where tar.gz packages are stored.
func ClientPackDir(cfg *config.Config) string {
	return clientPackDir(cfg)
}

// ---- ed25519 helper ---------------------------------------------------------

// marshalED25519Private encodes an ed25519 private key as PKCS8 DER.
func marshalED25519Private(priv ed25519.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(fmt.Sprintf("marshal ed25519: %v", err))
	}
	return der
}
