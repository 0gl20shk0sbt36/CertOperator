// Package ca manages the CA key pair, HTTPS certificate, mTLS client
// certificate, and deploy script — roughly equivalent to the Python
// ca_server.py "init" workflow.
package ca

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cert-operator/ca-server/v2/internal/config"
)

// dataDir returns the data directory path relative to the config file directory.
func dataDir(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Path()), "data")
}

// Init creates a CA key pair, HTTPS self-signed certificate, mTLS client
// certificate, deploy script, and serial counter. It refuses to run if
// the CA private key already exists.
func Init(cfg *config.Config) error {
	caKeyPath := filepath.Join(dataDir(cfg), "ca_key")
	caKeyPubPath := filepath.Join(dataDir(cfg), "ca_key.pub")
	httpsKeyPath := filepath.Join(dataDir(cfg), "https_key.pem")
	httpsCertPath := filepath.Join(dataDir(cfg), "https_cert.pem")
	clientKeyPath := filepath.Join(dataDir(cfg), "client.key")
	clientCertPath := filepath.Join(dataDir(cfg), "client.cert")
	serialPath := filepath.Join(dataDir(cfg), "serial.txt")
	distDir := filepath.Join(dataDir(cfg), "dist")

	if err := os.MkdirAll(dataDir(cfg), 0755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	if _, err := os.Stat(caKeyPath); err == nil {
		return fmt.Errorf("CA key already exists at %s — remove data dir to re-initialise", caKeyPath)
	}

	keyType := cfg.CA.KeyType
	if keyType == "" {
		keyType = "ed25519"
	}

	san := cfg.Server.SAN

	// 1. Generate CA key pair ------------------------------------------------
	fmt.Printf("🔨 Generating CA key pair (%s)...\n", keyType)
	runOut("ssh-keygen",
		"-t", keyType,
		"-f", caKeyPath,
		"-N", "",
		"-C", "ca-server@cert-operator",
	)
	os.Chmod(caKeyPath, 0600)
	os.Chmod(caKeyPubPath, 0644)
	fmt.Printf("   ✅ CA private key: %s\n", caKeyPath)
	fmt.Printf("   ✅ CA public key:  %s\n", caKeyPubPath)

	// 2. Generate HTTPS self-signed certificate -------------------------------
	fmt.Println("🔨 Generating HTTPS self-signed certificate...")
	sanList := []string{"DNS:localhost", "IP:127.0.0.1"}
	if strings.TrimSpace(san) != "" {
		for _, entry := range strings.Fields(strings.ReplaceAll(san, ",", " ")) {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				sanList = append(sanList, entry)
			}
		}
	}
	sanExt := "subjectAltName=" + strings.Join(sanList, ",")
	runOut("openssl", "req", "-x509",
		"-newkey", "ec",
		"-pkeyopt", "ec_paramgen_curve:prime256v1",
		"-days", "3650",
		"-nodes",
		"-keyout", httpsKeyPath,
		"-out", httpsCertPath,
		"-subj", "/CN=CertOperator/O=CertOperator/C=CN",
		"-addext", sanExt,
	)
	os.Chmod(httpsKeyPath, 0600)
	os.Chmod(httpsCertPath, 0644)
	fmt.Printf("   ✅ HTTPS key:  %s\n", httpsKeyPath)
	fmt.Printf("   ✅ HTTPS cert: %s\n", httpsCertPath)

	// 3. Init serial counter -------------------------------------------------
	if err := os.WriteFile(serialPath, []byte("0"), 0644); err != nil {
		return fmt.Errorf("write serial: %w", err)
	}
	fmt.Printf("   ✅ Serial counter: %s (initial value 0)\n", serialPath)

	// 4. Generate mTLS client certificate ------------------------------------
	if err := generateClientCert(clientKeyPath, clientCertPath); err != nil {
		return err
	}

	// 5. Generate deploy script ----------------------------------------------
	if err := generateDeployScript(distDir, httpsCertPath, clientCertPath, clientKeyPath); err != nil {
		return err
	}

	// 6. Target server configuration guide -----------------------------------
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("📋 Target server configuration guide")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	fmt.Println("Deploy CA public key to target server:")
	fmt.Println()
	caPub, _ := os.ReadFile(caKeyPubPath)
	fmt.Printf("  # 1. Copy CA public key\n")
	fmt.Printf("  scp %s root@target-server:/etc/ssh/ca_key.pub\n", caKeyPubPath)
	fmt.Println()
	fmt.Printf("  # 2. Edit /etc/ssh/sshd_config and add:\n")
	fmt.Printf("  TrustedUserCAKeys /etc/ssh/ca_key.pub\n")
	fmt.Println()
	fmt.Printf("  # 3. Restart SSH service\n")
	fmt.Printf("  sudo systemctl restart sshd\n")
	fmt.Println()
	fmt.Printf("  # 4. Verify\n")
	fmt.Printf("  sudo sshd -T | grep trust\n")
	fmt.Println()
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println("🔑 CA public key content:")
	fmt.Println(strings.TrimSpace(string(caPub)))
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println()
	fmt.Println("📦 Client deploy package (three files, one transfer):")
	fmt.Printf("  scp %s user@client:~\n", filepath.Join(distDir, "deploy.sh"))
	fmt.Printf("  Client runs: bash ~/deploy.sh\n")

	return nil
}

// ResetCA regenerates the CA key pair, invalidating all issued SSH certificates.
func ResetCA(cfg *config.Config) error {
	caKeyPath := filepath.Join(dataDir(cfg), "ca_key")
	caKeyPubPath := filepath.Join(dataDir(cfg), "ca_key.pub")

	if err := generateCAKey(caKeyPath, caKeyPubPath); err != nil {
		return err
	}
	fmt.Printf("   ✅ CA key:  %s\n", caKeyPath)
	fmt.Printf("   ✅ CA pub:  %s\n", caKeyPubPath)
	fmt.Println("   ⚠️  所有已签发的 SSH 证书立即失效！")
	return nil
}

// ResetHTTPS regenerates the HTTPS (TLS) certificate only.
// Existing client ca-https-cert.pem files must be re-deployed.
func ResetHTTPS(cfg *config.Config) error {
	httpsKeyPath := filepath.Join(dataDir(cfg), "https_key.pem")
	httpsCertPath := filepath.Join(dataDir(cfg), "https_cert.pem")

	if err := generateHTTPSCert(httpsKeyPath, httpsCertPath); err != nil {
		return err
	}
	fmt.Printf("   ✅ HTTPS key:  %s\n", httpsKeyPath)
	fmt.Printf("   ✅ HTTPS cert: %s\n", httpsCertPath)
	fmt.Println("   ⚠️  所有客户端需要重新运行 deploy.sh！")
	return nil
}

// ResetClient regenerates the mTLS client cert + deploy script.
func ResetClient(cfg *config.Config) error {
	clientKeyPath := filepath.Join(dataDir(cfg), "client.key")
	clientCertPath := filepath.Join(dataDir(cfg), "client.cert")
	distDir := filepath.Join(dataDir(cfg), "dist")
	httpsCertPath := filepath.Join(dataDir(cfg), "https_cert.pem")

	if err := generateClientCert(clientKeyPath, clientCertPath); err != nil {
		return err
	}
	fmt.Printf("   ✅ Client key:  %s\n", clientKeyPath)
	fmt.Printf("   ✅ Client cert: %s\n", clientCertPath)

	if err := generateDeployScript(distDir, httpsCertPath, clientCertPath, clientKeyPath); err != nil {
		return fmt.Errorf("deploy script: %w", err)
	}
	fmt.Printf("   ✅ Deploy script: %s\n", filepath.Join(distDir, "deploy.sh"))
	return nil
}

// ResetAll deletes everything and re-runs Init.
func ResetAll(cfg *config.Config) error {
	d := dataDir(cfg)
	if err := os.RemoveAll(d); err != nil {
		return fmt.Errorf("remove data dir: %w", err)
	}
	return Init(cfg)
}

// generateCAKey creates an ed25519 CA key pair.
func generateCAKey(caKeyPath, caKeyPubPath string) error {
	cmd := exec.Command("ssh-keygen",
		"-t", "ed25519",
		"-f", caKeyPath,
		"-N", "",
		"-C", "ca-server@cert-operator",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ssh-keygen: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if err := os.Chmod(caKeyPath, 0600); err != nil {
		return err
	}
	if err := os.Chmod(caKeyPubPath, 0644); err != nil {
		return err
	}
	return nil
}

// generateHTTPSCert creates a self-signed HTTPS certificate.
func generateHTTPSCert(httpsKeyPath, httpsCertPath string) error {
	san := "DNS:localhost,IP:127.0.0.1"
	cmd := exec.Command("openssl",
		"req", "-newkey", "ed25519",
		"-days", "3650",
		"-x509",
		"-nodes",
		"-keyout", httpsKeyPath,
		"-out", httpsCertPath,
		"-subj", "/CN=CertOperator/O=CertOperator/C=CN",
		"-addext", fmt.Sprintf("subjectAltName=%s", san),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("openssl: %s: %w", strings.TrimSpace(string(out)), err)
	}
	os.Chmod(httpsKeyPath, 0600)
	os.Chmod(httpsCertPath, 0644)
	return nil
}

// generateClientCert creates an ed25519 mTLS client key + self-signed cert.
func generateClientCert(clientKeyPath, clientCertPath string) error {
	cmd := exec.Command("openssl",
		"req", "-newkey", "ed25519",
		"-days", "3650",
		"-nodes",
		"-x509",
		"-keyout", clientKeyPath,
		"-out", clientCertPath,
		"-subj", "/CN=CertOperatorClient/O=CertOperator/C=CN",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("openssl client: %s: %w", strings.TrimSpace(string(out)), err)
	}
	os.Chmod(clientKeyPath, 0600)
	os.Chmod(clientCertPath, 0644)
	return nil
}

func generateDeployScript(distDir, httpsCertPath, clientCertPath, clientKeyPath string) error {
	if err := os.MkdirAll(distDir, 0755); err != nil {
		return err
	}

	httpsPEM, _ := os.ReadFile(httpsCertPath)
	clientPEM, _ := os.ReadFile(clientCertPath)
	clientKeyPEM, _ := os.ReadFile(clientKeyPath)

	httpsB64 := base64.StdEncoding.EncodeToString(httpsPEM)
	clientCertB64 := base64.StdEncoding.EncodeToString(clientPEM)
	clientKeyB64 := base64.StdEncoding.EncodeToString(clientKeyPEM)

	script := fmt.Sprintf(`#!/bin/bash
set -euo pipefail
CERT_DIR="${HOME}/.hermes/certs"
mkdir -p "$CERT_DIR"
echo '📦 Deploying client certificates to ' "$CERT_DIR"
echo '%s' | base64 -d > "$CERT_DIR/ca-https-cert.pem"
chmod 644 "$CERT_DIR/ca-https-cert.pem"
echo '%s' | base64 -d > "$CERT_DIR/client.cert"
chmod 644 "$CERT_DIR/client.cert"
echo '%s' | base64 -d > "$CERT_DIR/client.key"
chmod 600 "$CERT_DIR/client.key"
echo '✅ Deployment complete!'
`, httpsB64, clientCertB64, clientKeyB64)

	return os.WriteFile(filepath.Join(distDir, "deploy.sh"), []byte(script), 0755)
}

// Pubkey returns the CA public key as a trimmed string.
func Pubkey(cfg *config.Config) (string, error) {
	caPubPath := filepath.Join(dataDir(cfg), "ca_key.pub")
	data, err := os.ReadFile(caPubPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// KeyPaths returns (private-key-path, public-key-path) for the CA key pair.
func KeyPaths(cfg *config.Config) (priv, pub string) {
	d := dataDir(cfg)
	return filepath.Join(d, "ca_key"), filepath.Join(d, "ca_key.pub")
}

// HTTPSKeyPath returns the path to the HTTPS private key.
func HTTPSKeyPath(cfg *config.Config) string {
	return filepath.Join(dataDir(cfg), "https_key.pem")
}

// HTTPSCertPath returns the path to the HTTPS certificate.
func HTTPSCertPath(cfg *config.Config) string {
	return filepath.Join(dataDir(cfg), "https_cert.pem")
}

// ClientCertPath returns the path to the mTLS client certificate.
func ClientCertPath(cfg *config.Config) string {
	return filepath.Join(dataDir(cfg), "client.cert")
}

// ClientKeyPath returns the path to the mTLS client private key.
func ClientKeyPath(cfg *config.Config) string {
	return filepath.Join(dataDir(cfg), "client.key")
}

// DataDir returns the data directory path.
func DataDir(cfg *config.Config) string {
	return dataDir(cfg)
}

// RenewCert regenerates the HTTPS self-signed certificate without touching
// the CA key pair or client mTLS certs.
func RenewCert(cfg *config.Config) error {
	httpsKeyPath := filepath.Join(dataDir(cfg), "https_key.pem")
	httpsCertPath := filepath.Join(dataDir(cfg), "https_cert.pem")
	distDir := filepath.Join(dataDir(cfg), "dist")

	if _, err := os.Stat(httpsKeyPath); err != nil {
		return fmt.Errorf("HTTPS key not found — run init first")
	}

	san := cfg.Server.SAN
	sanList := []string{"DNS:localhost", "IP:127.0.0.1"}
	if strings.TrimSpace(san) != "" {
		for _, entry := range strings.Fields(strings.ReplaceAll(san, ",", " ")) {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				sanList = append(sanList, entry)
			}
		}
	}
	sanExt := "subjectAltName=" + strings.Join(sanList, ",")

	fmt.Println("🔨 Regenerating HTTPS self-signed certificate...")
	fmt.Printf("   SAN: %v\n", sanList)
	runOut("openssl", "req", "-x509",
		"-newkey", "ec",
		"-pkeyopt", "ec_paramgen_curve:prime256v1",
		"-days", "3650",
		"-nodes",
		"-keyout", httpsKeyPath,
		"-out", httpsCertPath,
		"-subj", "/CN=CertOperator/O=CertOperator/C=CN",
		"-addext", sanExt,
	)
	os.Chmod(httpsKeyPath, 0600)
	os.Chmod(httpsCertPath, 0644)
	fmt.Printf("   ✅ HTTPS cert updated: %s\n", httpsCertPath)

	// Regenerate deploy script (embeds HTTPS cert)
	clientCertPath := filepath.Join(dataDir(cfg), "client.cert")
	clientKeyPath := filepath.Join(dataDir(cfg), "client.key")
	if err := generateDeployScript(distDir, httpsCertPath, clientCertPath, clientKeyPath); err != nil {
		return err
	}
	return nil
}

// Fingerprint returns the SHA256 fingerprint of the CA public key using
// ssh-keygen -lf (same as the Python version).
func Fingerprint(cfg *config.Config) (string, error) {
	caPubPath := filepath.Join(dataDir(cfg), "ca_key.pub")
	cmd := exec.Command("ssh-keygen", "-lf", caPubPath)
	out, err := cmd.Output()
	if err != nil {
		// Fallback: compute ourselves
		data, err2 := os.ReadFile(caPubPath)
		if err2 != nil {
			return "", fmt.Errorf("ssh-keygen -lf: %w", err)
		}
		h := sha256.Sum256(data)
		return fmt.Sprintf("SHA256:%x", h), nil
	}
	fields := strings.Fields(string(out))
	for _, f := range fields {
		if strings.HasPrefix(f, "SHA256:") {
			return f, nil
		}
	}
	// Fallback
	data, err := os.ReadFile(caPubPath)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("SHA256:%x", h), nil
}

// ---- internal helpers ------------------------------------------------------

func runOut(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Command failed: %s %v: %v\n", name, args, err)
		os.Exit(1)
	}
}

func _unused_generateClientCert(clientKeyPath, clientCertPath string) error {
	fmt.Println("🔨 Generating client mTLS certificate...")
	runOut("openssl", "ecparam", "-genkey", "-name", "prime256v1",
		"-out", clientKeyPath,
	)
	os.Chmod(clientKeyPath, 0600)
	runOut("openssl", "req", "-new", "-x509",
		"-key", clientKeyPath,
		"-out", clientCertPath,
		"-days", "3650",
		"-subj", "/CN=CertOperatorClient/O=CertOperator/C=CN",
	)
	os.Chmod(clientCertPath, 0644)
	fmt.Printf("   ✅ Client key:  %s\n", clientKeyPath)
	fmt.Printf("   ✅ Client cert: %s\n", clientCertPath)
	return nil
}

func _unused_generateDeployScript(distDir, httpsCertPath, clientCertPath, clientKeyPath string) error {
	if err := os.MkdirAll(distDir, 0755); err != nil {
		return err
	}

	httpsCert, err := os.ReadFile(httpsCertPath)
	if err != nil {
		return err
	}
	clientCert, err := os.ReadFile(clientCertPath)
	if err != nil {
		return err
	}
	clientKey, err := os.ReadFile(clientKeyPath)
	if err != nil {
		return err
	}

	httpsB64 := base64.StdEncoding.EncodeToString(httpsCert)
	clientCertB64 := base64.StdEncoding.EncodeToString(clientCert)
	clientKeyB64 := base64.StdEncoding.EncodeToString(clientKey)

	script := fmt.Sprintf(`#!/bin/bash
# cert-operator client deploy package — auto-generated by ca-server init
set -euo pipefail

CERT_DIR="${HOME}/.hermes/certs"
mkdir -p "$CERT_DIR"

echo "📦 Deploying client certificates to $CERT_DIR"

# ---- ca-https-cert.pem (644) ----
echo '%s' | base64 -d > "$CERT_DIR/ca-https-cert.pem"
chmod 644 "$CERT_DIR/ca-https-cert.pem"

# ---- client.cert (644) ----
echo '%s' | base64 -d > "$CERT_DIR/client.cert"
chmod 644 "$CERT_DIR/client.cert"

# ---- client.key (600) ----
echo '%s' | base64 -d > "$CERT_DIR/client.key"
chmod 600 "$CERT_DIR/client.key"

echo ""
echo "✅ Deployment complete!"
echo "   HTTPS cert: $CERT_DIR/ca-https-cert.pem"
echo "   Client cert: $CERT_DIR/client.cert"
echo "   Client key:  $CERT_DIR/client.key"
echo ""
echo "CA server connection:"
echo "  CA server address was NOT included in deploy.sh"
echo "  Ask your admin for the CA server IP address."
echo "  Then use:"
echo "    get_sub_cert(server='https://<CA_SERVER_IP>:8443', ...)"
echo "    cert-operator get-cert https://<CA_SERVER_IP>:8443 ..."
`, httpsB64, clientCertB64, clientKeyB64)

	deployPath := filepath.Join(distDir, "deploy.sh")
	if err := os.WriteFile(deployPath, []byte(script), 0755); err != nil {
		return err
	}
	fi, _ := os.Stat(deployPath)
	fmt.Printf("   ✅ Deploy script: %s (%d bytes)\n", deployPath, fi.Size())
	return nil
}