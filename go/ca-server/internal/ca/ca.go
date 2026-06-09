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

	if err := os.MkdirAll(dataDir(cfg), 0700); err != nil {
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

func generateClientCert(clientKeyPath, clientCertPath string) error {
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

func generateDeployScript(distDir, httpsCertPath, clientCertPath, clientKeyPath string) error {
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
echo "Parameters needed for get_sub_cert:"
echo "  ca_cert_path=$CERT_DIR/ca-https-cert.pem"
echo "  client_cert=$CERT_DIR/client.cert"
echo "  client_key=$CERT_DIR/client.key"
`, httpsB64, clientCertB64, clientKeyB64)

	deployPath := filepath.Join(distDir, "deploy.sh")
	if err := os.WriteFile(deployPath, []byte(script), 0755); err != nil {
		return err
	}
	fi, _ := os.Stat(deployPath)
	fmt.Printf("   ✅ Deploy script: %s (%d bytes)\n", deployPath, fi.Size())
	return nil
}
