package ca

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/cert-operator/ca-server/v2/internal/config"
)

func TestGenerateMTLSCA(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := GenerateMTLSCA(cfg); err != nil {
		t.Fatal(err)
	}

	keyPath := mtlsCAKeyPath(cfg)
	certPath := mtlsCACertPath(cfg)

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("mTLS CA key not created")
	}
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatal("mTLS CA cert not created")
	}

	// Second call should fail
	if err := GenerateMTLSCA(cfg); err == nil {
		t.Fatal("expected error on second generate")
	}
}

func TestIssueAndRevokeClientCert(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)

	if err := GenerateMTLSCA(cfg); err != nil {
		t.Fatal(err)
	}

	// Issue
	tarPath, err := IssueClientCert(cfg, "test-laptop", "alice@example.com", 365, "DNS:test.local", "root")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tarPath); os.IsNotExist(err) {
		t.Fatal("tar.gz package not created")
	}

	// List
	records, err := ListClientCerts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 client, got %d", len(records))
	}
	if records[0].Name != "test-laptop" {
		t.Fatalf("expected name test-laptop, got %s", records[0].Name)
	}
	if records[0].GrantedTo != "alice@example.com" {
		t.Fatalf("expected granted_to alice@example.com, got %s", records[0].GrantedTo)
	}
	if records[0].SAN != "DNS:test.local" {
		t.Fatalf("expected SAN 'DNS:test.local', got %s", records[0].SAN)
	}

	// Show
	r, err := GetClientCert(cfg, "test-laptop")
	if err != nil {
		t.Fatal(err)
	}
	if r.User != "root" {
		t.Fatalf("expected user root, got %s", r.User)
	}

	// Authorized check
	ok, err := IsClientAuthorized(cfg, big.NewInt(records[0].Serial))
	if err != nil || !ok {
		t.Fatalf("expected authorized, got ok=%v err=%v", ok, err)
	}

	// Revoke
	if err := RevokeClientCert(cfg, "test-laptop"); err != nil {
		t.Fatal(err)
	}

	// Should not be authorized anymore
	ok, err = IsClientAuthorized(cfg, big.NewInt(records[0].Serial))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected not authorized after revoke")
	}

	// List should be empty
	records, err = ListClientCerts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 clients after revoke, got %d", len(records))
	}
}

func TestValidateClientName(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(dir)
	GenerateMTLSCA(cfg)

	// Valid name
	_, err := IssueClientCert(cfg, "valid-name", "test", 1, "", "")
	if err != nil {
		t.Fatalf("expected ok, got %v", err)
	}

	// Invalid name with slash
	_, err = IssueClientCert(cfg, "../evil", "test", 1, "", "")
	if err == nil {
		t.Fatal("expected error for path traversal name")
	}

	// Invalid name with special chars
	_, err = IssueClientCert(cfg, "evil;rm", "test", 1, "", "")
	if err == nil {
		t.Fatal("expected error for special chars")
	}
}

func testConfig(dir string) *config.Config {
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"ca":{"key_type":"ed25519","validity_minutes":60},"server":{"host":"0.0.0.0","port":8443},"rate_limit":{"max_attempts":5,"window_seconds":300}}`), 0644)
	cfg, _ := config.Load(cfgPath)
	dataDir := filepath.Join(filepath.Dir(cfg.Path()), "data")
	os.MkdirAll(dataDir, 0755)
	// Test needs a dummy HTTPS cert (buildClientPack reads it)
	dummyCert := []byte("-----BEGIN CERTIFICATE-----\nMIIB9jCCAV+gAwIBAgIU...\n-----END CERTIFICATE-----\n")
	os.WriteFile(filepath.Join(dataDir, "https_cert.pem"), dummyCert, 0644)
	return cfg
}
