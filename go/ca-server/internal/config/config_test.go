package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndSave(t *testing.T) {
	cfg := &Config{
		CA: CAConfig{KeyType: "ed25519", ValidityMinutes: 60},
		Server: ServerConfig{Host: "0.0.0.0", Port: 8443},
		Groups: map[string]GroupConfig{
			"default": {
				AllowedUsers:    "root",
				TOTPSecret:      "A6ZYALIV6KYL3DJTF4NNOEQNT6FT4P3I",
				ValidityMinutes: 60,
			},
			"test": {
				AllowedUsers:    "root",
				ValidityMinutes: 30,
				Frozen:          true,
				Parent:          "default",
				Extensions:      map[string]string{"sudo": "yes"},
			},
		},
		RateLimit: RateLimitConfig{MaxAttempts: 5, WindowSeconds: 300},
		TOTP:      TOTPConfig{Issuer: "CertOperator", Account: "admin"},
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	// Write as JSON
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(cfgPath, data, 0644)

	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.CA.KeyType != "ed25519" {
		t.Errorf("CA.KeyType = %q, want ed25519", loaded.CA.KeyType)
	}
	if loaded.Server.Port != 8443 {
		t.Errorf("Server.Port = %d, want 8443", loaded.Server.Port)
	}
	if loaded.RateLimit.MaxAttempts != 5 {
		t.Errorf("RateLimit.MaxAttempts = %d, want 5", loaded.RateLimit.MaxAttempts)
	}
	if loaded.TOTP.Issuer != "CertOperator" {
		t.Errorf("TOTP.Issuer = %q, want CertOperator", loaded.TOTP.Issuer)
	}
	if len(loaded.Groups) != 2 {
		t.Errorf("len(Groups) = %d, want 2", len(loaded.Groups))
	}
	if g, ok := loaded.Groups["test"]; !ok {
		t.Error("test group missing")
	} else {
		if !g.IsFrozen() {
			t.Error("test group not frozen")
		}
		if g.Parent != "default" {
			t.Errorf("test parent = %q, want default", g.Parent)
		}
		if g.Extensions["sudo"] != "yes" {
			t.Errorf("test sudo = %q, want yes", g.Extensions["sudo"])
		}
	}

	// Round-trip
	if err := loaded.Save(); err != nil {
		t.Fatal(err)
	}
	cfg2, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.CA.KeyType != "ed25519" {
		t.Errorf("roundtrip CA.KeyType = %q", cfg2.CA.KeyType)
	}
	if cfg2.Groups["test"].Frozen != true {
		t.Errorf("roundtrip frozen = %v", cfg2.Groups["test"].Frozen)
	}
	if cfg2.Groups["test"].Extensions["sudo"] != "yes" {
		t.Error("roundtrip sudo extension lost")
	}
}

func TestDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"server":{"host":"10.0.0.1"}}`), 0644)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CA.KeyType != "ed25519" {
		t.Errorf("default CA.KeyType = %q, want ed25519", cfg.CA.KeyType)
	}
	if cfg.Server.Port != 8443 {
		t.Errorf("default Server.Port = %d, want 8443", cfg.Server.Port)
	}
	if cfg.RateLimit.MaxAttempts != 5 {
		t.Errorf("default MaxAttempts = %d, want 5", cfg.RateLimit.MaxAttempts)
	}
	if cfg.RateLimit.WindowSeconds != 300 {
		t.Errorf("default WindowSeconds = %d, want 300", cfg.RateLimit.WindowSeconds)
	}
	if cfg.TOTP.Issuer != "CertOperator" {
		t.Errorf("default TOTP.Issuer = %q", cfg.TOTP.Issuer)
	}
	if cfg.TOTP.Account != "admin" {
		t.Errorf("default TOTP.Account = %q", cfg.TOTP.Account)
	}
}
