// Package config provides configuration loading for cert-operator v4.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// RootConfig is the top-level CA server configuration.
// Fixed path: /opt/ca_server/config.json
type RootConfig struct {
	Server   ServerConfig       `json:"server"`
	Clients  ClientsConfig      `json:"clients"`
	Defaults DefaultsConfig     `json:"defaults"`
	path     string
}

type ServerConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	SAN  string `json:"san"`
}

type ClientsConfig struct {
	MaxPendingRules int    `json:"max_pending_rules"` // 0 = 10
	CAIssuerID      string `json:"ca_issuer_id"`      // e.g. "ca-primary"
}

type DefaultsConfig struct {
	IssueMode string `json:"issue_mode"` // totp | passwordless | deny
	SUDOAllowed bool `json:"sudo_allowed"`
	MaxCount    int  `json:"max_count"`
	ValidityMinutes int `json:"validity_minutes"` // 0 = 60
}

// TargetConfig is per-target configuration.
// Path: data/targets/<name>/config.json
type TargetConfig struct {
	Name             string   `json:"name"`
	OnlineTimeoutSec int      `json:"online_timeout_seconds"` // 0 = 30
	CAIssuerID       string   `json:"ca_issuer_id"`          // e.g. "ca-primary"
	path             string
}

// LoadRoot reads the root config.json.
func LoadRoot(path string) (*RootConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &RootConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse root config: %w", err)
	}
	cfg.path = path
	cfg.applyDefaults()
	return cfg, nil
}

func (c *RootConfig) Path() string    { return c.path }
func (c *RootConfig) DataDir() string { return filepath.Join(filepath.Dir(c.path), "data") }

func (c *RootConfig) applyDefaults() {
	if c.Server.Host == "" { c.Server.Host = "0.0.0.0" }
	if c.Server.Port == 0  { c.Server.Port = 8443 }
	if c.Clients.MaxPendingRules <= 0 { c.Clients.MaxPendingRules = 10 }
	if c.Defaults.IssueMode == ""      { c.Defaults.IssueMode = "totp" }
	if c.Defaults.ValidityMinutes <= 0 { c.Defaults.ValidityMinutes = 60 }
}

// LoadTarget reads a target config from data/targets/<name>/config.json.
func LoadTarget(dataDir, name string) (*TargetConfig, error) {
	path := filepath.Join(dataDir, "targets", name, "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &TargetConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse target config: %w", err)
	}
	cfg.path = path
	cfg.Name = name
	if cfg.OnlineTimeoutSec <= 0 {
		cfg.OnlineTimeoutSec = 30
	}
	return cfg, nil
}

// SaveTarget persists a target config.
func SaveTarget(cfg *TargetConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cfg.path, append(data, '\n'), 0644)
}
