// Package config provides configuration loading and types for cert-operator v2.
// Uses encoding/json for configuration, reading config.json from the binary directory.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config represents the root configuration structure.
type Config struct {
	CA        CAConfig               `json:"ca"`
	Server    ServerConfig           `json:"server"`
	Groups    map[string]GroupConfig `json:"groups"`
	RateLimit RateLimitConfig        `json:"rate_limit"`
	TOTP      TOTPConfig             `json:"totp"`
	path      string
}

// CAConfig holds CA key and signing parameters.
type CAConfig struct {
	KeyType         string `json:"key_type"`
	ValidityMinutes int    `json:"validity_minutes"`
}

// ServerConfig holds HTTPS server parameters.
type ServerConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	SAN  string `json:"san"`
}

// GroupConfig holds per-group TOTP, users, and extensions.
type GroupConfig struct {
	AllowedUsers    string            `json:"allowed_users"`
	TOTPSecret      string            `json:"totp_secret"`
	ValidityMinutes int               `json:"validity_minutes"`
	Frozen          interface{}       `json:"frozen"`
	Parent          string            `json:"parent"`
	Extensions      map[string]string `json:"extensions"`
}

// RateLimitConfig holds rate-limit parameters.
type RateLimitConfig struct {
	MaxAttempts   int `json:"max_attempts"`
	WindowSeconds int `json:"window_seconds"`
}

// TOTPConfig holds TOTP display parameters.
type TOTPConfig struct {
	Issuer  string `json:"issuer"`
	Account string `json:"account"`
}

// Load reads and parses config.json from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.path = path
	// Apply defaults
	applyDefaults(cfg)
	return cfg, nil
}

// Path returns the config file path.
func (c *Config) Path() string { return c.path }

// Save writes the config back to the file.
func (c *Config) Save() error {
	if c.path == "" {
		return fmt.Errorf("config has no file path")
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, append(data, '\n'), 0644)
}

// IsFrozen returns true when the Frozen field represents a truthy value.
func (g *GroupConfig) IsFrozen() bool {
	switch v := g.Frozen.(type) {
	case bool:
		return v
	case string:
		return v == "yes" || v == "1" || v == "true"
	default:
		return false
	}
}

// ResolveGroup resolves a group config with parent inheritance.
func (c *Config) ResolveGroup(groupName string) *GroupConfig {
	if groupName == "" {
		groupName = "default"
	}
	gcfg, ok := c.Groups[groupName]
	if !ok {
		return nil
	}
	resolved := resolveGroup(c.Groups, gcfg)
	resolved.Parent = gcfg.Parent
	return resolved
}

func resolveGroup(groups map[string]GroupConfig, child GroupConfig) *GroupConfig {
	if child.Parent == "" {
		r := child
		return &r
	}
	parent, ok := groups[child.Parent]
	if !ok {
		r := child
		return &r
	}
	base := resolveGroup(groups, parent)

	baseUsers := splitUsers(base.AllowedUsers)
	childUsers := splitUsers(child.AllowedUsers)
	union := make(map[string]bool)
	for _, u := range baseUsers { union[u] = true }
	for _, u := range childUsers { union[u] = true }
	merged := ""
	for u := range union {
		if merged != "" { merged += "," }
		merged += u
	}
	base.AllowedUsers = merged

	if child.Extensions != nil {
		if base.Extensions == nil { base.Extensions = make(map[string]string) }
		for k, v := range child.Extensions { base.Extensions[k] = v }
	}
	if child.ValidityMinutes != 0 { base.ValidityMinutes = child.ValidityMinutes }
	if child.TOTPSecret != "" { base.TOTPSecret = child.TOTPSecret }
	if child.Frozen != nil { base.Frozen = child.Frozen }
	return base
}

func splitUsers(s string) []string {
	if s == "" { return nil }
	var users []string
	cur := ""
	for _, ch := range s {
		if ch == ',' || ch == ' ' {
			if cur != "" { users = append(users, cur); cur = "" }
		} else {
			cur += string(ch)
		}
	}
	if cur != "" { users = append(users, cur) }
	return users
}

func applyDefaults(cfg *Config) {
	if cfg.CA.KeyType == "" { cfg.CA.KeyType = "ed25519" }
	if cfg.CA.ValidityMinutes == 0 { cfg.CA.ValidityMinutes = 60 }
	if cfg.Server.Host == "" { cfg.Server.Host = "0.0.0.0" }
	if cfg.Server.Port == 0 { cfg.Server.Port = 8443 }
	if cfg.RateLimit.MaxAttempts == 0 { cfg.RateLimit.MaxAttempts = 5 }
	if cfg.RateLimit.WindowSeconds == 0 { cfg.RateLimit.WindowSeconds = 300 }
	if cfg.TOTP.Issuer == "" { cfg.TOTP.Issuer = "CertOperator" }
	if cfg.TOTP.Account == "" { cfg.TOTP.Account = "admin" }
	if cfg.Groups == nil { cfg.Groups = make(map[string]GroupConfig) }
}
