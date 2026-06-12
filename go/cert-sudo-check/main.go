// Command cert-sudo-check verifies that an SSH certificate in the agent has
// valid sudo@cert-operator permission for the current user, and that the
// certificate's group version matches the locally stored version.
//
// Copyright 2026 cert-operator. MIT license.
//
// This code is similar to the previous cert-operator sudo-check mentioned in
// various project documents for the sudo wrapper for SSH certificate.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	// Parse flags
	checkOnline := false
	checkSudo := false
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--check-online":
			checkOnline = true
		case "--check-sudo":
			checkOnline = true
			checkSudo = true
		}
	}

	// Load config
	configPath := os.Getenv("CERT_SUDO_CONFIG")
	if configPath == "" {
		configPath = "/opt/ca_server/config.json"
	}
	timeout := loadOnlineTimeout(configPath)

	// 1. Online check (always)
	if checkOnline {
		if !isOnline(timeout) {
			os.Exit(1)
		}
	}

	// 2. Sudo check (only with --check-sudo)
	if checkSudo {
		if !hasSUDOCert() {
			os.Exit(1)
		}
	}

	os.Exit(0)
}

// ---- online check ----------------------------------------------------------

func loadOnlineTimeout(configPath string) int {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return 30
	}
	var cfg struct {
		Server struct {
			OnlineTimeoutSeconds int `json:"online_timeout_seconds"`
		} `json:"server"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return 30
	}
	if cfg.Server.OnlineTimeoutSeconds <= 0 {
		return 30
	}
	return cfg.Server.OnlineTimeoutSeconds
}

func isOnline(timeoutSec int) bool {
	data, err := os.ReadFile("/opt/ca_server/data/last-sync-timestamp")
	if err != nil {
		return true // No sync file = skip online check (legacy/standalone mode)
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix()-ts <= int64(timeoutSec)
}

// ---- sudo check ------------------------------------------------------------

func hasSUDOCert() bool {
	// 1. Get SSH agent socket
	sockPath := getAgentSocket()
	if sockPath == "" {
		return false
	}

	// 2. List certificates from agent
	certOutput, err := sshAddL(sockPath)
	if err != nil || len(certOutput) == 0 {
		return false
	}

	// 3. Check each certificate
	for _, certPath := range certOutput {
		if strings.HasPrefix(certPath, "The agent has no identities") {
			continue
		}
		info, err := sshKeygenL(certPath)
		if err != nil {
			continue
		}
		if hasSUDOExtension(info) && versionMatches(info) {
			return true
		}
	}
	return false
}

func getAgentSocket() string {
	// Try environment variable first
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock != "" {
		return sock
	}
	// Fallback: file written by sudo-wrapper
	data, err := os.ReadFile("/tmp/.cert-sudo-sock")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func sshAddL(sockPath string) ([]string, error) {
	cmd := exec.Command("ssh-add", "-L")
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sockPath)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var certs []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && strings.HasPrefix(l, "ssh-") {
			certs = append(certs, l)
		}
	}
	return certs, nil
}

func sshKeygenL(certPEM string) (string, error) {
	// Write cert to temp file and run ssh-keygen -L
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("cert-check-%d", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, []byte(certPEM), 0600); err != nil {
		return "", err
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("ssh-keygen", "-L", "-f", tmpFile)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func hasSUDOExtension(info string) bool {
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "sudo@cert-operator") {
			return true
		}
	}
	return false
}

func versionMatches(info string) bool {
	// Extract group-version@cert-operator from cert info
	var group, versionStr string
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "group-version@cert-operator") {
			// Format: extension:group-version@cert-operator admin-v3
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				verParts := strings.SplitN(parts[len(parts)-1], "-", 2)
				if len(verParts) == 2 {
					group = verParts[0]
					versionStr = strings.TrimPrefix(verParts[1], "v")
				}
			}
		}
	}
	// No version extension in cert → allow (backward compatible)
	if group == "" || versionStr == "" {
		return true
	}
	version, err := strconv.Atoi(versionStr)
	if err != nil {
		return false
	}

	// Read group-versions file
	data, err := os.ReadFile("/opt/ca_server/data/group-versions.json")
	if err != nil {
		return true // No file = no version check (legacy mode)
	}
	var gv struct {
		Issuers map[string]map[string]int `json:"issuers"`
	}
	if err := json.Unmarshal(data, &gv); err != nil {
		return false
	}
	for _, groups := range gv.Issuers {
		if expected, ok := groups[group]; ok && expected == version {
			return true
		}
	}
	return false
}
