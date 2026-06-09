// Package cert handles SSH certificate signing using ssh-keygen with the
// CA key, mirroring the Python _issue_cert / serial-number logic.
package cert

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Signer signs temporary SSH key pairs with the CA key.
type Signer struct {
	CAKey     string
	KeyType   string
	SerialFile string
}

// NewSigner returns a Signer configured with the given CA key path, key type,
// and serial-number counter file.
func NewSigner(caKey, keyType, serialFile string) *Signer {
	if keyType == "" {
		keyType = "ed25519"
	}
	return &Signer{
		CAKey:      caKey,
		KeyType:    keyType,
		SerialFile: serialFile,
	}
}

// Sign generates a temporary key pair, signs it with the CA key via
// ssh-keygen -s, and returns the private key PEM, certificate PEM, serial
// number, and expiry timestamp.  Temporary files are cleaned up before
// returning.
func (s *Signer) Sign(allowedUsers string, validityMinutes int, extensions map[string]string) (
	privateKeyPEM string,
	certPEM string,
	serial int,
	expiresAt string,
	err error,
) {
	dataDir := filepath.Dir(s.CAKey)

	serial, err = s.nextSerial()
	if err != nil {
		return "", "", 0, "", fmt.Errorf("serial: %w", err)
	}

	// 1. Generate temporary key pair -----------------------------------------
	tmpKey := filepath.Join(dataDir, fmt.Sprintf(".tmp_%d", serial))
	run("ssh-keygen",
		"-t", s.KeyType,
		"-f", tmpKey,
		"-N", "",
		"-C", fmt.Sprintf("ca-server-user-%d", serial),
	)
	tmpPub := tmpKey + ".pub"
	certPath := tmpKey + "-cert.pub"

	// Ensure cleanup
	defer func() {
		for _, p := range []string{tmpKey, tmpPub, certPath} {
			os.Remove(p)
		}
	}()

	// 2. CA-sign the temporary public key ------------------------------------
	identity := fmt.Sprintf("cert-%d", serial)
	validity := fmt.Sprintf("+%dm", validityMinutes)

	args := []string{
		"-s", s.CAKey,
		"-I", identity,
		"-n", allowedUsers,
		"-V", validity,
		"-z", strconv.Itoa(serial),
	}

	// Add extension options, mirroring the Python auto-prefix logic.
	if extensions != nil {
		for k, v := range extensions {
			opt := k
			val := strings.ToLower(strings.TrimSpace(v))

			// If the key doesn't contain ":" and isn't a known built-in
			// option, prefix with "extension:<k>@cert-operator".
			if !strings.Contains(opt, ":") && !isBuiltinOption(opt) {
				opt = fmt.Sprintf("extension:%s@cert-operator", opt)
			}

			if val != "" && val != "true" && val != "yes" && val != "1" {
				args = append(args, "-O", fmt.Sprintf("%s=%s", opt, v))
			} else {
				args = append(args, "-O", opt)
			}
		}
	}

	args = append(args, tmpPub)
	run("ssh-keygen", args...)

	// 3. Read results --------------------------------------------------------
	privData, err := os.ReadFile(tmpKey)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("read temp key: %w", err)
	}
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("read cert: %w", err)
	}

	// 4. Compute expiry ------------------------------------------------------
	expiresDT := time.Now().UTC().Add(time.Duration(validityMinutes) * time.Minute)
	expiresAt = expiresDT.Format("2006-01-02T15:04:05Z")

	return string(privData), string(certData), serial, expiresAt, nil
}

// ---- internal helpers ------------------------------------------------------

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ %s %v: %s\n", name, args, string(out))
		os.Exit(1)
	}
}

func (s *Signer) readSerial() (int, error) {
	data, err := os.ReadFile(s.SerialFile)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func (s *Signer) writeSerial(n int) error {
	return os.WriteFile(s.SerialFile, []byte(strconv.Itoa(n)), 0644)
}

func (s *Signer) nextSerial() (int, error) {
	current, err := s.readSerial()
	if err != nil {
		return 0, err
	}
	next := current + 1
	if err := s.writeSerial(next); err != nil {
		return 0, err
	}
	return next, nil
}

// isBuiltinOption returns true for ssh-keygen -O options that do not need
// the "extension:" prefix.
func isBuiltinOption(opt string) bool {
	switch opt {
	case "clear", "force-command", "source-address", "verify-required",
		"no-agent-forwarding", "no-port-forwarding", "no-pty",
		"no-user-rc", "no-x11-forwarding", "permit-agent-forwarding",
		"permit-port-forwarding", "permit-pty", "permit-user-rc",
		"permit-x11-forwarding":
		return true
	}
	return false
}
