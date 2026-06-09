// Package totp provides TOTP generation and verification matching pyotp behavior.
//
// Uses SHA1, 30-second time steps, and 6-digit codes per RFC 6238 / RFC 4226.
// Only the standard library is used — no third-party dependencies.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

const (
	digits   = 6
	timeStep = 30
)

// GenerateSecret returns a random 32-character base32-encoded TOTP secret
// (20 random bytes), matching pyotp.random_base32().
func GenerateSecret() string {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("totp: failed to read random bytes: %v", err))
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(buf), "=")
}

// GenerateURI returns an otpauth:// URI for use with authenticator apps.
// Matches pyotp.totp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer).
func GenerateURI(secret, issuer, account string) string {
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   fmt.Sprintf("/%s:%s", url.PathEscape(issuer), url.PathEscape(account)),
	}
	q := u.Query()
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	u.RawQuery = q.Encode()
	return u.String()
}

// Verify checks whether the given TOTP code is valid for the secret within
// ±window time steps.  Matches pyotp.TOTP(secret).verify(code, valid_window=window).
func Verify(secret string, code string, window int) bool {
	if len(code) != digits {
		return false
	}
	codeInt, err := decodeDigits(code)
	if err != nil {
		return false
	}

	secretBytes, err := decodeSecret(secret)
	if err != nil {
		return false
	}

	counter := timeStepCounter(time.Now().Unix())

	for i := -window; i <= window; i++ {
		if int(hotp(secretBytes, counter+int64(i))) == codeInt {
			return true
		}
	}
	return false
}

// Now returns the current TOTP code for display / verification purposes.
func Now(secret string) string {
	secretBytes, err := decodeSecret(secret)
	if err != nil {
		return ""
	}
	counter := timeStepCounter(time.Now().Unix())
	return formatDigits(hotp(secretBytes, counter))
}

// timeStepCounter returns the number of time steps since Unix epoch.
func timeStepCounter(unixTime int64) int64 {
	return unixTime / timeStep
}

// hotp computes an HOTP value per RFC 4226.
func hotp(key []byte, counter int64) uint32 {
	mac := hmac.New(sha1.New, key)
	binary.Write(mac, binary.BigEndian, counter)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
	return code % uint32(math.Pow10(digits))
}

// decodeSecret normalizes a base32 secret (uppercase, no padding) for HMAC.
func decodeSecret(secret string) ([]byte, error) {
	// pyotp uses uppercase base32 without padding
	secret = strings.ToUpper(strings.TrimSpace(secret))
	// Add padding if needed
	switch len(secret) % 8 {
	case 2:
		secret += "======"
	case 4:
		secret += "===="
	case 5:
		secret += "==="
	case 7:
		secret += "="
	}
	return base32.StdEncoding.DecodeString(secret)
}

// decodeDigits converts a 6-digit string to an integer.
func decodeDigits(s string) (int, error) {
	var n int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("totp: non-digit character in code")
		}
		n = n*10 + int(ch-'0')
	}
	return n, nil
}

// formatDigits formats a uint32 as a zero-padded 6-digit string.
func formatDigits(n uint32) string {
	return fmt.Sprintf("%06d", n)
}
