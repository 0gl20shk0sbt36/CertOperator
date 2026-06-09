package totp

import (
	"testing"
)

func TestGenerateSecret(t *testing.T) {
	s := GenerateSecret()
	if len(s) != 32 {
		t.Fatalf("expected 32-char secret, got %d: %s", len(s), s)
	}
	// Should be uppercase base32 without padding
	for _, ch := range s {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= '2' && ch <= '7')) {
			t.Fatalf("invalid base32 character: %c in %s", ch, s)
		}
	}
}

func TestGenerateURI(t *testing.T) {
	uri := GenerateURI("JBSWY3DPEHPK3PXP", "TestIssuer", "test@example.com")
	if uri == "" {
		t.Fatal("expected non-empty URI")
	}
	if uri[:15] != "otpauth://totp/" {
		t.Fatalf("unexpected URI prefix: %s", uri[:15])
	}
}

func TestVerify(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	code := Now(secret)
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %s", code)
	}
	if !Verify(secret, code, 1) {
		t.Fatalf("failed to verify own code: %s", code)
	}
}

func TestVerifyBadCode(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	if Verify(secret, "000000", 1) {
		t.Fatal("expected failure for bad code")
	}
	if Verify(secret, "12345", 1) {
		t.Fatal("expected failure for 5-digit code")
	}
}
