package pbkdf

import (
	"crypto/fips140"
	"errors"
	"testing"
)

func TestRejectsUnsupportedHash(t *testing.T) {
	// PBKDF2-HMAC-SHA256("password", "salt", 1, 32): valid PBKDF2, unsupported policy.
	encoded := "$pbkdf2-sha256$i=1,l=32$c2FsdA$Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs"
	if _, err := Verify([]byte("password"), encoded); !errors.Is(err, ErrInvalidHash) {
		t.Fatal("accepted weak hash", err)
	}
	if _, err := Hash(make([]byte, MaxPasswordLength+1)); err == nil {
		t.Fatal("accepted excessive password")
	}
	if _, err := Verify(make([]byte, MaxPasswordLength+1), encoded); err == nil {
		t.Fatal("accepted excessive password")
	}
}

func TestFIPSPolicy(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("requires FIPS mode")
	}
	encoded, err := Hash([]byte("a sufficiently long password"))
	if err != nil {
		t.Fatal(err)
	}
	matched, err := Verify([]byte("a sufficiently long password"), encoded)
	if err != nil || !matched {
		t.Fatalf("verify=%v,%v", matched, err)
	}
	TestRejectsUnsupportedHash(t)
}
