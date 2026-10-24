package pbkdf

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	p := DefaultParams()
	p.Iterations = 800000
	encoded, err := p.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		password string
		match    bool
	}{{"correct password", true}, {"wrong password", false}} {
		got, err := Verify([]byte(tc.password), encoded)
		if err != nil || got != tc.match {
			t.Fatalf("verify = %v, %v", got, err)
		}
	}
	if !strings.Contains(encoded, "i=800000") {
		t.Fatal("missing work factor")
	}
}

func TestRejectsInvalidParams(t *testing.T) {
	for _, p := range []Params{
		{}, {Iterations: MinIterations}, {Iterations: MinIterations - 1, KeyLen: 32, SaltLen: 16},
		{Iterations: maxIterations + 1, KeyLen: 32, SaltLen: 16},
		{Iterations: MinIterations, KeyLen: 31, SaltLen: 16},
		{Iterations: MinIterations, KeyLen: 32, SaltLen: 15},
		{Iterations: MinIterations, KeyLen: 65, SaltLen: 16},
	} {
		if _, err := p.Hash([]byte("password")); err == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
	for _, size := range []int{0, -1, 15, maxSaltLength + 1} {
		if _, err := GenerateSalt(size); err == nil {
			t.Fatal("accepted salt size", size)
		}
	}
}

func TestCanonicalHashParser(t *testing.T) {
	encoded, err := Hash([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"invalid", "prefix" + encoded,
		strings.Replace(encoded, "i=600000,l=32", "i=1,l=32", 1),
		strings.Replace(encoded, "i=600000,l=32", "i=600000,i=600000,l=32", 1),
		strings.Replace(encoded, "i=600000,l=32", "l=32,i=600000", 1),
		strings.Replace(encoded, "i=600000,l=32", "i=0600000,l=32", 1),
		strings.Replace(encoded, "i=600000,l=32", "i=+600000,l=32", 1),
		strings.Replace(encoded, "i=600000,l=32", fmt.Sprintf("i=%d,l=32", maxIterations+1), 1),
	} {
		if _, err := Verify([]byte("password"), bad); !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("accepted malformed/unsupported hash: %v", err)
		}
	}
	parts := strings.Split(encoded, "$")
	parts[3] += "\n"
	if _, err := Verify([]byte("password"), strings.Join(parts, "$")); !errors.Is(err, ErrInvalidHash) {
		t.Fatal(err)
	}
}

func TestDefaultsAreIndependent(t *testing.T) {
	p := DefaultParams()
	p.Iterations++
	if DefaultParams().Iterations != MinIterations {
		t.Fatal("mutated default configuration")
	}
}
