// MIT License
//
// Copyright (c) 2025 Abdullah Fawwaz Qudamah
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package pbkdf

import (
	"crypto/sha512"
	"fmt"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	password := []byte("securepassword")

	hash, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if !strings.HasPrefix(hash, "$pbkdf2-sha256$") {
		t.Errorf("Invalid hash format: %s", hash)
	}

	match, err := Verify(password, hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !match {
		t.Error("Verify returned false for correct password")
	}

	wrongPassword := []byte("wrongpassword")
	match, err = Verify(wrongPassword, hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if match {
		t.Error("Verify returned true for wrong password")
	}
}

func TestHashRejectsInvalidParams(t *testing.T) {
	tests := []Params{
		{Iterations: -1},
		{Iterations: maxIterations + 1},
		{KeyLen: -1},
		{KeyLen: maxKeyLength + 1},
		{SaltLen: -1},
		{SaltLen: maxSaltLength + 1},
		{HashFunc: sha512.New},
	}

	for _, params := range tests {
		if _, err := params.Hash([]byte("password")); err == nil {
			t.Errorf("Hash(%+v) unexpectedly succeeded", params)
		}
	}
}

func TestVerifyRejectsResourceExhaustionParameters(t *testing.T) {
	tests := []string{
		fmt.Sprintf("$pbkdf2-sha256$i=%d,l=32$c2FsdA$aGFzaA", maxIterations+1),
		fmt.Sprintf("$pbkdf2-sha256$i=1,l=%d$c2FsdA$aGFzaA", maxKeyLength+1),
		"$pbkdf2-sha256$i=-1,l=32$c2FsdA$aGFzaA",
		"$pbkdf2-sha256$i=1,l=-1$c2FsdA$aGFzaA",
	}

	for _, encoded := range tests {
		if _, err := Verify([]byte("password"), encoded); err == nil {
			t.Errorf("Verify(%q) unexpectedly succeeded", encoded)
		}
	}
}

func TestVerifyRejectsMismatchedDerivedKeyLength(t *testing.T) {
	encoded := "$pbkdf2-sha256$i=1,l=32$c2FsdA$aGFzaA"
	if _, err := Verify([]byte("password"), encoded); err == nil {
		t.Error("Verify unexpectedly accepted a hash with the wrong decoded length")
	}
}

func TestVerifyInvalidHash(t *testing.T) {
	_, err := Verify([]byte("pass"), "invalid")
	if err == nil {
		t.Error("Expected error for invalid hash format")
	}
}

func TestCustomParams(t *testing.T) {
	password := []byte("custom")
	// Use partial params, expecting defaults for 0 values
	params := Params{
		Iterations: 1000,
		// KeyLen and SaltLen 0 -> defaults
	}

	hash, err := params.Hash(password)
	if err != nil {
		t.Fatalf("Custom Hash failed: %v", err)
	}

	// Verify standard Verify works with custom params encoded in string
	match, err := Verify(password, hash)
	if err != nil {
		t.Fatalf("Verify failed for custom params: %v", err)
	}
	if !match {
		t.Error("Verify returned false for custom params")
	}

	if !strings.Contains(hash, "i=1000") {
		t.Error("Hash did not contain custom iterations")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt(16)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}
	if len(salt) != 16 {
		t.Errorf("GenerateSalt returned length %d, want 16", len(salt))
	}

	// Optionally, generate another salt and check length/type, but do not assert uniqueness.
	salt2, err := GenerateSalt(16)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}
	if len(salt2) != 16 {
		t.Errorf("GenerateSalt returned length %d, want 16", len(salt2))
	}
}

func TestGenerateSaltInvalidLength(t *testing.T) {
	// Test zero length
	_, err := GenerateSalt(0)
	if err == nil {
		t.Error("Expected error for zero salt length")
	}

	// Test negative length
	_, err = GenerateSalt(-1)
	if err == nil {
		t.Error("Expected error for negative salt length")
	}
}

func TestVerifyMalformedParameters(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{
			name: "non-numeric iterations",
			hash: "$pbkdf2-sha256$i=abc,l=32$dGVzdHNhbHQxMjM0NTY$dGVzdGhhc2gxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy",
		},
		{
			name: "non-numeric key length",
			hash: "$pbkdf2-sha256$i=120000,l=xyz$dGVzdHNhbHQxMjM0NTY$dGVzdGhhc2gxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify([]byte("password"), tt.hash)
			if err == nil {
				t.Error("Expected error for malformed parameter")
			}
			if err.Error() != "invalid or corrupted hash" {
				t.Errorf("Expected generic error message, got: %v", err)
			}
		})
	}
}

func TestVerifyMalformedBase64(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{
			name: "invalid base64 in salt",
			hash: "$pbkdf2-sha256$i=120000,l=32$!!!invalid!!!$dGVzdGhhc2gxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy",
		},
		{
			name: "invalid base64 in hash",
			hash: "$pbkdf2-sha256$i=120000,l=32$dGVzdHNhbHQxMjM0NTY$!!!invalid!!!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify([]byte("password"), tt.hash)
			if err == nil {
				t.Error("Expected error for malformed base64")
			}
			if err.Error() != "invalid or corrupted hash" {
				t.Errorf("Expected generic error message, got: %v", err)
			}
		})
	}
}
