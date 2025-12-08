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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// DefaultParams are the recommended parameters for PBKDF2 as per NIST SP 800-132.
// NIST recommends a salt length of at least 128 bits (16 bytes).
// We use 120,000 iterations for SHA-256 to meet modern security standards (2025).
var DefaultParams = Params{
	Iterations: 120000,
	KeyLen:     32,
	SaltLen:    16,
	HashFunc:   sha256.New,
}

// Params configures the PBKDF2 hashing.
type Params struct {
	Iterations int
	KeyLen     int
	SaltLen    int
	HashFunc   func() hash.Hash
}

// GenerateSalt generates a random salt of the specified length.
func GenerateSalt(length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("salt length must be positive")
	}
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// Hash hashes a password using PBKDF2 with the default parameters.
// It returns a formatted string: $pbkdf2-sha256$i=<iterations>,l=<keyLen>$<base64Salt>$<base64Hash>
func Hash(password []byte) (string, error) {
	return DefaultParams.Hash(password)
}

// Hash hashes a password using the configured parameters.
// If any parameter is 0 (or nil for HashFunc), the value from DefaultParams is used.
func (p Params) Hash(password []byte) (string, error) {
	// Apply defaults for zero values
	if p.Iterations == 0 {
		p.Iterations = DefaultParams.Iterations
	}
	if p.KeyLen == 0 {
		p.KeyLen = DefaultParams.KeyLen
	}
	if p.SaltLen == 0 {
		p.SaltLen = DefaultParams.SaltLen
	}
	if p.HashFunc == nil {
		p.HashFunc = DefaultParams.HashFunc
	}

	salt, err := GenerateSalt(p.SaltLen)
	if err != nil {
		return "", err
	}

	dk := pbkdf2.Key(password, salt, p.Iterations, p.KeyLen, p.HashFunc)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(dk)

	// Format: $pbkdf2-sha256$i=<iterations>,l=<keyLen>$<base64Salt>$<base64Hash>
	// Note: This library currently only supports SHA-256, which is hardcoded in the
	// format string and Verify function. While the Params struct allows setting HashFunc,
	// only SHA-256 should be used for compatibility.
	return fmt.Sprintf("$pbkdf2-sha256$i=%d,l=%d$%s$%s", p.Iterations, p.KeyLen, b64Salt, b64Hash), nil
}

// Verify checks if a password matches the encoded hash.
func Verify(password []byte, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 5 {
		return false, errors.New("invalid or corrupted hash")
	}

	if parts[1] != "pbkdf2-sha256" {
		return false, errors.New("invalid or corrupted hash")
	}

	var iterations, keyLen int
	params := strings.Split(parts[2], ",")
	for _, param := range params {
		kv := strings.Split(param, "=")
		if len(kv) != 2 {
			continue
		}
		var err error
		switch kv[0] {
		case "i":
			iterations, err = strconv.Atoi(kv[1])
			if err != nil {
				return false, errors.New("invalid or corrupted hash")
			}
		case "l":
			keyLen, err = strconv.Atoi(kv[1])
			if err != nil {
				return false, errors.New("invalid or corrupted hash")
			}
		}
	}

	if iterations == 0 || keyLen == 0 {
		return false, errors.New("invalid or corrupted hash")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, errors.New("invalid or corrupted hash")
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("invalid or corrupted hash")
	}

	dk := pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)

	if subtle.ConstantTimeCompare(dk, decodedHash) == 1 {
		return true, nil
	}

	return false, nil
}
