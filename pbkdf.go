// Package pbkdf hashes and verifies passwords with PBKDF2-HMAC-SHA256.
package pbkdf

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// MinIterations is the project work floor; it is not a NIST-mandated count.
	MinIterations        = 600_000
	MaxPasswordLength    = 1024 * 1024
	maxEncodedHashLength = 4096
	maxIterations        = 1_000_000
	maxKeyLength         = 64
	maxSaltLength        = 1024
)

var ErrInvalidHash = errors.New("pbkdf: invalid or unsupported hash")
var phcBase64 = base64.RawStdEncoding.Strict()

// Params specifies all hashing parameters. Zero fields are invalid.
type Params struct {
	Iterations int
	KeyLen     int
	SaltLen    int
}

// DefaultParams returns an independent configuration value.
func DefaultParams() Params {
	return Params{Iterations: MinIterations, KeyLen: 32, SaltLen: 16}
}

// GenerateSalt creates a random salt of 16 through 1024 bytes.
func GenerateSalt(length int) ([]byte, error) {
	if length < 16 || length > maxSaltLength {
		return nil, fmt.Errorf("salt length must be between 16 and %d", maxSaltLength)
	}
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// Hash hashes a password using DefaultParams.
func Hash(password []byte) (string, error) { return DefaultParams().Hash(password) }

// Hash produces $pbkdf2-sha256$i=<iterations>,l=<keyLen>$<salt>$<key>.
// Every parameter must be explicit and satisfy the same policy as Verify.
func (p Params) Hash(password []byte) (string, error) {
	if len(password) > MaxPasswordLength {
		return "", errors.New("password exceeds maximum length")
	}
	if err := validateParams(p); err != nil {
		return "", err
	}
	salt, err := GenerateSalt(p.SaltLen)
	if err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, string(password), salt, p.Iterations, p.KeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$pbkdf2-sha256$i=%d,l=%d$%s$%s", p.Iterations, p.KeyLen, phcBase64.EncodeToString(salt), phcBase64.EncodeToString(key)), nil
}

// Verify checks a canonical current-policy hash. Unsupported parameters are errors.
func Verify(password []byte, encoded string) (bool, error) {
	if len(password) > MaxPasswordLength {
		return false, errors.New("password exceeds maximum length")
	}
	p, salt, expected, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	actual, err := pbkdf2.Key(sha256.New, string(password), salt, p.Iterations, p.KeyLen)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func decodeHash(encoded string) (Params, []byte, []byte, error) {
	invalid := func() (Params, []byte, []byte, error) { return Params{}, nil, nil, ErrInvalidHash }
	if len(encoded) > maxEncodedHashLength {
		return invalid()
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "pbkdf2-sha256" {
		return invalid()
	}
	fields := strings.Split(parts[2], ",")
	if len(fields) != 2 {
		return invalid()
	}
	iterations, err := parseParameter(fields[0], "i=")
	if err != nil {
		return invalid()
	}
	keyLen, err := parseParameter(fields[1], "l=")
	if err != nil {
		return invalid()
	}
	salt, err := phcBase64.DecodeString(parts[3])
	if err != nil || phcBase64.EncodeToString(salt) != parts[3] {
		return invalid()
	}
	key, err := phcBase64.DecodeString(parts[4])
	if err != nil || phcBase64.EncodeToString(key) != parts[4] || len(key) != keyLen {
		return invalid()
	}
	p := Params{Iterations: iterations, KeyLen: keyLen, SaltLen: len(salt)}
	if err := validateParams(p); err != nil {
		return invalid()
	}
	return p, salt, key, nil
}

func parseParameter(field, prefix string) (int, error) {
	value, ok := strings.CutPrefix(field, prefix)
	if !ok {
		return 0, ErrInvalidHash
	}
	n, err := strconv.Atoi(value)
	if err != nil || strconv.Itoa(n) != value {
		return 0, ErrInvalidHash
	}
	return n, nil
}

func validateParams(p Params) error {
	if p.Iterations < MinIterations || p.Iterations > maxIterations {
		return fmt.Errorf("iterations must be between %d and %d", MinIterations, maxIterations)
	}
	if p.KeyLen < 32 || p.KeyLen > maxKeyLength {
		return fmt.Errorf("key length must be between 32 and %d", maxKeyLength)
	}
	if p.SaltLen < 16 || p.SaltLen > maxSaltLength {
		return fmt.Errorf("salt length must be between 16 and %d", maxSaltLength)
	}
	return nil
}
