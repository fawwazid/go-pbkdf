# go-pbkdf

[![Go Reference](https://pkg.go.dev/badge/github.com/fawwazid/go-pbkdf.svg)](https://pkg.go.dev/github.com/fawwazid/go-pbkdf)
[![Go Report Card](https://goreportcard.com/badge/github.com/fawwazid/go-pbkdf)](https://goreportcard.com/report/github.com/fawwazid/go-pbkdf)

A simple and secure Go library for password hashing using PBKDF2.

## Installation

```bash
go get github.com/fawwazid/go-pbkdf
```

## Usage

```go
package main

import (
	"fmt"
	"log"

	"github.com/fawwazid/go-pbkdf"
)

func main() {
	password := []byte("mySecurePassword123!")

	// 1. Standard Hash (Recommended)
	hash, err := pbkdf.Hash(password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Standard Hash: %s\n", hash)

	// 2. Custom Parameters
	// You can specify just what you want to change, 0 values use defaults.
	params := pbkdf.Params{
		Iterations: 200000, // Stronger than default
		SaltLen:    32,     // Longer salt
	}
	customHash, err := params.Hash(password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Custom Hash:   %s\n", customHash)

	// Verify either hash
	match, err := pbkdf.Verify(password, customHash)
	if err != nil {
		log.Fatal(err)
	}

	if match {
		fmt.Println("Password matches!")
	} else {
		fmt.Println("Invalid password.")
	}
	
	// Helper: Generate a random salt
	salt, err := pbkdf.GenerateSalt(16)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Random Salt: %x\n", salt)
}
```

## Security

This library is designed to comply with **NIST SP 800-132 (Recommendation for Password-Based Key Derivation)**.

Default parameters:
- **Algorithm**: SHA-256 (Approved mode)
- **Iterations**: 120,000 (Exceeds minimum; tuned for 2025)
- **Salt Length**: 16 bytes (128 bits, meets NIST minimum)
- **Key Length**: 32 bytes (256 bits)

You can customize these parameters using the `Params` struct. Zero values will automatically use the defaults.

## License

[MIT](LICENSE)
