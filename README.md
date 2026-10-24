# go-pbkdf

Install: `go get github.com/fawwazid/go-pbkdf/v2@v2.0.0`.
See [v2 release notes](CHANGELOG.md) for breaking changes.

PBKDF2-HMAC-SHA256 password hashing using standard-library `crypto/pbkdf2`.
Requires Go 1.27.3; no external dependencies.

## Usage

```go
package main

import (
 "fmt"
 "log"
 pbkdf "github.com/fawwazid/go-pbkdf/v2"
)

func main() {
 params := pbkdf.DefaultParams()
 params.Iterations = 800000
 encoded, err := params.Hash([]byte("example password"))
 if err != nil { log.Fatal(err) }
 matched, err := pbkdf.Verify([]byte("example password"), encoded)
 if err != nil { log.Fatal(err) }
 fmt.Println(matched)
}
```

## API and policy

- `Hash(password)`: use a fresh default configuration.
- `DefaultParams()`: return an independent configuration value.
- `Params.Hash(password)`: every field must be explicitly populated.
- `Verify(password, encoded)`: apply the same parameter policy as creation.
- `GenerateSalt(length)`: generate 16–1024 random bytes.

| Parameter | Default | Allowed |
| --- | --- | --- |
| Iterations | 600,000 | 600,000–1,000,000 |
| SaltLen | 16 bytes | 16–1024 bytes |
| KeyLen | 32 bytes | 32–64 bytes |

The iteration floor is project policy, not a NIST-mandated count. Benchmark
work factors for your deployment. Password input is bounded at 1 MiB.

The canonical record is
`$pbkdf2-sha256$i=<iterations>,l=<keyLen>$<unpadded-base64-salt>$<unpadded-base64-key>`.
Field order, canonical integer/base64 encodings, and all limits are checked
before derivation. Comparison is constant-time.

## Breaking changes

The mutable `DefaultParams` variable is now a function. `Params.HashFunc`,
zero-value default substitution, and verification of weak historical settings
have been removed. Unsupported records fail in every runtime mode.
There are no conversion helpers or permissive verification paths.

See [SECURITY.md](SECURITY.md). This is not a complete authentication system.
Run `go test ./...` and `go vet ./...`. License: [MIT](LICENSE).
