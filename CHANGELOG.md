# Changelog

## v2.0.0 — 2026-10-24

Use standard-library PBKDF2 with one strict creation and verification policy.

### Breaking changes

- Module path is now `github.com/fawwazid/go-pbkdf/v2`. Update imports and use Go 1.27.3 or later.
- Replace the mutable DefaultParams variable with DefaultParams() returning an independent value.
- Remove Params.HashFunc, zero-field default substitution, and weak-record verification.
- Require 600,000–1,000,000 iterations, 16–1024 salt bytes, and 32–64 derived-key bytes in every mode.

### Security and maintenance

- Use crypto/pbkdf2 with SHA-256; remove the external dependency.
- Reject noncanonical record order, integer and Base64 encodings; bound inputs before derivation.
- The iteration floor is project policy, not a NIST-mandated count.
- Remove redundant code, obsolete comments, and compatibility paths.
- Add regression tests, current README examples, security guidance, and CI for Linux and Windows.
- FIPS policy tests use the frozen Go module v1.0.0 in both approved and strict assessment modes. This library is not independently FIPS certified; consult SECURITY.md for deployment requirements.

### Install

```sh
go get github.com/fawwazid/go-pbkdf/v2@v2.0.0
```
