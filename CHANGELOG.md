# Changelog

## [2.0.2](https://github.com/fawwazid/go-pbkdf/compare/v2.0.1...v2.0.2) (2026-11-08)


### Documentation

* document branch and pull request workflow ([b10b115](https://github.com/fawwazid/go-pbkdf/commit/b10b1157d98c25895825d67f9028dbb86a64e428))

## [2.0.1](https://github.com/fawwazid/go-pbkdf/compare/v2.0.0...v2.0.1) (2026-11-01)


### Bug Fixes

* **release:** configure semantic versioning ([#16](https://github.com/fawwazid/go-pbkdf/issues/16)) ([928137b](https://github.com/fawwazid/go-pbkdf/commit/928137b4793ab9a35357df06b71d1ab4794aba4a))


### Documentation

* clarify PBKDF2 and FIPS policy ([#15](https://github.com/fawwazid/go-pbkdf/issues/15)) ([f93dc6d](https://github.com/fawwazid/go-pbkdf/commit/f93dc6d559ba8a243d8fe09ee15bb7d4aee5d55f))


### Chores

* configure Google Release Please ([56d61a9](https://github.com/fawwazid/go-pbkdf/commit/56d61a99c3811ee6c6ee60130bf2ca4edfb143a3))
* reset Release Please baseline ([e3ddfdc](https://github.com/fawwazid/go-pbkdf/commit/e3ddfdcd3b2bbc2c913f5ff02da4ee36c02bf52c))

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

## v1.0.1 — 2026-10-15

- Harden PBKDF2 handling and update `golang.org/x/crypto`.

## v1.0.0 — 2025-12-09

- Initial release of configurable PBKDF2 password hashing and verification.
