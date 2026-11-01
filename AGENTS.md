# Agent instructions

This repository is the `go-pbkdf` Go module. Keep changes within this module
unless the task explicitly spans other repositories. Preserve existing user
changes. Do not create or edit changelogs; Release Please generates them.

## Security and API

- Use PBKDF2-HMAC-SHA256 with `crypto/pbkdf2`; preserve canonical encoded
  records and identical parameter policy for creation and verification.
- Keep current bounds on password length, iterations, salt, and derived key.
- Do not add weak-hash fallback or silently accept unsupported encodings.
- Describe FIPS use as conditional on the validated Go module, approved mode,
  operating environment, and consuming application controls. The iteration
  floor is project policy, not a NIST-mandated value.

## Development

- Workspace mail invariant: `go-mail` caps messages at 1,000 recipients, 100
  attachments, and 25 MiB; untrusted attachment bytes use its checked API.
- Workspace MFA invariant: `ConstantTimeCompare` rejects strings longer than
  4,096 UTF-8 bytes before allocating byte slices.

- Target the Go version in `go.mod`; format Go changes with `gofmt`.
- Keep README and security documentation aligned with the record format and
  parameter policy.
- Remove only clearly unused internal code; preserve exported APIs unless a
  breaking change is explicitly requested.
- Add or update regression tests for every code change and run the affected
  module's complete test suite before finishing. Run `go vet ./...` as well.
- Review password-derivation changes against applicable NIST SP 800-132,
  SP 800-63B, OWASP, and FIPS guidance; do not describe project cost limits as
  NIST-mandated.
- For every workspace code, test, or security-policy change, review and update
  all eight module-level `AGENTS.md` files in the same change set so their
  constraints and test-coverage notes stay aligned. Keep updates concise; this
  is not a changelog.

## Test coverage notes

- The latest work changed policy documentation only; PBKDF2 implementation and
  unit tests were unchanged.
