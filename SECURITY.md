# Security policy

## Current contract

PBKDF2-HMAC-SHA256 uses crypto/pbkdf2. Creation and verification both require
600,000–1,000,000 iterations, 16–1024 salt bytes, and 32–64 derived key bytes.
The iteration floor is project policy, not a NIST-mandated count. Passwords
are bounded at 1 MiB. Only canonical parameter order, integers, and unpadded
Base64 are accepted. Constant-time comparison follows derivation.

DefaultParams() returns a value; explicit Params have no zero-field fallback.
There is no HashFunc selector or verification path for weaker records.
SP 800-132 covers storage key derivation; SP 800-63B-4 supplies the broader
password-verifier requirements an application must implement.

This release removes source and behavior compatibility with the APIs listed
under Breaking changes in README.md. Unsupported inputs are rejected.
Applications must replace unsupported records or enrollments before upgrading;
this library does not provide conversion or permissive verification helpers.

## FIPS deployment

This library is not independently FIPS 140-3 certified. Deployment compliance
depends on the validated Go module, its approved operating environment,
security policy, and application controls. A library cannot enable FIPS mode
for its caller.

The baseline is Go 1.27.3. The frozen Go module v1.0.0 corresponds to
[CMVP certificate 5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247),
checked active on 2026-10-24. Review certificate status and operating-environment
coverage before deployment. A consuming application can build with
GOFIPS140=v1.0.0 and must not override it with fips140=off.
The strict only setting below is an assessment aid, not a production setting.

## Verification

Ordinary checks:

```sh
go mod verify
go vet ./...
go test ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

Dedicated policy tests with the frozen module:

```sh
GOFIPS140=v1.0.0 GODEBUG=fips140=on go test -count=1 -run FIPS ./...
GOFIPS140=v1.0.0 GODEBUG=fips140=only go test -count=1 -run FIPS ./...
```

In PowerShell, set the variables with
`$env:GOFIPS140 = 'v1.0.0'` and `$env:GODEBUG = 'fips140=on'` or
`'fips140=only'`, then run the go test command. Restore the original environment
after checking.

CI is configured for Windows and Linux, including Linux race detection.
Local validation is limited to the platform and commands actually executed;
see the workspace SECURITY_REVIEW.md for the recorded results.

## References

- [Go FIPS documentation](https://go.dev/doc/security/fips140)
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
- [NIST SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final)
