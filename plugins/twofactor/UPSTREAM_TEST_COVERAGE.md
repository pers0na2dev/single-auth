# single-auth 1.6.26 two-factor coverage

The frozen upstream inventory contains exactly 83 runnable tests:

| Upstream file | IDs | Go coverage |
| --- | ---: | --- |
| `two-factor.account-lockout.test.source` | 7 | account-level cross-challenge/factor lockout, reset, expiry, disable and legacy-null counter tests |
| `two-factor.attempt-cap.test.source` | 4 | TOTP/backup challenge caps, concurrent burst and transient-server-error restoration tests |
| `two-factor.security.test.source` | 15 | cookie-cache leakage/replay, chunk cleanup, single-use challenge and atomic OTP concurrency tests |
| `two-factor.test.source` | 57 | API, TOTP/OTP/backup, trust, passwordless, schema, storage, client and enforcement-scope tests |
| **Total** | **83** | **83 exact IDs mapped to executable Go test references** |

The authoritative frozen ID-to-test mapping is checked into
`testdata/reference-1.6.26-oracle.json` and updated through manual review of
the read-only upstream snapshot. `TestFrozenReferenceTwoFactorOracle` fails if
a frozen ID is removed, duplicated, unmapped, or points at a Go test function
that does not exist.

Validation commands:

```sh
go test ./plugins/twofactor -count=1
go test -race ./plugins/twofactor -count=1
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```
