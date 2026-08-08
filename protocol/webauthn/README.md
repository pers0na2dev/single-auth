# Better Auth passkey protocol layer

This package ports the server-side protocol behavior used by Better Auth
`1.6.26`'s passkey plugin (`@simplewebauthn/server` `13.2.3`). It is independent
of HTTP routing, cookies, challenge storage, and the passkey database model.

Implemented protocol surface:

- registration and authentication option generation;
- bounded base64url, JSON, CBOR, authenticator-data, and COSE parsing;
- RP ID, origin, challenge, ceremony type, UP/UV, BE/BS, and sign-counter checks;
- EC2 (P-256/P-384/P-521), RSA (PKCS#1 v1.5 and PSS), and OKP Ed25519 signatures;
- `none`, `packed` (self and x5c), `fido-u2f`, `android-key`,
  `android-safetynet`, Apple, and TPM attestation statements;
- the Apple, Google Android Key, and GlobalSign SafetyNet trust anchors shipped
  by SimpleWebAuthn 13.2.3, with per-format root overrides.

The fixed Go fixtures are copied from SimpleWebAuthn 13.2.3's registration,
authentication, authenticator-data, and backup-flag tests. Fixture updates are
manually reviewed against the read-only upstream snapshot.

```sh
go test ./webauthn
go test -race ./webauthn
```

Metadata Service (MDS) policy, online CRL fetching, browser-side
`navigator.credentials` wrappers, Better Auth routes/cookies/storage, and
plugin hooks are intentionally outside this protocol-only package.

There are no omitted public attestation formats from SimpleWebAuthn 13.2.3.
Two upstream infrastructure branches remain outside the package: FIDO MDS
statement/status enforcement and network-backed certificate revocation checks.
The upstream code enumerates secp256k1 (`crv=8`) but its EC verifier rejects
that curve; this package rejects it explicitly as well because Go's standard
library does not provide secp256k1.
