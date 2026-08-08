---
title: "WebAuthn"
---

Generate credential options and verify passkey registration and authentication responses in Go.

Package `github.com/pers0na2dev/single-auth/protocol/webauthn` implements the protocol layer used by the Passkey plugin. It generates browser-compatible options, decodes client/authenticator data, verifies attestation and assertion signatures, enforces origin/RP/challenge/user-verification policy, and returns persistence-ready credential records.

The package has no browser API wrapper and no storage. Use [Passkey plugin](../plugins/passkey.md) for ready-to-mount routes, challenge storage, credential persistence, sessions, and account behavior.

## Registration options

```go
creation, err := webauthn.GenerateRegistrationOptions(
    webauthn.GenerateRegistrationOptionsInput{
        RPName:          "Example",
        RPID:            "example.com",
        UserName:        user.Email,
        UserDisplayName: user.Name,
        UserID:          []byte(user.ID),
        ExcludeCredentials: []webauthn.CredentialDescriptor{
            {
                ID:         existingCredential.ID,
                Transports: existingCredential.Transports,
            },
        },
    },
)
if err != nil {
    return err
}
```

Defaults:

| Option | Default |
| --- | --- |
| Challenge | 32 cryptographically random bytes when omitted |
| User ID | 32 random bytes when `UserID` is nil |
| Timeout | 60,000 ms |
| Attestation | `none` |
| Algorithms | EdDSA, ES256, RS256 in that preference order |
| Resident key | `preferred` |
| Require resident key | `false` |
| User verification | `preferred` in generated options |
| Extension | `credProps: true` is always added |

`PreferredAuthenticatorType` accepts `securityKey`, `localDevice`, or `remoteDevice` and sets WebAuthn hints plus authenticator attachment. An explicit `AuthenticatorSelection` overrides the default selection policy. Credential IDs are normalized as unpadded base64url and bounded in size.

Serialize `CreationOptionsJSON` to the browser and pass it to `navigator.credentials.create({ publicKey })`. Persist the exact challenge or a one-time challenge verifier before returning it.

## Verify registration

```go
requireUserVerification := true
verified, err := webauthn.VerifyRegistrationResponse(
    webauthn.VerifyRegistrationOptions{
        Response:                browserResponse,
        ExpectedChallenge:       storedChallenge,
        ExpectedOrigins:         []string{"https://app.example.com"},
        ExpectedRPIDs:           []string{"example.com"},
        RequireUserVerification: &requireUserVerification,
    },
)
if err != nil {
    return err
}
if !verified.Verified || verified.RegistrationInfo == nil {
    return errors.New("registration was not verified")
}

credential := verified.RegistrationInfo.Credential
// Persist credential.ID, PublicKey, Counter, and Transports with the user.
```

Registration verification checks:

- credential ID/raw ID/type consistency;
- client-data type `webauthn.create` (or an explicit accepted type), challenge, and origin;
- RP ID hash;
- user-presence and user-verification flags;
- authenticator-data structure, credential ID, AAGUID, and COSE public key;
- the configured COSE algorithm allow-list;
- attestation statement/certificate/signature rules;
- backup eligibility/state flag consistency;
- strict input-size ceilings for client data, attestation, authenticator data, public key, credential ID, and signatures.

`ChallengeVerifier` can replace direct string equality when the application stores hashed or structured one-time challenges. It must atomically consume the challenge to prevent replay.

> **Warning: Cross-origin is caller policy**
>
> The low-level verifier decodes `clientDataJSON.crossOrigin` but currently does not reject a true value. If cross-origin ceremonies are outside your trust model, decode/check that field before accepting the verification result.

Registration defaults both user presence and user verification to required when their pointer options are nil. `ExpectedOrigins` must contain the browser origin. RP ID validation is performed only when `ExpectedRPIDs` is non-nil, so production callers should always pass an explicit list.

## Authentication options

```go
request, err := webauthn.GenerateAuthenticationOptions(
    webauthn.GenerateAuthenticationOptionsInput{
        RPID: "example.com",
        AllowCredentials: []webauthn.CredentialDescriptor{
            {
                ID:         credential.ID,
                Transports: credential.Transports,
            },
        },
        UserVerification: "required",
    },
)
```

The default timeout is 60,000 ms and default user-verification hint is `preferred`. A nil `AllowCredentials` permits discoverable credentials; a non-nil list is copied and normalized.

Serialize `RequestOptionsJSON` and pass it to `navigator.credentials.get({ publicKey })`. Store the generated challenge before returning it.

## Verify authentication

```go
requireUserVerification := true
verified, err := webauthn.VerifyAuthenticationResponse(
    webauthn.VerifyAuthenticationOptions{
        Response:                browserAssertion,
        ExpectedChallenge:       storedChallenge,
        ExpectedOrigins:         []string{"https://app.example.com"},
        ExpectedRPIDs:           []string{"example.com"},
        Credential:              credential,
        RequireUserVerification: &requireUserVerification,
    },
)
if err != nil {
    return err
}
if !verified.Verified {
    return errors.New("assertion signature was not verified")
}

newCounter := verified.AuthenticationInfo.NewCounter
// Persist newCounter atomically before creating a session.
```

Authentication verifies client data, RP ID, user-presence/verification policy, backup flags, the monotonic signature counter, and the signature over `authenticatorData || SHA-256(clientDataJSON)`.

Authentication defaults user verification to required when `RequireUserVerification` is nil. Supplying `AdvancedFIDOConfig` or `AdvancedUserVerification` switches to compatibility semantics: user presence is not checked, and user verification is checked only when the advanced value is exactly `required`. Do not enable that path unless this weaker flag policy is intentional.

`ValidateSignCount` permits authenticators that report zero forever only while both stored and reported values are zero. Once either value is non-zero, the reported counter must strictly increase. Persist the new counter in the same security boundary that accepts the authentication result.

## Keys and algorithms

Credential public keys are COSE/CBOR values. `DecodeCredentialPublicKey` parses OKP, EC2, and RSA representations and `CryptoPublicKey` returns a Go crypto public key. Verification supports:

- Ed25519 / EdDSA;
- NIST ECDSA curves used by ES256 and ES512;
- RSA PKCS#1 v1.5 and RSA-PSS variants in the package allow-list.

The registration verification allow-list is EdDSA, ES256, ES512, PS256/384/512, RS256/384/512, and RS1. Generated registration options advertise only EdDSA, ES256, and RS256 unless the caller supplies a different list.

The package defines the secp256k1 identifier for wire decoding compatibility but does not include ES256K in the supported verification allow-list; secp256k1 credentials are rejected.

## Attestation formats

Registration supports `none`, `packed`, `fido-u2f`, `android-key`, `android-safetynet`, `apple`, and `tpm`. Embedded default roots exist only for `android-key`, `android-safetynet`, and `apple`. For other formats, a nil root pool skips certificate-chain validation, so supply `AttestationRoots` by format whenever attestation trust is part of the acceptance decision. Android SafetyNet CTS enforcement defaults to true and can be controlled with the pointer option.

The current package does not implement FIDO Metadata Service synchronization, revocation-list fetching, or a general browser compatibility layer. If your policy depends on authenticator model status or certificate revocation, provide that lifecycle outside the package and update root pools/policy accordingly.

## Origin and RP ID

Origin and RP ID are separate checks. Origins include the scheme and host (and non-default port); RP IDs are domain identifiers hashed into authenticator data. Supply explicit expected lists derived from server configuration, not request headers, unless those headers have already passed trusted-proxy validation.

## Input ceilings

The verifier rejects client data above 64 KiB, attestation objects above 2 MiB, authenticator data above 1 MiB, credential public keys above 16 KiB, credential IDs above 1,024 bytes, and signatures above 16 KiB. Apply a smaller HTTP request-body limit at the route boundary when your deployment does not need those maxima.
