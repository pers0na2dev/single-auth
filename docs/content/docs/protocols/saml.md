---
title: "SAML 2.0"
---

Metadata, AuthnRequest, POST and Redirect bindings, XML signatures, assertions, replay protection, encryption, and logout.

Package `github.com/pers0na2dev/single-auth/protocol/saml` implements transport-independent SAML 2.0 service-provider primitives. `plugins/sso` composes them into HTTP routes, provider storage, user provisioning, account/session creation, and redirects.

> **Warning: Use the complete validation pipeline**
>
> Decoding or parsing a SAML response does not authenticate it. Production code must validate signatures, algorithms, issuer, status, timestamps, audience, recipient/destination, request correlation, assertion count, and replay state before using attributes.

## SP-initiated request

```go
request, err := saml.NewAuthnRequest(saml.AuthnRequestOptions{
    Destination:                 "https://idp.example.com/sso",
    AssertionConsumerServiceURL: "https://auth.example.com/api/auth/sso/saml2/sp/acs/corp",
    Issuer:                      "https://auth.example.com/saml/metadata",
    ProtocolBinding:             saml.HTTPPostBinding,
})
if err != nil {
    return err
}

store := saml.NewMemoryStore(nil)
_, err = saml.RecordAuthnRequest(ctx, store, request, "corp", 0, nil)
if err != nil {
    return err
}

location, err := saml.BuildRedirectURL(
    ctx,
    "https://idp.example.com/sso",
    saml.SAMLRequestParameter,
    request.XML,
    relayState,
    spSigner,
    saml.SignatureRSASHA256,
)
```

`NewAuthnRequest` generates a random 20-byte hex ID with an underscore prefix when no ID/generator is supplied. Issue time defaults to UTC now and protocol binding defaults to HTTP-POST. Destination and issuer are required.

`RecordAuthnRequest` stores the request/provider correlation with a five-minute default TTL. A distributed deployment must replace `MemoryStore` with shared storage whose `ConsumeAuthnRequest` is atomic.

The exported defaults are `DefaultAuthnRequestTTL` (5 minutes), `DefaultAssertionTTL` (15 minutes), `DefaultClockSkew` (5 minutes), `DefaultMaxResponseSize` (256 KiB), and `DefaultMaxMetadataSize` (100 KiB).

## Bindings

| Function | Binding behavior |
| --- | --- |
| `EncodePOSTMessage` / `DecodePOSTMessage` | Base64 encodes/decodes XML and enforces a decoded-size bound. |
| `BuildPOSTForm` | Creates an escaped, auto-submitting HTML form for an absolute HTTP(S) action. |
| `EncodeRedirectMessage` / `DecodeRedirectMessage` | Applies raw DEFLATE plus Base64 and enforces compressed/decompressed bounds. |
| `BuildRedirectURL` | Adds SAMLRequest/SAMLResponse, RelayState, SigAlg, and an optional signature over the exact encoded query for an absolute HTTP or HTTPS endpoint. |
| `ParseRedirectBinding` | Rejects duplicate protocol fields, verifies a binding signature, inflates XML, and returns the relay state. |

HTTP-POST XML signing and HTTP-Redirect query signing are different operations. Use `SignAuthnRequest`/`SignXMLMessage` for an enveloped XML signature in POST, and pass a signer to `BuildRedirectURL` for Redirect binding.

## Metadata

```go
document, err := saml.ParseMetadata(metadataXML, saml.DefaultMaxMetadataSize)
if err != nil {
    return err
}
for _, entity := range document.Entities {
    if entity.IDP == nil {
        continue
    }
    certificates := entity.IDP.SigningCertificates()
    redirectSSO, hasRedirect := saml.EndpointForBinding(
        entity.IDP.SingleSignOnServices,
        saml.HTTPRedirectBinding,
    )
    _ = certificates
    _ = redirectSSO
    _ = hasRedirect
}
```

Metadata parsing supports one `EntityDescriptor` or an `EntitiesDescriptor` collection, rejects unsafe XML, and applies an input-size limit. It extracts IdP/SP signing certificates, SSO/SLO/ACS endpoints, name-ID formats, and signing requirements. Treat configured metadata/certificates as trust anchors and control how updates are authorized.

## Complete response validation

```go
clockSkew := 2 * time.Minute
allowIDPInitiated := false

validated, err := saml.ValidatePOSTResponse(ctx, encodedSAMLResponse, relayState,
    saml.ResponseValidationOptions{
        MaxResponseSize: saml.DefaultMaxResponseSize,
        ExpectedIssuer:  "https://idp.example.com/metadata",
        Signatures: saml.SignatureVerificationOptions{
            Certificates: idpCertificates,
            Requirement:  saml.SignatureAssertion,
            Algorithms: saml.AlgorithmValidationOptions{
                OnDeprecated: saml.DeprecatedReject,
            },
        },
        Timestamp: saml.TimestampValidationOptions{
            ClockSkew:         &clockSkew,
            RequireTimestamps: true,
        },
        Binding: saml.ResponseBindingValidationOptions{
            ExpectedAudiences:  []string{"https://auth.example.com/saml/metadata"},
            ExpectedRecipients: []string{"https://auth.example.com/api/auth/sso/saml2/sp/acs/corp"},
        },
        InResponseTo: saml.InResponseToValidationOptions{
            ProviderID:         "corp",
            ExpectedRecipients: []string{"https://auth.example.com/api/auth/sso/saml2/sp/acs/corp"},
            AllowIDPInitiated:  &allowIDPInitiated,
            Store:              store,
        },
        Replay: saml.AssertionReplayOptions{
            ProviderID: "corp",
            Store:      store,
        },
    },
)
if err != nil {
    return err
}
nameID := validated.Response.Assertion.NameID
```

The pipeline performs these gates in order:

1. Bound the encoded and decoded message sizes.
2. Require exactly one plain or encrypted assertion and reject ambiguous/duplicate XML IDs.
3. Validate encryption algorithms and decrypt a required encrypted assertion when configured.
4. Validate every present XML signature and enforce the configured signature placement.
5. Require SAML success status, expected issuer, and a consistent protocol envelope.
6. Validate assertion and subject-confirmation timestamps with clock skew.
7. Validate audience restrictions, bearer recipient, and response destination.
8. Atomically consume `InResponseTo` correlation when present.
9. Atomically reserve the assertion ID, when one is present, to prevent replay while replay protection is enabled.

The zero-value response policy uses a 256 KiB maximum, 5 minutes of clock skew, does not require timestamps, accepts a signature on either the response or assertion, enables request-correlation and replay checks, and permits IdP-initiated responses when `AllowIDPInitiated` is nil. Supply expected audiences and recipients: audience restrictions and bearer recipients are required by the validator. Set `RequireTimestamps=true` and an explicit false `AllowIDPInitiated` value when those stricter policies match your deployment.

Replay protection requires an atomic `AssertionReplayStore` when the assertion has an ID. A missing assertion ID currently emits a warning and is accepted, so applications that require replay-safe assertions must reject a successful result whose assertion ID is empty. The SSO plugin additionally restricts success/error redirect targets to configured/trusted values.

## Signature and encryption algorithms

SHA-256/384/512 RSA and ECDSA signature algorithms are supported. SHA-1 signatures/digests, RSA1_5 key encryption, and Triple DES data encryption are deprecated and controlled by `DeprecatedReject`, `DeprecatedWarn`, or `DeprecatedAllow`. The zero value is `DeprecatedWarn` and writes to the configured warning callback or stderr; set `DeprecatedReject` explicitly for production unless a documented interoperability exception is required.

Encrypted assertions support RSA key transport and AES CBC/GCM data encryption according to the package allow-list. `AssertionDecryptionOptions` requires an RSA private key and, when present, requires the response to contain an encrypted assertion.

Configured signing certificates are treated as trust anchors regardless of their validity dates by default. Set `SignatureVerificationOptions.CheckCertificateValidity` when `NotBefore`/`NotAfter` must be enforced; certificate-path revocation remains an application responsibility.

## Replay and correlation stores

`AuthnRequestStore.ConsumeAuthnRequest` must be a single atomic take. A read followed by delete permits two concurrent callbacks to succeed. `AssertionReplayStore.ReserveAssertion` must atomically compare and insert an unexpired tombstone.

`MemoryStore` is concurrency-safe inside one process and implements both interfaces. Use a database or Redis-backed shared implementation for multiple replicas.

## Single Logout

The package can create, parse, sign, and validate `LogoutRequest` and `LogoutResponse` messages over POST or Redirect bindings. Validation can require signatures and enforces issuer, destination, timestamp, algorithm, certificate, and message-size policy. The SSO plugin adds session-index persistence, SP-initiated logout, IdP-initiated logout, response correlation, local session deletion, and cookie expiry when `EnableSingleLogout` is enabled.

## Errors

Protocol failures expose stable codes through `*saml.Error` and HTTP-facing failures through `*saml.APIError`. Use `saml.IsErrorCode` or `errors.As` for policy decisions. Log the wrapped cause server-side, but return only the stable code/message to a remote party.

For route-level setup, provider registration JSON, attribute mapping, the OIDC alternative, domain verification, provisioning, callback handling, and Single Logout, read [SSO plugin](../plugins/sso.md).
