---
title: "Passkey"
description: "Configure native Go WebAuthn registration, authentication, challenge storage, passkey CRUD, origins, and passkey-first identity resolution."
---

Register and authenticate WebAuthn credentials with signed, single-use server challenges and verified authenticator sign counters.

All paths below are relative to the auth `BasePath` (`/api/auth` by default). The Go server creates and verifies WebAuthn options; the browser or platform authenticator still performs `navigator.credentials.create` / `get` or the native equivalent.

## Install and register

Import `github.com/pers0na2dev/single-auth/plugins/passkey`. The factory derives base URL, app name, secret, cookie policy, storage, sessions, and verification services from the root runtime.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/passkey"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        AppName: "Example Account",
        BaseURL: "https://auth.example.com",
        BasePath: "/api/auth",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        TrustedOrigins: []string{"https://app.example.com", "https://admin.example.com"},
        PluginFactories: []singleauth.PluginFactory{
            passkey.NewFactory(passkey.Options{
                RPID:    "example.com",
                RPName:  "Example Account",
                Origins: []string{"https://app.example.com", "https://admin.example.com"},
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

The RP ID must be the effective domain accepted by the authenticator. Each configured origin is an exact WebAuthn origin, including scheme and non-default port. Root `TrustedOrigins` is a separate HTTP CSRF boundary; configure both lists for browser applications.

Compose and migrate the passkey model before serving traffic. See [Schemas](../storage/schemas.md), [Migrations](../storage/migrations.md), and the underlying [WebAuthn protocol](../protocols/webauthn.md).

## Registration ceremony

By default, registration requires a fresh authenticated session for both option generation and verification. Keep one cookie jar for the root session and the five-minute passkey challenge:

```bash
curl --fail-with-body \
  --cookie cookies.txt \
  --cookie-jar cookies.txt \
  'https://auth.example.com/api/auth/passkey/generate-register-options?authenticatorAttachment=platform&name=ada%40example.com'
```

The response is WebAuthn `PublicKeyCredentialCreationOptionsJSON`; values vary per request:

```json
{
  "rp": {"id":"example.com","name":"Example Account"},
  "user": {"id":"<base64url-user-handle>","name":"ada@example.com","displayName":"ada@example.com"},
  "challenge": "<base64url-challenge>",
  "pubKeyCredParams": [{"type":"public-key","alg":-7}],
  "timeout": 60000,
  "excludeCredentials": [],
  "authenticatorSelection": {
    "authenticatorAttachment":"platform",
    "residentKey":"preferred",
    "requireResidentKey":false,
    "userVerification":"preferred"
  },
  "attestation":"none"
}
```

Give those options to the browser/platform authenticator. Convert its binary fields to base64url and post the returned credential object in the `response` envelope. The values below are placeholders, not reusable test credentials:

```bash
curl --fail-with-body \
  --cookie cookies.txt \
  --cookie-jar cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: https://app.example.com' \
  --request POST \
  --data '{
    "name":"Ada laptop",
    "response":{
      "id":"<credential-id>",
      "rawId":"<credential-id>",
      "type":"public-key",
      "response":{
        "clientDataJSON":"<base64url-client-data>",
        "attestationObject":"<base64url-attestation>",
        "transports":["internal"]
      },
      "clientExtensionResults":{},
      "authenticatorAttachment":"platform"
    }
  }' \
  https://auth.example.com/api/auth/passkey/verify-registration
```

A successful response is the persisted passkey:

```json
{
  "id": "<passkey-row-id>",
  "name": "Ada laptop",
  "publicKey": "<standard-base64-cose-key>",
  "userId": "<account-user-id>",
  "credentialID": "<credential-id>",
  "counter": 0,
  "deviceType": "singleDevice",
  "backedUp": false,
  "transports": "internal",
  "createdAt": "<timestamp>",
  "aaguid": "<aaguid>"
}
```

`name` on option generation is the WebAuthn user name. `name` on verification is the optional human-readable label stored with the credential. Existing credentials for the resolved user are returned as `excludeCredentials`.

## Authentication ceremony

Authentication option generation is public. Without a session it omits `allowCredentials`, allowing discoverable credentials and Conditional UI. With an optional session it restricts the list to that user's stored credentials.

```bash
curl --fail-with-body \
  --cookie-jar passkey-cookies.txt \
  https://auth.example.com/api/auth/passkey/generate-authenticate-options
```

Pass the returned `PublicKeyCredentialRequestOptionsJSON` to the authenticator, then submit its assertion with the same challenge cookie:

```bash
curl --fail-with-body \
  --cookie passkey-cookies.txt \
  --cookie-jar passkey-cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: https://app.example.com' \
  --request POST \
  --data '{
    "response":{
      "id":"<credential-id>",
      "rawId":"<credential-id>",
      "type":"public-key",
      "response":{
        "clientDataJSON":"<base64url-client-data>",
        "authenticatorData":"<base64url-authenticator-data>",
        "signature":"<base64url-signature>",
        "userHandle":"<base64url-user-handle>"
      },
      "clientExtensionResults":{}
    }
  }' \
  https://auth.example.com/api/auth/passkey/verify-authentication
```

On success the server verifies the assertion, updates the stored counter, issues the normal root session cookie, and returns:

```json
{"session":{"id":"<session-id>","userId":"<user-id>"},"user":{"id":"<user-id>","email":"ada@example.com"}}
```

The browser-side Conditional UI call, mediation mode, cancellation handling, and ArrayBuffer/base64url conversion remain application responsibilities. The Go plugin does not pretend to implement a browser client.

## Endpoint reference

| Method | Path | Input | Result | Authority and important validation |
| --- | --- | --- | --- | --- |
| GET | `/passkey/generate-register-options` | Optional `authenticatorAttachment=platform|cross-platform`, `name`, `context` | Registration options and challenge cookie | Fresh session by default; otherwise optional session or `Registration.ResolveUser` |
| POST | `/passkey/verify-registration` | Object-valued WebAuthn `response`; optional credential `name` | Persisted passkey | Same fresh registration identity by default, signed unexpired registration challenge, exact RP/origin/protocol checks |
| GET | `/passkey/generate-authenticate-options` | No body | Authentication options and challenge cookie | Public; optional session narrows `allowCredentials` |
| POST | `/passkey/verify-authentication` | Object-valued WebAuthn `response` | `{session,user}` and session cookie | Signed unexpired authentication challenge, known credential, signature/origin/RP/counter checks |
| GET | `/passkey/list-user-passkeys` | No body | Passkey array | Required session; only current user's rows |
| POST | `/passkey/delete-passkey` | String `id` | `{"status":true}` | Required owning-user session |
| POST | `/passkey/update-passkey` | String `id`, non-whitespace string `name` | `{"passkey":{...}}` | Required owning-user session |

Verification request bodies are limited to 4 MiB, must contain one JSON document, and reject trailing values. Starting a new option-generation request replaces the challenge-cookie pointer in that cookie jar, so do not run parallel registration and authentication ceremonies in the same jar.

Manage labels without touching credential material:

```bash
curl --fail-with-body \
  --cookie cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: https://app.example.com' \
  --request POST \
  --data '{"id":"<passkey-row-id>","name":"Primary security key"}' \
  https://auth.example.com/api/auth/passkey/update-passkey
```

## Options and defaults

| Option | Default and behavior |
| --- | --- |
| `RPID` | Hostname from root `BaseURL`, then `localhost` |
| `RPName` | Root `AppName` |
| `Origins` / `Origin` | Nil/empty; see the explicit precedence below |
| `Registration.RequireSession` | `true` |
| `Registration.ResolveUser` | nil; required for unauthenticated registration when session requirement is false |
| `AuthenticatorSelection` | Resident key `preferred`, user verification `preferred`, no fixed attachment |
| Request attachment override | Empty; query accepts only `platform` or `cross-platform` |
| Registration attestation | Fixed to `none` |
| Authentication user verification | `preferred`; protocol verifier does not force UV when the authenticator returns otherwise valid flags |
| Registration/authentication extensions | nil; static map and request resolver are mutually exclusive per ceremony |
| Verification callbacks | nil |
| Challenge lifetime | 5 minutes |
| `Advanced.WebAuthnChallengeCookie` | `single-auth-passkey` key, resolved through the root cookie policy |
| `Schema` | Canonical passkey model/fields |

`AuthenticatorSelection` controls attachment, resident-key policy, `RequireResidentKey`, and user verification. The request query can override only attachment. `Registration.Extensions` and `ResolveExtensions` cannot both be set; the same rule applies to authentication. Resolver outputs are request-local and errors abort option generation.

`Registration.AfterVerification` runs after protocol verification and may supply a final user ID and credential label. It cannot reassign away from an authenticated session user. `Authentication.AfterVerification` runs after assertion verification and before the counter update/session issue. Callback errors fail the ceremony, and the already-consumed challenge is not restored.

Set `Origins` explicitly in production. If it is non-nil it is authoritative; otherwise `Origin` is used, and only when neither option is configured does the implementation accept the request's `Origin` header as the expected origin. That last fallback is compatibility behavior, not a recommended trust policy.

An explicitly empty non-nil `Origins` slice is still authoritative and causes verification to have no allowed origin. Origins are exact values; do not put paths in them and do not rely on root `TrustedOrigins` as a substitute.

## Passkey-first registration

To mint registration options before a normal session exists, disable the requirement explicitly and resolve a stable application identity:

```go
passkey.NewFactory(passkey.Options{
    RPID:    "example.com",
    RPName:  "Example Account",
    Origins: []string{"https://app.example.com"},
    Registration: passkey.RegistrationOptions{
        RequireSession: passkey.Bool(false),
        ResolveUser: func(args passkey.ResolveRegistrationUserArgs) (passkey.RegistrationUser, error) {
            claim, err := consumeSignedEnrollmentClaim(args.Context)
            if err != nil {
                return passkey.RegistrationUser{}, err
            }
            return passkey.RegistrationUser{
                ID: claim.UserID, Name: claim.Email, DisplayName: claim.DisplayName,
            }, nil
        },
    },
})
```

`context` is an opaque query string passed to `ResolveUser`, stored with the registration challenge, and passed again to the registration after-verification callback. It is not authenticated by the plugin on its own. The resolver must validate/consume its own signed or one-time claim, return a non-empty stable `ID` and `Name`, and avoid trusting an arbitrary email or user ID from the raw query.

If a session appears before verification, its user must match the identity bound into the challenge. This prevents an anonymous challenge from being silently attached to a different signed-in account.

## Storage schema and migrations

The plugin contributes one `passkey` model:

| Field | Behavior |
| --- | --- |
| `name` | Optional human-readable label |
| `publicKey` | Standard-base64 encoded credential public key |
| `userId` | Indexed user reference with cascade delete |
| `credentialID` | Indexed WebAuthn credential ID |
| `counter` | Last accepted authenticator sign counter |
| `deviceType` / `backedUp` | Credential backup characteristics reported at registration |
| `transports` | Optional comma-separated authenticator transports |
| `createdAt` / `aaguid` | Optional registration metadata |

`credentialID` is indexed but not unique in the canonical schema. Option generation excludes credentials already stored for the resolved user, but the database does not enforce global credential-ID uniqueness by default. Account for that fact when importing or writing credentials outside this plugin.

Challenges use the core `verification` model rather than the passkey table. Stored values include the ceremony type, expected challenge, bound registration identity, and optional flow context. Changing schema aliases requires a migration.

## Replay, counters, and concurrency

The challenge cookie contains a random handle and root-secret signature; the protocol challenge and bound identity remain server-side. The server checks cookie signature, expiry, ceremony type, expected challenge, RP ID, exact origin, credential type, authenticator flags, signature, owner, and sign counter as applicable.

Challenge consumption uses core `ConsumeVerification`/`Adapter.ConsumeOne`. The row is consumed before protocol verification, so malformed or failed protocol responses normally burn the ceremony and require new options. Registration and authentication challenges cannot be swapped. Untagged challenges created by versions before 1.6.17 remain accepted during an in-flight upgrade.

Concurrent verification of the same challenge can create at most one passkey or session. Authenticator replay is also checked against the stored sign counter, and a successful assertion writes `NewCounter`. That counter write is an ordinary adapter update rather than a compare-and-set against the old counter; do not describe independent simultaneous ceremonies for the same credential as atomically serialized by the counter alone. The single-use challenge closes replay of one ceremony, while backend transaction/serialization policy governs separate concurrent ceremonies.

## Errors and direct API

Common codes include `CHALLENGE_NOT_FOUND`, `SESSION_REQUIRED`, `RESOLVE_USER_REQUIRED`, `RESOLVED_USER_INVALID`, `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY`, `FAILED_TO_VERIFY_REGISTRATION`, `PASSKEY_NOT_FOUND`, `AUTHENTICATION_FAILED`, `UNABLE_TO_CREATE_SESSION`, and `FAILED_TO_UPDATE_PASSKEY`. Missing/expired/consumed/wrong-ceremony challenges return 400 `CHALLENGE_NOT_FOUND`. Unknown credentials return 401 `PASSKEY_NOT_FOUND`. Match on code; protocol and callback failures may preserve a more specific API error.

`NewFactory` is the normal root integration. `New` is reserved for explicit-runtime embedding and requires the adapter, session resolver/issuer, and challenge services to be supplied correctly. Trusted direct calls can invoke the same registered operation names through `auth.API()`, but HTTP-only CSRF, origin-path middleware, and rate limiting are outside the direct boundary; see [Direct API](../transports/direct-api.md).

Exported declarations are listed in the [passkey package reference](../reference/packages/plugins--passkey.md). See also [Security](../core/security.md), [Sessions](../core/sessions.md), and [Storage transactions](../storage/transactions.md). **Status:** implemented with native WebAuthn verification.
