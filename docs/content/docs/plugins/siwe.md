---
title: "Sign-In with Ethereum"
description: "Issue single-use wallet nonces, verify EIP-4361 messages, persist wallet identities, and create root sessions."
---

Sign-In with Ethereum (SIWE) issues a wallet- and chain-bound nonce, validates core EIP-4361 message fields, delegates cryptographic signature verification to application code, persists the wallet identity, and creates a normal root session.

## Install and configure

Import `github.com/pers0na2dev/single-auth/plugins/siwe`. `Domain`, `GetNonce`, and `VerifyMessage` are all required; there is no built-in nonce generator or signature verifier. The example uses `crypto/rand` for an EIP-4361-compatible nonce and go-ethereum for EIP-191 recovery.

```go
package main

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "log"
    "net/http"
    "os"
    "strings"

    "github.com/ethereum/go-ethereum/accounts"
    "github.com/ethereum/go-ethereum/common/hexutil"
    ethcrypto "github.com/ethereum/go-ethereum/crypto"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/siwe"
)

func newNonce(_ context.Context) (string, error) {
    value := make([]byte, 16)
    if _, err := rand.Read(value); err != nil {
        return "", err
    }
    return hex.EncodeToString(value), nil
}

func verifyEthereumMessage(_ context.Context, args siwe.VerifyMessageArgs) (bool, error) {
    parsed := siwe.ParseMessage(args.Message)
    if parsed.Version != "1" || parsed.URI != "https://app.example.com" {
        return false, errors.New("unexpected SIWE version or URI")
    }

    signature, err := hexutil.Decode(args.Signature)
    if err != nil || len(signature) != 65 {
        return false, errors.New("invalid Ethereum signature")
    }
    if signature[64] >= 27 {
        signature[64] -= 27
    }
    publicKey, err := ethcrypto.SigToPub(accounts.TextHash([]byte(args.Message)), signature)
    if err != nil {
        return false, err
    }
    recovered := ethcrypto.PubkeyToAddress(*publicKey).Hex()
    return strings.EqualFold(recovered, args.Address), nil
}

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "https://app.example.com",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        PluginFactories: []singleauth.PluginFactory{
            siwe.NewFactory(siwe.Options{
                Domain:          "app.example.com",
                EmailDomainName: "wallet.example.invalid",
                GetNonce:        newNonce,
                VerifyMessage:   verifyEthereumMessage,
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

The sample verifies the personal-sign signature and also applies an application URI/version policy. A production verifier should use a maintained SIWE implementation or perform complete EIP-4361 validation for every field your application relies on.

## HTTP routes

| Method | Path | Input | Success result | Authority |
| --- | --- | --- | --- | --- |
| POST | `/siwe/nonce` | wallet address, optional chain | `nonce` | Public issuance |
| POST | `/siwe/get-nonce` | compatibility alias; address, optional chain | `nonce` | Public issuance |
| POST | `/siwe/verify` | message, signature, wallet address, optional chain/email | `token`, `success`, wallet user | Live nonce plus valid bound message and signature |

All bodies are JSON and limited to 4 MiB.

### Request a nonce

```http
POST /api/auth/siwe/nonce
Content-Type: application/json
Origin: https://app.example.com

{
  "walletAddress": "0x000000000000000000000000000000000000dEaD",
  "chainId": 1
}
```

```json
{"nonce":"5083ae72459198a0dc8340a0ac7e9ca2"}
```

`walletAddress` must be exactly `0x` plus 40 hexadecimal characters. The nonce alias also accepts `address`; if both keys are present, `walletAddress` wins. `chainId` defaults to `1` and must be a positive integer.

The address is converted to EIP-55 checksum form. The server calls `GetNonce` and stores its result for 15 minutes under an identifier derived from checksummed address and chain.

`GetNonce` has no wallet argument because the server performs binding after generation. It must return a fresh, unpredictable value suitable for the EIP-4361 nonce grammar. Do not use timestamps, counters, `math/rand`, wallet addresses, or reusable constants.

Issuing multiple nonces for the same address and chain creates multiple verification rows, but verification selects the newest row and atomically removes all rows for that identifier. An attempt signed with an older nonce can therefore burn the newer challenge. Keep one outstanding request per wallet/chain in the application and discard superseded UI prompts.

### Build and sign the message

The wallet signs an EIP-4361 message containing at least the same domain, wallet address, chain ID, and returned nonce:

```text
app.example.com wants you to sign in with your Ethereum account:
0x000000000000000000000000000000000000dEaD

Sign in to Example.

URI: https://app.example.com
Version: 1
Chain ID: 1
Nonce: 5083ae72459198a0dc8340a0ac7e9ca2
Issued At: 2026-08-10T12:00:00Z
Expiration Time: 2026-08-10T12:10:00Z
```

### Verify and create a session

```http
POST /api/auth/siwe/verify
Content-Type: application/json
Origin: https://app.example.com

{
  "message": "app.example.com wants you to sign in with your Ethereum account:\n...",
  "signature": "0x...",
  "walletAddress": "0x000000000000000000000000000000000000dEaD",
  "chainId": 1
}
```

```json
{
  "token": "session-token",
  "success": true,
  "user": {
    "id": "user-id",
    "walletAddress": "0x000000000000000000000000000000000000dEaD",
    "chainId": 1
  }
}
```

`message`, `signature`, and `walletAddress` are required. `chainId` defaults to 1. `email` is optional when anonymous mode is enabled and required when it is disabled.

Before calling `VerifyMessage`, the server atomically consumes the newest nonce and checks:

- exact nonce match;
- message address equals the EIP-55 request address, case-insensitively;
- message chain equals the request chain;
- normalized message domain equals configured `Domain`;
- a parseable `Expiration Time` is still in the future;
- a parseable `Not Before` is no later than now.

The nonce is consumed before these checks and before cryptographic verification. A malformed message, mismatch, expired message, invalid signature, verifier error, user-creation failure, or session failure burns the challenge. Request a new nonce before retrying.

## What `VerifyMessage` must validate

The built-in parser is intentionally compatibility-tolerant. The server does **not** independently bind or strictly validate URI/audience, version, issued-at, request ID, resources, statement, or invalidly formatted time strings. `VerifyMessage` must cryptographically verify the exact message bytes and enforce any of those fields required by your relying party.

`VerifyMessageArgs` includes:

- exact `Message` and `Signature` strings;
- checksummed `Address` and requested `ChainID`;
- a compatibility `Cacao` object with configured domain as `domain`, `audience`, and issuer, the consumed nonce, version `1`, and EIP-191 signature metadata.

The `Cacao` fields are constructed compatibility data; they are not evidence that the message URI or every EIP-4361 suffix field was parsed and verified. Base policy on the exact signed message and a strict parser.

A verifier error is returned as a redacted 401 response and the nonce stays consumed. Avoid leaking key material, raw signatures, or internal verifier details in public errors. The callback can run concurrently and must be thread-safe.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `Domain` | required | Expected normalized EIP-4361 domain/authority |
| `GetNonce` | required | Cryptographically secure nonce generator |
| `VerifyMessage` | required | Cryptographic signature and application message-policy verifier |
| `Anonymous` | `true` when nil | Permit sign-in without caller-supplied email; explicit false requires valid email |
| `EmailDomainName` | resolved root origin | Domain appended to synthetic wallet email; set an explicit valid email domain in production |
| `ENSLookup` | none | Optional new-user name/avatar lookup by checksummed wallet address |
| `Schema` | built-in wallet schema | Extension/override merged into `walletAddress` schema |

Use a pointer for explicit non-anonymous mode:

```go
anonymous := false
factory := siwe.NewFactory(siwe.Options{
    Domain:          "app.example.com",
    EmailDomainName: "wallet.example.invalid",
    Anonymous:       &anonymous,
    GetNonce:        newNonce,
    VerifyMessage:   verifyEthereumMessage,
})
```

With `Anonymous: false`, verify requires a syntactically valid email and lowercases it. If that email is unused, the new wallet user adopts it. If it already belongs to another user, the plugin deliberately does not link the wallet to that account; it creates the wallet user with a synthetic address instead. SIWE proof is not proof of mailbox ownership.

With anonymous mode, or on an email collision, the synthetic email is `checksummed-address@EmailDomainName`. When `EmailDomainName` is empty, compatibility behavior appends the resolved root origin string, including scheme. Set an explicit valid domain to avoid unusable synthetic addresses and deployment-dependent identities.

`ENSLookup` runs only while creating a new wallet user. A non-empty name replaces the address-based name and avatar populates the root image. An ENS error aborts creation after the nonce has been consumed.

## Wallet and account behavior

Addresses are stored and returned in EIP-55 checksum form. The first wallet row for a new user is primary. A later sign-in with the same address on another chain finds the existing user, adds a non-primary wallet row, and creates another root account whose ID is `address:chainId` with provider ID `siwe`.

Sequential sign-ins for an existing address/chain reuse the same user, wallet row, and provider account, while issuing a new session. The built-in schema does not declare a compound unique constraint on `(address, chainId)`. If independently issued nonces can be verified concurrently for a previously unseen wallet, enforce uniqueness or serialization at the application/storage boundary to prevent duplicate identity creation.

## Schema and migrations

The plugin adds `walletAddress`:

| Field | Type | Behavior |
| --- | --- | --- |
| `userId` | string | Indexed reference to root `user.id` |
| `address` | string | EIP-55 checksummed address |
| `chainId` | number | Positive request chain ID |
| `isPrimary` | boolean | Defaults false; true for the first wallet created with a user |
| `createdAt` | date | Wallet creation time |

It also uses root `user`, `account`, `session`, and `verification`. Apply the wallet-model migration before enabling the routes. `Options.Schema` can override physical table/column names or extend the model; it is cloned and merged with the built-in declaration.

```go
Schema: storage.Schema{Models: map[string]storage.ModelSchema{
    "walletAddress": {
        ModelName: "wallet_address",
        Fields: map[string]storage.FieldAttribute{
            "address": {Type: storage.FieldString, FieldName: "wallet_address"},
            "chainId": {Type: storage.FieldNumber, FieldName: "chain_id"},
        },
    },
}},
```

An override replaces only supplied model/field attributes. Preserve the `userId` reference, required fields, and indexes your adapter needs.

## Direct API

There is no separately bound typed server service. Trusted code can call `getSiweNonce`, `getNonce`, and `verifySiweMessage` through `auth.API().Call`. Direct dispatch still executes the production handlers and mandatory callbacks, but bypasses outer HTTP origin checks, rate limiting, and transport body limits. Preserve abuse controls and pass response cookies to subsequent calls.

## Errors, replay, and troubleshooting

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `VALIDATION_ERROR` | Malformed JSON, wallet, chain, email, message, or signature input |
| 401 | `UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE` | No live newest nonce; expired, replayed, already burned, or wrong wallet/chain |
| 401 | `UNAUTHORIZED_SIWE_MESSAGE_MISMATCH` | Signed message nonce/domain/address/chain does not match server state |
| 401 | `UNAUTHORIZED_SIWE_MESSAGE_EXPIRED` | Parseable expiration is no longer in the future |
| 401 | `UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID` | Parseable not-before time is in the future |
| 401 | `UNAUTHORIZED` | Signature callback returned false or failed; callback errors are redacted |

Atomic nonce consumption allows one success when the same nonce is verified concurrently. Expired rows and all sibling rows for the wallet/chain identifier are removed during consumption. Cross-replica correctness requires an adapter or secondary verification store whose consume primitive is atomic.

- An immediate invalid-nonce response often means another tab requested a newer nonce or a previous failed verify already burned it.
- A message-mismatch response occurs before the verifier; compare exact checksum address, chain, returned nonce, and normalized domain.
- A verifier that accepts arbitrary text with a valid personal-sign signature is unsafe. Require a strict EIP-4361 structure and relying-party fields.
- Invalid date strings are not rejected by the built-in time checks. Reject them in `VerifyMessage` when those fields are present.
- If the same address creates separate users on concurrent first sign-in, add a storage uniqueness/transaction boundary for `(address, chainId)` and the SIWE account ID.
- If synthetic emails contain `@https://`, configure `EmailDomainName` explicitly and migrate affected identities deliberately.
- Never log the signed message if it may contain private statement/resources, and never log session tokens.

## Related pages

- [Sessions](../core/sessions.md)
- [Storage schemas](../storage/schemas.md)
- [Migrations](../storage/migrations.md)
- [Direct API](../transports/direct-api.md)
- [Security](../core/security.md)

**Status:** implemented with required fail-closed callbacks, EIP-55 normalization, nonce expiry/atomic replay protection, strict bound-field checks, email collision policy, multi-chain persistence, schema overrides, direct API, all server transports, and concurrency coverage.
