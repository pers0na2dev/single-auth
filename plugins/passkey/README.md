# Passkey plugin

`passkey` is the transport-neutral server port of `@single-auth/passkey` 1.6.26.
Registering its `engine.Plugin` makes the same endpoints available through the
project's `net/http`, `fasthttp`, and Fiber transports.

## Compatibility surface

The package ports the upstream model schema, error catalogue, RP and origin
options, authenticator selection, registration and authentication extensions,
passkey-first user resolution, verification callbacks, passkey CRUD, and the
five-minute signed-cookie challenge lifecycle. Challenges are atomically
consumed before protocol verification, tagged by ceremony, and accept the
untagged pre-1.6.17 representation during an in-flight upgrade.

The unauthenticated authentication-options response deliberately omits
`allowCredentials`. That is the server half of WebAuthn Conditional UI and lets
the browser use discoverable credentials. Calls to `navigator.credentials`,
`mediation: "conditional"`, input `autocomplete="webauthn"`, browser cancellation
mapping, and client-store invalidation remain JavaScript/browser concerns; they
cannot be implemented by a Go HTTP server package.

## Root runtime integration

The current public `engine.Context` intentionally contains transport request and
response state, but does not expose the root auth adapter or session manager.
Until the root runtime provides those dependencies to plugins, callers must pass
them explicitly in `Options.Runtime`:

- `Adapter` is the configured `storage.Adapter`. Its schema must be constructed
  from `storage.CoreSchema()` merged with the plugin descriptor's schema. The
  adapter must implement the atomic `ConsumeOne` contract used for single-use
  verification challenges.
- `ResolveSession` resolves an optional, required, or fresh session and its user.
  `SessionFresh` must apply the application's configured freshness policy.
- `IssueSession` creates the authenticated session, resolves its user, and adds
  the normal session cookie(s) to the supplied `engine.Context`.

`Runtime.Clock`, `Runtime.Random`, and both protocol verifiers are injectable for
deterministic tests; production defaults use the system clock, `crypto/rand`, and
the local `webauthn` implementation.

```go
plugin, err := passkey.New(passkey.Options{
	BaseURL: "https://example.com",
	Runtime: passkey.Runtime{
		Adapter:        adapter,
		ResolveSession: resolveSession,
		IssueSession:   issueSession,
	},
})
```

## Endpoints

| Method | Path |
| --- | --- |
| `GET` | `/passkey/generate-register-options` |
| `GET` | `/passkey/generate-authenticate-options` |
| `POST` | `/passkey/verify-registration` |
| `POST` | `/passkey/verify-authentication` |
| `GET` | `/passkey/list-user-passkeys` |
| `POST` | `/passkey/delete-passkey` |
| `POST` | `/passkey/update-passkey` |

`testdata/options-oracle.json` is a frozen deterministic oracle derived from
single-auth 1.6.26 and `@simplewebauthn/server` 13.2.3. Package tests additionally
cover the upstream lifecycle, error status, ownership, identity, naming,
expiration, ceremony, legacy-upgrade, and concurrent-consumption cases.
