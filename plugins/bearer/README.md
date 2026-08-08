# Bearer plugin

`bearer` is the transport-neutral server port of single-auth 1.6.26's built-in
bearer plugin. Its engine hooks work through the same `net/http`, `fasthttp`, and
Fiber dispatch pipeline.

## Behavior

Before every matched endpoint, a valid `Authorization: Bearer <token>` value is
converted into the configured signed session cookie:

- the auth scheme is ASCII case-insensitive as required by RFC 7235;
- a signed token is URL-decoded when necessary and HMAC-SHA256 verified;
- a raw token is first signed unless `RequireSignature` is true;
- an empty, malformed, incorrectly signed, or non-bearer value is ignored
  without an authentication error;
- invalid authorization never removes or overwrites an existing valid cookie;
- a valid bearer value takes precedence over an existing session cookie while
  preserving every unrelated request cookie.

After every endpoint response, a non-empty session `Set-Cookie` whose
`Max-Age` is not zero is copied to `set-auth-token`. The hook adds the lowercase
header name to `Access-Control-Expose-Headers`, preserving the upstream
case-sensitive JavaScript `Set` ordering and deduplication behavior. Logout
cookie writes are not exposed as new tokens.

## Root runtime integration

single-auth gives the plugin its normalized auth secret and resolved session
cookie name through an internal hook context. The public Go `engine.Context`
does not expose root auth configuration, so this port makes those two immutable
dependencies explicit:

```go
plugin, err := bearer.New(bearer.Options{
	RequireSignature: false,
	Runtime: bearer.Runtime{
		Secret:            normalizedAuthSecret,
		SessionCookieName: resolvedSessionCookieName,
	},
})
```

The root integration should construct this descriptor after cookie
normalization and pass its private `cookie.sessionName`; hard-coding
`single-auth.session_token` would be incorrect for secure prefixes and custom
cookie overrides. No adapter or session-manager dependency is needed: the
normal root session path authenticates the injected cookie after the before
hook runs.

## Compatibility evidence

`testdata/bearer-oracle.json` freezes the signature and wire values produced by
single-auth 1.6.26, `better-call` 1.4.0, and `@single-auth/utils` 0.5.0. Tests
cover the upstream server and direct-call flows, raw-token compatibility,
`requireSignature`, standard and URL-safe signatures, encoded tokens, malformed
input, existing-cookie precedence, repeated and comma-joined `Set-Cookie`, CORS
exposure, logout, typed-error responses, and concurrent dispatch.
