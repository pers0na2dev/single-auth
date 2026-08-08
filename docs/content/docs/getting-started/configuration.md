---
title: "Configuration"
---

Every root option, its default, and the distinctions encoded by pointer values.

`singleauth.New` validates and snapshots `singleauth.Options`. Slices, maps, plugin and endpoint descriptors, hook lists, provider descriptions, and pointer-backed values are copied. Changing the input after construction does not reconfigure the runtime.

```go
package authconfig

import (
    "os"
    "time"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/storage"
)

func New(adapter storage.Adapter) (*singleauth.Auth, error) {
    updateAge := 12 * time.Hour

    return singleauth.New(singleauth.Options{
        AppName:     "Acme",
        Environment: "production",
        BaseURL:     "https://accounts.example.com",
        BasePath:    "/api/auth",
        Secret:      os.Getenv("SINGLE_AUTH_SECRET"),
        Database:    adapter,
        EmailAndPassword: singleauth.EmailAndPasswordOptions{
            Enabled: true,
        },
        Session: singleauth.SessionOptions{
            UpdateAge: &updateAge,
        },
        TrustedOrigins: []string{"https://app.example.com"},
    })
}
```

The root package exports `User`, `Session`, `Account`, `Verification`, `RateLimit`, `Request`, `Response`, `APIError`, `Endpoint`, `Plugin`, and `DirectInput` aliases, but the adapter interface itself lives in `github.com/pers0na2dev/single-auth/storage`. Use `storage.Adapter` in application signatures.

## Top-level options

| Field | Purpose and default |
| --- | --- |
| `AppName` | User-facing application name. Defaults to `"Better Auth"`. |
| `Environment` | Explicit runtime mode such as `development`, `test`, or `production`. Empty stays empty; the root runtime does not infer `SINGLE_AUTH_ENV`. |
| `BaseURL` | Static public auth URL. Mutually exclusive with `DynamicBaseURL`. If empty, environment variables are checked in the order documented below. |
| `DynamicBaseURL` | Per-request host resolution with an allowlist. Mutually exclusive with `BaseURL`. |
| `BasePath` | Mounted auth prefix. Defaults to `/api/auth`; `/` means no prefix. |
| `Secret` | Legacy signing/encryption secret. Explicit value wins, followed by `SINGLE_AUTH_SECRET`, then `AUTH_SECRET`. |
| `Secrets` | Ordered versioned secret ring. The first entry is the active `Secret`; all entries can decode supported version-tagged encrypted values. Signed values still use only the active secret. |
| `Database` | Primary `storage.Adapter`. Empty selects a process-local memory adapter. |
| `DatabaseHooks` | Create, update, and delete lifecycle hooks by canonical model name. |
| `Schema` | Additional or overridden storage schema merged with core and plugin schemas. |
| `EmailAndPassword` | Credential endpoint, password policy, reset, and callback settings. Disabled by default. |
| `EmailVerification` | Verification sender, lifetime, and lifecycle callbacks. No sender by default. |
| `User` | Change-email and delete-user behavior. Both capabilities are disabled by default. |
| `Session` | Session lifetime, refresh, secondary persistence, and cookie-cache settings. |
| `Verification` | Single-use value persistence and identifier hashing. |
| `Account` | OAuth token storage, state strategy, account cookie, and linking policy. |
| `Advanced` | Cookie, proxy, IP, origin, CSRF, and trailing-slash settings. |
| `OnAPIError` | Error-page redirect and default-page customization. |
| `RateLimit` | HTTP rate limiting. An omitted `Enabled` is on only when `Environment == "production"`. |
| `SecondaryStorage` | String-valued session, verification, and rate-limit store. Mutually exclusive with `SecondaryValueStorage`. |
| `SecondaryValueStorage` | Object-valued secondary store for wrappers that decode JSON before returning it. |
| `Logger` | Leveled logger options. Default threshold is `warn`. |
| `SocialProviders` | Provider ID to configured `*providers.Provider`. Empty means no social providers. |
| `TrustedOrigins` | Static browser and redirect origins added to the runtime's own origin. |
| `ResolveTrustedOrigins` | Request-scoped trusted-origin callback. |
| `DisabledPaths` | Exact endpoint-relative paths rejected with 404 before plugin `OnRequest`. |
| `Plugins` | Static `engine.Plugin` descriptors. |
| `PluginFactories` | Runtime-bound plugin factories whose schemas are known before adapter creation. |
| `Endpoints` | Custom endpoints merged after core endpoints. |
| `Middleware` | User path middleware, executed after core security middleware and before plugin middleware. |
| `Hooks` | User before and after endpoint hooks. |
| `Clock` | Defaults to `time.Now`; useful for deterministic tests. |
| `Random` | Defaults to `crypto/rand.Reader`. |
| `GenerateID` | Defaults to random 32-character IDs; returning `generated=false` delegates ID creation to the database. |
| `HTTPClient` | Shared provider client. Defaults to `&http.Client{Timeout: 30 * time.Second}`. |
| `RunBackground` | Non-critical work runner. Nil executes the callback synchronously and returns its error. |

## Normalized defaults

### Credentials and email

| Option | Default |
| --- | --- |
| `EmailAndPassword.Enabled` | `false` |
| `DisableSignUp` | `false` |
| `RequireEmailVerification` | `false` |
| `MinPasswordLength` | 8 UTF-16 code units |
| `MaxPasswordLength` | 128 UTF-16 code units |
| `Password.Hash` / `Password.Verify` | Built-in scrypt implementation |
| `AutoSignIn` | Omitted means enabled; explicit `false` disables it |
| `ResetPasswordTokenExpiresIn` | 1 hour |
| `RevokeSessionsOnReset` | `false` |
| `EmailVerification.ExpiresIn` | 1 hour |
| `EmailVerification.SendOnSignUp` | Omitted follows `RequireEmailVerification` |
| `SendOnSignIn` / `AutoSignInAfterVerification` | `false` |
| `User.ChangeEmail.Enabled` | `false` |
| `User.DeleteUser.Enabled` | `false` |
| `User.DeleteUser.DeleteTokenExpiresIn` | 24 hours |

### Sessions, verifications, and accounts

| Option | Default |
| --- | --- |
| `Session.ExpiresIn` | 7 days |
| `Session.UpdateAge` | 24 hours; explicit zero refreshes on every eligible read |
| `Session.FreshAge` | 24 hours; explicit zero makes every valid session fresh |
| `Session.Stateless` | `false` |
| `DisableSessionRefresh` / `DeferSessionRefresh` | `false` |
| `StoreSessionInDatabase` / `PreserveSessionInDatabase` | `false` |
| `CookieCache.Enabled` | `false` |
| `CookieCache.MaxAge` | 5 minutes |
| `CookieCache.Strategy` | `compact`; alternatives are `jwt` and `jwe` |
| `CookieCache.Version` | `"1"` |
| `CookieCache.RefreshCache` | `false` |
| `RefreshCacheUpdateAge` | Omitted; when refresh is enabled, floor of 20% of `MaxAge` |
| `Verification.DisableCleanup` | `false` |
| `Verification.StoreInDatabase` | `false`; relevant when secondary storage is configured |
| `Verification.StoreIdentifier` | Plain identifiers |
| `Account.StoreStateStrategy` | `cookie` only when no explicit primary or secondary store was configured; otherwise `database` |
| `Account.StoreAccountCookie` | `true` when no explicit primary database was supplied, otherwise `false` |
| `Account.UpdateAccountOnSignIn` | Omitted means `true` |
| `Account.EncryptOAuthTokens` | `false` |
| `Account.AccountLinking.Enabled` | Omitted means `true` |
| `AllowUnlinkingAll`, `AllowDifferentEmails`, `DisableImplicitLinking`, `UpdateUserInfoOnLink` | `false` |
| `RequireLocalEmailVerified` | Omitted means `true` |

### Cookies, security, and rate limiting

| Option | Default |
| --- | --- |
| `Advanced.CookiePrefix` | `better-auth` |
| Default cookie attributes | `Path=/`, `HttpOnly`, `SameSite=Lax`; `Secure` is derived |
| `UseSecureCookies` | Explicit pointer wins; otherwise static URL scheme, pinned dynamic protocol, or `Environment == "production"` for dynamic `auto`/empty |
| `DisableCSRFCheck` / `DisableOriginCheck` | Checks enabled |
| `TrustedProxyHeaders` | `false` for ordinary/static mode, `true` for dynamic base URLs, unless explicitly set |
| `SkipOriginCheckPaths` | Empty |
| `CrossSubDomainCookies.Enabled` | `false` |
| `SkipTrailingSlashes` | `false` |
| `RateLimit.Enabled` | Omitted: enabled only in explicit production mode |
| `RateLimit.Window` / `Max` | 10 seconds / 100 requests |
| `RateLimit.Storage` | Secondary storage when configured; otherwise isolated memory |
| `RateLimit.ModelName` | `rateLimit` |
| `Logger.Level` | `warn` |

## Pointer values are intentional

Several booleans and durations distinguish omission from an explicit false or zero. Keep small helpers in application code:

```go
func boolPtr(value bool) *bool { return &value }

func durationPtr(value time.Duration) *time.Duration { return &value }

options := singleauth.Options{
    EmailAndPassword: singleauth.EmailAndPasswordOptions{
        Enabled:    true,
        AutoSignIn: boolPtr(false),
    },
    Session: singleauth.SessionOptions{
        UpdateAge: durationPtr(0), // refresh on every eligible read
        FreshAge:  durationPtr(0), // every valid session is fresh
    },
    Advanced: singleauth.AdvancedOptions{
        DisableOriginCheck: boolPtr(false),
        DisableCSRFCheck:   boolPtr(false),
    },
}
```

An explicit `DisableOriginCheck: true` with an omitted `DisableCSRFCheck` uses Better Auth 1.6 backward compatibility, disables both checks, and emits a warning. Setting `DisableCSRFCheck` explicitly to false opts out of that compatibility branch, but current CSRF proof is itself origin-based: `DisableOriginCheck: true` still makes the CSRF validator return without checking an origin. Leave both settings false or unset to preserve protection.

## Base URL resolution

When `BaseURL` and `DynamicBaseURL` are both absent, the first non-empty environment variable wins:

1. `SINGLE_AUTH_URL`
2. `NEXT_PUBLIC_SINGLE_AUTH_URL`
3. `PUBLIC_SINGLE_AUTH_URL`
4. `NUXT_PUBLIC_SINGLE_AUTH_URL`
5. `NUXT_PUBLIC_AUTH_URL`
6. `BASE_URL`

`BASE_URL=/` is ignored. Static values must include `http://` or `https://`. If their URL path is empty, `BasePath` is appended; if the URL already contains a path, that path is retained.

Use a static URL whenever possible. Dynamic resolution requires a non-empty host allowlist:

```go
DynamicBaseURL: &singleauth.DynamicBaseURLOptions{
    AllowedHosts: []string{"accounts.example.com", "*.tenant.example.com"},
    Protocol:     "https",
    Fallback:     "https://accounts.example.com",
},
```

`Protocol` accepts `http`, `https`, or `auto`. `http` and `https` pin the scheme. `auto` and the empty value use a valid `X-Forwarded-Proto` when trusted proxy headers are enabled, then the request scheme, then HTTP for a loopback host, and finally HTTPS. The fallback is required for typed direct calls that need absolute URLs because those calls do not carry an HTTP host or scheme.

## Secret precedence

Versioned secrets take precedence over a legacy secret. The lookup order is:

1. `Options.Secrets`;
2. `SINGLE_AUTH_SECRETS`;
3. `Options.Secret`;
4. `SINGLE_AUTH_SECRET`;
5. `AUTH_SECRET`;
6. the built-in development fallback.

`SINGLE_AUTH_SECRETS` uses comma-separated `version:value` entries, for example `2:new-secret,1:old-secret`. The first entry is active. The development fallback is rejected when `Environment` is exactly `production`. Secrets shorter than 32 characters or estimated below 120 bits of entropy produce warnings outside test mode.

Rotation is format-specific. Retained entries decode version-tagged encrypted/JWE values used by OAuth state, encrypted OAuth tokens, the account-data cookie, and plugin encryption helpers. Session-token signatures, compact/JWT/JWE session-cache values, verification-email JWTs, the do-not-remember cookie, and the OAuth-state cookie binding use only the active secret. Changing the first entry therefore invalidates those signed/cache values even while old ring entries remain; plan for reauthentication, new verification emails, and interrupted in-flight OAuth browser flows.

## Invalid combinations fail at startup

`New` rejects, among other validation errors:

- simultaneous `BaseURL` and `DynamicBaseURL`;
- dynamic mode without `AllowedHosts`, or with an unsupported protocol;
- simultaneous `SecondaryStorage` and `SecondaryValueStorage`;
- unsupported account-state or rate-limit storage values;
- invalid verification identifier strategies;
- duplicate endpoint names or routes, invalid middleware patterns, invalid schemas, and plugin factory identity mismatches;
- an explicit primary adapter together with a raw database initializer.

Use `New` when startup errors can be returned. `MustNew` panics and is appropriate only when static application initialization cannot continue.
