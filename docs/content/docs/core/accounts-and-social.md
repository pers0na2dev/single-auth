---
title: "Accounts and social sign-in"
---

Provider configuration, OAuth state, identity linking, account cookies, token refresh, and unlinking.

An account links one user to one authentication provider. Credential accounts use provider ID `credential`; social accounts retain provider account IDs, OAuth tokens, token expiries, scope, and optional additional fields.

## Configure providers

Provider constructors validate and freeze provider-specific behavior. Configure them before creating the auth runtime:

```go
google, err := providers.Google(providers.Options{
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
})
if err != nil {
    return nil, err
}

github, err := providers.GitHub(providers.Options{
    ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
    ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
})
if err != nil {
    return nil, err
}

return singleauth.New(singleauth.Options{
    BaseURL: "https://accounts.example.com",
    Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
    Database: adapter,
    SocialProviders: map[string]*providers.Provider{
        "google": google,
        "github": github,
    },
})
```

`providers.New(id, options)` is the dynamic constructor. `providers.SocialProviderList()` returns the frozen built-in list. A provider receives the root `HTTPClient` unless its own client is set.

The OAuth redirect URI is the public base URL plus `/callback/<provider-id>`. Use the exact URL configured with the provider. Dynamic base URLs must constrain hosts, and direct calls needing an absolute URL need a fallback.

## Start social sign-in

`POST /sign-in/social` accepts:

```json
{
  "provider": "google",
  "callbackURL": "/dashboard",
  "errorCallbackURL": "/sign-in/error",
  "newUserCallbackURL": "/welcome",
  "disableRedirect": false,
  "requestSignUp": false,
  "scopes": ["calendar.readonly"],
  "loginHint": "ada@example.com",
  "additionalData": {"invite": "abc"}
}
```

The runtime validates redirect fields, resolves the provider, creates random state and PKCE material, persists callback/error/new-user data, and builds the provider authorization URL. A normal response contains the URL and `redirect:true`; `disableRedirect` keeps the URL in JSON without requiring the caller to navigate immediately.

Providers supporting direct ID-token sign-in also accept an `idToken` object containing `token` and optional access token, refresh token, nonce, expiry, scopes, and user data. Unsupported or invalid ID tokens are rejected according to provider policy.

## OAuth state and callback

`GET` or `POST /callback/:id` validates state before exchanging the code or processing an error. Database/secondary state is atomically consumed. Cookie state is stateless: the response expires the cookie, but a copied pre-expiry cookie has no server-side consumed marker, so applications that require cross-request replay rejection should select the database strategy.

The default state strategy is:

- `cookie` when no explicit primary or secondary store was configured;
- `database` when a primary or secondary store was explicitly configured.

Set `Account.StoreStateStrategy` to `cookie` or `database` to override it. `SkipStateCookieCheck` disables the state-cookie binding check but not state validation/consumption; use it only when an audited protocol integration cannot preserve the browser cookie.

Database/secondary state is a single-use verification value plus a separately signed state-cookie binding. Cross-process deployments should use an atomic consume implementation. Cookie strategy stores the complete state in an encrypted `oauth_state` cookie and verifies that its embedded state matches the provider callback; it is bounded by the cookie and embedded expiry.

After provider validation, the runtime finds the account by provider/account ID, creates a user and account when signup is allowed, or links an eligible existing user. Successful callbacks issue session cookies and redirect to the validated callback, new-user, or error destination.

## Account linking policy

```go
Account: singleauth.AccountOptions{
    EncryptOAuthTokens: true,
    AccountLinking: singleauth.AccountLinkingOptions{
        Enabled:                   boolPtr(true),
        RequireLocalEmailVerified: boolPtr(true),
        TrustedProviders:          []string{"google"},
        AllowDifferentEmails:      false,
        AllowUnlinkingAll:         false,
        DisableImplicitLinking:    false,
        UpdateUserInfoOnLink:      false,
    },
},
```

Linking is enabled when `Enabled` is omitted. Implicit linking requires:

- an existing local user with the provider email;
- a trusted provider identity, established by verified provider email, protocol trust, or exact `TrustedProviders` membership;
- local email verification by default (`RequireLocalEmailVerified` omitted means true);
- implicit linking not disabled.

`AllowDifferentEmails` permits the explicit link route to link an account whose provider email differs from the current user's email. It does not make an untrusted implicit match safe. `UpdateUserInfoOnLink` applies provider profile data during a link; provider-level `OverrideUserInfo` can also update profile data on sign-in.

`POST /link-social` requires a session and accepts the same provider, callback, scope, ID-token, and additional-data shape as social sign-in. Concurrent link/unlink/token-rotation windows are serialized within one runtime; the durable adapter must still enforce uniqueness and transaction isolation across replicas.

## Account persistence

`UpdateAccountOnSignIn` omitted means true: fresh provider tokens update the linked account on sign-in. Explicit false preserves stored values. `EncryptOAuthTokens` encrypts stored access and refresh tokens using the configured secret policy; the core account writer stores `idToken` as received. If ID tokens must be encrypted at rest, use a database hook/adapter policy or avoid retaining them. Retain old secrets during rotation until encrypted access/refresh values are rewritten or expired.

`StoreAccountCookie` defaults to true only when no explicit primary database was provided. The encrypted `account_data` cookie helps stateless and provider-token flows resolve the selected account. A primary database normally remains authoritative and the default is false.

The account cookie uses the normal cookie prefix/attributes, is JWE-encrypted with context `better-auth-account`, and may be chunked. It never replaces ownership checks: account data must match the authenticated user and provider selection.

## Listing and unlinking

`GET /list-accounts` requires a session and returns public account fields plus `scopes` as a string array. Token and password fields are not exposed as usable credentials.

`POST /unlink-account` requires a valid, fresh session and accepts:

```json
{
  "providerId": "github",
  "accountId": "provider-account-id"
}
```

`accountId` is optional when the provider has only one matching account. The route verifies ownership. It rejects removal of the last login method unless `AllowUnlinkingAll` is true. It never uses a caller-supplied user ID.

## Access and refresh tokens

The following core routes operate on configured social providers:

- `POST /get-access-token` accepts required `providerId` and optional `accountId`;
- `POST /refresh-token` accepts the same selection and requires provider refresh support plus a stored refresh token;
- `GET /account-info` accepts optional `providerId` and `accountId`, obtains a valid access token, and calls provider user-info.

HTTP requests must authenticate with a session; stateful mode uses authoritative lookup. The direct server API additionally accepts `UserID` only when no session headers are supplied. That server-only shortcut is intentionally unavailable to an HTTP caller.

`get-access-token` returns the stored token directly unless its recorded expiry is less than five seconds away and a refresh token plus provider refresh support are available. In that near-expiry or expired case, the runtime serializes refresh for the account, calls the provider, persists the new token set, and refreshes the account cookie when enabled. If refresh prerequisites are absent, the stored token is returned even when its recorded expiry has passed, so callers should inspect `accessTokenExpiresAt`. Ambiguous account IDs require a `providerId`.

Returned data includes provider-defined token expiries and scopes when available. A provider user-info callback may return nil, in which case `account-info` returns JSON null.

## Direct server API

The account methods are `SignInSocial`, `CallbackOAuth`, `ListUserAccounts`, `LinkSocialAccount`, `UnlinkAccount`, `GetAccessToken`, `RefreshToken`, and `AccountInfo`.

Direct calls use the same provider, state, storage, hook, and response code as HTTP. They do not automatically follow redirects or maintain cookies. Preserve `Location` and every `Set-Cookie` header when adapting a result to a browser. Direct execution also skips the HTTP rate limiter, origin/CSRF middleware, path middleware, plugin `OnRequest`, and plugin `OnResponse`; keep it behind trusted server authorization.
