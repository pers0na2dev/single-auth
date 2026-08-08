---
title: "github.com/pers0na2dev/single-auth/plugins/oauthpopup"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/oauthpopup.

- Import path: `github.com/pers0na2dev/single-auth/plugins/oauthpopup`
- Package name: `oauthpopup`

Package oauthpopup ports single-auth's popup-based OAuth handoff plugin.

The server endpoint starts the normal root OAuth flow in a first-party
popup, then replaces the callback redirect with a CSP-locked page that sends
the signed session cookie value to the trusted opener.

## Constants

```go
const (
	Version = "1.6.26"

	MessageType           = "single-auth:oauth-popup"
	DataElementID         = "single-auth-oauth-popup"
	MarkerCookie          = "oauth_popup"
	TokenStorageKey       = "single-auth.popup_token"
	CompleteScriptCSPHash = "sha256-s+yLgvEa6zmVvpZkoaPyaf0XlH5FrZn6IBLDhREDH/c="
)
```

```go
const (
	ErrorPopupSignInFailed = "POPUP_SIGN_IN_FAILED"
	ErrorPopupBlocked      = "POPUP_BLOCKED"
	ErrorPopupClosed       = "POPUP_CLOSED"
	ErrorPopupTimeout      = "POPUP_TIMEOUT"
)
```

```go
const CompleteScript = `(function () {
	var el = document.getElementById("single-auth-oauth-popup");
	if (!el) return;
	var payload;
	try {
		payload = JSON.parse(el.textContent || "");
	} catch (e) {
		return;
	}
	var target = window.opener || window.parent;
	if (target && target !== window) {
		try {
			target.postMessage(
				{
					type: payload.type,
					nonce: payload.nonce,
					token: payload.token,
					redirectTo: payload.redirectTo,
					error: payload.error,
				},
				payload.targetOrigin,
			);
		} catch (e) {}
	}
	window.close();
})();
`
```

## Variables

```go
var ErrorMessages = map[string]string{
	ErrorPopupSignInFailed: "Popup sign-in failed",
	ErrorPopupBlocked:      "Sign-in popup was blocked by the browser",
	ErrorPopupClosed:       "Sign-in popup was closed before completing",
	ErrorPopupTimeout:      "Sign-in popup timed out",
}
```

## Functions

### `MustNew`

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New constructs a standalone popup server plugin from explicit runtime
dependencies. Applications using singleauth.Auth should use NewFactory.

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

```go
func NewFactory() singleauth.PluginFactory
```

## Types

### `BaseURLResolver`

```go
type BaseURLResolver func(contract.Request) (string, error)
```

### `CookieResolver`

```go
type CookieResolver func(contract.Request, string, string) (string, cookies.Options)
```

### `Options`

```go
type Options struct {
	Runtime Runtime
}
```

### `OriginResolver`

```go
type OriginResolver func(contract.Request, string, bool) (bool, error)
```

### `PopupError`

```go
type PopupError struct {
	Code        string  `json:"code"`
	Description *string `json:"description,omitempty"`
}
```

### `ProviderResolver`

```go
type ProviderResolver func(string) *providers.Provider
```

### `Runtime`

Runtime contains the root services used by the server plugin. NewFactory
binds every field to the final immutable Auth runtime.

```go
type Runtime struct {
	Secret           string
	Logger           *logger.Logger
	Cookie           CookieResolver
	SessionCookie    func(contract.Request) (string, cookies.Options)
	IsTrustedOrigin  OriginResolver
	ResolveBaseURL   BaseURLResolver
	SocialProvider   ProviderResolver
	CreateOAuthState StateCreator
	HasPlugin        func(string) bool
}
```

### `StateCreator`

```go
type StateCreator func(*engine.Context, singleauth.PluginOAuthStateInput) (singleauth.PluginOAuthState, error)
```

