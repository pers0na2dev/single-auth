---
title: "github.com/pers0na2dev/single-auth/plugins/captcha"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/captcha.

- Import path: `github.com/pers0na2dev/single-auth/plugins/captcha`
- Package name: `captcha`

Package captcha implements the single-auth 1.6.26 CAPTCHA request plugin.

Verification runs in the HTTP-only onRequest stage. Direct endpoint calls
intentionally bypass it, matching single-auth's direct API contract.

## Constants

```go
const (
	ErrorVerificationFailed = "VERIFICATION_FAILED"
	ErrorMissingResponse    = "MISSING_RESPONSE"
	ErrorUnknown            = "UNKNOWN_ERROR"

	MessageVerificationFailed = "Captcha verification failed"
	MessageMissingResponse    = "Missing CAPTCHA response"
	MessageUnknown            = "Something went wrong"
)
```

```go
const (
	Version = "1.6.26"

	PluginID = "captcha"

	VerifyTimeout = 10 * time.Second
)
```

```go
const (
	CloudflareTurnstileSiteVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	GoogleRecaptchaSiteVerifyURL     = "https://www.google.com/recaptcha/api/siteverify"
	HCaptchaSiteVerifyURL            = "https://api.hcaptcha.com/siteverify"
	CaptchaFoxSiteVerifyURL          = "https://api.captchafox.com/siteverify"
)
```

## Functions

### `DefaultEndpoints`

DefaultEndpoints returns an independent copy of the protected path list.

```go
func DefaultEndpoints() []string
```

### `MustNew`

MustNew is New for static application setup.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New snapshots options and constructs a standalone CAPTCHA descriptor.

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds provider HTTP, IP, base-path, and logger dependencies to the
root configuration finalized by singleauth.New.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `Score`

Score returns a pointer for MinScore, preserving omitted versus zero.

```go
func Score(value float64) *float64
```

### `SiteVerifyURL`

SiteVerifyURL returns the upstream endpoint for provider. Unknown providers
return an empty string, mirroring an undefined map lookup in JavaScript.

```go
func SiteVerifyURL(provider Provider) string
```

## Types

### `HTTPDoer`

HTTPDoer is implemented by *http.Client. A custom implementation makes
provider calls deterministic in tests and supports custom network policy.

```go
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}
```

### `IPResolver`

IPResolver returns the single-auth client address for a request. An empty
value omits the provider's remote-IP field.

```go
type IPResolver func(contract.Request) string
```

### `Options`

Options is the Go union of single-auth's provider-specific CAPTCHA options.
Fields irrelevant to the selected provider are retained but ignored.

```go
type Options struct {
	Provider Provider

	SecretKey             string
	Endpoints             []string
	SiteVerifyURLOverride string

	// Google reCAPTCHA settings. Nil MinScore selects the upstream 0.5
	// default, while an explicit zero is retained.
	MinScore         *float64
	ExpectedAction   string
	AllowedHostnames []string

	// SiteKey is sent only by hCaptcha and CaptchaFox, and only when non-empty.
	SiteKey string

	Runtime Runtime
}
```

### `Provider`

Provider is one of the provider identifiers accepted by single-auth.
Unknown values are deliberately not rejected during construction: upstream
only encounters them at request time and fails open after no branch matches.

```go
type Provider string
```

## Constants associated with `Provider`

```go
const (
	CloudflareTurnstile Provider = "cloudflare-turnstile"
	GoogleRecaptcha     Provider = "google-recaptcha"
	HCaptcha            Provider = "hcaptcha"
	CaptchaFox          Provider = "captchafox"
)
```

### `Runtime`

Runtime contains dependencies injected by NewFactory. They are public so a
standalone engine plugin can be assembled in focused conformance tests.

```go
type Runtime struct {
	HTTPClient       HTTPDoer
	BasePath         string
	ResolveIPAddress IPResolver
	Logger           *logger.Logger
}
```

