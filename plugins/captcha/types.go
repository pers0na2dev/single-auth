package captcha

import (
	"net/http"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/observability/logger"
)

const (
	// Version is the frozen single-auth package version implemented here.
	Version = "1.6.26"

	PluginID = "captcha"

	// VerifyTimeout is the upstream upper bound for one provider request.
	VerifyTimeout = 10 * time.Second
)

// Provider is one of the provider identifiers accepted by single-auth.
// Unknown values are deliberately not rejected during construction: upstream
// only encounters them at request time and fails open after no branch matches.
type Provider string

const (
	CloudflareTurnstile Provider = "cloudflare-turnstile"
	GoogleRecaptcha     Provider = "google-recaptcha"
	HCaptcha            Provider = "hcaptcha"
	CaptchaFox          Provider = "captchafox"
)

const (
	CloudflareTurnstileSiteVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	GoogleRecaptchaSiteVerifyURL     = "https://www.google.com/recaptcha/api/siteverify"
	HCaptchaSiteVerifyURL            = "https://api.hcaptcha.com/siteverify"
	CaptchaFoxSiteVerifyURL          = "https://api.captchafox.com/siteverify"
)

var defaultEndpoints = []string{
	"/sign-up/email",
	"/sign-in/email",
	"/request-password-reset",
}

// HTTPDoer is implemented by *http.Client. A custom implementation makes
// provider calls deterministic in tests and supports custom network policy.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// IPResolver returns the single-auth client address for a request. An empty
// value omits the provider's remote-IP field.
type IPResolver func(contract.Request) string

// Runtime contains dependencies injected by NewFactory. They are public so a
// standalone engine plugin can be assembled in focused conformance tests.
type Runtime struct {
	HTTPClient       HTTPDoer
	BasePath         string
	ResolveIPAddress IPResolver
	Logger           *logger.Logger
}

// Options is the Go union of single-auth's provider-specific CAPTCHA options.
// Fields irrelevant to the selected provider are retained but ignored.
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

// Score returns a pointer for MinScore, preserving omitted versus zero.
func Score(value float64) *float64 { return &value }

// DefaultEndpoints returns an independent copy of the protected path list.
func DefaultEndpoints() []string {
	return append([]string(nil), defaultEndpoints...)
}

// SiteVerifyURL returns the upstream endpoint for provider. Unknown providers
// return an empty string, mirroring an undefined map lookup in JavaScript.
func SiteVerifyURL(provider Provider) string {
	switch provider {
	case CloudflareTurnstile:
		return CloudflareTurnstileSiteVerifyURL
	case GoogleRecaptcha:
		return GoogleRecaptchaSiteVerifyURL
	case HCaptcha:
		return HCaptchaSiteVerifyURL
	case CaptchaFox:
		return CaptchaFoxSiteVerifyURL
	default:
		return ""
	}
}
