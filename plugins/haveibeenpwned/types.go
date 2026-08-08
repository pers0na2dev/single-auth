package haveibeenpwned

import (
	"net/http"

	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	Version  = "1.6.26"
	PluginID = "have-i-been-pwned"

	ErrorPasswordCompromised  = "PASSWORD_COMPROMISED"
	DefaultCompromisedMessage = "The password you entered has been compromised. Please choose a different password."
	RangeAPIBaseURL           = "https://api.pwnedpasswords.com/range/"
)

var defaultPaths = []string{
	"/sign-up/email",
	"/change-password",
	"/reset-password",
	"/email-otp/reset-password",
	"/phone-number/reset-password",
	"/admin/create-user",
	"/admin/set-user-password",
}

// HTTPDoer is implemented by *http.Client. Supplying a client with a custom
// RoundTripper keeps conformance tests and private deployments off the real
// Pwned Passwords network endpoint.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// PasswordHashFunc is the context-aware password hash chain installed by the
// root PluginFactory. The endpoint context is nil outside an auth dispatch.
type PasswordHashFunc func(*engine.Context, string) (string, error)

// PasswordHashWrapper wraps the hash chain in plugin initialization order.
type PasswordHashWrapper func(PasswordHashFunc) PasswordHashFunc

type Runtime struct {
	WrapPasswordHash func(PasswordHashWrapper) error
}

// Options configures the single-auth-compatible plugin. Nil Paths selects the
// upstream defaults; an explicit empty slice disables every endpoint path.
type Options struct {
	CustomPasswordCompromisedMessage string
	Paths                            []string
	// Enabled defaults to true. Bool(false) disables checks while preserving
	// the original password hash behavior.
	Enabled    *bool
	HTTPClient HTTPDoer
	Runtime    Runtime
}

func Bool(value bool) *bool { return &value }

// DefaultPaths returns an independent copy of the upstream path allowlist.
func DefaultPaths() []string { return append([]string(nil), defaultPaths...) }
