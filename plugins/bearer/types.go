package bearer

import "github.com/pers0na2dev/single-auth/core/contract"

const Version = "1.6.26"

// Runtime contains the normalized root-auth values single-auth exposes to
// plugin hooks through its internal context. The current public Go engine
// context deliberately does not expose either value, so they are explicit.
type Runtime struct {
	Secret            string
	SessionCookieName string
	// ResolveSessionCookie supplies the request-scoped session cookie name.
	// It is used by NewFactory for dynamic and secure root cookie settings.
	ResolveSessionCookie func(contract.Request) string
}

// Options configures the single-auth-compatible bearer plugin.
type Options struct {
	// RequireSignature rejects raw session tokens. Signed cookie values remain
	// accepted. The single-auth default is false.
	RequireSignature bool
	Runtime          Runtime
}
