package onetap

import (
	"context"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/protocol/providers"
)

const Version = "1.6.26"

type VerifyIDTokenInput struct {
	Token      string
	Audience   any
	HTTPClient any
}

type VerifyIDTokenFunc func(context.Context, VerifyIDTokenInput) (map[string]any, error)

// Runtime contains root identity/session services injected by NewFactory.
type Runtime struct {
	Logger          *logger.Logger
	SocialProvider  func(string) *providers.Provider
	HandleOAuthUser func(*engine.Context, singleauth.PluginOAuthUserInput) (singleauth.PluginOAuthUserResult, error)
	RefreshSession  func(*engine.Context, singleauth.PluginSessionState, bool) error
	SerializeUser   func(map[string]any) any
}

type Options struct {
	DisableSignup bool
	ClientID      string

	// VerifyIDToken is an injectable equivalent of verifyGoogleIdToken. Nil
	// uses the frozen providers.VerifyGoogleIDToken implementation.
	VerifyIDToken VerifyIDTokenFunc
	Runtime       Runtime
}
