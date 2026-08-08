package magiclink

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	defaultExpiry     = 5 * time.Minute
	defaultBasePath   = "/api/auth"
	defaultRateWindow = int64(60)
	defaultRateMax    = int64(5)
	warningAttempts   = "[single-auth/magic-link] `allowedAttempts` is ignored: tokens are consumed atomically on the first verification call. Any value other than `1` has no effect; remove the option to silence this warning."
)

type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (reader *lockedReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.r.Read(target)
}

type plugin struct {
	options Options
	clock   func() time.Time
	random  io.Reader
	locks   [64]sync.Mutex
}

func New(input Options) (engine.Plugin, error) {
	implementation, err := normalize(input)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID:      "magic-link",
		Version: Version,
		Schema:  Schema(),
		Endpoints: []engine.Endpoint{
			{
				Name: "signInMagicLink", Path: "/sign-in/magic-link", Methods: []string{"POST"},
				OperationID: "signInWithMagicLink", Handler: implementation.signInMagicLink,
			},
			{
				Name: "magicLinkVerify", Path: "/magic-link/verify", Methods: []string{"GET"},
				OperationID: "verifyMagicLink", Handler: implementation.magicLinkVerify,
			},
		},
		Middleware: []engine.Middleware{
			{Name: "magic-link-send-form-csrf", Path: "/sign-in/magic-link", Handler: implementation.sendMiddleware},
			{Name: "magic-link-verify-redirect-origin", Path: "/magic-link/verify", Handler: implementation.verifyRedirectMiddleware},
		},
		RateLimit: []ratelimit.MatcherRule{{
			Match: func(path string) bool {
				return strings.HasPrefix(path, "/sign-in/magic-link") || strings.HasPrefix(path, "/magic-link/verify")
			},
			Rule: ratelimit.Rule{Window: implementation.rateWindow(), Max: implementation.rateMax()},
		}},
	}, nil
}

func MustNew(options Options) engine.Plugin {
	result, err := New(options)
	if err != nil {
		panic(err)
	}
	return result
}

// NewFactory binds magic-link to the final root adapter, session lifecycle,
// dynamic base URL, serializers, and trusted-origin policy.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "magic-link" }

func (*rootFactory) Schema() (storage.Schema, error) { return Schema(), nil }

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime.Adapter = host.Adapter
	options.Runtime.Clock = host.Clock
	options.Runtime.Random = host.Random
	options.Runtime.BaseURL = host.Options.BaseURL
	options.Runtime.BasePath = host.Options.BasePath
	options.Runtime.ResolveBaseURL = func(ctx *engine.Context) (string, error) {
		return host.ResolveBaseURL(ctx.Request())
	}
	options.Runtime.TrustedOrigins = append([]string(nil), host.Options.TrustedOrigins...)
	options.Runtime.ResolveTrustedOrigins = func(_ context.Context, request contract.Request) ([]string, error) {
		return host.TrustedOrigins(request)
	}
	options.Runtime.ValidateFormRequest = host.ValidateFormCSRF
	if options.Runtime.ValidateFormRequest == nil {
		options.Runtime.ValidateFormRequest = host.ValidateCSRF
	}
	options.Runtime.ValidateRedirect = func(ctx *engine.Context, candidate string, kind RedirectKind) error {
		return host.ValidateRedirect(ctx, candidate, string(kind))
	}
	options.Runtime.CreateUser = func(ctx *engine.Context, input CreateUserInput) (storage.Record, error) {
		return host.CreateUser(ctx, storage.Record{
			"email": strings.ToLower(input.Email), "emailVerified": true, "name": input.Name,
		})
	}
	options.Runtime.IssueSession = func(ctx *engine.Context, user storage.Record) (*SessionState, error) {
		userID, ok := recordString(user, "id")
		if !ok || userID == "" {
			return nil, fmt.Errorf("magiclink: user id is invalid")
		}
		state, err := host.IssueSession(ctx, userID, false)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.SerializeUser = host.SerializeUser
	options.Runtime.SerializeSession = host.SerializeSession
	options.Runtime.RevokeUnproven = host.RevokeUnproven
	options.Runtime.RevokeSessions = host.RevokeSessions
	options.Runtime.CreateVerification = func(ctx context.Context, identifier, value string, expiresAt time.Time) (storage.Record, error) {
		return host.CreateVerification(ctx, identifier, value, expiresAt)
	}
	options.Runtime.ConsumeVerification = func(ctx context.Context, identifier string) (storage.Record, error) {
		return host.ConsumeVerification(ctx, identifier)
	}
	if host.Logger != nil {
		options.Runtime.Warn = func(message string) { host.Logger.Warn(message) }
	}
	return New(options)
}

func normalize(input Options) (*plugin, error) {
	if input.Runtime.Adapter == nil {
		return nil, fmt.Errorf("magiclink: Runtime.Adapter is required")
	}
	if input.SendMagicLink == nil {
		return nil, fmt.Errorf("magiclink: SendMagicLink is required")
	}
	if input.Runtime.IssueSession == nil {
		return nil, fmt.Errorf("magiclink: Runtime.IssueSession is required")
	}
	options := input
	options.Runtime.TrustedOrigins = append([]string(nil), input.Runtime.TrustedOrigins...)
	if options.ExpiresIn == 0 {
		options.ExpiresIn = defaultExpiry
	}
	if options.Storage.Mode == "" {
		options.Storage.Mode = StorePlain
	}
	if options.Storage.CustomHash != nil && options.Storage.Mode != StorePlain {
		return nil, fmt.Errorf("magiclink: custom hasher cannot be combined with StoreMode %q", options.Storage.Mode)
	}
	if options.Storage.Mode != StorePlain && options.Storage.Mode != StoreHashed {
		return nil, fmt.Errorf("magiclink: invalid token StoreMode %q", options.Storage.Mode)
	}
	if options.Runtime.BasePath == "" {
		options.Runtime.BasePath = defaultBasePath
	}
	if options.Runtime.BasePath != "/" {
		options.Runtime.BasePath = "/" + strings.Trim(options.Runtime.BasePath, "/")
	}
	if options.Runtime.BaseURL != "" {
		parsed, err := url.Parse(options.Runtime.BaseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("magiclink: invalid Runtime.BaseURL %q", options.Runtime.BaseURL)
		}
	}
	clock := options.Runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	randomSource := options.Runtime.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	if options.AllowedAttempts != nil && *options.AllowedAttempts != 1 {
		if options.Runtime.Warn != nil {
			options.Runtime.Warn(warningAttempts)
		} else {
			log.Print(warningAttempts)
		}
	}
	return &plugin{options: options, clock: clock, random: &lockedReader{r: randomSource}}, nil
}

func (p *plugin) rateWindow() int64 {
	if p.options.RateLimit.Window == 0 {
		return defaultRateWindow
	}
	return p.options.RateLimit.Window
}

func (p *plugin) rateMax() int64 {
	if p.options.RateLimit.Max == 0 {
		return defaultRateMax
	}
	return p.options.RateLimit.Max
}
