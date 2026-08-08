package anonymous

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	sensitiveSessionContextKey = "anonymous.sensitive-session"
	newSessionContextKey       = "anonymous.new-session"
)

type plugin struct {
	options Options
	schema  storage.Schema
	clock   func() time.Time
	random  *lockedReader
}

// New validates and snapshots a single-auth anonymous plugin descriptor.
func New(input Options) (engine.Plugin, error) {
	implementation, err := normalize(input)
	if err != nil {
		return engine.Plugin{}, err
	}
	return engine.Plugin{
		ID: "anonymous", Version: Version, Schema: implementation.schema.Clone(),
		Endpoints: []engine.Endpoint{
			{Name: "signInAnonymous", Path: "/sign-in/anonymous", Methods: []string{"POST"}, Handler: implementation.signInAnonymous},
			{Name: "deleteAnonymousUser", Path: "/delete-anonymous-user", Methods: []string{"POST"}, Handler: implementation.deleteAnonymousUser},
		},
		Middleware: []engine.Middleware{{
			Name: "anonymous-sensitive-session", Path: "/delete-anonymous-user",
			Handler: implementation.sensitiveSessionMiddleware,
		}},
		Hooks: engine.Hooks{After: []engine.AfterHook{{
			Name: "anonymous-link-account", Matcher: implementation.linkMatcher,
			Handler: implementation.linkAccount,
		}}},
		// Upstream 1.6.26 declares no plugin rateLimit rules. The root default
		// rule therefore applies to both HTTP endpoints.
		RateLimit: nil, ErrorCodes: pluginErrorCodes(),
	}, nil
}

// MustNew is New for static application setup.
func MustNew(options Options) engine.Plugin {
	descriptor, err := New(options)
	if err != nil {
		panic(err)
	}
	return descriptor
}

// NewFactory binds anonymous persistence, sessions, cookie cleanup, secondary
// storage invalidation, and logging to the final root runtime.
func NewFactory(options Options) singleauth.PluginFactory {
	options.Schema = options.Schema.Clone()
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "anonymous" }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return resolveSchema(factory.options.Schema)
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime.Adapter = host.Adapter
	options.Runtime.Clock = host.Clock
	options.Runtime.Random = host.Random
	options.Runtime.ResolveSession = func(ctx *engine.Context, resolution SessionResolution) (*SessionState, error) {
		mode := singleauth.PluginSessionOptional
		switch resolution {
		case SessionRequired:
			mode = singleauth.PluginSessionRequired
		case SessionAuthoritative:
			mode = singleauth.PluginSessionAuthoritative
		}
		state, err := host.ResolveSession(ctx, mode)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.IssueSession = func(ctx *engine.Context, userID string) (*SessionState, error) {
		state, err := host.IssueSession(ctx, userID, false)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.NewSession = func(ctx *engine.Context) *SessionState {
		state := host.NewSession(ctx)
		if state == nil {
			return nil
		}
		return &SessionState{Session: state.Session, User: state.User}
	}
	options.Runtime.SetNewSession = func(ctx *engine.Context, state *SessionState) {
		if state == nil {
			host.SetNewSession(ctx, nil)
			return
		}
		host.SetNewSession(ctx, &singleauth.PluginSessionState{
			Session: state.Session, User: state.User,
		})
	}
	options.Runtime.CreateUser = host.CreateUser
	options.Runtime.SerializeUser = host.SerializeUser
	options.Runtime.RevokeSessions = host.RevokeSessions
	options.Runtime.ResolveSessionCookies = func(request contract.Request) SessionCookies {
		tokenName, tokenOptions := host.SessionCookie(request)
		dataName, dataOptions := host.Cookie(request, "session_data", "session_data")
		rememberName, rememberOptions := host.Cookie(request, "dont_remember", "dont_remember")
		resolved := SessionCookies{
			SessionToken: Cookie{Name: tokenName, Attributes: tokenOptions},
			SessionData:  Cookie{Name: dataName, Attributes: dataOptions},
			DontRemember: Cookie{Name: rememberName, Attributes: rememberOptions},
		}
		if host.Options.Account.StoreAccountCookie != nil && *host.Options.Account.StoreAccountCookie {
			name, attributes := host.Cookie(request, "account_data", "account_data")
			value := Cookie{Name: name, Attributes: attributes}
			resolved.AccountData = &value
		}
		if host.Options.Account.StoreStateStrategy == "cookie" {
			name, attributes := host.Cookie(request, "oauth_state", "oauth_state")
			value := Cookie{Name: name, Attributes: attributes}
			resolved.OAuthState = &value
		}
		return resolved
	}
	if host.Logger != nil {
		options.Runtime.Error = host.Logger.Error
	}
	return New(options)
}

func normalize(input Options) (*plugin, error) {
	if input.Runtime.Adapter == nil {
		return nil, fmt.Errorf("anonymous: Runtime.Adapter is required")
	}
	if input.Runtime.ResolveSession == nil {
		return nil, fmt.Errorf("anonymous: Runtime.ResolveSession is required")
	}
	if input.Runtime.IssueSession == nil {
		return nil, fmt.Errorf("anonymous: Runtime.IssueSession is required")
	}
	options := input
	options.Schema = input.Schema.Clone()
	schema, err := resolveSchema(options.Schema)
	if err != nil {
		return nil, fmt.Errorf("anonymous: schema: %w", err)
	}
	clock := options.Runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	randomSource := options.Runtime.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	if options.Runtime.ResolveSessionCookies == nil {
		defaults := DefaultSessionCookies()
		options.Runtime.ResolveSessionCookies = func(contract.Request) SessionCookies { return defaults }
	}
	if options.Runtime.NewSession == nil {
		options.Runtime.NewSession = defaultNewSession
	}
	if options.Runtime.SetNewSession == nil {
		options.Runtime.SetNewSession = setDefaultNewSession
	}
	return &plugin{
		options: options, schema: schema, clock: clock,
		random: &lockedReader{r: randomSource},
	}, nil
}

func (p *plugin) signInAnonymous(ctx *engine.Context) (contract.Response, error) {
	existing, err := p.options.Runtime.ResolveSession(ctx, SessionOptional)
	if err != nil {
		return contract.Response{}, err
	}
	if existing != nil && jsTruthy(existing.User["isAnonymous"]) {
		return contract.Response{}, anonymousError(
			contract.StatusBadRequest,
			ErrorAnonymousUsersCannotSignInAgainAnonymously,
		)
	}

	email, err := p.anonymousEmail()
	if err != nil {
		return contract.Response{}, err
	}
	name := "Anonymous"
	if generate := p.options.GenerateName; generate != nil {
		generated, generateErr := generate(ctx)
		if generateErr != nil {
			return contract.Response{}, generateErr
		}
		if generated != "" {
			name = generated
		}
	}
	createdAt := p.clock()
	updatedAt := p.clock()
	input := storage.Record{
		"email": email, "emailVerified": false, "isAnonymous": true,
		"name": name, "createdAt": createdAt, "updatedAt": updatedAt,
	}
	var user storage.Record
	if create := p.options.Runtime.CreateUser; create != nil {
		user, err = create(ctx, input)
	} else {
		user, err = p.options.Runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{
			Model: "user", Data: input,
		})
	}
	if err != nil {
		return contract.Response{}, err
	}
	if user == nil {
		return contract.Response{}, anonymousError(contract.StatusInternalServerError, ErrorFailedToCreateUser)
	}
	userID, _ := recordString(user, "id")
	state, err := p.options.Runtime.IssueSession(ctx, userID)
	if err != nil {
		return contract.Response{}, err
	}
	if state == nil || state.Session == nil {
		return contract.Response{}, anonymousError(contract.StatusBadRequest, ErrorCouldNotCreateSession)
	}
	p.options.Runtime.SetNewSession(ctx, state)
	serializer := p.options.Runtime.SerializeUser
	var publicUser any = cloneRecord(user)
	if serializer != nil {
		publicUser = serializer(cloneRecord(user))
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"token": state.Session["token"],
		"user":  publicUser,
	})
}

func (p *plugin) anonymousEmail() (string, error) {
	if generate := p.options.GenerateRandomEmail; generate != nil {
		custom, err := generate()
		if err != nil {
			return "", err
		}
		if custom != "" {
			if !validGeneratedEmail(custom) {
				return "", anonymousError(contract.StatusBadRequest, ErrorInvalidEmailFormat)
			}
			return custom, nil
		}
	}
	id, err := randomIdentifier(p.random, 32)
	if err != nil {
		return "", err
	}
	return formatGeneratedEmail(id, p.options.EmailDomainName), nil
}

func (p *plugin) sensitiveSessionMiddleware(
	ctx *engine.Context,
	next engine.Next,
) (contract.Response, error) {
	state, err := p.options.Runtime.ResolveSession(ctx, SessionAuthoritative)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	if state == nil || state.Session == nil {
		err := unauthorized()
		return contract.ResponseFromError(err), err
	}
	ctx.Set(sensitiveSessionContextKey, state)
	return next()
}

func (p *plugin) deleteAnonymousUser(ctx *engine.Context) (contract.Response, error) {
	state, _ := ctx.Value(sensitiveSessionContextKey)
	session, _ := state.(*SessionState)
	if session == nil {
		var err error
		session, err = p.options.Runtime.ResolveSession(ctx, SessionAuthoritative)
		if err != nil {
			return contract.Response{}, err
		}
	}
	if session == nil || session.Session == nil {
		return contract.Response{}, unauthorized()
	}
	if p.options.DisableDeleteAnonymousUser {
		return contract.Response{}, anonymousError(contract.StatusBadRequest, ErrorDeleteAnonymousUserDisabled)
	}
	if !jsTruthy(session.User["isAnonymous"]) {
		return contract.Response{}, anonymousError(contract.StatusForbidden, ErrorUserIsNotAnonymous)
	}
	userID, _ := recordString(session.User, "id")
	if err := p.revokeSessions(ctx, userID); err != nil {
		p.logError("Failed to delete anonymous user sessions", err)
		return contract.Response{}, anonymousError(
			contract.StatusInternalServerError,
			ErrorFailedToDeleteAnonymousUserSessions,
		).WithCause(err)
	}
	if err := p.options.Runtime.Adapter.Delete(ctx.GoContext(), storage.DeleteParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	}); err != nil {
		p.logError("Failed to delete anonymous user", err)
		return contract.Response{}, anonymousError(
			contract.StatusInternalServerError,
			ErrorFailedToDeleteAnonymousUser,
		).WithCause(err)
	}
	p.expireSessionCookies(ctx)
	return contract.JSONResponse(contract.StatusOK, map[string]any{"success": true})
}

func (p *plugin) revokeSessions(ctx *engine.Context, userID string) error {
	if revoke := p.options.Runtime.RevokeSessions; revoke != nil {
		return revoke(ctx, userID)
	}
	_, err := p.options.Runtime.Adapter.DeleteMany(ctx.GoContext(), storage.DeleteManyParams{
		Model: "session", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	return err
}

func (p *plugin) logError(message string, args ...any) {
	if logger := p.options.Runtime.Error; logger != nil {
		logger(message, args...)
	}
}

func (p *plugin) linkMatcher(ctx *engine.Context) (bool, error) {
	path := ctx.Path()
	for _, prefix := range linkPathPrefixes() {
		if strings.HasPrefix(path, prefix) {
			return true, nil
		}
	}
	return false, nil
}

func linkPathPrefixes() []string {
	return []string{
		"/sign-in", "/sign-up", "/callback", "/oauth2/callback",
		"/magic-link/verify", "/email-otp/verify-email", "/one-tap/callback",
		"/passkey/verify-authentication", "/phone-number/verify", "/verify-email",
	}
}

func defaultNewSession(ctx *engine.Context) *SessionState {
	if ctx == nil {
		return nil
	}
	value, exists := ctx.Value(newSessionContextKey)
	if !exists || value == nil {
		return nil
	}
	state, ok := value.(SessionState)
	if !ok || state.Session == nil || state.User == nil {
		return nil
	}
	return &SessionState{Session: cloneRecord(state.Session), User: cloneRecord(state.User)}
}

func setDefaultNewSession(ctx *engine.Context, state *SessionState) {
	if ctx == nil {
		return
	}
	if state == nil {
		ctx.Set(newSessionContextKey, nil)
		return
	}
	ctx.Set(newSessionContextKey, SessionState{
		Session: cloneRecord(state.Session), User: cloneRecord(state.User),
	})
}
