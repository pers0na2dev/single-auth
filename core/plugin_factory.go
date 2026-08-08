package core

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

// PluginFactory delays runtime-dependent plugin construction until New has
// created the final adapter, schema, cookie configuration, and core services.
// Schema must be deterministic and must describe every model used by Build.
type PluginFactory interface {
	PluginID() string
	Schema() (storage.Schema, error)
	Build(PluginHost) (engine.Plugin, error)
}

// PluginSessionMode selects the host's regular, authoritative, or fresh
// session policy.
type PluginSessionMode uint8

const (
	PluginSessionOptional PluginSessionMode = iota
	PluginSessionRequired
	PluginSessionAuthoritative
	PluginSessionFresh
)

// PluginSessionState is the logical session/user pair shared with plugins.
type PluginSessionState struct {
	Session storage.Record
	User    storage.Record
}

// PluginOAuthStateInput is the transport-neutral input used by plugins that
// start a regular upstream implementation OAuth flow. AdditionalData is persisted in the
// same state record/cookie as core social sign-in after the caller has removed
// keys reserved by the state protocol.
type PluginOAuthStateInput struct {
	CallbackURL    string
	ErrorURL       string
	NewUserURL     string
	RequestSignUp  *bool
	AdditionalData map[string]any
}

// PluginOAuthState is the generated CSRF state and PKCE verifier supplied to
// the provider authorization URL builder.
type PluginOAuthState struct {
	State        string
	CodeVerifier string
}

// PluginOAuthStateData is the validated, single-use OAuth state exposed to
// protocol plugins. AdditionalData contains only plugin-owned fields that were
// persisted alongside the root callback, error, signup, and PKCE values.
type PluginOAuthStateData struct {
	CallbackURL    string
	ErrorURL       string
	NewUserURL     string
	CodeVerifier   string
	RequestSignUp  *bool
	AdditionalData map[string]any
}

// PluginOAuthStateError is returned after a state lookup, cookie binding, or
// atomic consume failure. Code is safe to expose as an OAuth redirect error;
// ErrorURL is populated only when it came from already-validated state.
type PluginOAuthStateError struct {
	Code     string
	ErrorURL string
	Cause    error
}

func (err *PluginOAuthStateError) Error() string {
	if err == nil {
		return "<nil>"
	}
	if err.Cause != nil {
		return err.Code + ": " + err.Cause.Error()
	}
	return err.Code
}

func (err *PluginOAuthStateError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

// PluginOAuthUserInput delegates identity/account resolution to the same
// implementation used by redirect social sign-in. Provider may be an
// ephemeral provider descriptor for protocol plugins such as One Tap that can
// operate without a configured redirect provider.
type PluginOAuthUserInput struct {
	Provider      *providers.Provider
	ProviderID    string
	User          oauth2.UserInfo
	Tokens        oauth2.Tokens
	DisableSignUp bool
	// IsTrustedProvider is protocol-level trust established independently of
	// the provider name. SSO uses it only after certificate validation and an
	// exact configured-domain match.
	IsTrustedProvider bool
	// TrustProviderByName preserves upstream implementation's regular social-provider
	// allow-list behavior when nil. Protocol plugins can set false so a
	// user-controlled provider ID can never inherit trust from a matching name.
	TrustProviderByName *bool
	// CallbackURL is preserved in verification email links for newly-created,
	// unverified OAuth users. Empty retains the legacy "/" fallback.
	CallbackURL string
}

// PluginOAuthUserResult carries the created session/user pair and the
// user-facing OAuth linking error that upstream returns separately from
// internal failures.
type PluginOAuthUserResult struct {
	State      PluginSessionState
	IsRegister bool
	LinkError  string
}

const pluginNewSessionKey = "single-auth:new-session"

func pluginNewSession(ctx *engine.Context) *PluginSessionState {
	if ctx == nil {
		return nil
	}
	value, exists := ctx.Value(pluginNewSessionKey)
	if !exists || value == nil {
		return nil
	}
	state, ok := value.(PluginSessionState)
	if !ok || state.Session == nil || state.User == nil {
		return nil
	}
	return &PluginSessionState{
		Session: cloneStorageRecord(state.Session),
		User:    cloneStorageRecord(state.User),
	}
}

func setPluginNewSession(ctx *engine.Context, state *PluginSessionState) {
	if ctx == nil {
		return
	}
	if state == nil {
		ctx.Set(pluginNewSessionKey, nil)
		return
	}
	ctx.Set(pluginNewSessionKey, PluginSessionState{
		Session: cloneStorageRecord(state.Session),
		User:    cloneStorageRecord(state.User),
	})
}

// PluginHost is the typed dependency surface supplied to PluginFactory.Build.
// Every callback enters the same root persistence, cookie, security, and
// background-work semantics as core endpoints.
type PluginHost struct {
	Options Options
	Adapter storage.Adapter
	// InternalAdapter exposes the hook-aware upstream implementation persistence facade to
	// plugins that need more than the raw database contract.
	InternalAdapter InternalAdapter
	Logger          *logger.Logger
	Clock           func() time.Time
	Random          io.Reader
	Secret          string

	AdapterForContext func(context.Context) storage.TransactionAdapter
	EncryptSecret     func([]byte) (string, error)
	DecryptSecret     func(string) ([]byte, error)

	ResolveBaseURL func(contract.Request) (string, error)
	// ListEndpoints returns registry snapshots after Auth.New has finalized the
	// endpoint registry. During PluginFactory.Build the closure is already safe
	// to capture but returns nil until initialization completes.
	ListEndpoints    func() []engine.Endpoint
	TrustedOrigins   func(contract.Request) ([]string, error)
	IsTrustedOrigin  func(contract.Request, string, bool) (bool, error)
	ResolveIPAddress func(contract.Request) string
	SessionCookie    func(contract.Request) (string, cookies.Options)
	Cookie           func(contract.Request, string, string) (string, cookies.Options)
	HasPlugin        func(string) bool
	SocialProvider   func(string) *providers.Provider
	// RegisterSocialProvider installs a provider during PluginFactory.Build so
	// core account/token endpoints share the same provider implementation as
	// plugin-owned OAuth routes. Provider IDs must remain globally unique.
	RegisterSocialProvider func(*providers.Provider) error
	CreateOAuthState       func(*engine.Context, PluginOAuthStateInput) (PluginOAuthState, error)
	ConsumeOAuthState      func(*engine.Context, string) (PluginOAuthStateData, error)
	OAuthErrorURL          func(contract.Request) string
	HandleOAuthUser        func(*engine.Context, PluginOAuthUserInput) (PluginOAuthUserResult, error)
	LinkOAuthAccount       func(*engine.Context, string, *providers.Provider, oauth2.UserInfo, oauth2.Tokens) error

	ResolveSession func(*engine.Context, PluginSessionMode) (*PluginSessionState, error)
	GetSession     func(*engine.Context) (contract.Response, error)
	FindSession    func(context.Context, string) (*PluginSessionState, error)
	FindSessions   func(context.Context, []string, bool) ([]PluginSessionState, error)
	// CreateSession persists a regular host session, including secondary
	// storage when configured, without writing browser cookies. Protocol
	// plugins use it when the session token is returned in a non-cookie token
	// response (for example RFC 8628 device authorization).
	CreateSession func(*engine.Context, string, bool) (*PluginSessionState, error)
	// CreateSessionWithData applies trusted plugin-owned session extension
	// fields before persistence and secondary-storage serialization.
	CreateSessionWithData func(*engine.Context, string, bool, storage.Record) (*PluginSessionState, error)
	IssueSession          func(*engine.Context, string, bool) (*PluginSessionState, error)
	RefreshSession        func(*engine.Context, PluginSessionState, bool) error
	ExpireSessionCookies  func(*engine.Context)
	DeleteSession         func(context.Context, string) error
	DeleteSessions        func(context.Context, []string) error
	RevokeSessions        func(*engine.Context, string) error
	RevokeUnproven        func(*engine.Context, string) error
	NewSession            func(*engine.Context) *PluginSessionState
	SetNewSession         func(*engine.Context, *PluginSessionState)

	CreateUser            func(*engine.Context, storage.Record) (storage.Record, error)
	UpdateUser            func(*engine.Context, string, storage.Record) (storage.Record, error)
	DeleteUser            func(*engine.Context, string) error
	ListUserSessions      func(context.Context, string, bool) ([]storage.Record, error)
	SetCredentialPassword func(*engine.Context, string, string) error
	ParseUserInput        func(*engine.Context, map[string]any) (storage.Record, error)
	SerializeUser         func(storage.Record) any
	SerializeSession      func(storage.Record) any

	RunBackground    func(context.Context, func(context.Context) error) error
	ValidateCSRF     func(*engine.Context) error
	ValidateFormCSRF func(*engine.Context) error
	ValidateRedirect func(*engine.Context, string, string) error
	HashPassword     PluginPasswordHash
	WrapPasswordHash func(PluginPasswordHashWrapper) error

	BeforeEmailVerification func(context.Context, *engine.Context, storage.Record) error
	AfterEmailVerification  func(context.Context, *engine.Context, storage.Record) error
	OnPasswordReset         func(context.Context, *engine.Context, storage.Record) error

	CreateVerification func(context.Context, string, string, time.Time) (storage.Record, error)
	FindVerification   func(context.Context, string) (storage.Record, error)
	// PeekVerification returns the latest verification row without deleting
	// expired database records. Plugins that must distinguish an expired value
	// from a missing value use this before their atomic consume step.
	PeekVerification    func(context.Context, string) (storage.Record, error)
	ConsumeVerification func(context.Context, string) (storage.Record, error)
	UpdateVerification  func(context.Context, string, storage.Record) error
	DeleteVerification  func(context.Context, string) error

	// InstallDefaultEmailVerification is only valid during Build. It adapts a
	// plugin email-only sender into the root verification hook.
	InstallDefaultEmailVerification func(func(context.Context, string) error) error
	RegisterDatabaseHooks           func(DatabaseHooks) error
}

func (a *Auth) pluginHost(options *runtimeOptions, pluginID string) PluginHost {
	return PluginHost{
		Options: cloneOptions(options.Options), Adapter: a.adapter,
		InternalAdapter: a.InternalAdapter(), Logger: a.logger,
		Clock: options.Clock, Random: options.Random, Secret: options.Secret,
		AdapterForContext: func(ctx context.Context) storage.TransactionAdapter {
			return currentTransactionAdapter(ctx, a.adapter)
		},
		EncryptSecret: func(value []byte) (string, error) {
			if len(options.secretConfig.Keys) == 0 {
				return baCrypto.EncryptWithReader(options.Secret, value, options.Random)
			}
			return baCrypto.EncryptWithConfigAndReader(
				options.secretConfig, value, options.Random,
			)
		},
		DecryptSecret: func(value string) ([]byte, error) {
			return baCrypto.DecryptWithConfig(options.secretConfig, value)
		},
		ResolveBaseURL: a.ResolveBaseURL,
		ListEndpoints: func() []engine.Endpoint {
			if a == nil || a.registry == nil {
				return nil
			}
			return a.registry.Endpoints()
		},
		TrustedOrigins: a.trustedOrigins,
		IsTrustedOrigin: func(request contract.Request, candidate string, allowRelative bool) (bool, error) {
			origins, err := a.trustedOrigins(request)
			if err != nil {
				return false, err
			}
			for _, origin := range origins {
				if matchesOriginPattern(candidate, origin, allowRelative) {
					return true, nil
				}
			}
			return false, nil
		},
		ResolveIPAddress: a.resolveIPAddress,
		SessionCookie: func(request contract.Request) (string, cookies.Options) {
			config := a.cookiesForRequest(request)
			return config.sessionName, config.sessionToken
		},
		Cookie: a.pluginCookieForRequest,
		HasPlugin: func(id string) bool {
			for _, plugin := range a.options.Plugins {
				if plugin.ID == id {
					return true
				}
			}
			return false
		},
		SocialProvider: a.socialProvider,
		RegisterSocialProvider: func(provider *providers.Provider) error {
			if provider == nil || strings.TrimSpace(provider.ID) == "" {
				return fmt.Errorf("single-auth: social provider ID must not be empty")
			}
			if options.SocialProviders == nil {
				options.SocialProviders = make(map[string]*providers.Provider)
			}
			if _, exists := options.SocialProviders[provider.ID]; exists {
				return fmt.Errorf("single-auth: social provider %q is already registered", provider.ID)
			}
			options.SocialProviders[provider.ID] = cloneSocialProvider(provider)
			return nil
		},
		CreateOAuthState: func(ctx *engine.Context, input PluginOAuthStateInput) (PluginOAuthState, error) {
			body := map[string]any{"callbackURL": input.CallbackURL}
			if input.ErrorURL != "" {
				body["errorCallbackURL"] = input.ErrorURL
			}
			if input.NewUserURL != "" {
				body["newUserCallbackURL"] = input.NewUserURL
			}
			if input.RequestSignUp != nil {
				body["requestSignUp"] = *input.RequestSignUp
			}
			if input.AdditionalData != nil {
				additional := make(map[string]any, len(input.AdditionalData))
				for key, value := range input.AdditionalData {
					additional[key] = value
				}
				body["additionalData"] = additional
			}
			state, raw, err := a.generateOAuthState(ctx, body, nil)
			if err != nil {
				return PluginOAuthState{}, err
			}
			return PluginOAuthState{State: raw, CodeVerifier: state.CodeVerifier}, nil
		},
		ConsumeOAuthState: func(ctx *engine.Context, raw string) (PluginOAuthStateData, error) {
			state, err := a.parseOAuthState(ctx, raw)
			if err != nil {
				code, errorURL := oauthStateFailure(err)
				return PluginOAuthStateData{}, &PluginOAuthStateError{
					Code: code, ErrorURL: errorURL, Cause: err,
				}
			}
			additional := make(map[string]any, len(state.Raw))
			for key, value := range state.Raw {
				switch key {
				case "callbackURL", "codeVerifier", "errorURL", "newUserURL", "oauthState", "expiresAt", "requestSignUp", "link":
					continue
				default:
					additional[key] = value
				}
			}
			return PluginOAuthStateData{
				CallbackURL: state.CallbackURL, ErrorURL: state.ErrorURL,
				NewUserURL: state.NewUserURL, CodeVerifier: state.CodeVerifier,
				RequestSignUp: state.RequestSignUp, AdditionalData: additional,
			}, nil
		},
		OAuthErrorURL: a.oauthErrorURL,
		HandleOAuthUser: func(ctx *engine.Context, input PluginOAuthUserInput) (PluginOAuthUserResult, error) {
			provider := input.Provider
			if provider == nil {
				provider = a.socialProvider(input.ProviderID)
			}
			if provider == nil || provider.ID == "" {
				return PluginOAuthUserResult{}, fmt.Errorf("single-auth: OAuth provider %q is not registered", input.ProviderID)
			}
			trustProviderByName := true
			if input.TrustProviderByName != nil {
				trustProviderByName = *input.TrustProviderByName
			}
			result, err := a.handleOAuthUserInfoWithTrust(
				ctx, provider, input.User, input.Tokens, input.DisableSignUp, input.CallbackURL,
				input.IsTrustedProvider, trustProviderByName,
			)
			if err != nil {
				return PluginOAuthUserResult{}, err
			}
			output := PluginOAuthUserResult{IsRegister: result.isRegister, LinkError: result.error}
			if result.user != nil && result.session != nil {
				output.State = PluginSessionState{
					Session: cloneStorageRecord(result.session),
					User:    cloneStorageRecord(result.user),
				}
			}
			return output, nil
		},
		LinkOAuthAccount: func(
			ctx *engine.Context,
			userID string,
			provider *providers.Provider,
			info oauth2.UserInfo,
			tokens oauth2.Tokens,
		) error {
			if provider == nil || provider.ID == "" {
				return fmt.Errorf("single-auth: OAuth provider is required for account linking")
			}
			return a.linkOAuthAccount(ctx, userID, provider, info, tokens)
		},
		ResolveSession: a.resolvePluginSession,
		GetSession: func(ctx *engine.Context) (contract.Response, error) {
			if ctx == nil {
				err := contract.NewAPIError(
					contract.StatusInternalServerError,
					"ENDPOINT_CONTEXT_REQUIRED",
					"Endpoint context is required",
				)
				return contract.ResponseFromError(err), err
			}
			endpoint := engine.Endpoint{
				Name: "getSession", Path: "/get-session", Methods: []string{"GET", "POST"},
				OperationID: "getSession", Handler: a.getSession,
			}
			return engine.RunEndpointIsolated(
				ctx,
				ctx.Request().WithMethod("GET"),
				endpoint,
			)
		},
		FindSession: func(ctx context.Context, token string) (*PluginSessionState, error) {
			resolved, err := a.findStoredSession(ctx, a.adapter, token)
			if err != nil || resolved == nil {
				return nil, err
			}
			return &PluginSessionState{
				Session: cloneStorageRecord(resolved.Session),
				User:    cloneStorageRecord(resolved.User),
			}, nil
		},
		FindSessions: func(ctx context.Context, tokens []string, onlyActive bool) ([]PluginSessionState, error) {
			resolved, err := a.findStoredSessions(ctx, tokens, onlyActive)
			if err != nil {
				return nil, err
			}
			result := make([]PluginSessionState, len(resolved))
			for index, state := range resolved {
				result[index] = PluginSessionState{
					Session: cloneStorageRecord(state.Session),
					User:    cloneStorageRecord(state.User),
				}
			}
			return result, nil
		},
		CreateSession:         a.createPluginSession,
		CreateSessionWithData: a.createPluginSessionWithData,
		IssueSession:          a.issuePluginSession,
		RefreshSession: func(ctx *engine.Context, state PluginSessionState, dontRemember bool) error {
			if state.Session == nil || state.User == nil {
				return fmt.Errorf("single-auth: plugin session state is incomplete")
			}
			if err := a.refreshSecondaryUser(ctx.GoContext(), state.User); err != nil {
				return err
			}
			a.setSessionCookies(ctx, state.Session, state.User, dontRemember)
			return nil
		},
		ExpireSessionCookies: a.expireSessionCookies,
		DeleteSession:        a.deleteStoredSession,
		DeleteSessions:       a.deleteStoredSessions,
		RevokeSessions: func(ctx *engine.Context, userID string) error {
			return a.deleteStoredUserSessions(ctx.GoContext(), userID, false)
		},
		RevokeUnproven:        a.revokePluginUnproven,
		NewSession:            pluginNewSession,
		SetNewSession:         setPluginNewSession,
		CreateUser:            a.createPluginUser,
		UpdateUser:            a.updatePluginUser,
		DeleteUser:            a.deletePluginUser,
		ListUserSessions:      a.listPluginUserSessions,
		SetCredentialPassword: a.setPluginCredentialPassword,
		ParseUserInput:        a.parsePluginUserInput,
		SerializeUser: func(user storage.Record) any {
			return a.publicUser(user)
		},
		SerializeSession: func(session storage.Record) any {
			return a.publicSession(session)
		},
		RunBackground:    a.runBackground,
		ValidateCSRF:     a.validateRequestCSRF,
		ValidateFormCSRF: a.validateFormRequestCSRF,
		HashPassword:     a.hashPassword,
		WrapPasswordHash: func(wrapper PluginPasswordHashWrapper) error {
			return a.passwordHash.wrap(wrapper)
		},
		ValidateRedirect: func(ctx *engine.Context, candidate, field string) error {
			if ctx == nil {
				return fmt.Errorf("single-auth: redirect validation requires an endpoint context")
			}
			return a.validateRedirectCandidate(ctx.Request(), candidate, field)
		},
		BeforeEmailVerification: func(ctx context.Context, _ *engine.Context, user storage.Record) error {
			if options.EmailVerification.BeforeEmailVerification == nil {
				return nil
			}
			return options.EmailVerification.BeforeEmailVerification(ctx, userFromRecord(user))
		},
		AfterEmailVerification: func(ctx context.Context, _ *engine.Context, user storage.Record) error {
			if options.EmailVerification.AfterEmailVerification == nil {
				return nil
			}
			return options.EmailVerification.AfterEmailVerification(ctx, userFromRecord(user))
		},
		OnPasswordReset: func(ctx context.Context, _ *engine.Context, user storage.Record) error {
			if options.EmailAndPassword.OnPasswordReset == nil {
				return nil
			}
			return options.EmailAndPassword.OnPasswordReset(ctx, userFromRecord(user))
		},
		CreateVerification:  a.createStoredVerification,
		FindVerification:    a.findStoredVerification,
		PeekVerification:    a.peekStoredVerification,
		ConsumeVerification: a.consumeStoredVerification,
		UpdateVerification:  a.updateStoredVerification,
		DeleteVerification:  a.deleteStoredVerification,
		InstallDefaultEmailVerification: func(handler func(context.Context, string) error) error {
			if handler == nil {
				return fmt.Errorf("single-auth: default email verification handler is nil")
			}
			options.EmailVerification.SendVerificationEmail = func(ctx context.Context, message EmailVerificationMessage) error {
				return handler(ctx, message.User.Email)
			}
			return nil
		},
		RegisterDatabaseHooks: func(hooks DatabaseHooks) error {
			return a.dbHooks.add("plugin:"+pluginID, hooks)
		},
	}
}

func (a *Auth) resolvePluginSession(ctx *engine.Context, mode PluginSessionMode) (*PluginSessionState, error) {
	if ctx == nil {
		return nil, unauthorized()
	}
	authoritative := mode == PluginSessionAuthoritative || mode == PluginSessionFresh
	resolved, err := a.sessionForEndpoint(ctx, authoritative)
	if err != nil {
		if mode == PluginSessionOptional {
			if apiError, ok := contract.AsAPIError(err); ok && apiError.Code == "UNAUTHORIZED" {
				return nil, nil
			}
		}
		return nil, err
	}
	if mode == PluginSessionFresh {
		if err := a.requireFreshSession(resolved.Session); err != nil {
			return nil, err
		}
	}
	return &PluginSessionState{
		Session: cloneStorageRecord(resolved.Session), User: cloneStorageRecord(resolved.User),
	}, nil
}

func (a *Auth) issuePluginSession(
	ctx *engine.Context,
	userID string,
	dontRemember bool,
) (*PluginSessionState, error) {
	state, err := a.createPluginSession(ctx, userID, dontRemember)
	if err != nil || state == nil {
		return state, err
	}
	a.setSessionCookies(ctx, state.Session, state.User, dontRemember)
	return state, nil
}

func (a *Auth) createPluginSession(
	ctx *engine.Context,
	userID string,
	dontRemember bool,
) (*PluginSessionState, error) {
	if ctx == nil || userID == "" {
		return nil, fmt.Errorf("single-auth: plugin session requires a user ID")
	}
	session, err := a.createSession(ctx, a.adapter, userID, dontRemember)
	if err != nil || session == nil {
		return nil, err
	}
	user, err := a.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
	if err != nil || user == nil {
		return nil, err
	}
	return &PluginSessionState{Session: session, User: user}, nil
}

func (a *Auth) createPluginUser(ctx *engine.Context, input storage.Record) (storage.Record, error) {
	if ctx == nil {
		return nil, fmt.Errorf("single-auth: plugin user creation requires an endpoint context")
	}
	data := cloneStorageRecord(input)
	if data == nil {
		data = storage.Record{}
	}
	id, generated, err := generateIdentifier(a.options, "user", 32)
	if err != nil {
		return nil, err
	}
	if generated {
		data["id"] = id
	}
	now := a.options.Clock().UTC()
	if _, exists := data["createdAt"]; !exists {
		data["createdAt"] = now
	}
	if _, exists := data["updatedAt"]; !exists {
		data["updatedAt"] = now
	}
	return a.adapter.Create(ctx.GoContext(), storage.CreateParams{
		Model: "user", Data: data, ForceAllowID: generated,
	})
}

func (a *Auth) parsePluginUserInput(ctx *engine.Context, input map[string]any) (storage.Record, error) {
	if ctx == nil {
		return nil, fmt.Errorf("single-auth: plugin user input requires an endpoint context")
	}
	return a.parseAdditionalInput("user", input)
}

func (a *Auth) revokePluginUnproven(ctx *engine.Context, userID string) error {
	if ctx == nil || userID == "" {
		return fmt.Errorf("single-auth: revoke unproven access requires a user ID")
	}
	user, err := a.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
	if err != nil || user == nil {
		return err
	}
	if verified, _ := recordBool(user, "emailVerified"); verified {
		return nil
	}
	accounts, err := a.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return err
	}
	for _, account := range accounts {
		providerID, _ := recordString(account, "providerId")
		accountID, _ := recordString(account, "id")
		if providerID != "credential" || accountID == "" {
			continue
		}
		if err := a.adapter.Delete(ctx.GoContext(), storage.DeleteParams{
			Model: "account", Where: []storage.Where{{Field: "id", Value: accountID}},
		}); err != nil {
			return err
		}
	}
	return a.deleteStoredUserSessions(ctx.GoContext(), userID, false)
}
