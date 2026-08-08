package core

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/secondary"
)

const (
	defaultAppName              = "single-auth"
	defaultBasePath             = "/api/auth"
	defaultSecret               = baCrypto.DefaultSecret
	defaultSessionExpiresIn     = 7 * 24 * time.Hour
	defaultSessionUpdateAge     = 24 * time.Hour
	defaultSessionFreshAge      = 24 * time.Hour
	defaultMinPasswordLength    = 8
	defaultMaxPasswordLength    = 128
	defaultCookieCacheMaxAge    = 5 * time.Minute
	defaultVerificationLifetime = time.Hour
)

// IDGenerator returns a upstream implementation identifier. The bool is false when the
// backing database must generate the identifier itself.
type IDGenerator func(model string, size int) (value string, generated bool, err error)

// BackgroundRunner receives non-critical work. A nil runner executes work
// synchronously, matching upstream implementation's server fallback.
type BackgroundRunner func(context.Context, func(context.Context) error) error

// PasswordOptions configures credential hashing and validation. Nil functions
// use upstream implementation's scrypt implementation from package crypto.
type PasswordOptions struct {
	Hash   func(string) (string, error)
	Verify func(hash, password string) bool
}

// PasswordResetMessage contains the reset link delivered by the configured
// mail hook.
type PasswordResetMessage struct {
	User  model.User
	URL   string
	Token string
}

// EmailAndPasswordOptions configures the built-in credential endpoints.
type EmailAndPasswordOptions struct {
	Enabled                     bool
	DisableSignUp               bool
	RequireEmailVerification    bool
	MinPasswordLength           int
	MaxPasswordLength           int
	AutoSignIn                  *bool
	RevokeSessionsOnReset       bool
	ResetPasswordTokenExpiresIn time.Duration
	SendResetPassword           func(context.Context, PasswordResetMessage) error
	Password                    PasswordOptions
	OnExistingUserSignUp        func(context.Context, model.User) error
	OnPasswordReset             func(context.Context, model.User) error
}

// EmailVerificationMessage contains the exact data passed to the email hook.
type EmailVerificationMessage struct {
	User  model.User
	URL   string
	Token string
}

// EmailVerificationOptions configures verification mail and token behavior.
type EmailVerificationOptions struct {
	SendVerificationEmail       func(context.Context, EmailVerificationMessage) error
	SendOnSignUp                *bool
	SendOnSignIn                bool
	AutoSignInAfterVerification bool
	ExpiresIn                   time.Duration
	BeforeEmailVerification     func(context.Context, model.User) error
	AfterEmailVerification      func(context.Context, model.User) error
}

// ChangeEmailConfirmationMessage is delivered to the current address before
// the new address is verified in the two-step flow.
type ChangeEmailConfirmationMessage struct {
	User     model.User
	NewEmail string
	URL      string
	Token    string
}

type ChangeEmailOptions struct {
	Enabled                        bool
	UpdateEmailWithoutVerification bool
	SendChangeEmailConfirmation    func(context.Context, ChangeEmailConfirmationMessage) error
}

type DeleteAccountMessage struct {
	User  model.User
	URL   string
	Token string
}

type DeleteUserOptions struct {
	Enabled                       bool
	SendDeleteAccountVerification func(context.Context, DeleteAccountMessage) error
	BeforeDelete                  func(context.Context, model.User) error
	AfterDelete                   func(context.Context, model.User) error
	DeleteTokenExpiresIn          time.Duration
}

type UserOptions struct {
	ChangeEmail ChangeEmailOptions
	DeleteUser  DeleteUserOptions
}

// CookieCacheOptions configures upstream implementation's session-data cookie.
type CookieCacheOptions struct {
	Enabled bool
	MaxAge  time.Duration
	// Strategy is compact, jwt, or jwe.
	Strategy string
	Version  string
	// RefreshCache enables upstream implementation's stateless cache refresh. When the
	// remaining session-data cookie lifetime falls below the refresh age, both
	// session_data and session_token are reissued without extending the logical
	// session expiry. upstream implementation ignores this option when a server-side session
	// store is configured.
	RefreshCache bool
	// RefreshCacheUpdateAge is the Go representation of upstream implementation's object
	// form, refreshCache: { updateAge }. Nil uses floor(MaxAge * 0.2).
	RefreshCacheUpdateAge *time.Duration
}

// SessionOptions configures database sessions and their cookies.
type SessionOptions struct {
	ExpiresIn time.Duration
	// Stateless makes the signed cookie cache authoritative. The core runtime
	// otherwise uses its configured (or built-in memory) adapter as a durable
	// session store.
	Stateless bool
	// UpdateAge and FreshAge are pointers because zero has defined upstream implementation
	// semantics: update on every use and always consider the session fresh.
	// Nil selects the upstream defaults.
	UpdateAge             *time.Duration
	FreshAge              *time.Duration
	DisableSessionRefresh bool
	// DeferSessionRefresh keeps GET /get-session read-only. A POST to the same
	// endpoint performs the write-side refresh when this option is enabled.
	DeferSessionRefresh bool
	// StoreSessionInDatabase keeps a database copy when SecondaryStorage is
	// configured. PreserveSessionInDatabase retains that copy after revocation
	// for audit use, while the secondary entry remains authoritative.
	StoreSessionInDatabase    bool
	PreserveSessionInDatabase bool
	CookieCache               CookieCacheOptions
}

// VerificationOptions controls persistence of single-use verification data.
// With SecondaryStorage or SecondaryValueStorage configured, values are
// cache-only unless StoreInDatabase is true.
type VerificationOptions struct {
	DisableCleanup  bool
	StoreInDatabase bool
	// StoreIdentifier controls how verification identifiers (tokens, OTPs,
	// OAuth state values, and similar secrets) are persisted. The zero value is
	// plain storage. Overrides are evaluated in order and the first matching
	// prefix wins, matching Object.entries ordering in upstream implementation.
	StoreIdentifier VerificationIdentifierStorage
}

// VerificationIdentifierStrategy is a built-in verification identifier
// storage strategy.
type VerificationIdentifierStrategy string

const (
	// VerificationIdentifierPlain stores identifiers unchanged.
	VerificationIdentifierPlain VerificationIdentifierStrategy = "plain"
	// VerificationIdentifierHashed stores SHA-256 identifiers as unpadded
	// base64url, matching upstream implementation's "hashed" strategy.
	VerificationIdentifierHashed VerificationIdentifierStrategy = "hashed"
)

// VerificationIdentifierHasher implements upstream implementation's custom
// { hash(identifier) } storeIdentifier option.
type VerificationIdentifierHasher func(identifier string) (string, error)

// VerificationIdentifierOverride selects a storage rule for identifiers with
// Prefix. Hash takes precedence over Strategy and represents the upstream
// custom-hasher form.
type VerificationIdentifierOverride struct {
	Prefix   string
	Strategy VerificationIdentifierStrategy
	Hash     VerificationIdentifierHasher
}

// VerificationIdentifierStorage configures the default identifier storage
// rule and optional ordered prefix overrides. Hash takes precedence over
// Strategy and represents the upstream custom-hasher form.
type VerificationIdentifierStorage struct {
	Strategy  VerificationIdentifierStrategy
	Hash      VerificationIdentifierHasher
	Overrides []VerificationIdentifierOverride
}

// SecondaryStorage is upstream implementation's string-valued session, verification, and
// rate-limit storage contract.
type SecondaryStorage = secondary.Storage

// SecondaryGetAndDeleter provides cross-process atomic consumption for
// single-use verification values.
type SecondaryGetAndDeleter = secondary.GetAndDeleter

// SecondaryValueStorage is the object-valued form of upstream implementation's secondary
// storage contract. Some Redis wrappers parse JSON before returning it, so a
// Go implementation cannot expose that behavior through SecondaryStorage's
// string-returning Get method. Configure this interface through
// Options.SecondaryValueStorage instead. Set still receives the canonical JSON
// string written by upstream implementation.
type SecondaryValueStorage = secondary.ValueStorage

// SecondaryValueGetAndDeleter provides atomic consumption for an
// object-valued secondary store.
type SecondaryValueGetAndDeleter = secondary.ValueGetAndDeleter

// AccountLinkingOptions configures built-in account linking and unlinking.
type AccountLinkingOptions struct {
	Enabled                   *bool
	AllowUnlinkingAll         bool
	AllowDifferentEmails      bool
	DisableImplicitLinking    bool
	RequireLocalEmailVerified *bool
	UpdateUserInfoOnLink      bool
	TrustedProviders          []string
}

// AccountOptions configures provider account persistence and linking.
type AccountOptions struct {
	UpdateAccountOnSignIn *bool
	EncryptOAuthTokens    bool
	StoreAccountCookie    *bool
	// StoreStateStrategy is "database" or "cookie". An empty value follows
	// upstream implementation: database when a database is configured, cookie otherwise.
	StoreStateStrategy   string
	SkipStateCookieCheck bool
	AccountLinking       AccountLinkingOptions
}

// CookieOverride customizes one upstream implementation cookie. Attribute pointers retain
// the distinction between an omitted override and an explicit false value.
type CookieOverride struct {
	Name        string
	MaxAge      *int
	Expires     *time.Time
	Domain      *string
	Path        *string
	Secure      *bool
	HTTPOnly    *bool
	Partitioned *bool
	SameSite    *string
}

// DynamicBaseURLOptions resolves the public auth URL from each request while
// constraining the host to an explicit allowlist. Protocol accepts "http",
// "https", or "auto"; an empty value defaults to HTTPS and also permits HTTP
// for loopback hosts, matching upstream implementation's development behavior.
type DynamicBaseURLOptions struct {
	AllowedHosts []string
	Protocol     string
	Fallback     string
}

// CrossSubDomainCookieOptions shares auth cookies across subdomains. When
// Domain is empty, a static base URL supplies its hostname; dynamic base URLs
// resolve it from each allowed incoming request.
type CrossSubDomainCookieOptions struct {
	Enabled           bool
	Domain            string
	AdditionalCookies []string
}

// TrustedOriginsResolver contributes request-scoped trusted origins. The
// returned slice is copied and empty entries are ignored.
type TrustedOriginsResolver func(context.Context, contract.Request) ([]string, error)

// AdvancedOptions contains security- and transport-sensitive settings.
type AdvancedOptions struct {
	UseSecureCookies *bool
	// IPAddress controls the shared upstream implementation client-IP resolver used for
	// session tracking, rate limiting, and plugins such as captcha.
	IPAddress ratelimit.IPOptions
	// Pointer values retain the upstream distinction between an omitted option
	// and an explicit false value. In particular, an explicitly enabled
	// DisableOriginCheck also disables CSRF only when DisableCSRFCheck is nil.
	DisableCSRFCheck    *bool
	DisableOriginCheck  *bool
	TrustedProxyHeaders *bool
	// SkipOriginCheckPaths disables both URL and CSRF origin checks only for an
	// exact path or a slash-boundary child of a configured path.
	SkipOriginCheckPaths    []string
	CrossSubDomainCookies   CrossSubDomainCookieOptions
	CookiePrefix            string
	DefaultCookieAttributes CookieOverride
	Cookies                 map[string]CookieOverride
	SkipTrailingSlashes     bool
}

type APIErrorOptions struct {
	ErrorURL                  string
	CustomizeDefaultErrorPage bool
}

// RateLimitOptions configures the built-in request limiter. Window and Max
// are the default rule. Storage accepts "memory", "database", or
// "secondary-storage"; CustomStorage takes precedence when present.
type RateLimitOptions struct {
	Enabled       *bool
	Window        int64
	Max           int64
	Storage       string
	ModelName     string
	Fields        map[string]string
	CustomStorage ratelimit.Storage
	CustomRules   []ratelimit.CustomRule
	IP            ratelimit.IPOptions
	Warn          func(string)
	Error         func(string, error)
}

// Options is the immutable configuration snapshot consumed by New.
//
// Engine-level extension points are intentionally public so plugin packages
// can depend on focused contracts without creating a cycle through the
// canonical core runtime.
type Options struct {
	AppName               string
	Environment           string
	BaseURL               string
	DynamicBaseURL        *DynamicBaseURLOptions
	BasePath              string
	Secret                string
	Secrets               []baCrypto.SecretEntry
	Database              storage.Adapter
	DatabaseHooks         DatabaseHooks
	Schema                storage.Schema
	EmailAndPassword      EmailAndPasswordOptions
	EmailVerification     EmailVerificationOptions
	User                  UserOptions
	Session               SessionOptions
	Verification          VerificationOptions
	Account               AccountOptions
	Advanced              AdvancedOptions
	OnAPIError            APIErrorOptions
	RateLimit             RateLimitOptions
	SecondaryStorage      SecondaryStorage
	SecondaryValueStorage SecondaryValueStorage
	Logger                logger.Options
	SocialProviders       map[string]*providers.Provider
	TrustedOrigins        []string
	ResolveTrustedOrigins TrustedOriginsResolver
	DisabledPaths         []string
	Plugins               []engine.Plugin
	PluginFactories       []PluginFactory
	Endpoints             []engine.Endpoint
	Middleware            []engine.Middleware
	Hooks                 engine.Hooks
	Clock                 func() time.Time
	Random                io.Reader
	GenerateID            IDGenerator
	HTTPClient            *http.Client
	RunBackground         BackgroundRunner
	databaseInitializer   contextDatabaseInitializer
}

type runtimeOptions struct {
	Options
	secretConfig                 baCrypto.SecretConfig
	cookie                       cookieConfig
	stateful                     bool
	logger                       *logger.Logger
	pluginTrustedOrigins         []string
	pluginTrustedOriginResolvers []TrustedOriginsResolver
}

type cookieConfig struct {
	sessionToken     cookies.Options
	sessionName      string
	sessionData      cookies.Options
	sessionDataName  string
	dontRemember     cookies.Options
	dontRememberName string
	state            cookies.Options
	stateName        string
	oauthState       cookies.Options
	oauthStateName   string
	accountData      cookies.Options
	accountDataName  string
}

func normalizeOptions(options Options) (runtimeOptions, error) {
	clone := cloneOptions(options)
	if clone.SecondaryStorage != nil && clone.SecondaryValueStorage != nil {
		return runtimeOptions{}, fmt.Errorf(
			"single-auth: secondary storage and secondary value storage are mutually exclusive",
		)
	}
	if clone.BaseURL != "" && clone.DynamicBaseURL != nil {
		return runtimeOptions{}, fmt.Errorf("single-auth: base URL and dynamic base URL are mutually exclusive")
	}
	if clone.DynamicBaseURL != nil {
		if len(clone.DynamicBaseURL.AllowedHosts) == 0 {
			return runtimeOptions{}, fmt.Errorf("baseURL.allowedHosts cannot be empty")
		}
		switch clone.DynamicBaseURL.Protocol {
		case "", "auto", "http", "https":
		default:
			return runtimeOptions{}, fmt.Errorf("single-auth: dynamic base URL protocol must be http, https, or auto")
		}
		if clone.DynamicBaseURL.Fallback != "" {
			if _, err := staticBaseURL(clone.DynamicBaseURL.Fallback, clone.BasePath); err != nil {
				return runtimeOptions{}, err
			}
		}
	}
	if clone.AppName == "" {
		clone.AppName = defaultAppName
	}
	if clone.BasePath == "" {
		clone.BasePath = defaultBasePath
	}
	if clone.BaseURL == "" && clone.DynamicBaseURL == nil {
		clone.BaseURL = baseURLFromEnvironment()
	}
	if clone.BaseURL != "" {
		if _, err := staticBaseURL(clone.BaseURL, clone.BasePath); err != nil {
			return runtimeOptions{}, err
		}
	}
	if clone.Clock == nil {
		clone.Clock = time.Now
	}
	if clone.Random == nil {
		clone.Random = rand.Reader
	}
	if clone.HTTPClient == nil {
		clone.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	for _, provider := range clone.SocialProviders {
		if provider != nil && provider.Options.HTTPClient == nil {
			provider.Options.HTTPClient = clone.HTTPClient
		}
	}
	runtimeLogger, err := logger.New(clone.Logger)
	if err != nil {
		return runtimeOptions{}, err
	}
	if invalid := ratelimit.FindInvalidTrustedProxies(clone.Advanced.IPAddress.TrustedProxies); len(invalid) > 0 {
		runtimeLogger.Warn(fmt.Sprintf(
			"Ignoring invalid `advanced.ipAddress.trustedProxies` entries: %s. Each entry must be an IP address or CIDR range.",
			strings.Join(invalid, ", "),
		))
	}
	secretConfig, err := resolveSecretConfiguration(&clone, runtimeLogger)
	if err != nil {
		return runtimeOptions{}, err
	}
	if clone.EmailAndPassword.MinPasswordLength == 0 {
		clone.EmailAndPassword.MinPasswordLength = defaultMinPasswordLength
	}
	if clone.EmailAndPassword.MaxPasswordLength == 0 {
		clone.EmailAndPassword.MaxPasswordLength = defaultMaxPasswordLength
	}
	if clone.EmailAndPassword.Password.Hash == nil {
		clone.EmailAndPassword.Password.Hash = baCrypto.HashPassword
	}
	if clone.EmailAndPassword.Password.Verify == nil {
		clone.EmailAndPassword.Password.Verify = baCrypto.VerifyPassword
	}
	if clone.EmailAndPassword.ResetPasswordTokenExpiresIn == 0 {
		clone.EmailAndPassword.ResetPasswordTokenExpiresIn = defaultVerificationLifetime
	}
	if clone.Session.ExpiresIn == 0 {
		clone.Session.ExpiresIn = defaultSessionExpiresIn
	}
	if clone.Session.UpdateAge == nil {
		clone.Session.UpdateAge = durationPointer(defaultSessionUpdateAge)
	}
	if clone.Session.FreshAge == nil {
		clone.Session.FreshAge = durationPointer(defaultSessionFreshAge)
	}
	if clone.Session.CookieCache.MaxAge == 0 {
		clone.Session.CookieCache.MaxAge = defaultCookieCacheMaxAge
	}
	if clone.Session.CookieCache.Strategy == "" {
		clone.Session.CookieCache.Strategy = "compact"
	}
	if clone.Session.CookieCache.Version == "" {
		clone.Session.CookieCache.Version = "1"
	}
	if clone.EmailVerification.ExpiresIn == 0 {
		clone.EmailVerification.ExpiresIn = defaultVerificationLifetime
	}
	if clone.User.DeleteUser.DeleteTokenExpiresIn == 0 {
		clone.User.DeleteUser.DeleteTokenExpiresIn = 24 * time.Hour
	}
	primaryDatabaseConfigured := options.Database != nil || options.databaseInitializer != nil
	if clone.Account.StoreStateStrategy == "" {
		if !primaryDatabaseConfigured && options.SecondaryStorage == nil && options.SecondaryValueStorage == nil {
			clone.Account.StoreStateStrategy = "cookie"
		} else {
			clone.Account.StoreStateStrategy = "database"
		}
	}
	if clone.Account.StoreAccountCookie == nil {
		clone.Account.StoreAccountCookie = cloneBoolValue(!primaryDatabaseConfigured)
	}
	if clone.Account.StoreStateStrategy != "database" && clone.Account.StoreStateStrategy != "cookie" {
		return runtimeOptions{}, fmt.Errorf("single-auth: account store state strategy must be database or cookie")
	}
	if clone.RateLimit.ModelName == "" {
		clone.RateLimit.ModelName = "rateLimit"
	}
	switch clone.RateLimit.Storage {
	case "", "memory", "database", "secondary-storage":
	default:
		return runtimeOptions{}, fmt.Errorf(
			"single-auth: rate limit storage must be memory, database, or secondary-storage",
		)
	}
	for field, physical := range clone.RateLimit.Fields {
		switch field {
		case "key", "count", "lastRequest":
		default:
			return runtimeOptions{}, fmt.Errorf("single-auth: unsupported rate limit field %q", field)
		}
		if strings.TrimSpace(physical) == "" {
			return runtimeOptions{}, fmt.Errorf("single-auth: rate limit field %q has an empty physical name", field)
		}
	}
	if err := validateVerificationIdentifierStorage(clone.Verification.StoreIdentifier); err != nil {
		return runtimeOptions{}, err
	}

	cookie, err := resolveCookies(clone)
	if err != nil {
		return runtimeOptions{}, err
	}
	return runtimeOptions{
		Options: clone, secretConfig: secretConfig, cookie: cookie,
		stateful: !clone.Session.Stateless, logger: runtimeLogger,
	}, nil
}

func cloneOptions(options Options) Options {
	clone := options
	if options.DynamicBaseURL != nil {
		dynamic := *options.DynamicBaseURL
		dynamic.AllowedHosts = append([]string(nil), options.DynamicBaseURL.AllowedHosts...)
		clone.DynamicBaseURL = &dynamic
	}
	clone.Schema = options.Schema.Clone()
	clone.DatabaseHooks = cloneDatabaseHooks(options.DatabaseHooks)
	clone.Secrets = append([]baCrypto.SecretEntry(nil), options.Secrets...)
	clone.TrustedOrigins = append([]string(nil), options.TrustedOrigins...)
	clone.DisabledPaths = append([]string(nil), options.DisabledPaths...)
	clone.Plugins = make([]engine.Plugin, len(options.Plugins))
	for index, plugin := range options.Plugins {
		clone.Plugins[index] = clonePlugin(plugin)
	}
	clone.PluginFactories = append([]PluginFactory(nil), options.PluginFactories...)
	clone.Endpoints = make([]engine.Endpoint, len(options.Endpoints))
	for index, endpoint := range options.Endpoints {
		clone.Endpoints[index] = cloneEndpoint(endpoint)
	}
	clone.Middleware = append([]engine.Middleware(nil), options.Middleware...)
	clone.Hooks.Before = append([]engine.BeforeHook(nil), options.Hooks.Before...)
	clone.Hooks.After = append([]engine.AfterHook(nil), options.Hooks.After...)
	clone.EmailAndPassword.AutoSignIn = cloneBool(options.EmailAndPassword.AutoSignIn)
	clone.EmailVerification.SendOnSignUp = cloneBool(options.EmailVerification.SendOnSignUp)
	clone.Verification.StoreIdentifier.Overrides = append(
		[]VerificationIdentifierOverride(nil),
		options.Verification.StoreIdentifier.Overrides...,
	)
	clone.Session.UpdateAge = cloneDuration(options.Session.UpdateAge)
	clone.Session.FreshAge = cloneDuration(options.Session.FreshAge)
	clone.Session.CookieCache.RefreshCacheUpdateAge = cloneDuration(
		options.Session.CookieCache.RefreshCacheUpdateAge,
	)
	clone.Account.UpdateAccountOnSignIn = cloneBool(options.Account.UpdateAccountOnSignIn)
	clone.Account.StoreAccountCookie = cloneBool(options.Account.StoreAccountCookie)
	clone.Account.AccountLinking.Enabled = cloneBool(options.Account.AccountLinking.Enabled)
	clone.Account.AccountLinking.RequireLocalEmailVerified = cloneBool(
		options.Account.AccountLinking.RequireLocalEmailVerified,
	)
	clone.Account.AccountLinking.TrustedProviders = append(
		[]string(nil), options.Account.AccountLinking.TrustedProviders...,
	)
	if options.SocialProviders != nil {
		clone.SocialProviders = make(map[string]*providers.Provider, len(options.SocialProviders))
		for id, provider := range options.SocialProviders {
			clone.SocialProviders[id] = cloneSocialProvider(provider)
		}
	}
	clone.Advanced.UseSecureCookies = cloneBool(options.Advanced.UseSecureCookies)
	clone.Advanced.DisableCSRFCheck = cloneBool(options.Advanced.DisableCSRFCheck)
	clone.Advanced.DisableOriginCheck = cloneBool(options.Advanced.DisableOriginCheck)
	clone.Advanced.TrustedProxyHeaders = cloneBool(options.Advanced.TrustedProxyHeaders)
	clone.Advanced.IPAddress = cloneIPOptions(options.Advanced.IPAddress)
	clone.Advanced.SkipOriginCheckPaths = append(
		[]string(nil), options.Advanced.SkipOriginCheckPaths...,
	)
	clone.Advanced.CrossSubDomainCookies.AdditionalCookies = append(
		[]string(nil), options.Advanced.CrossSubDomainCookies.AdditionalCookies...,
	)
	clone.RateLimit.Enabled = cloneBool(options.RateLimit.Enabled)
	clone.Logger.DisableColors = cloneBool(options.Logger.DisableColors)
	clone.RateLimit.CustomRules = append(
		[]ratelimit.CustomRule(nil), options.RateLimit.CustomRules...,
	)
	clone.RateLimit.IP = cloneIPOptions(options.RateLimit.IP)
	if options.RateLimit.Fields != nil {
		clone.RateLimit.Fields = make(map[string]string, len(options.RateLimit.Fields))
		for name, field := range options.RateLimit.Fields {
			clone.RateLimit.Fields[name] = field
		}
	}
	clone.Advanced.DefaultCookieAttributes = cloneCookieOverride(options.Advanced.DefaultCookieAttributes)
	if options.Advanced.Cookies != nil {
		clone.Advanced.Cookies = make(map[string]CookieOverride, len(options.Advanced.Cookies))
		for name, value := range options.Advanced.Cookies {
			clone.Advanced.Cookies[name] = cloneCookieOverride(value)
		}
	}
	return clone
}

func cloneIPOptions(options ratelimit.IPOptions) ratelimit.IPOptions {
	clone := options
	if options.Headers != nil {
		clone.Headers = append([]string{}, options.Headers...)
	}
	if options.TrustedProxies != nil {
		clone.TrustedProxies = append([]string{}, options.TrustedProxies...)
	}
	if options.IPv6Subnet != nil {
		value := *options.IPv6Subnet
		clone.IPv6Subnet = &value
	}
	return clone
}

func cloneSocialProvider(provider *providers.Provider) *providers.Provider {
	if provider == nil {
		return nil
	}
	clone := *provider
	clone.Options.Scopes = append([]string(nil), provider.Options.Scopes...)
	clone.Options.Fields = append([]string(nil), provider.Options.Fields...)
	clone.Options.Claims = append([]string(nil), provider.Options.Claims...)
	clone.Metadata.DefaultScopes = append([]string(nil), provider.Metadata.DefaultScopes...)
	return &clone
}

func clonePlugin(plugin engine.Plugin) engine.Plugin {
	clone := plugin
	clone.Schema = plugin.Schema.Clone()
	clone.TrustedOrigins = append([]string(nil), plugin.TrustedOrigins...)
	clone.Endpoints = make([]engine.Endpoint, len(plugin.Endpoints))
	for index, endpoint := range plugin.Endpoints {
		clone.Endpoints[index] = cloneEndpoint(endpoint)
	}
	clone.Middleware = append([]engine.Middleware(nil), plugin.Middleware...)
	clone.RateLimit = append([]ratelimit.MatcherRule(nil), plugin.RateLimit...)
	clone.Hooks.Before = append([]engine.BeforeHook(nil), plugin.Hooks.Before...)
	clone.Hooks.After = append([]engine.AfterHook(nil), plugin.Hooks.After...)
	if plugin.ErrorCodes != nil {
		clone.ErrorCodes = make(map[string]engine.ErrorDefinition, len(plugin.ErrorCodes))
		for code, definition := range plugin.ErrorCodes {
			clone.ErrorCodes[code] = definition
		}
	}
	return clone
}

func cloneEndpoint(endpoint engine.Endpoint) engine.Endpoint {
	clone := endpoint
	clone.Methods = append([]string(nil), endpoint.Methods...)
	return clone
}

func cloneCookieOverride(value CookieOverride) CookieOverride {
	clone := value
	clone.MaxAge = cloneInt(value.MaxAge)
	if value.Expires != nil {
		expires := *value.Expires
		clone.Expires = &expires
	}
	clone.Domain = cloneString(value.Domain)
	clone.Path = cloneString(value.Path)
	clone.Secure = cloneBool(value.Secure)
	clone.HTTPOnly = cloneBool(value.HTTPOnly)
	clone.Partitioned = cloneBool(value.Partitioned)
	clone.SameSite = cloneString(value.SameSite)
	return clone
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneBoolValue(value bool) *bool { return &value }

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneDuration(value *time.Duration) *time.Duration {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func durationPointer(value time.Duration) *time.Duration { return &value }
