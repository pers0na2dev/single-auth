---
title: "github.com/pers0na2dev/single-auth/core"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/core.

- Import path: `github.com/pers0na2dev/single-auth/core`
- Package name: `core`

Package core contains the canonical single-auth server runtime.

Most applications should import github.com/pers0na2dev/single-auth, whose
generated facade re-exports this package's public API. The explicit core
path is useful to tooling and integrations that want the canonical type
identities directly.

## Variables

```go
var (
	ErrMinimalMigrationsUnsupported = &UpstreamError{message: minimalMigrationsErrorMessage}

	ErrMinimalDirectDatabaseUnsupported = &UpstreamError{message: minimalDirectDatabaseErrorMessage}
)
```

BaseErrorMessages is the exact upstream implementation 1.6.26 base error catalog.

```go
var BaseErrorMessages = map[ErrorCode]string{
	ErrorUserNotFound:                    "User not found",
	ErrorFailedToCreateUser:              "Failed to create user",
	ErrorFailedToCreateSession:           "Failed to create session",
	ErrorFailedToUpdateUser:              "Failed to update user",
	ErrorFailedToGetSession:              "Failed to get session",
	ErrorInvalidPassword:                 "Invalid password",
	ErrorInvalidEmail:                    "Invalid email",
	ErrorInvalidEmailOrPassword:          "Invalid email or password",
	ErrorInvalidUser:                     "Invalid user",
	ErrorSocialAccountAlreadyLinked:      "Social account already linked",
	ErrorProviderNotFound:                "Provider not found",
	ErrorInvalidToken:                    "Invalid token",
	ErrorTokenExpired:                    "Token expired",
	ErrorIDTokenNotSupported:             "id_token not supported",
	ErrorFailedToGetUserInfo:             "Failed to get user info",
	ErrorUserEmailNotFound:               "User email not found",
	ErrorEmailNotVerified:                "Email not verified",
	ErrorPasswordTooShort:                "Password too short",
	ErrorPasswordTooLong:                 "Password too long",
	ErrorUserAlreadyExists:               "User already exists.",
	ErrorUserAlreadyExistsAnotherEmail:   "User already exists. Use another email.",
	ErrorEmailCannotBeUpdated:            "Email can not be updated",
	ErrorChangeEmailDisabled:             "Change email is disabled",
	ErrorCredentialAccountNotFound:       "Credential account not found",
	ErrorSessionExpired:                  "Session expired. Re-authenticate to perform this action.",
	ErrorFailedToUnlinkLastAccount:       "You can't unlink your last account",
	ErrorAccountNotFound:                 "Account not found",
	ErrorUserAlreadyHasPassword:          "User already has a password. Provide that to delete the account.",
	ErrorCrossSiteNavigationLoginBlocked: "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
	ErrorVerificationEmailNotEnabled:     "Verification email isn't enabled",
	ErrorEmailAlreadyVerified:            "Email is already verified",
	ErrorEmailMismatch:                   "Email mismatch",
	ErrorSessionNotFresh:                 "Session is not fresh",
	ErrorLinkedAccountAlreadyExists:      "Linked account already exists",
	ErrorInvalidOrigin:                   "Invalid origin",
	ErrorInvalidCallbackURL:              "Invalid callbackURL",
	ErrorInvalidRedirectURL:              "Invalid redirectURL",
	ErrorInvalidErrorCallbackURL:         "Invalid errorCallbackURL",
	ErrorInvalidNewUserCallbackURL:       "Invalid newUserCallbackURL",
	ErrorMissingOrNullOrigin:             "Missing or null Origin",
	ErrorCallbackURLRequired:             "callbackURL is required",
	ErrorFailedToCreateVerification:      "Unable to create verification",
	ErrorFieldNotAllowed:                 "Field not allowed to be set",
	ErrorAsyncValidationNotSupported:     "Async validation is not supported",
	ErrorValidation:                      "Validation Error",
	ErrorMissingField:                    "Field is required",
	ErrorMethodNeedsDeferredSession:      "POST method requires deferSessionRefresh to be enabled in session config",
	ErrorBodyMustBeObject:                "Body must be an object",
	ErrorPasswordAlreadySet:              "User already has a password set",
}
```

```go
var (
	ErrFullMigrationsRequireDatabase = &UpstreamError{message: fullMigrationAdapterErrorMessage}
)
```

## Functions

### `DecodeDBField`

DecodeDBField reads an optional database field without collapsing the three
states represented by upstream implementation output types: absent (undefined), explicit
null, and present. A present value with the wrong Go type is rejected.

```go
func DecodeDBField[Value any](fields model.Fields, name string) (model.Value[Value], error)
```

### `DecodeDirectJSON`

DecodeDirectJSON decodes the exact response body into Output. It is useful
for typed plugin endpoint façades and rejects malformed JSON.

```go
func DecodeDirectJSON[Output any](result DirectCallResult) (Output, error)
```

### `DecodeUserField`

DecodeUserField reads one configured user field without collapsing absent,
null, and present values. A present value of the wrong Go type is rejected
instead of being silently replaced by its zero value.

```go
func DecodeUserField[Value any](fields model.Fields, name string) (model.Value[Value], error)
```

### `ErrorMessage`

ErrorMessage returns a stable message or an empty string for unknown codes.

```go
func ErrorMessage(code ErrorCode) string
```

### `ExpireCookie`

ExpireCookie removes pending writes for a cookie and its chunk variants,
then appends an expiring cookie while preserving all configured attributes.

```go
func ExpireCookie(ctx *engine.Context, cookieName string, options cookies.Options)
```

### `GetCookieCache`

GetCookieCache verifies and decodes a upstream implementation session-data Cookie
header. A missing cookie is not an error. A present cookie requires a secret,
matching the upstream helper's fail-closed behavioral compatibility.

```go
func GetCookieCache(cookieHeader string, options ...CookieCacheLookupOptions) (map[string]any, error)
```

### `GetCookieCacheFromHTTPRequest`

GetCookieCacheFromHTTPRequest is the net/http form of GetCookieCache.

```go
func GetCookieCacheFromHTTPRequest(request *http.Request, options ...CookieCacheLookupOptions) (map[string]any, error)
```

### `GetSessionCookie`

GetSessionCookie reads a upstream implementation session token from a Cookie header.

```go
func GetSessionCookie(cookieHeader string, options ...SessionCookieLookupOptions) (string, bool)
```

### `GetSessionCookieFromHTTPRequest`

GetSessionCookieFromHTTPRequest is the net/http form of GetSessionCookie.

```go
func GetSessionCookieFromHTTPRequest(request *http.Request, options ...SessionCookieLookupOptions) (string, bool)
```

### `GetSessionCookieFromHeaderGetter`

GetSessionCookieFromHeaderGetter reads from any net/http-compatible header
getter, including inherited and cross-runtime wrappers.

```go
func GetSessionCookieFromHeaderGetter(headers CookieHeaderGetter, options ...SessionCookieLookupOptions) (string, bool)
```

### `PreserveInferenceWithUntypedPlugins`

PreserveInferenceWithUntypedPlugins deliberately keeps the inferred static
session type when an integration also supplies dynamically typed plugins.

```go
func PreserveInferenceWithUntypedPlugins[Inference any](
	inference Inference,
	_ ...any,
) Inference
```

### `QueueAfterTransactionHook`

QueueAfterTransactionHook queues hook on the current adapter scope. Outside
a scope it executes immediately.

```go
func QueueAfterTransactionHook(ctx context.Context, hook func() error) error
```

### `RequireDBField`

RequireDBField reads a required configured or plugin database field. Missing,
null, and wrong-typed values are errors rather than implicit zero values.

```go
func RequireDBField[Value any](fields model.Fields, name string) (Value, error)
```

### `RequiredKeysOf`

RequiredKeysOf returns a compile-time marker without reflection. Result is
inferred from the shape's method signature on current Go toolchains.

```go
func RequiredKeysOf[
	Result RequiredKeysResult,
	Shape interface{ RequiredKeysResult() Result },
](shape Shape) Result
```

### `SessionMiddleware`

SessionMiddleware is the endpoint-local equivalent of upstream implementation's
sessionMiddleware. It resolves a valid logical session and merges the
session/user pair into request-local endpoint context for later middleware
and the handler.

```go
func SessionMiddleware(ctx *engine.Context) (engine.EndpointMiddlewareResult, error)
```

### `SetEndpointSession`

SetEndpointSession installs a logical session/user pair for the remainder of
the current dispatch. Authentication plugins use it when a non-cookie
credential has already been validated by a before hook.

```go
func SetEndpointSession(ctx *engine.Context, state *PluginSessionState)
```

## Types

### `APIError`

```go
type APIError = contract.APIError
```

### `APIErrorOptions`

```go
type APIErrorOptions struct {
	ErrorURL                  string
	CustomizeDefaultErrorPage bool
}
```

### `AccessTokenResult`

```go
type AccessTokenResult struct {
	AccessToken          string
	AccessTokenExpiresAt *time.Time
	Scopes               []string
	IDToken              string
	Headers              contract.Headers
}
```

### `Account`

```go
type Account = model.Account
```

### `AccountInfoInput`

```go
type AccountInfoInput struct {
	ProviderID string
	AccountID  string
	UserID     string
	Headers    contract.Headers
}
```

### `AccountInfoResult`

```go
type AccountInfoResult struct {
	User    ProviderUser
	Data    any
	Headers contract.Headers
}
```

### `AccountLinkingOptions`

AccountLinkingOptions configures built-in account linking and unlinking.

```go
type AccountLinkingOptions struct {
	Enabled                   *bool
	AllowUnlinkingAll         bool
	AllowDifferentEmails      bool
	DisableImplicitLinking    bool
	RequireLocalEmailVerified *bool
	UpdateUserInfoOnLink      bool
	TrustedProviders          []string
}
```

### `AccountOptions`

AccountOptions configures provider account persistence and linking.

```go
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
```

### `AccountTokenInput`

```go
type AccountTokenInput struct {
	ProviderID string
	AccountID  string
	// UserID is accepted only by direct server calls without session headers.
	UserID  string
	Headers contract.Headers
}
```

### `AdvancedOptions`

AdvancedOptions contains security- and transport-sensitive settings.

```go
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
```

### `AnyKeyShape`

AnyKeyShape represents an unconstrained any-shaped object. It deliberately
reports no statically known required keys.

```go
type AnyKeyShape struct{}
```

## Methods on `AnyKeyShape`

### `RequiredKeysResult`

```go
func (AnyKeyShape) RequiredKeysResult() RequiredKeysAbsent
```

### `Auth`

Auth is an immutable upstream implementation-compatible runtime. It is safe for
concurrent HTTP and direct API calls.

```go
type Auth struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Auth`

### `MustNew`

MustNew constructs an Auth or panics. It is intended for static application
setup where configuration errors cannot be recovered.

```go
func MustNew(options Options) *Auth
```

### `New`

New validates options, snapshots configuration, and constructs the shared
dispatcher used by every transport and the direct API.

```go
func New(options Options) (*Auth, error)
```

### `NewWithSQLiteDatabase`

NewWithSQLiteDatabase initializes the full runtime from a raw database/sql
SQLite handle and exposes the native SQLite adapter.

```go
func NewWithSQLiteDatabase(options Options, database *sql.DB) (*Auth, error)
```

## Methods on `Auth`

### `API`

API returns the typed direct API façade.

```go
func (a *Auth) API() DirectAPI
```

### `Adapter`

Adapter returns the configured persistence adapter.

```go
func (a *Auth) Adapter() storage.Adapter
```

### `AdapterForContext`

AdapterForContext returns the adapter bound to ctx, or the root adapter when
no transaction/adapter scope is active.

```go
func (a *Auth) AdapterForContext(ctx context.Context) storage.TransactionAdapter
```

### `Context`

Context returns the initialized full-mode context.

```go
func (a *Auth) Context() (*AuthContext, error)
```

### `DecodeOAuthToken`

DecodeOAuthToken returns an OAuth token in plaintext. When encryption is
enabled, legacy plaintext tokens are deliberately returned unchanged so an
installation can enable encryption without invalidating existing accounts.

```go
func (a *Auth) DecodeOAuthToken(token string) (string, error)
```

### `Dispatch`

Dispatch runs the transport-neutral HTTP pipeline.

```go
func (a *Auth) Dispatch(request contract.Request) (contract.Response, error)
```

### `Dispatcher`

Dispatcher returns the immutable transport-neutral dispatcher. It is the
input accepted by transport/fasthttp and transport/fiber.

```go
func (a *Auth) Dispatcher() *engine.Dispatcher
```

### `EncodeOAuthToken`

EncodeOAuthToken applies the configured account token-storage policy.
A nil token remains nil, matching upstream implementation's null/undefined behavioral compatibility,
while an empty string remains an empty string.

```go
func (a *Auth) EncodeOAuthToken(token *string) (*string, error)
```

### `ErrorCodes`

ErrorCodes returns the merged plugin error catalog. The map is an
independent snapshot and every definition includes its effective code.

```go
func (a *Auth) ErrorCodes() map[string]engine.ErrorDefinition
```

### `Handler`

Handler exposes Auth as a standard-library HTTP handler.

```go
func (a *Auth) Handler() http.Handler
```

### `InternalAdapter`

InternalAdapter returns a lightweight immutable facade backed by this Auth.

```go
func (a *Auth) InternalAdapter() InternalAdapter
```

### `Invoke`

Invoke calls an endpoint by its direct API name. Server-only endpoints are
available here but cannot be reached through HTTP routing.

```go
func (a *Auth) Invoke(name string, input engine.DirectInput) (contract.Response, error)
```

### `Logger`

Logger returns the configured immutable upstream implementation-compatible logger.

```go
func (a *Auth) Logger() *logger.Logger
```

### `Options`

Options returns an independent public configuration snapshot.

```go
func (a *Auth) Options() Options
```

### `RateLimiter`

RateLimiter returns the immutable limiter used by the HTTP request path.
Direct API calls intentionally bypass it, matching upstream implementation.

```go
func (a *Auth) RateLimiter() *ratelimit.Limiter
```

### `Registry`

Registry returns the immutable endpoint registry.

```go
func (a *Auth) Registry() *engine.Registry
```

### `ResolveBaseURL`

ResolveBaseURL returns the request-scoped public auth URL, including the
configured base path. It is useful to integrations that need the same
dynamic allowed-host and trusted-proxy semantics as core OAuth routes.

```go
func (a *Auth) ResolveBaseURL(request contract.Request) (string, error)
```

### `RunInTransaction`

RunInTransaction runs callback with a context carrying the active Better
Auth transaction adapter. Passing that context to Invoke/Dispatch requests
gives plugins the same nested getCurrentAdapter semantics as upstream's
AsyncLocalStorage transaction scope.

```go
func (a *Auth) RunInTransaction(
	ctx context.Context,
	callback func(context.Context) error,
) error
```

### `RunMigrations`

RunMigrations executes full-mode schema migrations using a background
context, matching upstream implementation's zero-argument runtime callback.

```go
func (a *Auth) RunMigrations() error
```

### `RunMigrationsContext`

RunMigrationsContext executes full-mode schema migrations with cancellation.

```go
func (a *Auth) RunMigrationsContext(ctx context.Context) error
```

### `RunWithAdapter`

RunWithAdapter binds the root adapter without marking the scope as an active
transaction. A nested RunInTransaction therefore still opens one, matching
upstream implementation's runWithAdapter semantics.

```go
func (a *Auth) RunWithAdapter(ctx context.Context, callback func(context.Context) error) error
```

### `ServeHTTP`

ServeHTTP adapts net/http to the same immutable request contract used by
fasthttp and Fiber. Transport-specific packages expose the same conversion
independently for hosts that do not use the canonical Auth type.

```go
func (a *Auth) ServeHTTP(writer http.ResponseWriter, request *http.Request)
```

### `AuthContext`

AuthContext exposes the initialized full-mode adapter and migration
capability. It is an immutable snapshot.

```go
type AuthContext struct {
	Adapter        storage.Adapter
	AdapterOptions AuthContextAdapterOptions
	DatabaseType   string
	// contains filtered or unexported fields
}
```

## Methods on `AuthContext`

### `RunMigrations`

RunMigrations executes this context's full-mode schema migrations.

```go
func (c *AuthContext) RunMigrations() error
```

### `RunMigrationsContext`

RunMigrationsContext executes this context's migrations with cancellation.

```go
func (c *AuthContext) RunMigrationsContext(ctx context.Context) error
```

### `AuthContextAdapterConfig`

AuthContextAdapterConfig is the Go counterpart of upstream implementation's adapter
factory metadata.

```go
type AuthContextAdapterConfig struct {
	AdapterID   string
	AdapterName string
}
```

### `AuthContextAdapterOptions`

AuthContextAdapterOptions describes the detected database dialect and the
adapter factory that was selected for it.

```go
type AuthContextAdapterOptions struct {
	Type          string
	AdapterConfig *AuthContextAdapterConfig
}
```

### `AuthCookie`

AuthCookie describes one request-scoped upstream implementation cookie declaration.
Attributes is copied when the context is created and whenever it is read.

```go
type AuthCookie struct {
	Name       string
	Attributes cookies.Options
}
```

### `AuthenticatedInput`

```go
type AuthenticatedInput struct{ Headers contract.Headers }
```

### `BackgroundRunner`

BackgroundRunner receives non-critical work. A nil runner executes work
synchronously, matching upstream implementation's server fallback.

```go
type BackgroundRunner func(context.Context, func(context.Context) error) error
```

### `BaseErrorCodes`

BaseErrorCodes is the statically typed core error-code subset used by type
contracts. Values retain the public ErrorCode type instead of widening to
string or any.

```go
type BaseErrorCodes struct {
	SessionExpired ErrorCode
}
```

### `ChangeEmailConfirmationMessage`

ChangeEmailConfirmationMessage is delivered to the current address before
the new address is verified in the two-step flow.

```go
type ChangeEmailConfirmationMessage struct {
	User     model.User
	NewEmail string
	URL      string
	Token    string
}
```

### `ChangeEmailInput`

```go
type ChangeEmailInput struct {
	NewEmail    string
	CallbackURL string
	Headers     contract.Headers
}
```

### `ChangeEmailOptions`

```go
type ChangeEmailOptions struct {
	Enabled                        bool
	UpdateEmailWithoutVerification bool
	SendChangeEmailConfirmation    func(context.Context, ChangeEmailConfirmationMessage) error
}
```

### `ChangePasswordInput`

```go
type ChangePasswordInput struct {
	NewPassword         string
	CurrentPassword     string
	RevokeOtherSessions *bool
	Headers             contract.Headers
}
```

### `ChangePasswordResult`

```go
type ChangePasswordResult struct {
	Token   *string
	User    model.User
	Headers contract.Headers
}
```

### `CookieCacheLookupOptions`

CookieCacheLookupOptions controls the public session-data cookie reader.
ResolveVersion is the Go equivalent of upstream implementation's synchronous or async
version callback; it takes precedence over Version when non-nil.

```go
type CookieCacheLookupOptions struct {
	CookiePrefix   string
	CookieName     string
	IsSecure       *bool
	Secret         string
	Strategy       string
	Version        string
	ResolveVersion func(session, user map[string]any) (string, error)
	Clock          func() time.Time
}
```

### `CookieCacheOptions`

CookieCacheOptions configures upstream implementation's session-data cookie.

```go
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
```

### `CookieHeaderGetter`

CookieHeaderGetter is implemented by net/http.Header and by header shims
from other runtimes. It keeps GetSessionCookie usable across realm or wrapper
boundaries without relying on a concrete header type.

```go
type CookieHeaderGetter interface {
	Get(string) string
}
```

### `CookieOverride`

CookieOverride customizes one upstream implementation cookie. Attribute pointers retain
the distinction between an omitted override and an explicit false value.

```go
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
```

### `CrossSubDomainCookieOptions`

CrossSubDomainCookieOptions shares auth cookies across subdomains. When
Domain is empty, a static base URL supplies its hostname; dynamic base URLs
resolve it from each allowed incoming request.

```go
type CrossSubDomainCookieOptions struct {
	Enabled           bool
	Domain            string
	AdditionalCookies []string
}
```

### `DBFieldsDecoder`

DBFieldsDecoder converts a model's lossless dynamic field map into the
caller's static Go representation. upstream implementation's TypeScript definitions can
intersect configured and plugin fields into the base model automatically;
Go callers provide the corresponding concrete Additional type and decoder.

```go
type DBFieldsDecoder[Additional any] func(model.Fields) (Additional, error)
```

### `DatabaseAfterHook`

```go
type DatabaseAfterHook func(any, DatabaseHookContext) error
```

### `DatabaseBeforeHook`

```go
type DatabaseBeforeHook func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error)
```

### `DatabaseHookContext`

DatabaseHookContext describes one upstream implementation database lifecycle callback.
Endpoint is nil when an adapter operation is initiated outside dispatch.

```go
type DatabaseHookContext struct {
	Context   context.Context
	Endpoint  *engine.Context
	Source    string
	Model     string
	Operation string
}
```

### `DatabaseHookResult`

DatabaseHookResult is the Go equivalent of upstream implementation's false or
&#123;data: ...&#125; before-hook result. Data is merged over the current write.

```go
type DatabaseHookResult struct {
	Cancel bool
	Data   storage.Record
}
```

### `DatabaseHooks`

DatabaseHooks maps canonical model names to create/update/delete lifecycle
callbacks. Core and plugin models use the same hook machinery.

```go
type DatabaseHooks map[string]DatabaseModelHooks
```

### `DatabaseModelHooks`

```go
type DatabaseModelHooks struct {
	Create DatabaseOperationHooks
	Update DatabaseOperationHooks
	Delete DatabaseOperationHooks
}
```

### `DatabaseOperationHooks`

```go
type DatabaseOperationHooks struct {
	Before DatabaseBeforeHook
	After  DatabaseAfterHook
}
```

### `DeleteAccountMessage`

```go
type DeleteAccountMessage struct {
	User  model.User
	URL   string
	Token string
}
```

### `DeleteUserCallbackInput`

```go
type DeleteUserCallbackInput struct {
	Token       string
	CallbackURL string
	Headers     contract.Headers
}
```

### `DeleteUserCallbackResult`

```go
type DeleteUserCallbackResult struct {
	Success  bool
	Message  string
	Location string
	Headers  contract.Headers
}
```

### `DeleteUserInput`

```go
type DeleteUserInput struct {
	Password    string
	Token       string
	CallbackURL string
	Headers     contract.Headers
}
```

### `DeleteUserOptions`

```go
type DeleteUserOptions struct {
	Enabled                       bool
	SendDeleteAccountVerification func(context.Context, DeleteAccountMessage) error
	BeforeDelete                  func(context.Context, model.User) error
	AfterDelete                   func(context.Context, model.User) error
	DeleteTokenExpiresIn          time.Duration
}
```

### `DirectAPI`

DirectAPI is the typed façade over Auth.Invoke. It uses the exact same
endpoint handlers and before/after hooks as HTTP dispatch.

```go
type DirectAPI struct {
	// contains filtered or unexported fields
}
```

## Methods on `DirectAPI`

### `AccountInfo`

```go
func (api DirectAPI) AccountInfo(ctx context.Context, input AccountInfoInput) (*AccountInfoResult, error)
```

### `Call`

Call invokes an endpoint by direct API name. Unknown JSON shapes remain
available through Value without lossy re-marshalling.

```go
func (api DirectAPI) Call(
	ctx context.Context,
	name string,
	input DirectCallInput,
) (DirectCallResult, error)
```

### `CallbackOAuth`

```go
func (api DirectAPI) CallbackOAuth(ctx context.Context, input OAuthCallbackInput) (RedirectResult, error)
```

### `ChangeEmail`

```go
func (api DirectAPI) ChangeEmail(ctx context.Context, input ChangeEmailInput) (StatusResult, error)
```

### `ChangePassword`

```go
func (api DirectAPI) ChangePassword(ctx context.Context, input ChangePasswordInput) (ChangePasswordResult, error)
```

### `DeleteUser`

```go
func (api DirectAPI) DeleteUser(ctx context.Context, input DeleteUserInput) (SuccessMessageResult, error)
```

### `DeleteUserCallback`

```go
func (api DirectAPI) DeleteUserCallback(
	ctx context.Context,
	input DeleteUserCallbackInput,
) (DeleteUserCallbackResult, error)
```

### `GetAccessToken`

```go
func (api DirectAPI) GetAccessToken(ctx context.Context, input AccountTokenInput) (AccessTokenResult, error)
```

### `GetSession`

```go
func (api DirectAPI) GetSession(ctx context.Context, input GetSessionInput) (*SessionResult, error)
```

### `LinkSocialAccount`

```go
func (api DirectAPI) LinkSocialAccount(
	ctx context.Context,
	input LinkSocialAccountInput,
) (LinkSocialAccountResult, error)
```

### `ListSessions`

```go
func (api DirectAPI) ListSessions(ctx context.Context, input ListSessionsInput) (ListSessionsResult, error)
```

### `ListUserAccounts`

```go
func (api DirectAPI) ListUserAccounts(
	ctx context.Context,
	input ListUserAccountsInput,
) (ListUserAccountsResult, error)
```

### `RefreshToken`

```go
func (api DirectAPI) RefreshToken(ctx context.Context, input AccountTokenInput) (RefreshTokenResult, error)
```

### `RequestPasswordReset`

```go
func (api DirectAPI) RequestPasswordReset(
	ctx context.Context,
	input RequestPasswordResetInput,
) (StatusMessageResult, error)
```

### `RequestPasswordResetCallback`

```go
func (api DirectAPI) RequestPasswordResetCallback(
	ctx context.Context,
	input PasswordResetCallbackInput,
) (RedirectResult, error)
```

### `ResetPassword`

```go
func (api DirectAPI) ResetPassword(ctx context.Context, input ResetPasswordInput) (StatusResult, error)
```

### `RevokeOtherSessions`

```go
func (api DirectAPI) RevokeOtherSessions(ctx context.Context, input AuthenticatedInput) (StatusResult, error)
```

### `RevokeSession`

```go
func (api DirectAPI) RevokeSession(ctx context.Context, input RevokeSessionInput) (StatusResult, error)
```

### `RevokeSessions`

```go
func (api DirectAPI) RevokeSessions(ctx context.Context, input AuthenticatedInput) (StatusResult, error)
```

### `SendVerificationEmail`

```go
func (api DirectAPI) SendVerificationEmail(
	ctx context.Context,
	input SendVerificationEmailInput,
) (StatusResult, error)
```

### `SetPassword`

```go
func (api DirectAPI) SetPassword(ctx context.Context, input SetPasswordInput) (StatusResult, error)
```

### `SignInEmail`

```go
func (api DirectAPI) SignInEmail(ctx context.Context, input SignInEmailInput) (SignInEmailResult, error)
```

### `SignInSocial`

```go
func (api DirectAPI) SignInSocial(ctx context.Context, input SignInSocialInput) (SignInSocialResult, error)
```

### `SignOut`

```go
func (api DirectAPI) SignOut(ctx context.Context, input SignOutInput) (SignOutResult, error)
```

### `SignUpEmail`

```go
func (api DirectAPI) SignUpEmail(ctx context.Context, input SignUpEmailInput) (SignUpEmailResult, error)
```

### `UnlinkAccount`

```go
func (api DirectAPI) UnlinkAccount(ctx context.Context, input UnlinkAccountInput) (StatusResult, error)
```

### `UpdateSession`

```go
func (api DirectAPI) UpdateSession(ctx context.Context, input UpdateSessionInput) (UpdateSessionResult, error)
```

### `UpdateUser`

```go
func (api DirectAPI) UpdateUser(ctx context.Context, input UpdateUserInput) (StatusResult, error)
```

### `VerifyEmail`

```go
func (api DirectAPI) VerifyEmail(ctx context.Context, input VerifyEmailInput) (VerifyEmailResult, error)
```

### `VerifyPassword`

```go
func (api DirectAPI) VerifyPassword(ctx context.Context, input VerifyPasswordInput) (StatusResult, error)
```

### `DirectCallInput`

DirectCallInput is the escape hatch for core and plugin endpoints that do
not yet have a dedicated typed convenience method. It still runs the exact
endpoint and before/after-hook pipeline used by all typed methods.

```go
type DirectCallInput struct {
	Method  string
	Scheme  string
	Host    string
	Headers contract.Headers
	Body    any
	Query   url.Values
	Params  map[string]string
	Values  map[string]any
}
```

### `DirectCallResult`

DirectCallResult preserves both the transport-neutral response (including
Set-Cookie and Location) and its decoded JSON value.

```go
type DirectCallResult struct {
	Response contract.Response
	Value    any
}
```

### `DirectInput`

```go
type DirectInput = engine.DirectInput
```

### `DirectResultDecoder`

DirectResultDecoder turns the production DirectCallResult into a concrete
caller-facing output type.

```go
type DirectResultDecoder[Output any] func(DirectCallResult) (Output, error)
```

### `DynamicBaseURLOptions`

DynamicBaseURLOptions resolves the public auth URL from each request while
constraining the host to an explicit allowlist. Protocol accepts "http",
"https", or "auto"; an empty value defaults to HTTPS and also permits HTTP
for loopback hosts, matching upstream implementation's development behavioral compatibility.

```go
type DynamicBaseURLOptions struct {
	AllowedHosts []string
	Protocol     string
	Fallback     string
}
```

### `EmailAndPasswordOptions`

EmailAndPasswordOptions configures the built-in credential endpoints.

```go
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
```

### `EmailVerificationMessage`

EmailVerificationMessage contains the exact data passed to the email hook.

```go
type EmailVerificationMessage struct {
	User  model.User
	URL   string
	Token string
}
```

### `EmailVerificationOptions`

EmailVerificationOptions configures verification mail and token behavioral compatibility.

```go
type EmailVerificationOptions struct {
	SendVerificationEmail       func(context.Context, EmailVerificationMessage) error
	SendOnSignUp                *bool
	SendOnSignIn                bool
	AutoSignInAfterVerification bool
	ExpiresIn                   time.Duration
	BeforeEmailVerification     func(context.Context, model.User) error
	AfterEmailVerification      func(context.Context, model.User) error
}
```

### `Endpoint`

```go
type Endpoint = engine.Endpoint
```

### `ErrorCode`

ErrorCode is a stable upstream implementation API error identifier.

```go
type ErrorCode string
```

## Constants associated with `ErrorCode`

```go
const (
	ErrorUserNotFound                    ErrorCode = "USER_NOT_FOUND"
	ErrorFailedToCreateUser              ErrorCode = "FAILED_TO_CREATE_USER"
	ErrorFailedToCreateSession           ErrorCode = "FAILED_TO_CREATE_SESSION"
	ErrorFailedToUpdateUser              ErrorCode = "FAILED_TO_UPDATE_USER"
	ErrorFailedToGetSession              ErrorCode = "FAILED_TO_GET_SESSION"
	ErrorInvalidPassword                 ErrorCode = "INVALID_PASSWORD"
	ErrorInvalidEmail                    ErrorCode = "INVALID_EMAIL"
	ErrorInvalidEmailOrPassword          ErrorCode = "INVALID_EMAIL_OR_PASSWORD"
	ErrorInvalidUser                     ErrorCode = "INVALID_USER"
	ErrorSocialAccountAlreadyLinked      ErrorCode = "SOCIAL_ACCOUNT_ALREADY_LINKED"
	ErrorProviderNotFound                ErrorCode = "PROVIDER_NOT_FOUND"
	ErrorInvalidToken                    ErrorCode = "INVALID_TOKEN"
	ErrorTokenExpired                    ErrorCode = "TOKEN_EXPIRED"
	ErrorIDTokenNotSupported             ErrorCode = "ID_TOKEN_NOT_SUPPORTED"
	ErrorFailedToGetUserInfo             ErrorCode = "FAILED_TO_GET_USER_INFO"
	ErrorUserEmailNotFound               ErrorCode = "USER_EMAIL_NOT_FOUND"
	ErrorEmailNotVerified                ErrorCode = "EMAIL_NOT_VERIFIED"
	ErrorPasswordTooShort                ErrorCode = "PASSWORD_TOO_SHORT"
	ErrorPasswordTooLong                 ErrorCode = "PASSWORD_TOO_LONG"
	ErrorUserAlreadyExists               ErrorCode = "USER_ALREADY_EXISTS"
	ErrorUserAlreadyExistsAnotherEmail   ErrorCode = "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"
	ErrorEmailCannotBeUpdated            ErrorCode = "EMAIL_CAN_NOT_BE_UPDATED"
	ErrorChangeEmailDisabled             ErrorCode = "CHANGE_EMAIL_DISABLED"
	ErrorCredentialAccountNotFound       ErrorCode = "CREDENTIAL_ACCOUNT_NOT_FOUND"
	ErrorSessionExpired                  ErrorCode = "SESSION_EXPIRED"
	ErrorFailedToUnlinkLastAccount       ErrorCode = "FAILED_TO_UNLINK_LAST_ACCOUNT"
	ErrorAccountNotFound                 ErrorCode = "ACCOUNT_NOT_FOUND"
	ErrorUserAlreadyHasPassword          ErrorCode = "USER_ALREADY_HAS_PASSWORD"
	ErrorCrossSiteNavigationLoginBlocked ErrorCode = "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED"
	ErrorVerificationEmailNotEnabled     ErrorCode = "VERIFICATION_EMAIL_NOT_ENABLED"
	ErrorEmailAlreadyVerified            ErrorCode = "EMAIL_ALREADY_VERIFIED"
	ErrorEmailMismatch                   ErrorCode = "EMAIL_MISMATCH"
	ErrorSessionNotFresh                 ErrorCode = "SESSION_NOT_FRESH"
	ErrorLinkedAccountAlreadyExists      ErrorCode = "LINKED_ACCOUNT_ALREADY_EXISTS"
	ErrorInvalidOrigin                   ErrorCode = "INVALID_ORIGIN"
	ErrorInvalidCallbackURL              ErrorCode = "INVALID_CALLBACK_URL"
	ErrorInvalidRedirectURL              ErrorCode = "INVALID_REDIRECT_URL"
	ErrorInvalidErrorCallbackURL         ErrorCode = "INVALID_ERROR_CALLBACK_URL"
	ErrorInvalidNewUserCallbackURL       ErrorCode = "INVALID_NEW_USER_CALLBACK_URL"
	ErrorMissingOrNullOrigin             ErrorCode = "MISSING_OR_NULL_ORIGIN"
	ErrorCallbackURLRequired             ErrorCode = "CALLBACK_URL_REQUIRED"
	ErrorFailedToCreateVerification      ErrorCode = "FAILED_TO_CREATE_VERIFICATION"
	ErrorFieldNotAllowed                 ErrorCode = "FIELD_NOT_ALLOWED"
	ErrorAsyncValidationNotSupported     ErrorCode = "ASYNC_VALIDATION_NOT_SUPPORTED"
	ErrorValidation                      ErrorCode = "VALIDATION_ERROR"
	ErrorMissingField                    ErrorCode = "MISSING_FIELD"
	ErrorMethodNeedsDeferredSession      ErrorCode = "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED"
	ErrorBodyMustBeObject                ErrorCode = "BODY_MUST_BE_AN_OBJECT"
	ErrorPasswordAlreadySet              ErrorCode = "PASSWORD_ALREADY_SET"
)
```

### `GetSessionInput`

```go
type GetSessionInput struct {
	Headers contract.Headers
}
```

### `IDGenerator`

IDGenerator returns a upstream implementation identifier. The bool is false when the
backing database must generate the identifier itself.

```go
type IDGenerator func(model string, size int) (value string, generated bool, err error)
```

### `InternalAdapter`

InternalAdapter is the Go counterpart of upstream implementation's internalAdapter.
It keeps lifecycle hooks, secondary-storage behavioral compatibility, identifier hashing,
and transaction scoping above the raw storage.Adapter contract.

```go
type InternalAdapter struct {
	// contains filtered or unexported fields
}
```

## Methods on `InternalAdapter`

### `ConsumeVerificationValue`

```go
func (internal InternalAdapter) ConsumeVerificationValue(ctx context.Context, identifier string) (storage.Record, error)
```

### `CreateAccount`

CreateAccount creates one provider or credential account through hooks.

```go
func (internal InternalAdapter) CreateAccount(ctx context.Context, account storage.Record) (storage.Record, error)
```

### `CreateOAuthUser`

CreateOAuthUser atomically creates the user and provider account, including
configured ID generation and every database create hook.

```go
func (internal InternalAdapter) CreateOAuthUser(
	ctx context.Context,
	user storage.Record,
	account storage.Record,
) (InternalOAuthUser, error)
```

### `CreateSession`

CreateSession creates a session without issuing browser cookies.

```go
func (internal InternalAdapter) CreateSession(
	ctx context.Context,
	userID string,
	options InternalSessionCreateOptions,
) (storage.Record, error)
```

### `CreateUser`

CreateUser creates one canonical user through the internal hook pipeline.

```go
func (internal InternalAdapter) CreateUser(ctx context.Context, user storage.Record) (storage.Record, error)
```

### `CreateVerificationValue`

```go
func (internal InternalAdapter) CreateVerificationValue(
	ctx context.Context,
	value VerificationValue,
) (storage.Record, error)
```

### `DeleteAccount`

DeleteAccount deletes by the account row's primary id, not accountId.

```go
func (internal InternalAdapter) DeleteAccount(ctx context.Context, id string) error
```

### `DeleteAccounts`

```go
func (internal InternalAdapter) DeleteAccounts(ctx context.Context, userID string) error
```

### `DeleteSession`

```go
func (internal InternalAdapter) DeleteSession(ctx context.Context, token string) error
```

### `DeleteUser`

DeleteUser removes every session from secondary storage and the database,
then deletes the user's accounts and user row through the hook-aware
adapter. It mirrors upstream implementation's internalAdapter.deleteUser operation.

```go
func (internal InternalAdapter) DeleteUser(ctx context.Context, userID string) error
```

### `DeleteVerificationByIdentifier`

```go
func (internal InternalAdapter) DeleteVerificationByIdentifier(ctx context.Context, identifier string) error
```

### `FindAccountByProviderID`

```go
func (internal InternalAdapter) FindAccountByProviderID(
	ctx context.Context,
	accountID string,
	providerID string,
) (storage.Record, error)
```

### `FindAccounts`

```go
func (internal InternalAdapter) FindAccounts(ctx context.Context, userID string) ([]storage.Record, error)
```

### `FindSession`

```go
func (internal InternalAdapter) FindSession(ctx context.Context, token string) (*InternalSession, error)
```

### `FindSessions`

```go
func (internal InternalAdapter) FindSessions(
	ctx context.Context,
	tokens []string,
	onlyActive bool,
) ([]InternalSession, error)
```

### `FindVerificationValue`

```go
func (internal InternalAdapter) FindVerificationValue(ctx context.Context, identifier string) (storage.Record, error)
```

### `ListSessions`

```go
func (internal InternalAdapter) ListSessions(
	ctx context.Context,
	userID string,
	onlyActive bool,
) ([]storage.Record, error)
```

### `ReserveVerificationValue`

ReserveVerificationValue is the first-writer-wins dual of consume. The
database path uses a deterministic primary key and therefore stays atomic
across processes on every conforming adapter.

```go
func (internal InternalAdapter) ReserveVerificationValue(
	ctx context.Context,
	value VerificationValue,
) (bool, error)
```

### `UpdateSession`

```go
func (internal InternalAdapter) UpdateSession(
	ctx context.Context,
	token string,
	update storage.Record,
) (storage.Record, error)
```

### `UpdateUser`

UpdateUser updates a user and refreshes every valid cached session payload.

```go
func (internal InternalAdapter) UpdateUser(
	ctx context.Context,
	userID string,
	update storage.Record,
) (storage.Record, error)
```

### `InternalOAuthUser`

InternalOAuthUser is the user/account pair created by CreateOAuthUser.

```go
type InternalOAuthUser struct {
	User    storage.Record
	Account storage.Record
}
```

### `InternalSession`

InternalSession is the joined session/user value returned by FindSession
and FindSessions.

```go
type InternalSession struct {
	Session storage.Record
	User    storage.Record
}
```

### `InternalSessionCreateOptions`

InternalSessionCreateOptions represents upstream implementation's optional
dontRememberMe, override, and overrideAll createSession arguments.

```go
type InternalSessionCreateOptions struct {
	DontRemember bool
	Override     storage.Record
	OverrideAll  bool
	IPAddress    string
	UserAgent    string
}
```

### `KnownPluginPresence`

KnownPluginPresence is the true literal marker returned for a plugin whose
position and type are known at compile time. Dynamic plugin IDs continue to
return an ordinary bool through TypedPluginContext2.HasPlugin.

```go
type KnownPluginPresence struct{}
```

## Methods on `KnownPluginPresence`

### `Bool`

```go
func (KnownPluginPresence) Bool() bool
```

### `LinkSocialAccountInput`

```go
type LinkSocialAccountInput struct {
	Provider           string
	CallbackURL        string
	ErrorCallbackURL   string
	NewUserCallbackURL string
	DisableRedirect    *bool
	RequestSignUp      *bool
	Scopes             []string
	IDToken            *SocialIDTokenInput
	AdditionalData     map[string]any
	Headers            contract.Headers
}
```

### `LinkSocialAccountResult`

```go
type LinkSocialAccountResult struct {
	URL      string
	Status   bool
	Redirect bool
	Headers  contract.Headers
}
```

### `ListSessionsInput`

```go
type ListSessionsInput struct{ Headers contract.Headers }
```

### `ListSessionsResult`

```go
type ListSessionsResult struct {
	Sessions []model.Session
	Headers  contract.Headers
}
```

### `ListUserAccountsInput`

```go
type ListUserAccountsInput struct{ Headers contract.Headers }
```

### `ListUserAccountsResult`

```go
type ListUserAccountsResult struct {
	Accounts []ListedAccount
	Headers  contract.Headers
}
```

### `ListedAccount`

```go
type ListedAccount struct {
	Account model.Account
	Scopes  []string
}
```

### `MinimalAuth`

MinimalAuth is the upstream implementation-compatible minimal runtime. It embeds the
regular Go runtime while keeping the minimal entry point's migration and
raw-connection constraints explicit.

```go
type MinimalAuth struct {
	*Auth
}
```

## Constructors and functions for `MinimalAuth`

### `NewMinimal`

NewMinimal constructs upstream implementation's adapter-only minimal runtime.

```go
func NewMinimal(options Options) (*MinimalAuth, error)
```

### `NewMinimalWithDatabase`

NewMinimalWithDatabase accepts the dynamic database shape exposed by the
JavaScript initializer. Go storage.Adapter values are supported; raw
connections are rejected with upstream implementation's exact minimal-mode diagnostic.

```go
func NewMinimalWithDatabase(options Options, database any) (*MinimalAuth, error)
```

## Methods on `MinimalAuth`

### `Context`

Context returns the initialized adapter-only minimal context.

```go
func (a *MinimalAuth) Context() (*MinimalContext, error)
```

### `RunMigrations`

RunMigrations always rejects in minimal mode.

```go
func (a *MinimalAuth) RunMigrations() error
```

### `MinimalContext`

MinimalContext exposes the adapter selected by the minimal initializer.
DatabaseType is always "unknown" because minimal mode accepts an already
configured storage adapter and does not perform database detection.

```go
type MinimalContext struct {
	Adapter      storage.Adapter
	DatabaseType string
}
```

## Methods on `MinimalContext`

### `RunMigrations`

RunMigrations always rejects in minimal mode.

```go
func (c *MinimalContext) RunMigrations() error
```

### `NoAdditionalFields`

NoAdditionalFields is the explicit Go representation of a upstream implementation model
with no configured or plugin-contributed fields. Go cannot intersect object
types, so TypedUser and TypedSession retain additional fields in a generic
slot whose empty form is this zero-sized type.

```go
type NoAdditionalFields struct{}
```

### `NoBody`

NoBody is the compile-time input for an endpoint override that deliberately
removes the base endpoint's request body contract.

```go
type NoBody struct{}
```

### `OAuthCallbackInput`

```go
type OAuthCallbackInput struct {
	ProviderID string
	Method     string
	Query      url.Values
	Body       map[string]any
	Headers    contract.Headers
}
```

### `OptionalKeyShape`

```go
type OptionalKeyShape[Fields any] struct{ Fields Fields }
```

## Methods on `OptionalKeyShape`

### `RequiredKeysResult`

```go
func (OptionalKeyShape[Fields]) RequiredKeysResult() RequiredKeysAbsent
```

### `Options`

Options is the immutable configuration snapshot consumed by New.

Engine-level extension points are intentionally public so plugin packages
can depend on focused contracts without creating a cycle through the
canonical core runtime.

```go
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
	// contains filtered or unexported fields
}
```

### `PasswordOptions`

PasswordOptions configures credential hashing and validation. Nil functions
use upstream implementation's scrypt implementation from package crypto.

```go
type PasswordOptions struct {
	Hash   func(string) (string, error)
	Verify func(hash, password string) bool
}
```

### `PasswordResetCallbackInput`

```go
type PasswordResetCallbackInput struct {
	Token       string
	CallbackURL string
	Headers     contract.Headers
}
```

### `PasswordResetMessage`

PasswordResetMessage contains the reset link delivered by the configured
mail hook.

```go
type PasswordResetMessage struct {
	User  model.User
	URL   string
	Token string
}
```

### `Plugin`

```go
type Plugin = engine.Plugin
```

### `PluginAPIs2`

PluginAPIs2 composes differently shaped plugin APIs without losing either
concrete type. TypeScript flattens plugin endpoints into one object; Go keeps
each collision-free API in an explicit slot.

```go
type PluginAPIs2[First, Second any] struct {
	First  First
	Second Second
}
```

## Constructors and functions for `PluginAPIs2`

### `ComposePluginAPIs2`

```go
func ComposePluginAPIs2[First, Second any](first First, second Second) PluginAPIs2[First, Second]
```

### `PluginFactory`

PluginFactory delays runtime-dependent plugin construction until New has
created the final adapter, schema, cookie configuration, and core services.
Schema must be deterministic and must describe every model used by Build.

```go
type PluginFactory interface {
	PluginID() string
	Schema() (storage.Schema, error)
	Build(PluginHost) (engine.Plugin, error)
}
```

### `PluginHost`

PluginHost is the typed dependency surface supplied to PluginFactory.Build.
Every callback enters the same root persistence, cookie, security, and
background-work semantics as core endpoints.

```go
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
```

### `PluginOAuthState`

PluginOAuthState is the generated CSRF state and PKCE verifier supplied to
the provider authorization URL builder.

```go
type PluginOAuthState struct {
	State        string
	CodeVerifier string
}
```

### `PluginOAuthStateData`

PluginOAuthStateData is the validated, single-use OAuth state exposed to
protocol plugins. AdditionalData contains only plugin-owned fields that were
persisted alongside the root callback, error, signup, and PKCE values.

```go
type PluginOAuthStateData struct {
	CallbackURL    string
	ErrorURL       string
	NewUserURL     string
	CodeVerifier   string
	RequestSignUp  *bool
	AdditionalData map[string]any
}
```

### `PluginOAuthStateError`

PluginOAuthStateError is returned after a state lookup, cookie binding, or
atomic consume failure. Code is safe to expose as an OAuth redirect error;
ErrorURL is populated only when it came from already-validated state.

```go
type PluginOAuthStateError struct {
	Code     string
	ErrorURL string
	Cause    error
}
```

## Methods on `PluginOAuthStateError`

### `Error`

```go
func (err *PluginOAuthStateError) Error() string
```

### `Unwrap`

```go
func (err *PluginOAuthStateError) Unwrap() error
```

### `PluginOAuthStateInput`

PluginOAuthStateInput is the transport-neutral input used by plugins that
start a regular upstream implementation OAuth flow. AdditionalData is persisted in the
same state record/cookie as core social sign-in after the caller has removed
keys reserved by the state protocol.

```go
type PluginOAuthStateInput struct {
	CallbackURL    string
	ErrorURL       string
	NewUserURL     string
	RequestSignUp  *bool
	AdditionalData map[string]any
}
```

### `PluginOAuthUserInput`

PluginOAuthUserInput delegates identity/account resolution to the same
implementation used by redirect social sign-in. Provider may be an
ephemeral provider descriptor for protocol plugins such as One Tap that can
operate without a configured redirect provider.

```go
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
```

### `PluginOAuthUserResult`

PluginOAuthUserResult carries the created session/user pair and the
user-facing OAuth linking error that upstream returns separately from
internal failures.

```go
type PluginOAuthUserResult struct {
	State      PluginSessionState
	IsRegister bool
	LinkError  string
}
```

### `PluginPasswordHash`

PluginPasswordHash is the request-aware password hash function exposed to
plugin factories. Context is nil for non-endpoint use; wrappers must then
behave as if no route path were active.

```go
type PluginPasswordHash func(*engine.Context, string) (string, error)
```

### `PluginPasswordHashWrapper`

PluginPasswordHashWrapper decorates the hash function installed by prior
factories. Factories are applied in declaration order, so the latest wrapper
becomes the outermost one, matching upstream implementation init context composition.

```go
type PluginPasswordHashWrapper func(PluginPasswordHash) PluginPasswordHash
```

### `PluginSessionMode`

PluginSessionMode selects the host's regular, authoritative, or fresh
session policy.

```go
type PluginSessionMode uint8
```

## Constants associated with `PluginSessionMode`

```go
const (
	PluginSessionOptional PluginSessionMode = iota
	PluginSessionRequired
	PluginSessionAuthoritative
	PluginSessionFresh
)
```

### `PluginSessionState`

PluginSessionState is the logical session/user pair shared with plugins.

```go
type PluginSessionState struct {
	Session storage.Record
	User    storage.Record
}
```

## Constructors and functions for `PluginSessionState`

### `SessionFromEndpointContext`

SessionFromEndpointContext returns the logical session/user pair established
by SessionMiddleware. Returned records are independent copies.

```go
func SessionFromEndpointContext(ctx *engine.Context) (*PluginSessionState, bool)
```

### `ProviderUser`

```go
type ProviderUser struct {
	ID            string
	Name          string
	Email         model.Value[string]
	Image         model.Value[string]
	EmailVerified bool
	Extra         model.Fields
}
```

### `RateLimit`

```go
type RateLimit = model.RateLimit
```

### `RateLimitOptions`

RateLimitOptions configures the built-in request limiter. Window and Max
are the default rule. Storage accepts "memory", "database", or
"secondary-storage"; CustomStorage takes precedence when present.

```go
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
```

### `RedirectResult`

```go
type RedirectResult struct {
	Location string
	Headers  contract.Headers
}
```

### `RefreshTokenResult`

```go
type RefreshTokenResult struct {
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 string
	ProviderID            string
	AccountID             string
	IDToken               string
	Headers               contract.Headers
}
```

### `Request`

```go
type Request = contract.Request
```

### `RequestAuthContext`

RequestAuthContext is the request-local counterpart of upstream implementation's
AuthContext. It exposes the resolved public URL, the resolved option
snapshot, trusted origins, cookie declarations, and the internal adapter to
hooks and plugin endpoints without mutating the shared Auth runtime.

```go
type RequestAuthContext struct {
	BaseURL         string
	Options         Options
	TrustedOrigins  []string
	AuthCookies     RequestAuthCookies
	InternalAdapter InternalAdapter
}
```

## Constructors and functions for `RequestAuthContext`

### `RequestContextFromEndpoint`

RequestContextFromEndpoint returns an independent snapshot of the auth
context associated with an engine endpoint invocation.

```go
func RequestContextFromEndpoint(ctx *engine.Context) (RequestAuthContext, bool)
```

### `RequestAuthCookies`

RequestAuthCookies contains the core cookie declarations available to an
endpoint for the current request. Dynamic base URLs may produce a different
Domain for every request.

```go
type RequestAuthCookies struct {
	SessionToken AuthCookie
	SessionData  AuthCookie
	DontRemember AuthCookie
	State        AuthCookie
	OAuthState   AuthCookie
	AccountData  AuthCookie
}
```

### `RequestPasswordResetInput`

```go
type RequestPasswordResetInput struct {
	Email      string
	RedirectTo string
	Headers    contract.Headers
}
```

### `RequiredKeyShape`

RequiredKeyShape and OptionalKeyShape retain the caller's field shape while
explicitly recording whether its keys are required or optional.

```go
type RequiredKeyShape[Fields any] struct{ Fields Fields }
```

## Methods on `RequiredKeyShape`

### `RequiredKeysResult`

```go
func (RequiredKeyShape[Fields]) RequiredKeysResult() RequiredKeysPresent
```

### `RequiredKeysAbsent`

```go
type RequiredKeysAbsent struct{}
```

## Methods on `RequiredKeysAbsent`

### `Bool`

```go
func (RequiredKeysAbsent) Bool() bool
```

### `RequiredKeysPresent`

RequiredKeysPresent and RequiredKeysAbsent are distinct compile-time result
types. upstream implementation computes this distinction structurally; Go callers use an
explicit shape wrapper because the language has no optional object keys.

```go
type RequiredKeysPresent struct{}
```

## Methods on `RequiredKeysPresent`

### `Bool`

```go
func (RequiredKeysPresent) Bool() bool
```

### `RequiredKeysResult`

RequiredKeysResult is the closed result set for RequiredKeysOf.

```go
type RequiredKeysResult interface {
	Bool() bool
	// contains filtered or unexported methods
}
```

### `ResetPasswordInput`

```go
type ResetPasswordInput struct {
	NewPassword string
	Token       string
	Headers     contract.Headers
}
```

### `Response`

```go
type Response = contract.Response
```

### `RevokeSessionInput`

```go
type RevokeSessionInput struct {
	Token   string
	Headers contract.Headers
}
```

### `SecondaryGetAndDeleter`

SecondaryGetAndDeleter provides cross-process atomic consumption for
single-use verification values.

```go
type SecondaryGetAndDeleter = secondary.GetAndDeleter
```

### `SecondaryStorage`

SecondaryStorage is upstream implementation's string-valued session, verification, and
rate-limit storage contract.

```go
type SecondaryStorage = secondary.Storage
```

### `SecondaryValueGetAndDeleter`

SecondaryValueGetAndDeleter provides atomic consumption for an
object-valued secondary store.

```go
type SecondaryValueGetAndDeleter = secondary.ValueGetAndDeleter
```

### `SecondaryValueStorage`

SecondaryValueStorage is the object-valued form of upstream implementation's secondary
storage contract. Some Redis wrappers parse JSON before returning it, so a
Go implementation cannot expose that behavioral compatibility through SecondaryStorage's
string-returning Get method. Configure this interface through
Options.SecondaryValueStorage instead. Set still receives the canonical JSON
string written by upstream implementation.

```go
type SecondaryValueStorage = secondary.ValueStorage
```

### `SendVerificationEmailInput`

```go
type SendVerificationEmailInput struct {
	Email       string
	CallbackURL string
	Headers     contract.Headers
}
```

### `Session`

```go
type Session = model.Session
```

### `SessionCookieLookupOptions`

SessionCookieLookupOptions controls the public session-cookie reader.

```go
type SessionCookieLookupOptions = cookies.SessionLookupOptions
```

### `SessionOptions`

SessionOptions configures database sessions and their cookies.

```go
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
```

### `SessionResult`

```go
type SessionResult struct {
	Session model.Session
	User    model.User
	Headers contract.Headers
}
```

### `SetPasswordInput`

```go
type SetPasswordInput struct {
	NewPassword string
	Headers     contract.Headers
}
```

### `SignInEmailInput`

```go
type SignInEmailInput struct {
	Email       string
	Password    string
	CallbackURL string
	RememberMe  *bool
	Headers     contract.Headers
}
```

### `SignInEmailResult`

```go
type SignInEmailResult struct {
	Redirect bool
	Token    string
	URL      model.Value[string]
	User     model.User
	Headers  contract.Headers
}
```

### `SignInSocialInput`

```go
type SignInSocialInput struct {
	Provider           string
	CallbackURL        string
	ErrorCallbackURL   string
	NewUserCallbackURL string
	DisableRedirect    *bool
	RequestSignUp      *bool
	Scopes             []string
	LoginHint          string
	IDToken            *SocialIDTokenInput
	AdditionalData     map[string]any
	Headers            contract.Headers
}
```

### `SignInSocialResult`

```go
type SignInSocialResult struct {
	URL      model.Value[string]
	Redirect bool
	Token    *string
	User     *model.User
	Headers  contract.Headers
}
```

### `SignOutInput`

```go
type SignOutInput struct {
	Headers contract.Headers
}
```

### `SignOutResult`

```go
type SignOutResult struct {
	Success bool
	Headers contract.Headers
}
```

### `SignUpEmailInput`

```go
type SignUpEmailInput struct {
	Name             string
	Email            string
	Password         string
	Image            model.Value[string]
	CallbackURL      string
	RememberMe       *bool
	AdditionalFields model.Fields
	Headers          contract.Headers
}
```

### `SignUpEmailResult`

```go
type SignUpEmailResult struct {
	Token   *string
	User    model.User
	Headers contract.Headers
}
```

### `SocialIDTokenInput`

```go
type SocialIDTokenInput struct {
	Token        string
	AccessToken  string
	RefreshToken string
	Nonce        string
	ExpiresAt    *float64
	Scopes       []string
	User         map[string]any
}
```

### `StatusMessageResult`

```go
type StatusMessageResult struct {
	Status  bool
	Message string
	Headers contract.Headers
}
```

### `StatusResult`

StatusResult is the common `&#123;status: boolean&#125;` response returned by Better
Auth mutation endpoints.

```go
type StatusResult struct {
	Status  bool
	Headers contract.Headers
}
```

### `SuccessMessageResult`

```go
type SuccessMessageResult struct {
	Success bool
	Message string
	Headers contract.Headers
}
```

### `TrustedOriginsResolver`

TrustedOriginsResolver contributes request-scoped trusted origins. The
returned slice is copied and empty entries are ignored.

```go
type TrustedOriginsResolver func(context.Context, contract.Request) ([]string, error)
```

### `TypedAccount`

TypedAccount is the statically typed form of model.Account.

```go
type TypedAccount[Additional any] struct {
	ID                    string
	CreatedAt             time.Time
	UpdatedAt             time.Time
	ProviderID            string
	AccountID             string
	UserID                string
	AccessToken           model.Value[string]
	RefreshToken          model.Value[string]
	IDToken               model.Value[string]
	AccessTokenExpiresAt  model.Value[time.Time]
	RefreshTokenExpiresAt model.Value[time.Time]
	Scope                 model.Value[string]
	Password              model.Value[string]
	Additional            Additional
}
```

## Constructors and functions for `TypedAccount`

### `DecodeAccount`

DecodeAccount converts a production model.Account to its static form.

```go
func DecodeAccount[Additional any](
	account model.Account,
	decoder DBFieldsDecoder[Additional],
) (TypedAccount[Additional], error)
```

### `TypedAuth`

TypedAuth binds a concrete user output type to an Auth runtime. The embedded
runtime retains the normal HTTP and dispatcher surface, while API returns
that same output type from every user-bearing endpoint.

```go
type TypedAuth[Output any] struct {
	*Auth
	// contains filtered or unexported fields
}
```

## Constructors and functions for `TypedAuth`

### `NewTypedAuth`

NewTypedAuth adds a compile-time user result type to an existing Auth.

```go
func NewTypedAuth[Output any](
	auth *Auth,
	decoder UserDecoder[Output],
) (*TypedAuth[Output], error)
```

### `NewTypedUserAuth`

NewTypedUserAuth is a convenience binding for TypedUser plus an additional-
fields decoder. NewTypedAuth can instead bind a completely flat caller type.

```go
func NewTypedUserAuth[Additional any](
	auth *Auth,
	decoder UserFieldsDecoder[Additional],
) (*TypedAuth[TypedUser[Additional]], error)
```

## Methods on `TypedAuth`

### `API`

API returns a typed façade over the production direct API. Calls still pass
through Auth.Invoke and the same endpoint, middleware, and hook pipeline.

```go
func (auth *TypedAuth[Output]) API() TypedDirectAPI[Output]
```

### `TypedContext`

TypedContext preserves fields contributed by plugin init hooks. Extension is
explicit because Go cannot synthesize fields onto AuthContext at compile
time; Runtime still provides the initialized production context.

```go
type TypedContext[Extension any] struct {
	Runtime *AuthContext
	// contains filtered or unexported fields
}
```

## Constructors and functions for `TypedContext`

### `NewTypedContext`

NewTypedContext binds a caller-defined init extension to an Auth context.

```go
func NewTypedContext[Extension any](auth *Auth, extension Extension) (TypedContext[Extension], error)
```

## Methods on `TypedContext`

### `Extension`

Extension returns the concrete init-hook context contribution.

```go
func (context TypedContext[Extension]) Extension() Extension
```

### `TypedDirectAPI`

TypedDirectAPI is the generic user-result counterpart of DirectAPI.

```go
type TypedDirectAPI[Output any] struct {
	// contains filtered or unexported fields
}
```

## Methods on `TypedDirectAPI`

### `Call`

Call exposes the production direct-API escape hatch unchanged.

```go
func (api TypedDirectAPI[Output]) Call(
	ctx context.Context,
	name string,
	input DirectCallInput,
) (DirectCallResult, error)
```

### `GetSession`

GetSession executes the production session endpoint and applies the same
configured user decoder used by sign-up and sign-in.

```go
func (api TypedDirectAPI[Output]) GetSession(
	ctx context.Context,
	input GetSessionInput,
) (*TypedSessionResult[Output], error)
```

### `SignInEmail`

SignInEmail executes the production sign-in endpoint and returns the same
configured User type as SignUpEmail.

```go
func (api TypedDirectAPI[Output]) SignInEmail(
	ctx context.Context,
	input SignInEmailInput,
) (TypedSignInEmailResult[Output], error)
```

### `SignOut`

SignOut delegates to the production direct API.

```go
func (api TypedDirectAPI[Output]) SignOut(
	ctx context.Context,
	input SignOutInput,
) (SignOutResult, error)
```

### `SignUpEmail`

SignUpEmail executes the production sign-up endpoint and decodes its user
into the configured static output type.

```go
func (api TypedDirectAPI[Output]) SignUpEmail(
	ctx context.Context,
	input SignUpEmailInput,
) (TypedSignUpEmailResult[Output], error)
```

### `TypedDirectEndpoint`

TypedDirectEndpoint binds a direct API name, method, input encoder, and
output decoder without passing values through any at the public boundary.

```go
type TypedDirectEndpoint[Input, Output any] struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `TypedDirectEndpoint`

### `BindTypedDirectEndpoint`

BindTypedDirectEndpoint constructs a typed façade over a production direct
endpoint. Plugin overrides can bind the same name with a completely new
Input and Output type.

```go
func BindTypedDirectEndpoint[Input, Output any](
	auth *Auth,
	name,
	method string,
	encode func(Input) DirectCallInput,
	decode DirectResultDecoder[Output],
) (TypedDirectEndpoint[Input, Output], error)
```

## Methods on `TypedDirectEndpoint`

### `Call`

Call invokes the real endpoint, preserving the statically selected input and
output types across the plugin override.

```go
func (endpoint TypedDirectEndpoint[Input, Output]) Call(
	ctx context.Context,
	input Input,
) (Output, error)
```

### `TypedErrorCodes`

TypedErrorCodes composes core and plugin-specific code sets.

```go
type TypedErrorCodes[PluginCodes any] struct {
	Base   BaseErrorCodes
	Plugin PluginCodes
}
```

## Constructors and functions for `TypedErrorCodes`

### `NewTypedErrorCodes`

```go
func NewTypedErrorCodes[PluginCodes any](plugin PluginCodes) TypedErrorCodes[PluginCodes]
```

### `PreserveErrorCodesWithUntypedPlugins`

PreserveErrorCodesWithUntypedPlugins is the error-code counterpart of
PreserveInferenceWithUntypedPlugins.

```go
func PreserveErrorCodesWithUntypedPlugins[PluginCodes any](
	codes TypedErrorCodes[PluginCodes],
	_ ...any,
) TypedErrorCodes[PluginCodes]
```

### `TypedPluginContext2`

TypedPluginContext2 binds two concrete plugin values to the runtime plugin
registry. Go has no string-literal indexed return types, so known plugins are
retrieved by stable typed positions while arbitrary IDs use HasPlugin.

```go
type TypedPluginContext2[First, Second any] struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `TypedPluginContext2`

### `NewTypedPluginContext2`

NewTypedPluginContext2 creates a typed view over two configured plugins.

```go
func NewTypedPluginContext2[First, Second any](
	auth *Auth,
	firstID string,
	first First,
	secondID string,
	second Second,
) (TypedPluginContext2[First, Second], error)
```

## Methods on `TypedPluginContext2`

### `First`

```go
func (context TypedPluginContext2[First, Second]) First() First
```

### `HasFirst`

```go
func (TypedPluginContext2[First, Second]) HasFirst() KnownPluginPresence
```

### `HasPlugin`

HasPlugin performs the dynamic counterpart of upstream implementation context.hasPlugin.

```go
func (context TypedPluginContext2[First, Second]) HasPlugin(id string) bool
```

### `HasSecond`

```go
func (TypedPluginContext2[First, Second]) HasSecond() KnownPluginPresence
```

### `Plugin`

Plugin returns the immutable runtime descriptor for a dynamic plugin ID.

```go
func (context TypedPluginContext2[First, Second]) Plugin(id string) (engine.Plugin, bool)
```

### `Second`

```go
func (context TypedPluginContext2[First, Second]) Second() Second
```

### `TypedRequestContext`

TypedRequestContext retains body and query as independent type parameters.
In particular, choosing any for Body cannot widen Query to any, mirroring
upstream implementation's InferCtx any-poisoning guard.

```go
type TypedRequestContext[Body, Query any] struct {
	Body   Body
	Query  Query
	Method string
	Path   string
	Params map[string]string
}
```

### `TypedSession`

TypedSession is the statically typed form of model.Session. Additional can
contain fields contributed by both session.additionalFields and plugins.

```go
type TypedSession[Additional any] struct {
	ID         string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	UserID     string
	ExpiresAt  time.Time
	Token      string
	IPAddress  model.Value[string]
	UserAgent  model.Value[string]
	Additional Additional
}
```

## Constructors and functions for `TypedSession`

### `DecodeSession`

DecodeSession converts a production model.Session to its static form.

```go
func DecodeSession[Additional any](
	session model.Session,
	decoder DBFieldsDecoder[Additional],
) (TypedSession[Additional], error)
```

### `TypedSessionInference`

TypedSessionInference is the static session/user pair exposed by Better
Auth's $Infer.Session contract. The two generic arguments allow plugins to
contribute user and session fields independently without erasing either
model's base fields.

```go
type TypedSessionInference[UserAdditional, SessionAdditional any] struct {
	Session TypedSession[SessionAdditional]
	User    TypedUser[UserAdditional]
}
```

### `TypedSessionResult`

TypedSessionResult is the statically typed user counterpart of SessionResult.

```go
type TypedSessionResult[Output any] struct {
	Session model.Session
	User    Output
	Headers contract.Headers
}
```

### `TypedSignInEmailOverrideAPI`

TypedSignInEmailOverrideAPI explicitly shadows DirectAPI.SignInEmail with a
bodyless plugin result. Other base methods remain promoted through DirectAPI.

```go
type TypedSignInEmailOverrideAPI[Output any] struct {
	DirectAPI
	// contains filtered or unexported fields
}
```

## Constructors and functions for `TypedSignInEmailOverrideAPI`

### `BindTypedSignInEmailOverrideAPI`

BindTypedSignInEmailOverrideAPI binds the canonical signInEmail endpoint
name while retaining the plugin's replacement return type.

```go
func BindTypedSignInEmailOverrideAPI[Output any](
	auth *Auth,
	decode DirectResultDecoder[Output],
) (TypedSignInEmailOverrideAPI[Output], error)
```

## Methods on `TypedSignInEmailOverrideAPI`

### `SignInEmail`

SignInEmail exposes only NoBody and the replacement Output; the base email
body's metadata cannot leak into this method's static type.

```go
func (api TypedSignInEmailOverrideAPI[Output]) SignInEmail(
	ctx context.Context,
	input NoBody,
) (Output, error)
```

### `TypedSignInEmailResult`

TypedSignInEmailResult preserves the SignInEmail result while exposing the
configured static user type.

```go
type TypedSignInEmailResult[Output any] struct {
	Redirect bool
	Token    string
	URL      model.Value[string]
	User     Output
	Headers  contract.Headers
}
```

### `TypedSignUpEmailResult`

TypedSignUpEmailResult preserves the SignUpEmail result while exposing the
configured static user type.

```go
type TypedSignUpEmailResult[Output any] struct {
	Token   *string
	User    Output
	Headers contract.Headers
}
```

### `TypedUser`

TypedUser is the statically typed form of model.User. TypeScript can intersect
configured additional fields directly into an object type; Go represents
the same composition through Additional while retaining the exact base user
field types.

```go
type TypedUser[Additional any] struct {
	ID            string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Email         string
	EmailVerified bool
	Name          string
	Image         model.Value[string]
	Additional    Additional
}
```

## Constructors and functions for `TypedUser`

### `DecodeUser`

DecodeUser converts a model.User into its statically typed public form.

```go
func DecodeUser[Additional any](
	user model.User,
	decoder UserFieldsDecoder[Additional],
) (TypedUser[Additional], error)
```

### `TypedVerification`

TypedVerification is the statically typed form of model.Verification.

```go
type TypedVerification[Additional any] struct {
	ID         string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Identifier string
	Value      string
	ExpiresAt  time.Time
	Additional Additional
}
```

## Constructors and functions for `TypedVerification`

### `DecodeVerification`

DecodeVerification converts a production model.Verification to its static form.

```go
func DecodeVerification[Additional any](
	verification model.Verification,
	decoder DBFieldsDecoder[Additional],
) (TypedVerification[Additional], error)
```

### `UnlinkAccountInput`

```go
type UnlinkAccountInput struct {
	ProviderID string
	AccountID  string
	Headers    contract.Headers
}
```

### `UpdateSessionInput`

```go
type UpdateSessionInput struct {
	Fields  model.Fields
	Headers contract.Headers
}
```

### `UpdateSessionResult`

```go
type UpdateSessionResult struct {
	Session model.Session
	Headers contract.Headers
}
```

### `UpdateUserInput`

```go
type UpdateUserInput struct {
	Name             model.Value[string]
	Image            model.Value[string]
	AdditionalFields model.Fields
	Headers          contract.Headers
}
```

### `UpstreamError`

UpstreamError is an initialization or capability error exposed verbatim
by upstream implementation. The concrete type preserves the upstream error identity for
callers that need to distinguish configuration errors from transport errors.

```go
type UpstreamError struct {
	// contains filtered or unexported fields
}
```

## Methods on `UpstreamError`

### `Error`

Error returns the unmodified upstream implementation diagnostic.

```go
func (e *UpstreamError) Error() string
```

### `User`

```go
type User = model.User
```

### `UserDecoder`

UserDecoder converts the production model.User into a caller-defined static
output type. This is the Go analogue of upstream implementation inferring a complete user
result from its configuration type.

```go
type UserDecoder[Output any] func(model.User) (Output, error)
```

### `UserFieldsDecoder`

UserFieldsDecoder converts the lossless dynamic additional-field map into a
caller-defined Go type. model.Value fields preserve absent, null, and present
values, matching upstream implementation's optional nullable inferred output fields.

```go
type UserFieldsDecoder[Additional any] func(model.Fields) (Additional, error)
```

### `UserOptions`

```go
type UserOptions struct {
	ChangeEmail ChangeEmailOptions
	DeleteUser  DeleteUserOptions
}
```

### `Verification`

```go
type Verification = model.Verification
```

### `VerificationIdentifierHasher`

VerificationIdentifierHasher implements upstream implementation's custom
&#123; hash(identifier) &#125; storeIdentifier option.

```go
type VerificationIdentifierHasher func(identifier string) (string, error)
```

### `VerificationIdentifierOverride`

VerificationIdentifierOverride selects a storage rule for identifiers with
Prefix. Hash takes precedence over Strategy and represents the upstream
custom-hasher form.

```go
type VerificationIdentifierOverride struct {
	Prefix   string
	Strategy VerificationIdentifierStrategy
	Hash     VerificationIdentifierHasher
}
```

### `VerificationIdentifierStorage`

VerificationIdentifierStorage configures the default identifier storage
rule and optional ordered prefix overrides. Hash takes precedence over
Strategy and represents the upstream custom-hasher form.

```go
type VerificationIdentifierStorage struct {
	Strategy  VerificationIdentifierStrategy
	Hash      VerificationIdentifierHasher
	Overrides []VerificationIdentifierOverride
}
```

### `VerificationIdentifierStrategy`

VerificationIdentifierStrategy is a built-in verification identifier
storage strategy.

```go
type VerificationIdentifierStrategy string
```

## Constants associated with `VerificationIdentifierStrategy`

```go
const (
	VerificationIdentifierPlain VerificationIdentifierStrategy = "plain"

	VerificationIdentifierHashed VerificationIdentifierStrategy = "hashed"
)
```

### `VerificationOptions`

VerificationOptions controls persistence of single-use verification data.
With SecondaryStorage or SecondaryValueStorage configured, values are
cache-only unless StoreInDatabase is true.

```go
type VerificationOptions struct {
	DisableCleanup  bool
	StoreInDatabase bool
	// StoreIdentifier controls how verification identifiers (tokens, OTPs,
	// OAuth state values, and similar secrets) are persisted. The zero value is
	// plain storage. Overrides are evaluated in order and the first matching
	// prefix wins, matching Object.entries ordering in upstream implementation.
	StoreIdentifier VerificationIdentifierStorage
}
```

### `VerificationValue`

VerificationValue is the create/reserve input for a single-use value.

```go
type VerificationValue struct {
	Identifier string
	Value      string
	ExpiresAt  time.Time
}
```

### `VerifyEmailInput`

```go
type VerifyEmailInput struct {
	Token       string
	CallbackURL string
	Headers     contract.Headers
}
```

### `VerifyEmailResult`

```go
type VerifyEmailResult struct {
	Status   bool
	User     *model.User
	Location string
	Headers  contract.Headers
}
```

### `VerifyPasswordInput`

```go
type VerifyPasswordInput struct {
	Password string
	Headers  contract.Headers
}
```

