---
title: "github.com/pers0na2dev/single-auth"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth.

- Import path: `github.com/pers0na2dev/single-auth`
- Package name: `singleauth`

Package singleauth is the application-facing facade for the native Go
authentication runtime. Its API is generated from package core so the root
import remains concise while implementation files stay logically grouped.

## Constants

Constants exported by the core runtime.

```go
const ErrorAccountNotFound = core.ErrorAccountNotFound
```

```go
const ErrorAsyncValidationNotSupported = core.ErrorAsyncValidationNotSupported
```

```go
const ErrorBodyMustBeObject = core.ErrorBodyMustBeObject
```

```go
const ErrorCallbackURLRequired = core.ErrorCallbackURLRequired
```

```go
const ErrorChangeEmailDisabled = core.ErrorChangeEmailDisabled
```

```go
const ErrorCredentialAccountNotFound = core.ErrorCredentialAccountNotFound
```

```go
const ErrorCrossSiteNavigationLoginBlocked = core.ErrorCrossSiteNavigationLoginBlocked
```

```go
const ErrorEmailAlreadyVerified = core.ErrorEmailAlreadyVerified
```

```go
const ErrorEmailCannotBeUpdated = core.ErrorEmailCannotBeUpdated
```

```go
const ErrorEmailMismatch = core.ErrorEmailMismatch
```

```go
const ErrorEmailNotVerified = core.ErrorEmailNotVerified
```

```go
const ErrorFailedToCreateSession = core.ErrorFailedToCreateSession
```

```go
const ErrorFailedToCreateUser = core.ErrorFailedToCreateUser
```

```go
const ErrorFailedToCreateVerification = core.ErrorFailedToCreateVerification
```

```go
const ErrorFailedToGetSession = core.ErrorFailedToGetSession
```

```go
const ErrorFailedToGetUserInfo = core.ErrorFailedToGetUserInfo
```

```go
const ErrorFailedToUnlinkLastAccount = core.ErrorFailedToUnlinkLastAccount
```

```go
const ErrorFailedToUpdateUser = core.ErrorFailedToUpdateUser
```

```go
const ErrorFieldNotAllowed = core.ErrorFieldNotAllowed
```

```go
const ErrorIDTokenNotSupported = core.ErrorIDTokenNotSupported
```

```go
const ErrorInvalidCallbackURL = core.ErrorInvalidCallbackURL
```

```go
const ErrorInvalidEmail = core.ErrorInvalidEmail
```

```go
const ErrorInvalidEmailOrPassword = core.ErrorInvalidEmailOrPassword
```

```go
const ErrorInvalidErrorCallbackURL = core.ErrorInvalidErrorCallbackURL
```

```go
const ErrorInvalidNewUserCallbackURL = core.ErrorInvalidNewUserCallbackURL
```

```go
const ErrorInvalidOrigin = core.ErrorInvalidOrigin
```

```go
const ErrorInvalidPassword = core.ErrorInvalidPassword
```

```go
const ErrorInvalidRedirectURL = core.ErrorInvalidRedirectURL
```

```go
const ErrorInvalidToken = core.ErrorInvalidToken
```

```go
const ErrorInvalidUser = core.ErrorInvalidUser
```

```go
const ErrorLinkedAccountAlreadyExists = core.ErrorLinkedAccountAlreadyExists
```

```go
const ErrorMethodNeedsDeferredSession = core.ErrorMethodNeedsDeferredSession
```

```go
const ErrorMissingField = core.ErrorMissingField
```

```go
const ErrorMissingOrNullOrigin = core.ErrorMissingOrNullOrigin
```

```go
const ErrorPasswordAlreadySet = core.ErrorPasswordAlreadySet
```

```go
const ErrorPasswordTooLong = core.ErrorPasswordTooLong
```

```go
const ErrorPasswordTooShort = core.ErrorPasswordTooShort
```

```go
const ErrorProviderNotFound = core.ErrorProviderNotFound
```

```go
const ErrorSessionExpired = core.ErrorSessionExpired
```

```go
const ErrorSessionNotFresh = core.ErrorSessionNotFresh
```

```go
const ErrorSocialAccountAlreadyLinked = core.ErrorSocialAccountAlreadyLinked
```

```go
const ErrorTokenExpired = core.ErrorTokenExpired
```

```go
const ErrorUserAlreadyExists = core.ErrorUserAlreadyExists
```

```go
const ErrorUserAlreadyExistsAnotherEmail = core.ErrorUserAlreadyExistsAnotherEmail
```

```go
const ErrorUserAlreadyHasPassword = core.ErrorUserAlreadyHasPassword
```

```go
const ErrorUserEmailNotFound = core.ErrorUserEmailNotFound
```

```go
const ErrorUserNotFound = core.ErrorUserNotFound
```

```go
const ErrorValidation = core.ErrorValidation
```

```go
const ErrorVerificationEmailNotEnabled = core.ErrorVerificationEmailNotEnabled
```

```go
const PluginSessionAuthoritative = core.PluginSessionAuthoritative
```

```go
const PluginSessionFresh = core.PluginSessionFresh
```

```go
const PluginSessionOptional = core.PluginSessionOptional
```

```go
const PluginSessionRequired = core.PluginSessionRequired
```

VerificationIdentifierHashed stores SHA-256 identifiers as unpadded
base64url, matching upstream implementation's "hashed" strategy.

```go
const VerificationIdentifierHashed = core.VerificationIdentifierHashed
```

VerificationIdentifierPlain stores identifiers unchanged.

```go
const VerificationIdentifierPlain = core.VerificationIdentifierPlain
```

## Variables

Variables exported by the core runtime.
BaseErrorMessages is the exact upstream implementation 1.6.26 base error catalog.

```go
var BaseErrorMessages = core.BaseErrorMessages
```

ErrFullMigrationsRequireDatabase is returned when full-mode migrations are
requested without a raw database connection.

```go
var ErrFullMigrationsRequireDatabase = core.ErrFullMigrationsRequireDatabase
```

ErrMinimalDirectDatabaseUnsupported is returned when a raw database
connection is passed to the minimal runtime instead of a storage adapter.

```go
var ErrMinimalDirectDatabaseUnsupported = core.ErrMinimalDirectDatabaseUnsupported
```

ErrMinimalMigrationsUnsupported is returned by the minimal runtime because
schema migrations require the database-specific full runtime upstream.

```go
var ErrMinimalMigrationsUnsupported = core.ErrMinimalMigrationsUnsupported
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
	inference Inference, arg0 ...any,
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

Types exported by the core runtime.

```go
type APIError = core.APIError
```

### `APIErrorOptions`

```go
type APIErrorOptions = core.APIErrorOptions
```

### `AccessTokenResult`

```go
type AccessTokenResult = core.AccessTokenResult
```

### `Account`

```go
type Account = core.Account
```

### `AccountInfoInput`

```go
type AccountInfoInput = core.AccountInfoInput
```

### `AccountInfoResult`

```go
type AccountInfoResult = core.AccountInfoResult
```

### `AccountLinkingOptions`

AccountLinkingOptions configures built-in account linking and unlinking.

```go
type AccountLinkingOptions = core.AccountLinkingOptions
```

### `AccountOptions`

AccountOptions configures provider account persistence and linking.

```go
type AccountOptions = core.AccountOptions
```

### `AccountTokenInput`

```go
type AccountTokenInput = core.AccountTokenInput
```

### `AdvancedOptions`

AdvancedOptions contains security- and transport-sensitive settings.

```go
type AdvancedOptions = core.AdvancedOptions
```

### `AnyKeyShape`

AnyKeyShape represents an unconstrained any-shaped object. It deliberately
reports no statically known required keys.

```go
type AnyKeyShape = core.AnyKeyShape
```

### `Auth`

Auth is an immutable upstream implementation-compatible runtime. It is safe for
concurrent HTTP and direct API calls.

```go
type Auth = core.Auth
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

### `AuthContext`

AuthContext exposes the initialized full-mode adapter and migration
capability. It is an immutable snapshot.

```go
type AuthContext = core.AuthContext
```

### `AuthContextAdapterConfig`

AuthContextAdapterConfig is the Go counterpart of upstream implementation's adapter
factory metadata.

```go
type AuthContextAdapterConfig = core.AuthContextAdapterConfig
```

### `AuthContextAdapterOptions`

AuthContextAdapterOptions describes the detected database dialect and the
adapter factory that was selected for it.

```go
type AuthContextAdapterOptions = core.AuthContextAdapterOptions
```

### `AuthCookie`

AuthCookie describes one request-scoped upstream implementation cookie declaration.
Attributes is copied when the context is created and whenever it is read.

```go
type AuthCookie = core.AuthCookie
```

### `AuthenticatedInput`

```go
type AuthenticatedInput = core.AuthenticatedInput
```

### `BackgroundRunner`

BackgroundRunner receives non-critical work. A nil runner executes work
synchronously, matching upstream implementation's server fallback.

```go
type BackgroundRunner = core.BackgroundRunner
```

### `BaseErrorCodes`

BaseErrorCodes is the statically typed core error-code subset used by type
contracts. Values retain the public ErrorCode type instead of widening to
string or any.

```go
type BaseErrorCodes = core.BaseErrorCodes
```

### `ChangeEmailConfirmationMessage`

ChangeEmailConfirmationMessage is delivered to the current address before
the new address is verified in the two-step flow.

```go
type ChangeEmailConfirmationMessage = core.ChangeEmailConfirmationMessage
```

### `ChangeEmailInput`

```go
type ChangeEmailInput = core.ChangeEmailInput
```

### `ChangeEmailOptions`

```go
type ChangeEmailOptions = core.ChangeEmailOptions
```

### `ChangePasswordInput`

```go
type ChangePasswordInput = core.ChangePasswordInput
```

### `ChangePasswordResult`

```go
type ChangePasswordResult = core.ChangePasswordResult
```

### `CookieCacheLookupOptions`

CookieCacheLookupOptions controls the public session-data cookie reader.
ResolveVersion is the Go equivalent of upstream implementation's synchronous or async
version callback; it takes precedence over Version when non-nil.

```go
type CookieCacheLookupOptions = core.CookieCacheLookupOptions
```

### `CookieCacheOptions`

CookieCacheOptions configures upstream implementation's session-data cookie.

```go
type CookieCacheOptions = core.CookieCacheOptions
```

### `CookieHeaderGetter`

CookieHeaderGetter is implemented by net/http.Header and by header shims
from other runtimes. It keeps GetSessionCookie usable across realm or wrapper
boundaries without relying on a concrete header type.

```go
type CookieHeaderGetter = core.CookieHeaderGetter
```

### `CookieOverride`

CookieOverride customizes one upstream implementation cookie. Attribute pointers retain
the distinction between an omitted override and an explicit false value.

```go
type CookieOverride = core.CookieOverride
```

### `CrossSubDomainCookieOptions`

CrossSubDomainCookieOptions shares auth cookies across subdomains. When
Domain is empty, a static base URL supplies its hostname; dynamic base URLs
resolve it from each allowed incoming request.

```go
type CrossSubDomainCookieOptions = core.CrossSubDomainCookieOptions
```

### `DBFieldsDecoder`

DBFieldsDecoder converts a model's lossless dynamic field map into the
caller's static Go representation. upstream implementation's TypeScript definitions can
intersect configured and plugin fields into the base model automatically;
Go callers provide the corresponding concrete Additional type and decoder.

```go
type DBFieldsDecoder[Additional any] = core.DBFieldsDecoder[Additional]
```

### `DatabaseAfterHook`

```go
type DatabaseAfterHook = core.DatabaseAfterHook
```

### `DatabaseBeforeHook`

```go
type DatabaseBeforeHook = core.DatabaseBeforeHook
```

### `DatabaseHookContext`

DatabaseHookContext describes one upstream implementation database lifecycle callback.
Endpoint is nil when an adapter operation is initiated outside dispatch.

```go
type DatabaseHookContext = core.DatabaseHookContext
```

### `DatabaseHookResult`

DatabaseHookResult is the Go equivalent of upstream implementation's false or
&#123;data: ...&#125; before-hook result. Data is merged over the current write.

```go
type DatabaseHookResult = core.DatabaseHookResult
```

### `DatabaseHooks`

DatabaseHooks maps canonical model names to create/update/delete lifecycle
callbacks. Core and plugin models use the same hook machinery.

```go
type DatabaseHooks = core.DatabaseHooks
```

### `DatabaseModelHooks`

```go
type DatabaseModelHooks = core.DatabaseModelHooks
```

### `DatabaseOperationHooks`

```go
type DatabaseOperationHooks = core.DatabaseOperationHooks
```

### `DeleteAccountMessage`

```go
type DeleteAccountMessage = core.DeleteAccountMessage
```

### `DeleteUserCallbackInput`

```go
type DeleteUserCallbackInput = core.DeleteUserCallbackInput
```

### `DeleteUserCallbackResult`

```go
type DeleteUserCallbackResult = core.DeleteUserCallbackResult
```

### `DeleteUserInput`

```go
type DeleteUserInput = core.DeleteUserInput
```

### `DeleteUserOptions`

```go
type DeleteUserOptions = core.DeleteUserOptions
```

### `DirectAPI`

DirectAPI is the typed façade over Auth.Invoke. It uses the exact same
endpoint handlers and before/after hooks as HTTP dispatch.

```go
type DirectAPI = core.DirectAPI
```

### `DirectCallInput`

DirectCallInput is the escape hatch for core and plugin endpoints that do
not yet have a dedicated typed convenience method. It still runs the exact
endpoint and before/after-hook pipeline used by all typed methods.

```go
type DirectCallInput = core.DirectCallInput
```

### `DirectCallResult`

DirectCallResult preserves both the transport-neutral response (including
Set-Cookie and Location) and its decoded JSON value.

```go
type DirectCallResult = core.DirectCallResult
```

### `DirectInput`

```go
type DirectInput = core.DirectInput
```

### `DirectResultDecoder`

DirectResultDecoder turns the production DirectCallResult into a concrete
caller-facing output type.

```go
type DirectResultDecoder[Output any] = core.DirectResultDecoder[Output]
```

### `DynamicBaseURLOptions`

DynamicBaseURLOptions resolves the public auth URL from each request while
constraining the host to an explicit allowlist. Protocol accepts "http",
"https", or "auto"; an empty value defaults to HTTPS and also permits HTTP
for loopback hosts, matching upstream implementation's development behavioral compatibility.

```go
type DynamicBaseURLOptions = core.DynamicBaseURLOptions
```

### `EmailAndPasswordOptions`

EmailAndPasswordOptions configures the built-in credential endpoints.

```go
type EmailAndPasswordOptions = core.EmailAndPasswordOptions
```

### `EmailVerificationMessage`

EmailVerificationMessage contains the exact data passed to the email hook.

```go
type EmailVerificationMessage = core.EmailVerificationMessage
```

### `EmailVerificationOptions`

EmailVerificationOptions configures verification mail and token behavioral compatibility.

```go
type EmailVerificationOptions = core.EmailVerificationOptions
```

### `Endpoint`

```go
type Endpoint = core.Endpoint
```

### `ErrorCode`

ErrorCode is a stable upstream implementation API error identifier.

```go
type ErrorCode = core.ErrorCode
```

### `GetSessionInput`

```go
type GetSessionInput = core.GetSessionInput
```

### `IDGenerator`

IDGenerator returns a upstream implementation identifier. The bool is false when the
backing database must generate the identifier itself.

```go
type IDGenerator = core.IDGenerator
```

### `InternalAdapter`

InternalAdapter is the Go counterpart of upstream implementation's internalAdapter.
It keeps lifecycle hooks, secondary-storage behavioral compatibility, identifier hashing,
and transaction scoping above the raw storage.Adapter contract.

```go
type InternalAdapter = core.InternalAdapter
```

### `InternalOAuthUser`

InternalOAuthUser is the user/account pair created by CreateOAuthUser.

```go
type InternalOAuthUser = core.InternalOAuthUser
```

### `InternalSession`

InternalSession is the joined session/user value returned by FindSession
and FindSessions.

```go
type InternalSession = core.InternalSession
```

### `InternalSessionCreateOptions`

InternalSessionCreateOptions represents upstream implementation's optional
dontRememberMe, override, and overrideAll createSession arguments.

```go
type InternalSessionCreateOptions = core.InternalSessionCreateOptions
```

### `KnownPluginPresence`

KnownPluginPresence is the true literal marker returned for a plugin whose
position and type are known at compile time. Dynamic plugin IDs continue to
return an ordinary bool through TypedPluginContext2.HasPlugin.

```go
type KnownPluginPresence = core.KnownPluginPresence
```

### `LinkSocialAccountInput`

```go
type LinkSocialAccountInput = core.LinkSocialAccountInput
```

### `LinkSocialAccountResult`

```go
type LinkSocialAccountResult = core.LinkSocialAccountResult
```

### `ListSessionsInput`

```go
type ListSessionsInput = core.ListSessionsInput
```

### `ListSessionsResult`

```go
type ListSessionsResult = core.ListSessionsResult
```

### `ListUserAccountsInput`

```go
type ListUserAccountsInput = core.ListUserAccountsInput
```

### `ListUserAccountsResult`

```go
type ListUserAccountsResult = core.ListUserAccountsResult
```

### `ListedAccount`

```go
type ListedAccount = core.ListedAccount
```

### `MinimalAuth`

MinimalAuth is the upstream implementation-compatible minimal runtime. It embeds the
regular Go runtime while keeping the minimal entry point's migration and
raw-connection constraints explicit.

```go
type MinimalAuth = core.MinimalAuth
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

### `MinimalContext`

MinimalContext exposes the adapter selected by the minimal initializer.
DatabaseType is always "unknown" because minimal mode accepts an already
configured storage adapter and does not perform database detection.

```go
type MinimalContext = core.MinimalContext
```

### `NoAdditionalFields`

NoAdditionalFields is the explicit Go representation of a upstream implementation model
with no configured or plugin-contributed fields. Go cannot intersect object
types, so TypedUser and TypedSession retain additional fields in a generic
slot whose empty form is this zero-sized type.

```go
type NoAdditionalFields = core.NoAdditionalFields
```

### `NoBody`

NoBody is the compile-time input for an endpoint override that deliberately
removes the base endpoint's request body contract.

```go
type NoBody = core.NoBody
```

### `OAuthCallbackInput`

```go
type OAuthCallbackInput = core.OAuthCallbackInput
```

### `OptionalKeyShape`

```go
type OptionalKeyShape[Fields any] = core.OptionalKeyShape[Fields]
```

### `Options`

Options is the immutable configuration snapshot consumed by New.

Engine-level extension points are intentionally public so plugin packages
can depend on focused contracts without creating a cycle through the
canonical core runtime.

```go
type Options = core.Options
```

### `PasswordOptions`

PasswordOptions configures credential hashing and validation. Nil functions
use upstream implementation's scrypt implementation from package crypto.

```go
type PasswordOptions = core.PasswordOptions
```

### `PasswordResetCallbackInput`

```go
type PasswordResetCallbackInput = core.PasswordResetCallbackInput
```

### `PasswordResetMessage`

PasswordResetMessage contains the reset link delivered by the configured
mail hook.

```go
type PasswordResetMessage = core.PasswordResetMessage
```

### `Plugin`

```go
type Plugin = core.Plugin
```

### `PluginAPIs2`

PluginAPIs2 composes differently shaped plugin APIs without losing either
concrete type. TypeScript flattens plugin endpoints into one object; Go keeps
each collision-free API in an explicit slot.

```go
type PluginAPIs2[First, Second any] = core.PluginAPIs2[First, Second]
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
type PluginFactory = core.PluginFactory
```

### `PluginHost`

PluginHost is the typed dependency surface supplied to PluginFactory.Build.
Every callback enters the same root persistence, cookie, security, and
background-work semantics as core endpoints.

```go
type PluginHost = core.PluginHost
```

### `PluginOAuthState`

PluginOAuthState is the generated CSRF state and PKCE verifier supplied to
the provider authorization URL builder.

```go
type PluginOAuthState = core.PluginOAuthState
```

### `PluginOAuthStateData`

PluginOAuthStateData is the validated, single-use OAuth state exposed to
protocol plugins. AdditionalData contains only plugin-owned fields that were
persisted alongside the root callback, error, signup, and PKCE values.

```go
type PluginOAuthStateData = core.PluginOAuthStateData
```

### `PluginOAuthStateError`

PluginOAuthStateError is returned after a state lookup, cookie binding, or
atomic consume failure. Code is safe to expose as an OAuth redirect error;
ErrorURL is populated only when it came from already-validated state.

```go
type PluginOAuthStateError = core.PluginOAuthStateError
```

### `PluginOAuthStateInput`

PluginOAuthStateInput is the transport-neutral input used by plugins that
start a regular upstream implementation OAuth flow. AdditionalData is persisted in the
same state record/cookie as core social sign-in after the caller has removed
keys reserved by the state protocol.

```go
type PluginOAuthStateInput = core.PluginOAuthStateInput
```

### `PluginOAuthUserInput`

PluginOAuthUserInput delegates identity/account resolution to the same
implementation used by redirect social sign-in. Provider may be an
ephemeral provider descriptor for protocol plugins such as One Tap that can
operate without a configured redirect provider.

```go
type PluginOAuthUserInput = core.PluginOAuthUserInput
```

### `PluginOAuthUserResult`

PluginOAuthUserResult carries the created session/user pair and the
user-facing OAuth linking error that upstream returns separately from
internal failures.

```go
type PluginOAuthUserResult = core.PluginOAuthUserResult
```

### `PluginPasswordHash`

PluginPasswordHash is the request-aware password hash function exposed to
plugin factories. Context is nil for non-endpoint use; wrappers must then
behave as if no route path were active.

```go
type PluginPasswordHash = core.PluginPasswordHash
```

### `PluginPasswordHashWrapper`

PluginPasswordHashWrapper decorates the hash function installed by prior
factories. Factories are applied in declaration order, so the latest wrapper
becomes the outermost one, matching upstream implementation init context composition.

```go
type PluginPasswordHashWrapper = core.PluginPasswordHashWrapper
```

### `PluginSessionMode`

PluginSessionMode selects the host's regular, authoritative, or fresh
session policy.

```go
type PluginSessionMode = core.PluginSessionMode
```

### `PluginSessionState`

PluginSessionState is the logical session/user pair shared with plugins.

```go
type PluginSessionState = core.PluginSessionState
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
type ProviderUser = core.ProviderUser
```

### `RateLimit`

```go
type RateLimit = core.RateLimit
```

### `RateLimitOptions`

RateLimitOptions configures the built-in request limiter. Window and Max
are the default rule. Storage accepts "memory", "database", or
"secondary-storage"; CustomStorage takes precedence when present.

```go
type RateLimitOptions = core.RateLimitOptions
```

### `RedirectResult`

```go
type RedirectResult = core.RedirectResult
```

### `RefreshTokenResult`

```go
type RefreshTokenResult = core.RefreshTokenResult
```

### `Request`

```go
type Request = core.Request
```

### `RequestAuthContext`

RequestAuthContext is the request-local counterpart of upstream implementation's
AuthContext. It exposes the resolved public URL, the resolved option
snapshot, trusted origins, cookie declarations, and the internal adapter to
hooks and plugin endpoints without mutating the shared Auth runtime.

```go
type RequestAuthContext = core.RequestAuthContext
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
type RequestAuthCookies = core.RequestAuthCookies
```

### `RequestPasswordResetInput`

```go
type RequestPasswordResetInput = core.RequestPasswordResetInput
```

### `RequiredKeyShape`

RequiredKeyShape and OptionalKeyShape retain the caller's field shape while
explicitly recording whether its keys are required or optional.

```go
type RequiredKeyShape[Fields any] = core.RequiredKeyShape[Fields]
```

### `RequiredKeysAbsent`

```go
type RequiredKeysAbsent = core.RequiredKeysAbsent
```

### `RequiredKeysPresent`

RequiredKeysPresent and RequiredKeysAbsent are distinct compile-time result
types. upstream implementation computes this distinction structurally; Go callers use an
explicit shape wrapper because the language has no optional object keys.

```go
type RequiredKeysPresent = core.RequiredKeysPresent
```

### `RequiredKeysResult`

RequiredKeysResult is the closed result set for RequiredKeysOf.

```go
type RequiredKeysResult = core.RequiredKeysResult
```

### `ResetPasswordInput`

```go
type ResetPasswordInput = core.ResetPasswordInput
```

### `Response`

```go
type Response = core.Response
```

### `RevokeSessionInput`

```go
type RevokeSessionInput = core.RevokeSessionInput
```

### `SecondaryGetAndDeleter`

SecondaryGetAndDeleter provides cross-process atomic consumption for
single-use verification values.

```go
type SecondaryGetAndDeleter = core.SecondaryGetAndDeleter
```

### `SecondaryStorage`

SecondaryStorage is upstream implementation's string-valued session, verification, and
rate-limit storage contract.

```go
type SecondaryStorage = core.SecondaryStorage
```

### `SecondaryValueGetAndDeleter`

SecondaryValueGetAndDeleter provides atomic consumption for an
object-valued secondary store.

```go
type SecondaryValueGetAndDeleter = core.SecondaryValueGetAndDeleter
```

### `SecondaryValueStorage`

SecondaryValueStorage is the object-valued form of upstream implementation's secondary
storage contract. Some Redis wrappers parse JSON before returning it, so a
Go implementation cannot expose that behavioral compatibility through SecondaryStorage's
string-returning Get method. Configure this interface through
Options.SecondaryValueStorage instead. Set still receives the canonical JSON
string written by upstream implementation.

```go
type SecondaryValueStorage = core.SecondaryValueStorage
```

### `SendVerificationEmailInput`

```go
type SendVerificationEmailInput = core.SendVerificationEmailInput
```

### `Session`

```go
type Session = core.Session
```

### `SessionCookieLookupOptions`

SessionCookieLookupOptions controls the public session-cookie reader.

```go
type SessionCookieLookupOptions = core.SessionCookieLookupOptions
```

### `SessionOptions`

SessionOptions configures database sessions and their cookies.

```go
type SessionOptions = core.SessionOptions
```

### `SessionResult`

```go
type SessionResult = core.SessionResult
```

### `SetPasswordInput`

```go
type SetPasswordInput = core.SetPasswordInput
```

### `SignInEmailInput`

```go
type SignInEmailInput = core.SignInEmailInput
```

### `SignInEmailResult`

```go
type SignInEmailResult = core.SignInEmailResult
```

### `SignInSocialInput`

```go
type SignInSocialInput = core.SignInSocialInput
```

### `SignInSocialResult`

```go
type SignInSocialResult = core.SignInSocialResult
```

### `SignOutInput`

```go
type SignOutInput = core.SignOutInput
```

### `SignOutResult`

```go
type SignOutResult = core.SignOutResult
```

### `SignUpEmailInput`

```go
type SignUpEmailInput = core.SignUpEmailInput
```

### `SignUpEmailResult`

```go
type SignUpEmailResult = core.SignUpEmailResult
```

### `SocialIDTokenInput`

```go
type SocialIDTokenInput = core.SocialIDTokenInput
```

### `StatusMessageResult`

```go
type StatusMessageResult = core.StatusMessageResult
```

### `StatusResult`

StatusResult is the common `&#123;status: boolean&#125;` response returned by Better
Auth mutation endpoints.

```go
type StatusResult = core.StatusResult
```

### `SuccessMessageResult`

```go
type SuccessMessageResult = core.SuccessMessageResult
```

### `TrustedOriginsResolver`

TrustedOriginsResolver contributes request-scoped trusted origins. The
returned slice is copied and empty entries are ignored.

```go
type TrustedOriginsResolver = core.TrustedOriginsResolver
```

### `TypedAccount`

TypedAccount is the statically typed form of model.Account.

```go
type TypedAccount[Additional any] = core.TypedAccount[Additional]
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
type TypedAuth[Output any] = core.TypedAuth[Output]
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

### `TypedContext`

TypedContext preserves fields contributed by plugin init hooks. Extension is
explicit because Go cannot synthesize fields onto AuthContext at compile
time; Runtime still provides the initialized production context.

```go
type TypedContext[Extension any] = core.TypedContext[Extension]
```

## Constructors and functions for `TypedContext`

### `NewTypedContext`

NewTypedContext binds a caller-defined init extension to an Auth context.

```go
func NewTypedContext[Extension any](auth *Auth, extension Extension) (TypedContext[Extension], error)
```

### `TypedDirectAPI`

TypedDirectAPI is the generic user-result counterpart of DirectAPI.

```go
type TypedDirectAPI[Output any] = core.TypedDirectAPI[Output]
```

### `TypedDirectEndpoint`

TypedDirectEndpoint binds a direct API name, method, input encoder, and
output decoder without passing values through any at the public boundary.

```go
type TypedDirectEndpoint[Input, Output any] = core.TypedDirectEndpoint[Input, Output]
```

## Constructors and functions for `TypedDirectEndpoint`

### `BindTypedDirectEndpoint`

Functions exported by the core runtime.
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

### `TypedErrorCodes`

TypedErrorCodes composes core and plugin-specific code sets.

```go
type TypedErrorCodes[PluginCodes any] = core.TypedErrorCodes[PluginCodes]
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
	codes TypedErrorCodes[PluginCodes], arg0 ...any,
) TypedErrorCodes[PluginCodes]
```

### `TypedPluginContext2`

TypedPluginContext2 binds two concrete plugin values to the runtime plugin
registry. Go has no string-literal indexed return types, so known plugins are
retrieved by stable typed positions while arbitrary IDs use HasPlugin.

```go
type TypedPluginContext2[First, Second any] = core.TypedPluginContext2[First, Second]
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

### `TypedRequestContext`

TypedRequestContext retains body and query as independent type parameters.
In particular, choosing any for Body cannot widen Query to any, mirroring
upstream implementation's InferCtx any-poisoning guard.

```go
type TypedRequestContext[Body, Query any] = core.TypedRequestContext[Body, Query]
```

### `TypedSession`

TypedSession is the statically typed form of model.Session. Additional can
contain fields contributed by both session.additionalFields and plugins.

```go
type TypedSession[Additional any] = core.TypedSession[Additional]
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
type TypedSessionInference[UserAdditional, SessionAdditional any] = core.TypedSessionInference[UserAdditional, SessionAdditional]
```

### `TypedSessionResult`

TypedSessionResult is the statically typed user counterpart of SessionResult.

```go
type TypedSessionResult[Output any] = core.TypedSessionResult[Output]
```

### `TypedSignInEmailOverrideAPI`

TypedSignInEmailOverrideAPI explicitly shadows DirectAPI.SignInEmail with a
bodyless plugin result. Other base methods remain promoted through DirectAPI.

```go
type TypedSignInEmailOverrideAPI[Output any] = core.TypedSignInEmailOverrideAPI[Output]
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

### `TypedSignInEmailResult`

TypedSignInEmailResult preserves the SignInEmail result while exposing the
configured static user type.

```go
type TypedSignInEmailResult[Output any] = core.TypedSignInEmailResult[Output]
```

### `TypedSignUpEmailResult`

TypedSignUpEmailResult preserves the SignUpEmail result while exposing the
configured static user type.

```go
type TypedSignUpEmailResult[Output any] = core.TypedSignUpEmailResult[Output]
```

### `TypedUser`

TypedUser is the statically typed form of model.User. TypeScript can intersect
configured additional fields directly into an object type; Go represents
the same composition through Additional while retaining the exact base user
field types.

```go
type TypedUser[Additional any] = core.TypedUser[Additional]
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
type TypedVerification[Additional any] = core.TypedVerification[Additional]
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
type UnlinkAccountInput = core.UnlinkAccountInput
```

### `UpdateSessionInput`

```go
type UpdateSessionInput = core.UpdateSessionInput
```

### `UpdateSessionResult`

```go
type UpdateSessionResult = core.UpdateSessionResult
```

### `UpdateUserInput`

```go
type UpdateUserInput = core.UpdateUserInput
```

### `UpstreamError`

UpstreamError is an initialization or capability error exposed verbatim
by upstream implementation. The concrete type preserves the upstream error identity for
callers that need to distinguish configuration errors from transport errors.

```go
type UpstreamError = core.UpstreamError
```

### `User`

```go
type User = core.User
```

### `UserDecoder`

UserDecoder converts the production model.User into a caller-defined static
output type. This is the Go analogue of upstream implementation inferring a complete user
result from its configuration type.

```go
type UserDecoder[Output any] = core.UserDecoder[Output]
```

### `UserFieldsDecoder`

UserFieldsDecoder converts the lossless dynamic additional-field map into a
caller-defined Go type. model.Value fields preserve absent, null, and present
values, matching upstream implementation's optional nullable inferred output fields.

```go
type UserFieldsDecoder[Additional any] = core.UserFieldsDecoder[Additional]
```

### `UserOptions`

```go
type UserOptions = core.UserOptions
```

### `Verification`

```go
type Verification = core.Verification
```

### `VerificationIdentifierHasher`

VerificationIdentifierHasher implements upstream implementation's custom
&#123; hash(identifier) &#125; storeIdentifier option.

```go
type VerificationIdentifierHasher = core.VerificationIdentifierHasher
```

### `VerificationIdentifierOverride`

VerificationIdentifierOverride selects a storage rule for identifiers with
Prefix. Hash takes precedence over Strategy and represents the upstream
custom-hasher form.

```go
type VerificationIdentifierOverride = core.VerificationIdentifierOverride
```

### `VerificationIdentifierStorage`

VerificationIdentifierStorage configures the default identifier storage
rule and optional ordered prefix overrides. Hash takes precedence over
Strategy and represents the upstream custom-hasher form.

```go
type VerificationIdentifierStorage = core.VerificationIdentifierStorage
```

### `VerificationIdentifierStrategy`

VerificationIdentifierStrategy is a built-in verification identifier
storage strategy.

```go
type VerificationIdentifierStrategy = core.VerificationIdentifierStrategy
```

### `VerificationOptions`

VerificationOptions controls persistence of single-use verification data.
With SecondaryStorage or SecondaryValueStorage configured, values are
cache-only unless StoreInDatabase is true.

```go
type VerificationOptions = core.VerificationOptions
```

### `VerificationValue`

VerificationValue is the create/reserve input for a single-use value.

```go
type VerificationValue = core.VerificationValue
```

### `VerifyEmailInput`

```go
type VerifyEmailInput = core.VerifyEmailInput
```

### `VerifyEmailResult`

```go
type VerifyEmailResult = core.VerifyEmailResult
```

### `VerifyPasswordInput`

```go
type VerifyPasswordInput = core.VerifyPasswordInput
```

