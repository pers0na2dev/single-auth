---
title: "github.com/pers0na2dev/single-auth/protocol/oauth2"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/protocol/oauth2.

- Import path: `github.com/pers0na2dev/single-auth/protocol/oauth2`
- Package name: `oauth2`

Package oauth2 implements the OAuth 2.0/OIDC primitives shared by Better
Auth providers.

## Variables

ErrOAuthRedirect identifies a refused server-side OAuth redirect.

```go
var ErrOAuthRedirect = errors.New("OAuth endpoint returned an HTTP redirect")
```

## Functions

### `AssertResponseMetadataNotRedirect`

AssertResponseMetadataNotRedirect returns RedirectRefusedError for every
response shape the reference implementation treats as a server-side OAuth SSRF boundary.

```go
func AssertResponseMetadataNotRedirect(endpoint string, response ResponseMetadata) error
```

### `AssertResponseNotRedirect`

AssertResponseNotRedirect applies redirect protection to net/http responses.

```go
func AssertResponseNotRedirect(endpoint string, response *http.Response) error
```

### `CreateAuthorizationURL`

CreateAuthorizationURL produces the reference implementation's ordered OAuth authorization
query, including PKCE and OIDC claims.

```go
func CreateAuthorizationURL(options AuthorizationURLOptions) (*url.URL, error)
```

### `DoForm`

DoForm posts a form, refuses redirects and decodes a JSON object response.

```go
func DoForm(ctx context.Context, client *http.Client, endpoint string, request FormRequest) (map[string]any, error)
```

### `DoRefusingRedirects`

DoRefusingRedirects executes one HTTP request and never follows a redirect.
The response body is closed before a redirect error is returned.

```go
func DoRefusingRedirects(client *http.Client, request *http.Request) (*http.Response, error)
```

### `GenerateCodeChallenge`

GenerateCodeChallenge returns an RFC 7636 S256 challenge.

```go
func GenerateCodeChallenge(verifier string) string
```

### `PrimaryClientID`

PrimaryClientID mirrors the reference implementation's string-or-array clientId behavioral compatibility.

```go
func PrimaryClientID(value any) (string, bool)
```

### `RefuseRedirects`

RefuseRedirects clones or creates a client whose redirect policy returns the
first redirect response without connecting to its target.

```go
func RefuseRedirects(client *http.Client) *http.Client
```

## Types

### `Authentication`

Authentication controls OAuth client authentication placement.

```go
type Authentication string
```

## Constants associated with `Authentication`

```go
const (
	AuthenticationPost  Authentication = "post"
	AuthenticationBasic Authentication = "basic"
)
```

### `AuthorizationCodeRequestOptions`

AuthorizationCodeRequestOptions controls CreateAuthorizationCodeRequest.

```go
type AuthorizationCodeRequestOptions struct {
	Code             string
	CodeVerifier     string
	RedirectURI      string
	Options          ProviderOptions
	Authentication   Authentication
	DeviceID         string
	Headers          map[string]string
	AdditionalParams []Param
	Resources        []string
}
```

### `AuthorizationURLOptions`

AuthorizationURLOptions controls CreateAuthorizationURL.

```go
type AuthorizationURLOptions struct {
	ID                    string
	Options               ProviderOptions
	AuthorizationEndpoint string
	RedirectURI           string
	State                 string
	CodeVerifier          string
	Scopes                []string
	Claims                []string
	Duration              string
	Prompt                string
	AccessType            string
	ResponseType          string
	Display               string
	LoginHint             string
	HostedDomain          string
	ResponseMode          string
	AdditionalParams      []Param
	ScopeJoiner           string
}
```

### `ClientCredentialsRequestOptions`

ClientCredentialsRequestOptions controls CreateClientCredentialsTokenRequest.

```go
type ClientCredentialsRequestOptions struct {
	Options        ProviderOptions
	Scope          string
	Authentication Authentication
	Resources      []string
}
```

### `Form`

Form mirrors URLSearchParams ordering, Set, Append, Has and Get semantics.

```go
type Form struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Form`

### `NewForm`

NewForm creates an empty ordered form.

```go
func NewForm() *Form
```

## Methods on `Form`

### `Append`

Append appends even when the name already exists.

```go
func (f *Form) Append(name, value string)
```

### `Encode`

Encode follows the WHATWG URLSearchParams form encoding set.

```go
func (f *Form) Encode() string
```

### `Get`

Get returns the first value.

```go
func (f *Form) Get(name string) (string, bool)
```

### `Has`

Has reports whether a name exists.

```go
func (f *Form) Has(name string) bool
```

### `Params`

Params returns a defensive copy.

```go
func (f *Form) Params() []Param
```

### `Set`

Set replaces the first value, removes later duplicates, or appends.

```go
func (f *Form) Set(name, value string)
```

### `Values`

Values returns every value in insertion order.

```go
func (f *Form) Values(name string) []string
```

### `FormRequest`

FormRequest is an OAuth form body and its request headers.

```go
type FormRequest struct {
	Body    *Form
	Headers map[string]string
}
```

## Constructors and functions for `FormRequest`

### `CreateAuthorizationCodeRequest`

CreateAuthorizationCodeRequest builds the authorization_code exchange.

```go
func CreateAuthorizationCodeRequest(options AuthorizationCodeRequestOptions) FormRequest
```

### `CreateClientCredentialsTokenRequest`

CreateClientCredentialsTokenRequest builds a client_credentials request.

```go
func CreateClientCredentialsTokenRequest(options ClientCredentialsRequestOptions) FormRequest
```

### `CreateRefreshAccessTokenRequest`

CreateRefreshAccessTokenRequest builds a refresh_token request.

```go
func CreateRefreshAccessTokenRequest(options RefreshTokenRequestOptions) FormRequest
```

### `JWKSet`

JWKSet is the JSON envelope returned by an OAuth/OIDC JWKS endpoint.

```go
type JWKSet struct {
	Keys []map[string]any `json:"keys"`
}
```

## Constructors and functions for `JWKSet`

### `FetchJWKSet`

FetchJWKSet retrieves a remote JWKS without allowing the endpoint to redirect
the server-side request to another host.

```go
func FetchJWKSet(ctx context.Context, client *http.Client, endpoint string) (JWKSet, error)
```

### `Param`

Param is one ordered application/x-www-form-urlencoded entry.

```go
type Param struct {
	Name  string
	Value string
}
```

### `ProviderOptions`

ProviderOptions is the runtime-neutral subset shared by provider factories.

```go
type ProviderOptions struct {
	ClientID              any
	ClientSecret          string
	ClientKey             string
	Scopes                []string
	DisableDefaultScope   bool
	RedirectURI           string
	AuthorizationEndpoint string
	DisableIDTokenSignIn  bool
	DisableImplicitSignUp bool
	DisableSignUp         bool
	Prompt                string
	ResponseMode          string
	OverrideUserInfo      bool
}
```

### `RedirectRefusedError`

RedirectRefusedError is the Go equivalent of ReferenceError emitted when a
server-side OAuth endpoint attempts an HTTP redirect.

```go
type RedirectRefusedError struct {
	Endpoint string
}
```

## Methods on `RedirectRefusedError`

### `Error`

```go
func (err *RedirectRefusedError) Error() string
```

### `Unwrap`

```go
func (err *RedirectRefusedError) Unwrap() error
```

### `RefreshAccessTokenOptions`

RefreshAccessTokenOptions controls RefreshAccessToken.

```go
type RefreshAccessTokenOptions struct {
	RefreshToken   string
	Options        ProviderOptions
	TokenEndpoint  string
	Authentication Authentication
	ExtraParams    []Param
	Resources      []string
	Client         *http.Client
}
```

### `RefreshTokenRequestOptions`

RefreshTokenRequestOptions controls CreateRefreshAccessTokenRequest.

```go
type RefreshTokenRequestOptions struct {
	RefreshToken   string
	Options        ProviderOptions
	Authentication Authentication
	ExtraParams    []Param
	Resources      []string
}
```

### `ResponseMetadata`

ResponseMetadata is the runtime-neutral subset used to recognize redirects.
Type is relevant to fetch-compatible transports, which expose manual browser
redirects as "opaqueredirect" with status zero.

```go
type ResponseMetadata struct {
	Status int    `json:"status"`
	Type   string `json:"type"`
}
```

### `Tokens`

Tokens is the reference implementation's normalized OAuth2 token response.

```go
type Tokens struct {
	TokenType             string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scopes                []string
	IDToken               string
	Raw                   map[string]any
}
```

## Constructors and functions for `Tokens`

### `ApplyDefaultAccessTokenExpiry`

ApplyDefaultAccessTokenExpiry fills a missing provider expiry.

```go
func ApplyDefaultAccessTokenExpiry(tokens Tokens, expiresIn time.Duration, now time.Time) Tokens
```

### `NormalizeTokens`

NormalizeTokens maps provider JSON fields to the reference implementation tokens.

```go
func NormalizeTokens(data map[string]any, now time.Time) Tokens
```

### `RefreshAccessToken`

RefreshAccessToken exchanges a refresh token without following redirects and
returns the normalized token object used by the reference implementation's core OAuth helper.

```go
func RefreshAccessToken(ctx context.Context, options RefreshAccessTokenOptions) (Tokens, error)
```

### `UserInfo`

UserInfo is the normalized social-provider identity.

```go
type UserInfo struct {
	ID            string
	Name          string
	Email         *string
	Image         string
	EmailVerified bool
	Extra         map[string]any
}
```

### `ValidateTokenOptions`

ValidateTokenOptions constrains the audience and issuer claims accepted by
ValidateToken. An empty slice leaves the corresponding claim unconstrained;
one or more values use any-match semantics like jose jwtVerify.

```go
type ValidateTokenOptions struct {
	Audience []string
	Issuer   []string
}
```

### `VerifiedToken`

VerifiedToken is the protected header and payload returned after signature
and claim validation.

```go
type VerifiedToken struct {
	ProtectedHeader map[string]any
	Payload         map[string]any
}
```

## Constructors and functions for `VerifiedToken`

### `ValidateToken`

ValidateToken fetches a remote JWK set without following redirects and
verifies a compact JWT against its matching key. RS256, ES256, and EdDSA
(Ed25519) match the reference implementation's validateToken test surface.

```go
func ValidateToken(
	ctx context.Context,
	client *http.Client,
	token string,
	jwksEndpoint string,
	options ValidateTokenOptions,
) (VerifiedToken, error)
```

