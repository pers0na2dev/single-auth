package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
)

// Authentication controls OAuth client authentication placement.
type Authentication string

const (
	AuthenticationPost  Authentication = "post"
	AuthenticationBasic Authentication = "basic"
)

// FormRequest is an OAuth form body and its request headers.
type FormRequest struct {
	Body    *Form
	Headers map[string]string
}

// AuthorizationURLOptions controls CreateAuthorizationURL.
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

// CreateAuthorizationURL produces the reference implementation's ordered OAuth authorization
// query, including PKCE and OIDC claims.
func CreateAuthorizationURL(options AuthorizationURLOptions) (*url.URL, error) {
	endpoint := options.AuthorizationEndpoint
	if options.Options.AuthorizationEndpoint != "" {
		endpoint = options.Options.AuthorizationEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	query := parseExistingQuery(parsed.RawQuery)
	responseType := options.ResponseType
	if responseType == "" {
		responseType = "code"
	}
	query.Set("response_type", responseType)
	query.Set("client_id", jsString(options.Options.ClientID))
	query.Set("state", options.State)
	if options.Scopes != nil {
		joiner := options.ScopeJoiner
		if joiner == "" {
			joiner = " "
		}
		query.Set("scope", strings.Join(options.Scopes, joiner))
	}
	redirectURI := options.RedirectURI
	if options.Options.RedirectURI != "" {
		redirectURI = options.Options.RedirectURI
	}
	query.Set("redirect_uri", redirectURI)
	setIfNotEmpty(query, "duration", options.Duration)
	setIfNotEmpty(query, "display", options.Display)
	setIfNotEmpty(query, "login_hint", options.LoginHint)
	setIfNotEmpty(query, "prompt", options.Prompt)
	setIfNotEmpty(query, "hd", options.HostedDomain)
	setIfNotEmpty(query, "access_type", options.AccessType)
	setIfNotEmpty(query, "response_mode", options.ResponseMode)
	if options.CodeVerifier != "" {
		query.Set("code_challenge_method", "S256")
		query.Set("code_challenge", GenerateCodeChallenge(options.CodeVerifier))
	}
	if options.Claims != nil {
		query.Set("claims", claimsJSON(options.Claims))
	}
	for _, param := range options.AdditionalParams {
		query.Set(param.Name, param.Value)
	}
	parsed.RawQuery = query.Encode()
	return parsed, nil
}

// AuthorizationCodeRequestOptions controls CreateAuthorizationCodeRequest.
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

// CreateAuthorizationCodeRequest builds the authorization_code exchange.
func CreateAuthorizationCodeRequest(options AuthorizationCodeRequestOptions) FormRequest {
	body := NewForm()
	body.Set("grant_type", "authorization_code")
	body.Set("code", options.Code)
	setIfNotEmpty(body, "code_verifier", options.CodeVerifier)
	setIfNotEmpty(body, "client_key", options.Options.ClientKey)
	setIfNotEmpty(body, "device_id", options.DeviceID)
	redirectURI := options.RedirectURI
	if options.Options.RedirectURI != "" {
		redirectURI = options.Options.RedirectURI
	}
	body.Set("redirect_uri", redirectURI)
	for _, resource := range options.Resources {
		body.Append("resource", resource)
	}
	headers := baseHeaders(options.Headers)
	primary := jsString(options.Options.ClientID)
	if options.Authentication == AuthenticationBasic {
		headers["authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(primary+":"+options.Options.ClientSecret))
	} else {
		body.Set("client_id", primary)
		if options.Options.ClientSecret != "" {
			body.Set("client_secret", options.Options.ClientSecret)
		}
	}
	for _, param := range options.AdditionalParams {
		if !body.Has(param.Name) {
			body.Append(param.Name, param.Value)
		}
	}
	return FormRequest{Body: body, Headers: headers}
}

// RefreshTokenRequestOptions controls CreateRefreshAccessTokenRequest.
type RefreshTokenRequestOptions struct {
	RefreshToken   string
	Options        ProviderOptions
	Authentication Authentication
	ExtraParams    []Param
	Resources      []string
}

// CreateRefreshAccessTokenRequest builds a refresh_token request.
func CreateRefreshAccessTokenRequest(options RefreshTokenRequestOptions) FormRequest {
	body := NewForm()
	body.Set("grant_type", "refresh_token")
	body.Set("refresh_token", options.RefreshToken)
	headers := baseHeaders(nil)
	primary, hasPrimary := PrimaryClientID(options.Options.ClientID)
	if options.Authentication == AuthenticationBasic {
		if !hasPrimary {
			primary = ""
		}
		headers["authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(primary+":"+options.Options.ClientSecret))
	} else {
		body.Set("client_id", jsString(options.Options.ClientID))
		if options.Options.ClientSecret != "" {
			body.Set("client_secret", options.Options.ClientSecret)
		}
	}
	for _, resource := range options.Resources {
		body.Append("resource", resource)
	}
	for _, param := range options.ExtraParams {
		body.Set(param.Name, param.Value)
	}
	return FormRequest{Body: body, Headers: headers}
}

// ClientCredentialsRequestOptions controls CreateClientCredentialsTokenRequest.
type ClientCredentialsRequestOptions struct {
	Options        ProviderOptions
	Scope          string
	Authentication Authentication
	Resources      []string
}

// CreateClientCredentialsTokenRequest builds a client_credentials request.
func CreateClientCredentialsTokenRequest(options ClientCredentialsRequestOptions) FormRequest {
	body := NewForm()
	body.Set("grant_type", "client_credentials")
	setIfNotEmpty(body, "scope", options.Scope)
	for _, resource := range options.Resources {
		body.Append("resource", resource)
	}
	headers := baseHeaders(nil)
	primary := jsString(options.Options.ClientID)
	if options.Authentication == AuthenticationBasic {
		// the reference implementation 1.6.26 uses padded base64url in this helper.
		headers["authorization"] = "Basic " + base64.URLEncoding.EncodeToString([]byte(primary+":"+options.Options.ClientSecret))
	} else {
		body.Set("client_id", primary)
		body.Set("client_secret", options.Options.ClientSecret)
	}
	return FormRequest{Body: body, Headers: headers}
}

// GenerateCodeChallenge returns an RFC 7636 S256 challenge.
func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func baseHeaders(extra map[string]string) map[string]string {
	headers := map[string]string{
		"content-type": "application/x-www-form-urlencoded",
		"accept":       "application/json",
	}
	for key, value := range extra {
		headers[key] = value
	}
	return headers
}

func setIfNotEmpty(form *Form, name, value string) {
	if value != "" {
		form.Set(name, value)
	}
}

func claimsJSON(claims []string) string {
	var builder strings.Builder
	builder.WriteString(`{"id_token":{"email":null,"email_verified":null`)
	for _, claim := range claims {
		builder.WriteByte(',')
		builder.WriteString(strconvQuote(claim))
		builder.WriteString(":null")
	}
	builder.WriteString("}}")
	return builder.String()
}

func strconvQuote(value string) string {
	// URL/OIDC claim names are normally ASCII; JSON marshaling here also keeps
	// escaping correct for custom names.
	encoded, _ := jsonMarshalString(value)
	return encoded
}

func jsonMarshalString(value string) (string, error) {
	var builder strings.Builder
	builder.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\', '"':
			builder.WriteByte('\\')
			builder.WriteRune(r)
		case '\b':
			builder.WriteString(`\b`)
		case '\f':
			builder.WriteString(`\f`)
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case '\t':
			builder.WriteString(`\t`)
		default:
			if r < 0x20 {
				return "", errors.New("control character in claim name")
			}
			builder.WriteRune(r)
		}
	}
	builder.WriteByte('"')
	return builder.String(), nil
}

func parseExistingQuery(raw string) *Form {
	form := NewForm()
	if raw == "" {
		return form
	}
	for _, pair := range strings.Split(raw, "&") {
		name, value, _ := strings.Cut(pair, "=")
		decodedName, err := url.QueryUnescape(name)
		if err != nil {
			decodedName = name
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			decodedValue = value
		}
		form.Append(decodedName, decodedValue)
	}
	return form
}
