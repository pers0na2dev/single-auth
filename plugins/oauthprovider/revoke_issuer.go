package oauthprovider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	jwtplugin "github.com/pers0na2dev/single-auth/plugins/jwt"
	"github.com/pers0na2dev/single-auth/storage"
)

const RevokeIssuerTokenPath = "/oauth2/token"

// RevokeIssuerOptions enables the production token endpoint used with the
// revocation service. It deliberately shares storage, hashing, prefixes, and
// JWT/JWKS options with RevokeService so an issued token is always consumable
// by oauth2Revoke without test-only glue.
type RevokeIssuerOptions struct {
	Random                        io.Reader
	AccessTokenExpiresIn          time.Duration
	M2MAccessTokenExpiresIn       time.Duration
	IDTokenExpiresIn              time.Duration
	RefreshTokenExpiresIn         time.Duration
	AuthorizationCodeExpiresIn    time.Duration
	ValidAudiences                []string
	ServerScopes                  []string
	ClientCredentialDefaultScopes []string
	GenerateOpaqueAccessToken     func() string
	GenerateRefreshToken          func() string
	SignJWT                       func(*engine.Context, map[string]any) (string, error)
	SignIDToken                   func(*engine.Context, storage.Record, storage.Record, []string, string, string, time.Time) (string, error)
	ResolveSubject                func(context.Context, string, storage.Record) (string, error)
	CustomAccessTokenClaims       CustomAccessTokenClaimsFunc
	CustomIDTokenClaims           CustomIDTokenClaimsFunc
}

// RevokeAuthorizationGrant is the trusted server-side result of a completed
// authorization request. CreateAuthorizationCode persists it as a single-use
// verification record consumed by the production /oauth2/token endpoint.
type RevokeAuthorizationGrant struct {
	ClientID            string
	UserID              string
	SessionID           string
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	ReferenceID         string
	AuthTime            time.Time
}

type revokeAuthorizationGrantRecord struct {
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	SessionID           string    `json:"session_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scopes              []string  `json:"scopes"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	Nonce               string    `json:"nonce,omitempty"`
	ReferenceID         string    `json:"reference_id,omitempty"`
	AuthTime            time.Time `json:"auth_time,omitempty"`
}

type RevokeIssuer struct {
	service                       *RevokeService
	random                        io.Reader
	accessTokenExpiresIn          time.Duration
	m2mAccessTokenExpiresIn       time.Duration
	idTokenExpiresIn              time.Duration
	refreshTokenExpiresIn         time.Duration
	authorizationCodeExpiresIn    time.Duration
	validAudiences                map[string]struct{}
	serverScopes                  []string
	clientCredentialDefaultScopes []string
	generateOpaqueAccessToken     func() string
	generateRefreshToken          func() string
	signJWT                       func(*engine.Context, map[string]any) (string, error)
	signIDToken                   func(*engine.Context, storage.Record, storage.Record, []string, string, string, time.Time) (string, error)
	resolveSubject                func(context.Context, string, storage.Record) (string, error)
	customAccessTokenClaims       CustomAccessTokenClaimsFunc
	customIDTokenClaims           CustomIDTokenClaimsFunc
}

type revokeTokenInput struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	Resource     string `json:"resource"`
}

type revokeIssuedTokens struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`
}

func newRevokeIssuer(service *RevokeService, input RevokeIssuerOptions) (*RevokeIssuer, error) {
	if service == nil {
		return nil, errors.New("oauthprovider: revoke issuer requires a service")
	}
	random := input.Random
	if random == nil {
		random = rand.Reader
	}
	accessExpiry := input.AccessTokenExpiresIn
	if accessExpiry == 0 {
		accessExpiry = time.Hour
	}
	m2mExpiry := input.M2MAccessTokenExpiresIn
	if m2mExpiry == 0 {
		m2mExpiry = time.Hour
	}
	idTokenExpiry := input.IDTokenExpiresIn
	if idTokenExpiry == 0 {
		idTokenExpiry = 10 * time.Hour
	}
	refreshExpiry := input.RefreshTokenExpiresIn
	if refreshExpiry == 0 {
		refreshExpiry = 30 * 24 * time.Hour
	}
	codeExpiry := input.AuthorizationCodeExpiresIn
	if codeExpiry == 0 {
		codeExpiry = 5 * time.Minute
	}
	if accessExpiry < 0 || m2mExpiry < 0 || idTokenExpiry < 0 || refreshExpiry < 0 || codeExpiry < 0 {
		return nil, errors.New("oauthprovider: revoke issuer token expirations must be positive")
	}
	audiences := make(map[string]struct{}, len(input.ValidAudiences))
	for _, audience := range input.ValidAudiences {
		if audience != "" {
			audiences[audience] = struct{}{}
		}
	}
	return &RevokeIssuer{
		service: service, random: random,
		accessTokenExpiresIn: accessExpiry, m2mAccessTokenExpiresIn: m2mExpiry,
		idTokenExpiresIn: idTokenExpiry, refreshTokenExpiresIn: refreshExpiry,
		authorizationCodeExpiresIn: codeExpiry, validAudiences: audiences,
		serverScopes:                  append([]string(nil), input.ServerScopes...),
		clientCredentialDefaultScopes: append([]string(nil), input.ClientCredentialDefaultScopes...),
		generateOpaqueAccessToken:     input.GenerateOpaqueAccessToken,
		generateRefreshToken:          input.GenerateRefreshToken,
		signJWT:                       input.SignJWT, signIDToken: input.SignIDToken,
		resolveSubject:          input.ResolveSubject,
		customAccessTokenClaims: input.CustomAccessTokenClaims,
		customIDTokenClaims:     input.CustomIDTokenClaims,
	}, nil
}

func (issuer *RevokeIssuer) endpoint() engine.Endpoint {
	return engine.Endpoint{
		Name: "oauth2Token", Path: RevokeIssuerTokenPath,
		Methods: []string{http.MethodPost}, OperationID: "oauth2Token",
		Handler: issuer.tokenEndpoint,
		Metadata: map[string]any{
			"allowedMediaTypes": []string{"application/x-www-form-urlencoded"},
			"openapi":           map[string]any{"description": "OAuth2 token endpoint"},
		},
	}
}

// CreateAuthorizationCode stores a random, hashed, single-use code for the
// authorization_code grant. This is the trusted binding an authorize endpoint
// calls after user/session/consent checks have completed.
func (service *RevokeService) CreateAuthorizationCode(
	ctx context.Context,
	input RevokeAuthorizationGrant,
) (string, error) {
	if service == nil || service.issuer == nil {
		return "", errors.New("oauthprovider: revoke token issuer is not configured")
	}
	return service.issuer.createAuthorizationCode(ctx, input)
}

func (issuer *RevokeIssuer) createAuthorizationCode(
	ctx context.Context,
	input RevokeAuthorizationGrant,
) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if input.ClientID == "" || input.UserID == "" || input.SessionID == "" ||
		input.RedirectURI == "" || len(input.Scopes) == 0 {
		return "", errors.New("oauthprovider: authorization grant is incomplete")
	}
	return issuer.createAuthorizationCodeWithAdapter(ctx, issuer.service.adapter(ctx), input)
}

func (issuer *RevokeIssuer) createAuthorizationCodeWithAdapter(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	input RevokeAuthorizationGrant,
) (string, error) {
	code, err := issuer.randomToken()
	if err != nil {
		return "", err
	}
	identifier, err := issuer.service.options.Runtime.StoredToken(
		ctx, code, RevokeAuthorizationCode,
	)
	if err != nil {
		return "", err
	}
	value, err := json.Marshal(revokeAuthorizationGrantRecord{
		ClientID: input.ClientID, UserID: input.UserID, SessionID: input.SessionID,
		RedirectURI: input.RedirectURI, Scopes: append([]string(nil), input.Scopes...),
		CodeChallenge: input.CodeChallenge, CodeChallengeMethod: input.CodeChallengeMethod,
		Nonce: input.Nonce, ReferenceID: input.ReferenceID, AuthTime: input.AuthTime,
	})
	if err != nil {
		return "", err
	}
	now := issuer.service.options.Runtime.Clock()
	_, err = adapter.Create(ctx, storage.CreateParams{
		Model: "verification",
		Data: storage.Record{
			"identifier": identifier,
			"value":      string(value),
			"expiresAt":  now.Add(issuer.authorizationCodeExpiresIn),
		},
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

func (issuer *RevokeIssuer) tokenEndpoint(ctx *engine.Context) (contract.Response, error) {
	input, err := decodeRevokeTokenInput(ctx.Request())
	if err != nil {
		return revokeErrorResponse(revokeProtocolError(
			contract.StatusBadRequest, "invalid_request", "Invalid request body",
		))
	}
	if authorization, _ := ctx.Request().Headers().Get("Authorization"); strings.HasPrefix(authorization, "Basic ") {
		credentials, parseErr := BasicToClientCredentials(authorization)
		if parseErr != nil {
			return revokeErrorResponse(revokeProtocolError(
				contract.StatusBadRequest,
				"invalid_client",
				"invalid authorization header format",
			))
		}
		if credentials != nil {
			input.ClientID = credentials.ClientID
			input.ClientSecret = credentials.ClientSecret
		}
	}

	var issued revokeIssuedTokens
	switch input.GrantType {
	case "client_credentials":
		issued, err = issuer.clientCredentials(ctx, input)
	case "authorization_code":
		issued, err = issuer.authorizationCode(ctx, input)
	case "refresh_token":
		issued, err = issuer.refreshToken(ctx, input)
	default:
		err = revokeProtocolError(
			contract.StatusBadRequest, "unsupported_grant_type", "unsupported grant type",
		)
	}
	if err != nil {
		if _, protocol := contract.AsAPIError(err); protocol {
			return revokeErrorResponse(err)
		}
		return revokeInternalError(err)
	}
	response, err := contract.JSONResponse(contract.StatusOK, issued)
	if err != nil {
		return revokeInternalError(err)
	}
	return response.WithHeader("Cache-Control", "no-store").WithHeader("Pragma", "no-cache"), nil
}

func (issuer *RevokeIssuer) clientCredentials(
	ctx *engine.Context,
	input revokeTokenInput,
) (revokeIssuedTokens, error) {
	if input.ClientID == "" {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_grant", "Missing required client_id",
		)
	}
	if input.ClientSecret == "" {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_grant", "Missing a required client_secret",
		)
	}
	client, err := issuer.service.validateClient(ctx.GoContext(), input.ClientID, input.ClientSecret)
	if err != nil {
		return revokeIssuedTokens{}, err
	}
	if !revokeClientAllowsGrant(client, "client_credentials") {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest,
			"unauthorized_client",
			"client is not authorized to use grant type client_credentials",
		)
	}
	scopes := splitRevokeScopes(input.Scope)
	allowedScopes := revokeRecordStrings(client, "scopes")
	_, clientScopesConfigured := client["scopes"]
	if !clientScopesConfigured || client["scopes"] == nil {
		allowedScopes = append([]string(nil), issuer.serverScopes...)
	}
	if len(scopes) == 0 {
		if !clientScopesConfigured && issuer.clientCredentialDefaultScopes != nil {
			scopes = append([]string(nil), issuer.clientCredentialDefaultScopes...)
		} else {
			scopes = append([]string(nil), allowedScopes...)
		}
	}
	if !serverSubset(scopes, allowedScopes) {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_scope", "The requested scopes are invalid",
		)
	}
	for _, scope := range scopes {
		switch scope {
		case "openid", "profile", "email", "offline_access":
			return revokeIssuedTokens{}, revokeProtocolError(
				contract.StatusBadRequest,
				"invalid_scope",
				"The following scopes are invalid: "+scope,
			)
		}
	}
	return issuer.issueDetailed(ctx, client, nil, "", scopes, input.Resource, "", "", time.Time{}, nil)
}

func (issuer *RevokeIssuer) authorizationCode(
	ctx *engine.Context,
	input revokeTokenInput,
) (revokeIssuedTokens, error) {
	if input.ClientID == "" || input.Code == "" || input.RedirectURI == "" {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_request", "authorization code request is incomplete",
		)
	}
	identifier, err := issuer.service.options.Runtime.StoredToken(
		ctx.GoContext(), input.Code, RevokeAuthorizationCode,
	)
	if err != nil {
		return revokeIssuedTokens{}, err
	}
	verification, err := issuer.service.adapter(ctx.GoContext()).ConsumeOne(
		ctx.GoContext(), storage.ConsumeOneParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
		},
	)
	if err != nil {
		return revokeIssuedTokens{}, err
	}
	if verification == nil {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusUnauthorized, "invalid_grant", "invalid code",
		)
	}
	expiresAt, ok := revokeTimeValue(verification["expiresAt"])
	if !ok || expiresAt.Before(issuer.service.options.Runtime.Clock()) {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusUnauthorized, "invalid_grant", "invalid code",
		)
	}
	var grant revokeAuthorizationGrantRecord
	value, _ := verification["value"].(string)
	if json.Unmarshal([]byte(value), &grant) != nil {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusUnauthorized, "invalid_grant", "malformed verification value",
		)
	}
	if grant.ClientID != input.ClientID {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusUnauthorized, "invalid_client", "invalid client_id",
		)
	}
	if grant.RedirectURI != input.RedirectURI {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_request", "redirect_uri mismatch",
		)
	}
	client, err := issuer.service.validateClient(ctx.GoContext(), input.ClientID, input.ClientSecret)
	if err != nil {
		return revokeIssuedTokens{}, err
	}
	if !revokeClientAllowsGrant(client, "authorization_code") {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest,
			"unauthorized_client",
			"client is not authorized to use grant type authorization_code",
		)
	}
	publicClient := revokeRecordBool(client, "public") ||
		revokeRecordString(client, "tokenEndpointAuthMethod") == string(TokenEndpointAuthMethodNone)
	requirePKCE := publicClient
	if configured, exists := client["requirePKCE"].(bool); exists {
		requirePKCE = requirePKCE || configured
	}
	if requirePKCE && input.CodeVerifier == "" {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_request", "PKCE is required for this client",
		)
	}
	pkceInAuthorization := grant.CodeChallenge != ""
	pkceInToken := input.CodeVerifier != ""
	if pkceInAuthorization != pkceInToken {
		description := "code_verifier provided but PKCE was not used in authorization"
		if pkceInAuthorization {
			description = "code_verifier required because PKCE was used in authorization"
		}
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusUnauthorized, "invalid_request", description,
		)
	}
	if pkceInAuthorization {
		if grant.CodeChallengeMethod != "S256" || serverPKCEChallenge(input.CodeVerifier) != grant.CodeChallenge {
			return revokeIssuedTokens{}, revokeProtocolError(
				contract.StatusUnauthorized, "invalid_request", "code verification failed",
			)
		}
	}
	user, err := issuer.service.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: grant.UserID}},
	})
	if err != nil {
		return revokeIssuedTokens{}, err
	}
	if user == nil {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_user", "missing user, user may have been deleted",
		)
	}
	session, err := issuer.service.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "id", Value: grant.SessionID}},
	})
	if err != nil {
		return revokeIssuedTokens{}, err
	}
	sessionExpires, validSession := revokeTimeValue(session["expiresAt"])
	if session == nil || !validSession || sessionExpires.Before(issuer.service.options.Runtime.Clock()) {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_request", "session no longer exists",
		)
	}
	authTime := grant.AuthTime
	if authTime.IsZero() {
		authTime, _ = revokeTimeValue(session["createdAt"])
	}
	return issuer.issueDetailed(ctx, client, user, grant.SessionID, grant.Scopes, input.Resource, grant.ReferenceID, grant.Nonce, authTime, nil)
}

func (issuer *RevokeIssuer) refreshToken(
	ctx *engine.Context,
	input revokeTokenInput,
) (revokeIssuedTokens, error) {
	if input.ClientID == "" {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_grant", "Missing required client_id",
		)
	}
	if input.RefreshToken == "" {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_grant", "Missing a required refresh_token for refresh_token grant",
		)
	}
	raw := input.RefreshToken
	if prefix := issuer.service.options.RefreshTokenPrefix; prefix != "" {
		if !strings.HasPrefix(raw, prefix) {
			return revokeIssuedTokens{}, revokeProtocolError(
				contract.StatusBadRequest, "invalid_token", "refresh token not found",
			)
		}
		raw = strings.TrimPrefix(raw, prefix)
	}
	decoded, err := issuer.service.options.Runtime.DecodeRefreshToken(ctx.GoContext(), raw)
	if err != nil {
		return revokeIssuedTokens{}, err
	}
	stored, err := issuer.service.options.Runtime.StoredToken(ctx.GoContext(), decoded, RevokeRefreshToken)
	if err != nil {
		return revokeIssuedTokens{}, err
	}
	refresh, err := issuer.service.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "oauthRefreshToken", Where: []storage.Where{{Field: "token", Value: stored}},
	})
	if err != nil {
		return revokeIssuedTokens{}, err
	}
	if refresh == nil {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_grant", "session not found",
		)
	}
	if revokeRecordString(refresh, "clientId") != input.ClientID {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_client", "invalid client_id",
		)
	}
	expiresAt, validExpiry := revokeTimeValue(refresh["expiresAt"])
	if !validExpiry || !expiresAt.After(issuer.service.options.Runtime.Clock()) {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_grant", "invalid refresh token",
		)
	}
	if refresh["revoked"] != nil {
		if err := issuer.service.invalidateRefreshFamily(ctx.GoContext(), input.ClientID, revokeRecordString(refresh, "userId")); err != nil {
			return revokeIssuedTokens{}, err
		}
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_grant", "invalid refresh token",
		)
	}
	grantedScopes := revokeRecordStrings(refresh, "scopes")
	requestedScopes := splitRevokeScopes(input.Scope)
	if len(requestedScopes) == 0 {
		requestedScopes = grantedScopes
	}
	if !serverSubset(requestedScopes, grantedScopes) {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_scope", "unable to issue requested scope",
		)
	}
	client, err := issuer.service.validateClient(ctx.GoContext(), input.ClientID, input.ClientSecret)
	if err != nil {
		return revokeIssuedTokens{}, err
	}
	if !revokeClientAllowsGrant(client, "refresh_token") {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "unauthorized_client", "client is not authorized to use grant type refresh_token",
		)
	}
	user, err := issuer.service.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: revokeRecordString(refresh, "userId")}},
	})
	if err != nil {
		return revokeIssuedTokens{}, err
	}
	if user == nil {
		return revokeIssuedTokens{}, revokeProtocolError(
			contract.StatusBadRequest, "invalid_request", "user not found",
		)
	}
	authTime, _ := revokeTimeValue(refresh["authTime"])
	return issuer.issueDetailed(
		ctx, client, user, revokeRecordString(refresh, "sessionId"), requestedScopes,
		input.Resource, revokeRecordString(refresh, "referenceId"), "", authTime, refresh,
	)
}

func (issuer *RevokeIssuer) issueDetailed(
	ctx *engine.Context,
	client storage.Record,
	user storage.Record,
	sessionID string,
	scopes []string,
	resource, referenceID, nonce string,
	authTime time.Time,
	originalRefresh storage.Record,
) (revokeIssuedTokens, error) {
	if resource != "" && len(issuer.validAudiences) > 0 {
		if _, valid := issuer.validAudiences[resource]; !valid {
			return revokeIssuedTokens{}, revokeProtocolError(
				contract.StatusBadRequest, "invalid_target", "invalid resource audience",
			)
		}
	}
	now := issuer.service.options.Runtime.Clock()
	clientID := revokeRecordString(client, "clientId")
	userID := revokeRecordString(user, "id")
	accessLifetime := issuer.accessTokenExpiresIn
	if user == nil {
		accessLifetime = issuer.m2mAccessTokenExpiresIn
	}
	expiresAt := now.Add(accessLifetime)
	if originalRefresh != nil {
		refreshID := originalRefresh["id"]
		if refreshID == nil {
			return revokeIssuedTokens{}, errors.New("oauthprovider: stored refresh token has no id")
		}
		won, err := issuer.service.adapter(ctx.GoContext()).IncrementOne(ctx.GoContext(), storage.IncrementOneParams{
			Model:     "oauthRefreshToken",
			Where:     []storage.Where{{Field: "id", Value: refreshID}, {Field: "revoked", Operator: storage.OpEq, Value: nil}},
			Increment: map[string]float64{}, Set: storage.Record{"revoked": now},
		})
		if err != nil {
			return revokeIssuedTokens{}, err
		}
		if won == nil {
			return revokeIssuedTokens{}, revokeProtocolError(
				contract.StatusBadRequest, "invalid_grant", "invalid refresh token",
			)
		}
	}
	var refreshID any
	refreshPresentation := ""
	if userID != "" && containsRevokeScope(scopes, "offline_access") && revokeClientAllowsGrant(client, "refresh_token") {
		rawRefresh := ""
		if issuer.generateRefreshToken != nil {
			rawRefresh = issuer.generateRefreshToken()
		}
		var err error
		if rawRefresh == "" {
			rawRefresh, err = issuer.randomToken()
		}
		if err != nil {
			return revokeIssuedTokens{}, err
		}
		storedRefresh, err := issuer.service.options.Runtime.StoredToken(
			ctx.GoContext(), rawRefresh, RevokeRefreshToken,
		)
		if err != nil {
			return revokeIssuedTokens{}, err
		}
		data := storage.Record{
			"token": storedRefresh, "clientId": clientID, "userId": userID,
			"expiresAt": now.Add(issuer.refreshTokenExpiresIn), "createdAt": now,
			"revoked": nil, "scopes": append([]string(nil), scopes...),
		}
		if sessionID != "" {
			data["sessionId"] = sessionID
		}
		if referenceID != "" {
			data["referenceId"] = referenceID
		}
		if !authTime.IsZero() {
			data["authTime"] = authTime
		}
		refresh, err := issuer.service.adapter(ctx.GoContext()).Create(
			ctx.GoContext(), storage.CreateParams{Model: "oauthRefreshToken", Data: data},
		)
		if err != nil {
			return revokeIssuedTokens{}, err
		}
		refreshID = refresh["id"]
		refreshPresentation = issuer.service.options.RefreshTokenPrefix + rawRefresh
	}

	accessPresentation := ""
	if resource != "" && (issuer.signJWT != nil || issuer.service.options.JWT != nil) {
		payload := map[string]any{
			"sub": userID, "client_id": clientID,
			"azp": clientID, "scope": strings.Join(scopes, " "), "aud": resource,
			"iat": now.Unix(), "exp": expiresAt.Unix(),
		}
		if sessionID != "" {
			payload["sid"] = sessionID
		}
		if issuer.customAccessTokenClaims != nil {
			custom, err := issuer.customAccessTokenClaims(ctx.GoContext(), user, append([]string(nil), scopes...), clientRecordToPublicClient(client), resource)
			if err != nil {
				return revokeIssuedTokens{}, err
			}
			for key, value := range custom {
				payload[key] = value
			}
			payload["sub"], payload["client_id"], payload["azp"] = userID, clientID, clientID
			payload["scope"], payload["aud"] = strings.Join(scopes, " "), resource
			payload["iat"], payload["exp"] = now.Unix(), expiresAt.Unix()
		}
		var err error
		if issuer.signJWT != nil {
			accessPresentation, err = issuer.signJWT(ctx, payload)
		} else {
			accessPresentation, err = jwtplugin.SignJWT(ctx, *issuer.service.options.JWT, payload)
		}
		if err != nil {
			return revokeIssuedTokens{}, err
		}
	} else {
		rawAccess := ""
		if issuer.generateOpaqueAccessToken != nil {
			rawAccess = issuer.generateOpaqueAccessToken()
		}
		var err error
		if rawAccess == "" {
			rawAccess, err = issuer.randomToken()
		}
		if err != nil {
			return revokeIssuedTokens{}, err
		}
		storedAccess, err := issuer.service.options.Runtime.StoredToken(
			ctx.GoContext(), rawAccess, RevokeAccessToken,
		)
		if err != nil {
			return revokeIssuedTokens{}, err
		}
		data := storage.Record{
			"token": storedAccess, "clientId": clientID,
			"expiresAt": expiresAt, "createdAt": now,
			"scopes": append([]string(nil), scopes...),
		}
		if userID != "" {
			data["userId"] = userID
		}
		if sessionID != "" {
			data["sessionId"] = sessionID
		}
		if refreshID != nil {
			data["refreshId"] = refreshID
		}
		if referenceID != "" {
			data["referenceId"] = referenceID
		}
		if _, err := issuer.service.adapter(ctx.GoContext()).Create(
			ctx.GoContext(), storage.CreateParams{Model: "oauthAccessToken", Data: data},
		); err != nil {
			return revokeIssuedTokens{}, err
		}
		accessPresentation = issuer.service.options.OpaqueAccessTokenPrefix + rawAccess
	}
	idToken := ""
	if user != nil && containsRevokeScope(scopes, "openid") && issuer.signIDToken != nil {
		var err error
		idToken, err = issuer.signIDToken(ctx, user, client, scopes, nonce, sessionID, authTime)
		if err != nil {
			return revokeIssuedTokens{}, err
		}
	}

	return revokeIssuedTokens{
		AccessToken: accessPresentation, ExpiresIn: int64(accessLifetime.Seconds()),
		ExpiresAt: expiresAt.Unix(), TokenType: "Bearer",
		RefreshToken: refreshPresentation, Scope: strings.Join(scopes, " "), IDToken: idToken,
	}, nil
}

func clientRecordToPublicClient(record storage.Record) Client {
	client := Client{
		ClientID: revokeRecordString(record, "clientId"), Scope: strings.Join(revokeRecordStrings(record, "scopes"), " "),
		ClientName: revokeRecordString(record, "name"), RedirectURIs: revokeRecordStrings(record, "redirectUris"),
		Public: revokeRecordBool(record, "public"), Type: revokeRecordString(record, "type"),
		SubjectType: revokeRecordString(record, "subjectType"), ReferenceID: revokeRecordString(record, "referenceId"),
	}
	for _, grant := range revokeRecordStrings(record, "grantTypes") {
		client.GrantTypes = append(client.GrantTypes, GrantType(grant))
	}
	return client
}

func (issuer *RevokeIssuer) randomToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := io.ReadFull(issuer.random, buffer); err != nil {
		return "", fmt.Errorf("oauthprovider: generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func decodeRevokeTokenInput(request contract.Request) (revokeTokenInput, error) {
	var input revokeTokenInput
	body := request.Body()
	contentType, _ := request.Headers().Get("Content-Type")
	if strings.HasPrefix(strings.ToLower(contentType), "application/json") ||
		strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		if err := json.Unmarshal(body, &input); err != nil {
			return revokeTokenInput{}, err
		}
		return input, nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return revokeTokenInput{}, err
	}
	input.GrantType = values.Get("grant_type")
	input.ClientID = values.Get("client_id")
	input.ClientSecret = values.Get("client_secret")
	input.Code = values.Get("code")
	input.CodeVerifier = values.Get("code_verifier")
	input.RedirectURI = values.Get("redirect_uri")
	input.RefreshToken = values.Get("refresh_token")
	input.Scope = values.Get("scope")
	input.Resource = values.Get("resource")
	return input, nil
}

func revokeClientAllowsGrant(client storage.Record, grant string) bool {
	grants := revokeRecordStrings(client, "grantTypes")
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}
	for _, allowed := range grants {
		if allowed == grant || (grant == "refresh_token" && allowed == "authorization_code") {
			return true
		}
	}
	return false
}

func revokeRecordStrings(record storage.Record, field string) []string {
	if record == nil {
		return nil
	}
	switch values := record[field].(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}

func splitRevokeScopes(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Fields(value)
}

func containsRevokeScope(scopes []string, expected string) bool {
	for _, scope := range scopes {
		if scope == expected {
			return true
		}
	}
	return false
}

func revokeTimeValue(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed, !typed.IsZero()
	case *time.Time:
		if typed != nil {
			return *typed, !typed.IsZero()
		}
	}
	return time.Time{}, false
}
