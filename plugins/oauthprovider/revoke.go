package oauthprovider

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	jwtplugin "github.com/pers0na2dev/single-auth/plugins/jwt"
	"github.com/pers0na2dev/single-auth/storage"
)

const RevokePath = "/oauth2/revoke"

// RevokeTokenType identifies the two token families accepted by RFC 7009.
type RevokeTokenType string

const (
	RevokeAccessToken       RevokeTokenType = "access_token"
	RevokeRefreshToken      RevokeTokenType = "refresh_token"
	RevokeAuthorizationCode RevokeTokenType = "authorization_code"
)

// RevokeJWTDisposition tells the revocation service whether a presented value
// is a valid stateless access token, an inactive JWT that RFC 7009 may accept,
// or a non-JWT value that must be looked up as an opaque access token.
type RevokeJWTDisposition uint8

const (
	RevokeJWTNotJWT RevokeJWTDisposition = iota
	RevokeJWTValid
	RevokeJWTInactive
)

// RevokeJWTValidator performs the configured JWT plugin's signature and claim
// validation. Only malformed compact JWS values return RevokeJWTNotJWT so
// opaque lookup can continue. Expired or structurally invalid JWT claim sets
// return RevokeJWTInactive; signature and issuer/audience failures are errors.
type RevokeJWTValidator func(*engine.Context, string) (RevokeJWTDisposition, error)

// RevokeStoredToken resolves the database representation of an externally
// presented access or refresh token. single-auth's default is SHA-256 encoded
// with unpadded base64url; custom storeTokens implementations bind here.
type RevokeStoredToken func(context.Context, string, RevokeTokenType) (string, error)

// RevokeRefreshTokenDecoder unwraps a custom formatted refresh token after its
// configured prefix has been removed.
type RevokeRefreshTokenDecoder func(context.Context, string) (string, error)

// RevokeClientSecretVerifier compares a presented client secret to its stored
// representation. The default verifies single-auth's SHA-256 hash format.
type RevokeClientSecretVerifier func(context.Context, string, string) (bool, error)

// RevokeRuntime supplies persistence and cryptographic services to the
// transport-neutral endpoint.
type RevokeRuntime struct {
	Adapter            storage.Adapter
	AdapterForContext  func(context.Context) storage.TransactionAdapter
	Clock              func() time.Time
	ValidateJWT        RevokeJWTValidator
	StoredToken        RevokeStoredToken
	DecodeRefreshToken RevokeRefreshTokenDecoder
	VerifyClientSecret RevokeClientSecretVerifier
}

// RevokeOptions mirrors the OAuth provider configuration that affects token
// revocation. Prefixes are presentation-only and are removed before custom
// decoding or storage hashing.
type RevokeOptions struct {
	OpaqueAccessTokenPrefix string
	RefreshTokenPrefix      string
	ClientSecretPrefix      string
	// JWT binds the same signing/JWKS configuration used by the JWT plugin.
	// When supplied, NewRevokeService installs a real stored-JWK validator if
	// Runtime.ValidateJWT was not explicitly overridden.
	JWT     *jwtplugin.Options
	Issuer  *RevokeIssuerOptions
	Runtime RevokeRuntime
}

// RevokeInput is the server-side and direct-API input for oauth2Revoke.
type RevokeInput struct {
	ClientID      string          `json:"client_id"`
	ClientSecret  string          `json:"client_secret"`
	Token         string          `json:"token"`
	TokenTypeHint RevokeTokenType `json:"token_type_hint"`
}

// RevokeService owns the OAuth provider's RFC 7009 revocation behavior.
type RevokeService struct {
	options RevokeOptions
	issuer  *RevokeIssuer
}

// NewRevokeService validates and snapshots a production revocation service.
func NewRevokeService(input RevokeOptions) (*RevokeService, error) {
	options := input
	if options.Runtime.Adapter == nil {
		return nil, errors.New("oauthprovider: RevokeRuntime.Adapter is required")
	}
	if options.Runtime.Clock == nil {
		options.Runtime.Clock = time.Now
	}
	if options.Runtime.StoredToken == nil {
		options.Runtime.StoredToken = defaultRevokeStoredToken
	}
	if options.Runtime.DecodeRefreshToken == nil {
		options.Runtime.DecodeRefreshToken = func(_ context.Context, token string) (string, error) {
			return token, nil
		}
	}
	if options.Runtime.VerifyClientSecret == nil {
		options.Runtime.VerifyClientSecret = defaultRevokeClientSecretVerifier
	}
	if input.JWT != nil {
		jwtOptions := *input.JWT
		if input.Issuer != nil && len(input.Issuer.ValidAudiences) > 0 {
			jwtOptions.Token.Audience = append(
				[]string(nil), input.Issuer.ValidAudiences...,
			)
		}
		if jwtOptions.Runtime.Adapter == nil {
			jwtOptions.Runtime.Adapter = options.Runtime.Adapter
		}
		if jwtOptions.Runtime.AdapterForContext == nil {
			jwtOptions.Runtime.AdapterForContext = options.Runtime.AdapterForContext
		}
		if jwtOptions.Runtime.Clock == nil {
			jwtOptions.Runtime.Clock = options.Runtime.Clock
		}
		options.JWT = &jwtOptions
		if options.Runtime.ValidateJWT == nil {
			options.Runtime.ValidateJWT = func(ctx *engine.Context, token string) (RevokeJWTDisposition, error) {
				_, disposition, err := jwtplugin.VerifyAccessToken(ctx, token, jwtOptions)
				if err != nil {
					return RevokeJWTNotJWT, err
				}
				switch disposition {
				case jwtplugin.AccessTokenValid:
					return RevokeJWTValid, nil
				case jwtplugin.AccessTokenInactive:
					return RevokeJWTInactive, nil
				case jwtplugin.AccessTokenNotJWT:
					return RevokeJWTNotJWT, nil
				case jwtplugin.AccessTokenInvalidSignature:
					return RevokeJWTNotJWT, errors.New(
						"oauthprovider: JWT signature verification failed",
					)
				case jwtplugin.AccessTokenInvalidClaims:
					return RevokeJWTNotJWT, errors.New(
						"oauthprovider: JWT claim validation failed",
					)
				default:
					return RevokeJWTNotJWT, fmt.Errorf(
						"oauthprovider: unknown JWT verification disposition %d",
						disposition,
					)
				}
			}
		}
	}
	service := &RevokeService{options: options}
	if options.Issuer != nil {
		issuer, err := newRevokeIssuer(service, *options.Issuer)
		if err != nil {
			return nil, err
		}
		service.issuer = issuer
	}
	return service, nil
}

// NewRevokePlugin constructs the descriptor used unchanged by net/http,
// fasthttp, Fiber, and direct API dispatch.
func NewRevokePlugin(options RevokeOptions) (engine.Plugin, error) {
	service, err := NewRevokeService(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	return service.Descriptor(), nil
}

// Descriptor returns the isolated OAuth revoke plugin surface.
func (service *RevokeService) Descriptor() engine.Plugin {
	descriptor := engine.Plugin{
		ID: PluginID, Version: Version, Schema: OAuthProviderSchema(),
		Endpoints: []engine.Endpoint{{
			Name: "oauth2Revoke", Path: RevokePath,
			Methods: []string{http.MethodPost}, OperationID: "oauth2Revoke",
			Handler: service.revokeEndpoint,
			Metadata: map[string]any{
				"allowedMediaTypes": []string{"application/x-www-form-urlencoded"},
				"openapi": map[string]any{
					"description": "Revoke an OAuth2 access or refresh token",
				},
			},
		}},
	}
	if service != nil && service.issuer != nil {
		descriptor.Endpoints = append([]engine.Endpoint{service.issuer.endpoint()}, descriptor.Endpoints...)
	}
	return descriptor
}

func (service *RevokeService) adapter(ctx context.Context) storage.TransactionAdapter {
	if service.options.Runtime.AdapterForContext != nil {
		if adapter := service.options.Runtime.AdapterForContext(ctx); adapter != nil {
			return adapter
		}
	}
	return service.options.Runtime.Adapter
}

func (service *RevokeService) revokeEndpoint(ctx *engine.Context) (contract.Response, error) {
	input, err := decodeRevokeInput(ctx.Request())
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
	return service.Revoke(ctx, input)
}

// Revoke validates client authentication and revokes the supplied token. A
// successful RFC 7009 response is JSON null, exactly as in single-auth 1.6.26.
func (service *RevokeService) Revoke(
	ctx *engine.Context,
	input RevokeInput,
) (contract.Response, error) {
	if service == nil {
		return revokeInternalError(errors.New("oauthprovider: revoke service is nil"))
	}
	if ctx == nil {
		return revokeInternalError(errors.New("oauthprovider: revoke context is nil"))
	}
	if input.ClientID == "" {
		return revokeErrorResponse(revokeProtocolError(
			contract.StatusUnauthorized,
			"invalid_client",
			"missing required credentials",
		))
	}
	input.Token = strings.TrimPrefix(input.Token, "Bearer ")
	if input.Token == "" {
		return revokeErrorResponse(revokeProtocolError(
			contract.StatusBadRequest,
			"invalid_request",
			"missing a required token for introspection",
		))
	}
	if input.TokenTypeHint != "" &&
		input.TokenTypeHint != RevokeAccessToken &&
		input.TokenTypeHint != RevokeRefreshToken {
		return revokeErrorResponse(revokeProtocolError(
			contract.StatusBadRequest,
			"invalid_request",
			"Invalid request body",
		))
	}

	client, err := service.validateClient(ctx.GoContext(), input.ClientID, input.ClientSecret)
	if err != nil {
		if _, protocol := contract.AsAPIError(err); protocol {
			return revokeErrorResponse(err)
		}
		return revokeInternalError(err)
	}
	clientID := revokeRecordString(client, "clientId")

	if input.TokenTypeHint == "" || input.TokenTypeHint == RevokeAccessToken {
		err = service.revokeAccessToken(ctx, clientID, input.Token)
		if err == nil {
			return revokeSuccess()
		}
		if _, protocol := contract.AsAPIError(err); !protocol {
			return revokeInternalError(err)
		}
		if input.TokenTypeHint == RevokeAccessToken {
			return revokeErrorResponse(err)
		}
	}

	if input.TokenTypeHint == "" || input.TokenTypeHint == RevokeRefreshToken {
		err = service.revokeRefreshToken(ctx.GoContext(), clientID, input.Token)
		if err == nil {
			return revokeSuccess()
		}
		if _, protocol := contract.AsAPIError(err); !protocol {
			return revokeInternalError(err)
		}
		if input.TokenTypeHint == RevokeRefreshToken {
			return revokeErrorResponse(err)
		}
	}

	return revokeErrorResponse(revokeProtocolError(
		contract.StatusBadRequest, "invalid_request", "token not found",
	))
}

func (service *RevokeService) validateClient(
	ctx context.Context,
	clientID, clientSecret string,
) (storage.Record, error) {
	client, err := service.adapter(ctx).FindOne(ctx, storage.FindOneParams{
		Model: "oauthClient", Where: []storage.Where{{Field: "clientId", Value: clientID}},
	})
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, revokeProtocolError(
			contract.StatusBadRequest, "invalid_client", "missing client",
		)
	}
	if revokeRecordBool(client, "disabled") {
		return nil, revokeProtocolError(
			contract.StatusBadRequest, "invalid_client", "client is disabled",
		)
	}
	public := revokeRecordBool(client, "public")
	storedSecret := revokeRecordString(client, "clientSecret")
	if !public && clientSecret == "" {
		return nil, revokeProtocolError(
			contract.StatusBadRequest,
			"invalid_client",
			"client secret must be provided",
		)
	}
	if clientSecret != "" && storedSecret == "" {
		return nil, revokeProtocolError(
			contract.StatusBadRequest,
			"invalid_client",
			"public client, client secret should not be received",
		)
	}
	if clientSecret != "" {
		if service.options.ClientSecretPrefix != "" {
			if !strings.HasPrefix(clientSecret, service.options.ClientSecretPrefix) {
				return nil, revokeProtocolError(
					contract.StatusUnauthorized,
					"invalid_client",
					"invalid client_secret",
				)
			}
			clientSecret = strings.TrimPrefix(clientSecret, service.options.ClientSecretPrefix)
		}
		valid, verifyErr := service.options.Runtime.VerifyClientSecret(
			ctx, storedSecret, clientSecret,
		)
		if verifyErr != nil {
			return nil, verifyErr
		}
		if !valid {
			return nil, revokeProtocolError(
				contract.StatusUnauthorized,
				"invalid_client",
				"invalid client_secret",
			)
		}
	}
	return client, nil
}

func (service *RevokeService) revokeAccessToken(
	ctx *engine.Context,
	clientID, token string,
) error {
	if service.options.Runtime.ValidateJWT != nil {
		disposition, err := service.options.Runtime.ValidateJWT(ctx, token)
		if err != nil {
			return err
		}
		switch disposition {
		case RevokeJWTValid, RevokeJWTInactive:
			return nil
		case RevokeJWTNotJWT:
		default:
			return fmt.Errorf("oauthprovider: unknown revoke JWT disposition %d", disposition)
		}
	}
	return service.revokeOpaqueAccessToken(ctx.GoContext(), clientID, token)
}

func (service *RevokeService) revokeOpaqueAccessToken(
	ctx context.Context,
	clientID, token string,
) error {
	lookup := token
	if prefix := service.options.OpaqueAccessTokenPrefix; prefix != "" {
		if !strings.HasPrefix(lookup, prefix) {
			return revokeProtocolError(
				contract.StatusBadRequest,
				"invalid_request",
				"opaque access token not found",
			)
		}
		lookup = strings.TrimPrefix(lookup, prefix)
	}
	lookup, err := service.options.Runtime.StoredToken(ctx, lookup, RevokeAccessToken)
	if err != nil {
		return err
	}
	accessToken, err := service.adapter(ctx).FindOne(ctx, storage.FindOneParams{
		Model: "oauthAccessToken", Where: []storage.Where{{Field: "token", Value: lookup}},
	})
	if err != nil {
		return err
	}
	if accessToken == nil {
		return revokeProtocolError(
			contract.StatusBadRequest,
			"invalid_request",
			"opaque access token not found",
		)
	}
	if storedClientID := revokeRecordString(accessToken, "clientId"); storedClientID == "" || storedClientID != clientID {
		return nil
	}
	where := storage.Where{Field: "token", Value: lookup}
	if id := accessToken["id"]; id != nil && fmt.Sprint(id) != "" {
		where = storage.Where{Field: "id", Value: id}
	}
	return service.adapter(ctx).Delete(ctx, storage.DeleteParams{
		Model: "oauthAccessToken", Where: []storage.Where{where},
	})
}

func (service *RevokeService) revokeRefreshToken(
	ctx context.Context,
	clientID, token string,
) error {
	decoded := token
	if prefix := service.options.RefreshTokenPrefix; prefix != "" {
		if !strings.HasPrefix(decoded, prefix) {
			return revokeProtocolError(
				contract.StatusBadRequest,
				"invalid_token",
				"refresh token not found",
			)
		}
		decoded = strings.TrimPrefix(decoded, prefix)
	}
	decoded, err := service.options.Runtime.DecodeRefreshToken(ctx, decoded)
	if err != nil {
		return err
	}
	lookup, err := service.options.Runtime.StoredToken(ctx, decoded, RevokeRefreshToken)
	if err != nil {
		return err
	}
	refreshToken, err := service.adapter(ctx).FindOne(ctx, storage.FindOneParams{
		Model: "oauthRefreshToken", Where: []storage.Where{{Field: "token", Value: lookup}},
	})
	if err != nil {
		return err
	}
	if refreshToken == nil {
		return revokeProtocolError(
			contract.StatusBadRequest, "invalid_request", "token not found",
		)
	}
	if refreshToken["revoked"] != nil {
		if err := service.invalidateRefreshFamily(
			ctx,
			clientID,
			revokeRecordString(refreshToken, "userId"),
		); err != nil {
			return err
		}
		return revokeProtocolError(
			contract.StatusBadRequest, "invalid_request", "refresh token revoked",
		)
	}
	if storedClientID := revokeRecordString(refreshToken, "clientId"); storedClientID == "" || storedClientID != clientID {
		return nil
	}
	refreshID := refreshToken["id"]
	if refreshID == nil || fmt.Sprint(refreshID) == "" {
		return errors.New("oauthprovider: stored refresh token has no id")
	}
	revokedAt := service.options.Runtime.Clock()
	revokedAt = time.Unix(revokedAt.Unix(), 0).UTC()
	won, err := service.adapter(ctx).IncrementOne(ctx, storage.IncrementOneParams{
		Model: "oauthRefreshToken",
		Where: []storage.Where{
			{Field: "id", Value: refreshID},
			{Field: "revoked", Operator: storage.OpEq, Value: nil},
		},
		Increment: map[string]float64{},
		Set:       storage.Record{"revoked": revokedAt},
	})
	if err != nil {
		return err
	}
	if won == nil {
		if err := service.invalidateRefreshFamily(
			ctx,
			clientID,
			revokeRecordString(refreshToken, "userId"),
		); err != nil {
			return err
		}
		return revokeProtocolError(
			contract.StatusBadRequest, "invalid_request", "refresh token revoked",
		)
	}
	_, err = service.adapter(ctx).DeleteMany(ctx, storage.DeleteManyParams{
		Model: "oauthAccessToken",
		Where: []storage.Where{{Field: "refreshId", Value: refreshID}},
	})
	return err
}

func (service *RevokeService) invalidateRefreshFamily(
	ctx context.Context,
	clientID, userID string,
) error {
	refreshTokens, err := service.adapter(ctx).FindMany(ctx, storage.FindManyParams{
		Model: "oauthRefreshToken",
		Where: []storage.Where{
			{Field: "clientId", Value: clientID},
			{Field: "userId", Value: userID},
		},
	})
	if err != nil {
		return err
	}
	if len(refreshTokens) > 0 {
		ids := make([]any, 0, len(refreshTokens))
		for _, refreshToken := range refreshTokens {
			if id := refreshToken["id"]; id != nil {
				ids = append(ids, id)
			}
		}
		if len(ids) > 0 {
			if _, err := service.adapter(ctx).DeleteMany(ctx, storage.DeleteManyParams{
				Model: "oauthAccessToken",
				Where: []storage.Where{{
					Field: "refreshId", Operator: storage.OpIn, Value: ids,
				}},
			}); err != nil {
				return err
			}
		}
	}
	_, err = service.adapter(ctx).DeleteMany(ctx, storage.DeleteManyParams{
		Model: "oauthRefreshToken",
		Where: []storage.Where{
			{Field: "clientId", Value: clientID},
			{Field: "userId", Value: userID},
		},
	})
	return err
}

func decodeRevokeInput(request contract.Request) (RevokeInput, error) {
	var input RevokeInput
	body := request.Body()
	contentType, _ := request.Headers().Get("Content-Type")
	if strings.HasPrefix(strings.ToLower(contentType), "application/json") ||
		strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		if err := json.Unmarshal(body, &input); err != nil {
			return RevokeInput{}, err
		}
		return input, nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return RevokeInput{}, err
	}
	input.ClientID = values.Get("client_id")
	input.ClientSecret = values.Get("client_secret")
	input.Token = values.Get("token")
	input.TokenTypeHint = RevokeTokenType(values.Get("token_type_hint"))
	return input, nil
}

func defaultRevokeStoredToken(
	_ context.Context,
	token string,
	_ RevokeTokenType,
) (string, error) {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func defaultRevokeClientSecretVerifier(
	_ context.Context,
	stored, presented string,
) (bool, error) {
	hashed, _ := defaultRevokeStoredToken(context.Background(), presented, RevokeAccessToken)
	if len(stored) != len(hashed) {
		return false, nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(hashed)) == 1, nil
}

func revokeRecordString(record storage.Record, field string) string {
	if record == nil {
		return ""
	}
	value, _ := record[field].(string)
	return value
}

func revokeRecordBool(record storage.Record, field string) bool {
	if record == nil {
		return false
	}
	value, _ := record[field].(bool)
	return value
}

func revokeSuccess() (contract.Response, error) {
	return contract.JSONResponse(contract.StatusOK, nil)
}

func revokeProtocolError(status int, code, description string) *contract.APIError {
	return contract.NewAPIError(status, strings.ToUpper(code), description).WithWireBody(map[string]any{
		"error": code, "error_description": description,
	})
}

func revokeErrorResponse(err error) (contract.Response, error) {
	return contract.ResponseFromError(err), err
}

func revokeInternalError(cause error) (contract.Response, error) {
	err := contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Internal Server Error",
	).WithCause(cause)
	return contract.ResponseFromError(err), err
}
