package oidcprovider

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) token(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	if body == nil {
		return contract.Response{}, oauthError(
			contract.StatusBadRequest, "invalid_request", "request body not found",
		)
	}
	clientID, clientIDPresent, err := optionalBodyString(body, "client_id")
	if err != nil {
		return contract.Response{}, err
	}
	clientSecret, clientSecretPresent, err := optionalBodyString(body, "client_secret")
	if err != nil {
		return contract.Response{}, err
	}
	authorization, _ := ctx.Request().Headers().Get("Authorization")
	if authorization != "" && !clientSecretPresent && strings.HasPrefix(authorization, "Basic ") {
		id, secret, parseErr := parseBasicCredentials(strings.TrimPrefix(authorization, "Basic "))
		if parseErr != nil {
			return contract.Response{}, oauthError(
				contract.StatusUnauthorized, "invalid_client", "invalid authorization header format",
			)
		}
		if clientIDPresent && clientID != id {
			return contract.Response{}, oauthError(
				contract.StatusUnauthorized, "invalid_client",
				"client_id in body does not match Authorization header",
			)
		}
		clientID, clientSecret = id, secret
		clientIDPresent, clientSecretPresent = true, true
	}
	grantType, _, err := optionalBodyString(body, "grant_type")
	if err != nil {
		return contract.Response{}, err
	}
	if grantType == "refresh_token" {
		refreshToken, _, fieldErr := optionalBodyString(body, "refresh_token")
		if fieldErr != nil {
			return contract.Response{}, fieldErr
		}
		return p.refreshGrant(ctx, clientID, clientSecret, refreshToken)
	}
	code, _, err := optionalBodyString(body, "code")
	if err != nil {
		return contract.Response{}, err
	}
	redirectURI, _, err := optionalBodyString(body, "redirect_uri")
	if err != nil {
		return contract.Response{}, err
	}
	codeVerifier, _, err := optionalBodyString(body, "code_verifier")
	if err != nil {
		return contract.Response{}, err
	}
	return p.authorizationCodeGrant(
		ctx, grantType, clientID, clientSecret, code, redirectURI, codeVerifier,
	)
}

func parseBasicCredentials(encoded string) (string, string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return "", "", err
	}
	separator := strings.IndexByte(string(decoded), ':')
	if separator < 0 {
		return "", "", base64.CorruptInputError(0)
	}
	id, err := url.PathUnescape(string(decoded[:separator]))
	if err != nil {
		return "", "", err
	}
	secret, err := url.PathUnescape(string(decoded[separator+1:]))
	if err != nil {
		return "", "", err
	}
	if id == "" || secret == "" {
		return "", "", base64.CorruptInputError(0)
	}
	return id, secret, nil
}

func (p *plugin) refreshGrant(
	ctx *engine.Context,
	clientID, clientSecret, refreshToken string,
) (contract.Response, error) {
	if refreshToken == "" {
		return contract.Response{}, oauthError(
			contract.StatusBadRequest, "invalid_request", "refresh_token is required",
		)
	}
	record, err := p.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "oauthAccessToken", Where: []storage.Where{{Field: "refreshToken", Value: refreshToken}},
	})
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if record == nil {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_grant", "invalid refresh token",
		)
	}
	token, err := accessTokenFromRecord(record)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if token.ClientID != clientID {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_client", "invalid client_id",
		)
	}
	if token.RefreshTokenExpiresAt.Before(p.clock()) {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_grant", "refresh token expired",
		)
	}
	client, err := p.findClient(ctx, clientID)
	if err != nil {
		return contract.Response{}, err
	}
	if client == nil {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_client", "invalid client_id",
		)
	}
	if client.Disabled {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_client", "client is disabled",
		)
	}
	if client.Type != "public" {
		if client.ClientSecret == "" || clientSecret == "" {
			return contract.Response{}, oauthError(
				contract.StatusUnauthorized, "invalid_client",
				"client_secret is required for confidential clients",
			)
		}
		valid, err := p.verifyClientSecret(ctx.GoContext(), client.ClientSecret, clientSecret)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		if !valid {
			return contract.Response{}, oauthError(
				contract.StatusUnauthorized, "invalid_client", "invalid client_secret",
			)
		}
	}
	accessToken, err := p.randomString(32, "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	newRefreshToken, err := p.randomString(32, "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	nowSeconds := p.clock().Unix()
	now := time.Unix(nowSeconds, 0).UTC()
	if _, err := p.adapter(ctx.GoContext()).Create(ctx.GoContext(), storage.CreateParams{
		Model: "oauthAccessToken",
		Data: storage.Record{
			"accessToken": accessToken, "refreshToken": newRefreshToken,
			"accessTokenExpiresAt":  now.Add(p.options.AccessTokenExpiresIn),
			"refreshTokenExpiresAt": now.Add(p.options.RefreshTokenExpiresIn),
			"clientId":              clientID, "userId": token.UserID, "scopes": token.Scopes,
			"createdAt": now, "updatedAt": now,
		},
	}); err != nil {
		return contract.Response{}, internalError(err)
	}
	return jsonResponse(contract.StatusOK, map[string]any{
		"access_token": accessToken, "token_type": "Bearer",
		"expires_in":    int64(p.options.AccessTokenExpiresIn / time.Second),
		"refresh_token": newRefreshToken, "scope": token.Scopes,
	})
}

func (p *plugin) authorizationCodeGrant(
	ctx *engine.Context,
	grantType, clientID, clientSecret, code, redirectURI, codeVerifier string,
) (contract.Response, error) {
	if code == "" {
		return contract.Response{}, oauthError(contract.StatusBadRequest, "invalid_request", "code is required")
	}
	if p.options.RequirePKCE && codeVerifier == "" {
		return contract.Response{}, oauthError(
			contract.StatusBadRequest, "invalid_request", "code verifier is missing",
		)
	}
	verification, err := p.consumeVerification(ctx.GoContext(), code)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if verification == nil {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_grant", "invalid code",
		)
	}
	if clientID == "" {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_client", "client_id is required",
		)
	}
	if grantType == "" {
		return contract.Response{}, oauthError(
			contract.StatusBadRequest, "invalid_request", "grant_type is required",
		)
	}
	if grantType != "authorization_code" {
		return contract.Response{}, oauthError(
			contract.StatusBadRequest, "unsupported_grant_type",
			"grant_type must be 'authorization_code'",
		)
	}
	if redirectURI == "" {
		return contract.Response{}, oauthError(
			contract.StatusBadRequest, "invalid_request", "redirect_uri is required",
		)
	}
	client, err := p.findClient(ctx, clientID)
	if err != nil {
		return contract.Response{}, err
	}
	if client == nil {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_client", "invalid client_id",
		)
	}
	if client.Disabled {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_client", "client is disabled",
		)
	}
	rawValue, ok := recordString(verification, "value")
	if !ok {
		return contract.Response{}, oauthError(contract.StatusUnauthorized, "invalid_grant", "invalid code")
	}
	var value AuthorizationCodeValue
	if err := json.Unmarshal([]byte(rawValue), &value); err != nil {
		return contract.Response{}, internalError(err)
	}
	if value.ClientID != clientID {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_client", "invalid client_id",
		)
	}
	if value.RedirectURI != redirectURI {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_client", "invalid redirect_uri",
		)
	}
	if value.CodeChallenge != "" && codeVerifier == "" {
		return contract.Response{}, oauthError(
			contract.StatusBadRequest, "invalid_request", "code verifier is missing",
		)
	}
	if client.Type == "public" {
		if codeVerifier == "" {
			return contract.Response{}, oauthError(
				contract.StatusBadRequest, "invalid_request",
				"code verifier is required for public clients",
			)
		}
	} else {
		if client.ClientSecret == "" || clientSecret == "" {
			return contract.Response{}, oauthError(
				contract.StatusUnauthorized, "invalid_client",
				"client_secret is required for confidential clients",
			)
		}
		valid, err := p.verifyClientSecret(ctx.GoContext(), client.ClientSecret, clientSecret)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		if !valid {
			return contract.Response{}, oauthError(
				contract.StatusUnauthorized, "invalid_client", "invalid client_secret",
			)
		}
	}
	if value.CodeChallenge != "" {
		challenge := pkceChallenge(codeVerifier)
		if value.CodeChallengeMethod == "plain" {
			challenge = codeVerifier
		}
		if challenge != value.CodeChallenge {
			return contract.Response{}, oauthError(
				contract.StatusUnauthorized, "invalid_request", "code verification failed",
			)
		}
	}

	nowSeconds := p.clock().Unix()
	now := time.Unix(nowSeconds, 0).UTC()
	accessTokenExpiresAt := now.Add(p.options.AccessTokenExpiresIn)
	refreshTokenExpiresAt := now.Add(p.options.RefreshTokenExpiresIn)
	accessToken, err := p.randomString(32, "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	refreshToken, err := p.randomString(32, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	requestedScopes := append([]string(nil), value.Scope...)
	if _, err := p.adapter(ctx.GoContext()).Create(ctx.GoContext(), storage.CreateParams{
		Model: "oauthAccessToken",
		Data: storage.Record{
			"accessToken": accessToken, "refreshToken": refreshToken,
			"accessTokenExpiresAt":  accessTokenExpiresAt,
			"refreshTokenExpiresAt": refreshTokenExpiresAt,
			"clientId":              clientID, "userId": value.UserID,
			"scopes":    strings.Join(requestedScopes, " "),
			"createdAt": now, "updatedAt": now,
		},
	}); err != nil {
		return contract.Response{}, internalError(err)
	}
	user, err := p.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: value.UserID}},
	})
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if user == nil {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_grant", "user not found",
		)
	}
	claims, err := p.idTokenClaims(ctx, user, requestedScopes, *client, value, nowSeconds)
	if err != nil {
		return contract.Response{}, err
	}
	claims["exp"] = accessTokenExpiresAt.Unix()
	var idToken string
	if p.options.UseJWTPlugin {
		if p.options.Runtime.SignWithJWTPlugin == nil {
			return contract.Response{}, oauthError(
				contract.StatusInternalServerError, "internal_server_error", "JWT plugin is not enabled",
			)
		}
		baseURL, err := p.options.Runtime.ResolveBaseURL(ctx.Request())
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		idToken, err = p.options.Runtime.SignWithJWTPlugin(
			ctx, claims, clientID, p.resolveIssuer(baseURL), accessTokenExpiresAt.Unix(),
		)
		if err != nil {
			return contract.Response{}, oauthError(
				contract.StatusInternalServerError, "internal_server_error", "JWT plugin is not enabled",
			).WithCause(err)
		}
	} else {
		idToken, err = signHS256(claims, client.ClientSecret)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	response := map[string]any{
		"access_token": accessToken, "token_type": "Bearer",
		"expires_in": int64(p.options.AccessTokenExpiresIn / time.Second),
		"scope":      strings.Join(requestedScopes, " "),
	}
	if contains(requestedScopes, "offline_access") {
		response["refresh_token"] = refreshToken
	}
	if contains(requestedScopes, "openid") {
		response["id_token"] = idToken
	}
	result, err := jsonResponse(contract.StatusOK, response)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	return result.WithHeader("Cache-Control", "no-store").WithHeader("Pragma", "no-cache"), nil
}

func (p *plugin) idTokenClaims(
	ctx *engine.Context,
	user storage.Record,
	scopes []string,
	client Client,
	value AuthorizationCodeValue,
	iat int64,
) (map[string]any, error) {
	userID, _ := recordString(user, "id")
	name, _ := recordString(user, "name")
	image, imageExists := recordString(user, "image")
	email, _ := recordString(user, "email")
	emailVerified, _ := recordBool(user, "emailVerified")
	updatedAt, _ := recordTime(user, "updatedAt")
	parts := strings.Split(name, " ")
	firstName := ""
	lastName := ""
	if len(parts) > 0 {
		firstName = parts[0]
	}
	if len(parts) > 1 {
		lastName = parts[1]
	}
	claims := map[string]any{
		"sub": userID, "aud": client.ClientID, "iat": iat,
		"acr": "urn:mace:incommon:iap:silver",
	}
	if value.Nonce != "" {
		claims["nonce"] = value.Nonce
	}
	if contains(scopes, "profile") {
		claims["given_name"] = firstName
		claims["family_name"] = lastName
		claims["name"] = name
		if imageExists {
			claims["profile"] = image
		} else {
			claims["profile"] = nil
		}
		claims["updated_at"] = updatedAt.Format(time.RFC3339Nano)
	}
	if contains(scopes, "email") {
		claims["email"] = email
		claims["email_verified"] = emailVerified
	}
	if p.options.GetAdditionalUserInfoClaim != nil {
		additional, err := p.options.GetAdditionalUserInfoClaim(
			ctx.GoContext(), user, append([]string(nil), scopes...), cloneClient(client),
		)
		if err != nil {
			return nil, internalError(err)
		}
		for key, value := range additional {
			claims[key] = value
		}
	}
	return claims, nil
}
