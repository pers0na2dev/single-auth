package oauthprovider

import (
	"context"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	jwtplugin "github.com/pers0na2dev/single-auth/plugins/jwt"
	"github.com/pers0na2dev/single-auth/storage"
)

func (server *Server) introspect(ctx *engine.Context) (contract.Response, error) {
	body, err := serverDecodeObject(ctx.Request())
	if err != nil || body == nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid request body")
	}
	clientID := serverString(body, "client_id")
	clientSecret := serverString(body, "client_secret")
	if authorization, _ := ctx.Request().Headers().Get("Authorization"); strings.HasPrefix(authorization, "Basic ") {
		credentials, parseErr := BasicToClientCredentials(authorization)
		if parseErr != nil {
			return serverOAuthError(contract.StatusBadRequest, "invalid_client", "invalid authorization header format")
		}
		if credentials != nil {
			clientID, clientSecret = credentials.ClientID, credentials.ClientSecret
		}
	}
	if clientID == "" {
		return serverOAuthError(contract.StatusUnauthorized, "invalid_client", "missing required credentials")
	}
	client, err := server.revoke.validateClient(ctx.GoContext(), clientID, clientSecret)
	if err != nil {
		if _, protocol := contract.AsAPIError(err); protocol {
			return revokeErrorResponse(err)
		}
		return serverInternalError(err)
	}
	token := strings.TrimPrefix(serverString(body, "token"), "Bearer ")
	if token == "" {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "missing a required token for introspection")
	}
	hint := serverString(body, "token_type_hint")
	if hint != "" && hint != string(RevokeAccessToken) && hint != string(RevokeRefreshToken) {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid request body")
	}
	if hint == "" || hint == string(RevokeAccessToken) {
		claims, active, inspectErr := server.introspectAccessToken(ctx, client, token)
		if inspectErr != nil {
			return serverInternalError(inspectErr)
		}
		if active {
			return server.introspectionResponse(claims)
		}
		if hint == string(RevokeAccessToken) {
			return server.introspectionResponse(map[string]any{"active": false})
		}
	}
	if hint == "" || hint == string(RevokeRefreshToken) {
		claims, active, inspectErr := server.introspectRefreshToken(ctx.GoContext(), client, token)
		if inspectErr != nil {
			return serverInternalError(inspectErr)
		}
		if active {
			return server.introspectionResponse(claims)
		}
	}
	return server.introspectionResponse(map[string]any{"active": false})
}

func (server *Server) introspectAccessToken(ctx *engine.Context, client storage.Record, token string) (map[string]any, bool, error) {
	clientID := serverRecordString(client, "clientId")
	if server.runtime.hasJWTPlugin && strings.Count(token, ".") == 2 {
		claims, disposition, err := server.verifyOAuthAccessJWT(ctx, token)
		if err != nil || disposition != jwtplugin.AccessTokenValid || claims == nil {
			return nil, false, nil
		}
		issuedClient := claimString(claims["client_id"])
		if issuedClient == "" {
			issuedClient = claimString(claims["azp"])
		}
		// A generic JWT-plugin session token has no OAuth client binding and
		// therefore cannot satisfy RFC 7662 introspection.
		if issuedClient == "" || issuedClient != clientID {
			return nil, false, nil
		}
		result := cloneUserInfoMap(claims)
		result["active"] = true
		result["client_id"] = issuedClient
		result["token_type"] = "access_token"
		return result, true, nil
	}
	raw := token
	if prefix := server.options.OpaqueAccessTokenPrefix; prefix != "" {
		if !strings.HasPrefix(raw, prefix) {
			return nil, false, nil
		}
		raw = strings.TrimPrefix(raw, prefix)
	}
	record, err := server.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "oauthAccessToken", Where: []storage.Where{{Field: "token", Value: serverHash(raw)}},
	})
	if err != nil || record == nil {
		return nil, false, err
	}
	if serverRecordString(record, "clientId") != clientID {
		return nil, false, nil
	}
	expiresAt, ok := serverRecordTime(record, "expiresAt")
	if !ok || !expiresAt.After(server.runtime.clock()) {
		return nil, false, nil
	}
	createdAt, _ := serverRecordTime(record, "createdAt")
	userID := serverRecordString(record, "userId")
	subject, err := server.resolveSubject(ctx.GoContext(), userID, client)
	if err != nil {
		return nil, false, err
	}
	return map[string]any{
		"active": true, "scope": strings.Join(serverStrings(record["scopes"]), " "),
		"client_id": clientID, "token_type": "access_token", "exp": expiresAt.Unix(),
		"iat": createdAt.Unix(), "sub": subject,
	}, true, nil
}

func (server *Server) introspectRefreshToken(ctx context.Context, client storage.Record, token string) (map[string]any, bool, error) {
	raw := token
	if prefix := server.options.RefreshTokenPrefix; prefix != "" {
		if !strings.HasPrefix(raw, prefix) {
			return nil, false, nil
		}
		raw = strings.TrimPrefix(raw, prefix)
	}
	record, err := server.adapter(ctx).FindOne(ctx, storage.FindOneParams{
		Model: "oauthRefreshToken", Where: []storage.Where{{Field: "token", Value: serverHash(raw)}},
	})
	if err != nil || record == nil {
		return nil, false, err
	}
	clientID := serverRecordString(client, "clientId")
	if serverRecordString(record, "clientId") != clientID || record["revoked"] != nil {
		return nil, false, nil
	}
	expiresAt, ok := serverRecordTime(record, "expiresAt")
	if !ok || !expiresAt.After(server.runtime.clock()) {
		return nil, false, nil
	}
	createdAt, _ := serverRecordTime(record, "createdAt")
	userID := serverRecordString(record, "userId")
	subject, err := server.resolveSubject(ctx, userID, client)
	if err != nil {
		return nil, false, err
	}
	result := map[string]any{
		"active": true, "scope": strings.Join(serverStrings(record["scopes"]), " "),
		"client_id": clientID, "token_type": "refresh_token", "exp": expiresAt.Unix(),
		"iat": createdAt.Unix(), "sub": subject,
	}
	if sessionID := serverRecordString(record, "sessionId"); sessionID != "" {
		result["sid"] = sessionID
	}
	return result, true, nil
}

func (server *Server) introspectionResponse(value map[string]any) (contract.Response, error) {
	response, err := serverJSON(contract.StatusOK, value)
	if err != nil {
		return serverInternalError(err)
	}
	return response.WithHeader("Cache-Control", "no-store").WithHeader("Pragma", "no-cache"), nil
}
