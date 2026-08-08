package oauthprovider

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

// authorize implements the OAuth 2.1 authorization-code entry point. The
// complete validation and consent flow is kept in this file so the same
// handler is used by direct API, net/http, fasthttp, and Fiber.
func (server *Server) authorize(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid authorization query")
	}
	return server.authorizeValues(ctx, query, false)
}

func (server *Server) authorizeConsent(ctx *engine.Context) (contract.Response, error) {
	session, err := server.runtime.resolveSession(ctx, true)
	if err != nil || session == nil {
		if err != nil {
			return contract.Response{}, err
		}
		return serverOAuthError(contract.StatusUnauthorized, "unauthorized", "Authentication required")
	}
	body, err := serverDecodeObject(ctx.Request())
	if err != nil || body == nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid request body")
	}
	accept, validAccept := serverBool(body, "accept")
	if !validAccept {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "accept is required")
	}
	rawQuery := serverString(body, "oauth_query")
	values, err := serverVerifySignedQuery(rawQuery, server.runtime.secret, 10*time.Minute, server.runtime.clock())
	if err != nil {
		return serverOAuthError(contract.StatusUnauthorized, "invalid_request", "Invalid or expired oauth_query")
	}
	client, requestedScopes, redirectURI, err := server.validateAuthorizationRequest(ctx, values)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	if !accept {
		location := serverErrorURL(
			redirectURI, values.Get("state"), server.issuer(ctx.Request()),
			"access_denied", "User denied access",
		)
		return serverJSON(contract.StatusOK, map[string]any{"redirect_uri": location})
	}
	acceptedScopes := requestedScopes
	if rawScope := serverString(body, "scope"); rawScope != "" {
		acceptedScopes = serverUniqueStrings(strings.Fields(rawScope))
		if !serverSubset(acceptedScopes, requestedScopes) {
			return serverOAuthError(contract.StatusBadRequest, "invalid_scope", "Accepted scopes must be a subset of requested scopes")
		}
	}
	userID, sessionID, authTime := authorizationSessionIdentity(session, server.runtime.clock())
	if userID == "" || sessionID == "" {
		return serverOAuthError(contract.StatusUnauthorized, "invalid_request", "Session is incomplete")
	}
	referenceID, err := server.resolveClientReference(ctx.GoContext(), session)
	if err != nil {
		return serverInternalError(err)
	}
	var code string
	err = server.runtime.adapter.Transaction(ctx.GoContext(), func(tx storage.TransactionAdapter) error {
		existing, findErr := tx.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "oauthConsent", Where: authorizationConsentWhere(client, userID, referenceID),
		})
		if findErr != nil {
			return findErr
		}
		now := time.Unix(server.runtime.clock().Unix(), 0).UTC()
		if existing == nil {
			data := storage.Record{
				"clientId": serverRecordString(client, "clientId"), "userId": userID,
				"scopes": append([]string(nil), acceptedScopes...), "createdAt": now, "updatedAt": now,
			}
			if referenceID != "" {
				data["referenceId"] = referenceID
			}
			if _, createErr := tx.Create(ctx.GoContext(), storage.CreateParams{Model: "oauthConsent", Data: data}); createErr != nil {
				return createErr
			}
		} else {
			where := []storage.Where{{Field: "id", Value: existing["id"]}}
			if _, updateErr := tx.Update(ctx.GoContext(), storage.UpdateParams{
				Model: "oauthConsent", Where: where,
				Update: storage.Record{"scopes": append([]string(nil), acceptedScopes...), "updatedAt": now},
			}); updateErr != nil {
				return updateErr
			}
		}
		var createErr error
		code, createErr = server.revoke.issuer.createAuthorizationCodeWithAdapter(ctx.GoContext(), tx, RevokeAuthorizationGrant{
			ClientID: serverRecordString(client, "clientId"), UserID: userID, SessionID: sessionID,
			RedirectURI: redirectURI, Scopes: acceptedScopes,
			CodeChallenge: values.Get("code_challenge"), CodeChallengeMethod: values.Get("code_challenge_method"),
			Nonce: values.Get("nonce"), ReferenceID: referenceID, AuthTime: authTime,
		})
		return createErr
	})
	if err != nil {
		return serverInternalError(err)
	}
	location, err := server.authorizationSuccessURL(redirectURI, code, values.Get("state"), ctx.Request())
	if err != nil {
		return serverInternalError(err)
	}
	return serverJSON(contract.StatusOK, map[string]any{"redirect_uri": location})
}

func (server *Server) continueAuthorization(ctx *engine.Context) (contract.Response, error) {
	if _, err := server.runtime.resolveSession(ctx, true); err != nil {
		return contract.Response{}, err
	}
	body, err := serverDecodeObject(ctx.Request())
	if err != nil || body == nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid request body")
	}
	values, err := serverVerifySignedQuery(serverString(body, "oauth_query"), server.runtime.secret, 10*time.Minute, server.runtime.clock())
	if err != nil {
		return serverOAuthError(contract.StatusUnauthorized, "invalid_request", "Invalid or expired oauth_query")
	}
	prompts, promptErr := authorizationPrompts(values.Get("prompt"))
	if promptErr != nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", promptErr.Error())
	}
	remove := map[string]bool{}
	if created, _ := serverBool(body, "created"); created {
		remove["create"] = true
		remove["login"] = true
	}
	if selected, _ := serverBool(body, "selected"); selected {
		remove["select_account"] = true
	}
	if postLogin, _ := serverBool(body, "postLogin"); postLogin {
		values.Set(PostLoginClearedParam, serverRecordStringFromSession(ctx, server.runtime.resolveSession))
	}
	filtered := make([]string, 0, len(prompts))
	for _, prompt := range prompts {
		if !remove[prompt] && prompt != "login" {
			filtered = append(filtered, prompt)
		}
	}
	if len(filtered) == 0 {
		values.Del("prompt")
	} else {
		values.Set("prompt", strings.Join(filtered, " "))
	}
	return server.authorizeValues(ctx, values, true)
}

func (server *Server) authorizeValues(ctx *engine.Context, input url.Values, continued bool) (contract.Response, error) {
	values := cloneURLValues(input)
	if requestURI := values.Get("request_uri"); requestURI != "" {
		if server.options.RequestURIResolver == nil {
			return server.authorizationError(ctx, "", values.Get("state"), "invalid_request_uri", "request_uri not supported")
		}
		resolved, err := server.options.RequestURIResolver(ctx.GoContext(), requestURI, values.Get("client_id"))
		if err != nil || resolved == nil {
			return server.authorizationError(ctx, "", values.Get("state"), "invalid_request_uri", "request_uri is invalid or expired")
		}
		clientID := values.Get("client_id")
		values = make(url.Values, len(resolved)+1)
		for key, value := range resolved {
			values.Set(key, value)
		}
		if clientID != "" {
			values.Set("client_id", clientID)
		}
	}
	client, scopes, redirectURI, err := server.validateAuthorizationRequest(ctx, values)
	if err != nil {
		var protocol *contract.APIError
		if errors.As(err, &protocol) {
			code := strings.ToLower(protocol.Code)
			if code == "bad_request" {
				code = "invalid_request"
			}
			return server.authorizationError(ctx, redirectURI, values.Get("state"), code, protocol.Message)
		}
		return serverInternalError(err)
	}
	prompts, err := authorizationPrompts(values.Get("prompt"))
	if err != nil {
		return server.authorizationError(ctx, redirectURI, values.Get("state"), "invalid_request", err.Error())
	}
	session, err := server.runtime.resolveSession(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if session == nil || (!continued && (serverContains(prompts, "login") || serverContains(prompts, "create"))) {
		if serverContains(prompts, "none") {
			return server.authorizationError(ctx, redirectURI, values.Get("state"), "login_required", "authentication required")
		}
		return server.authorizationPageRedirect(ctx, server.options.LoginPage, values)
	}
	userID, sessionID, authTime := authorizationSessionIdentity(session, server.runtime.clock())
	if userID == "" || sessionID == "" {
		return serverOAuthError(contract.StatusUnauthorized, "invalid_request", "Session is incomplete")
	}
	referenceID, err := server.resolveClientReference(ctx.GoContext(), session)
	if err != nil {
		return serverInternalError(err)
	}
	forceConsent := serverContains(prompts, "consent")
	consentGranted := serverRecordBool(client, "skipConsent")
	if !consentGranted && !forceConsent {
		consent, findErr := server.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "oauthConsent", Where: authorizationConsentWhere(client, userID, referenceID),
		})
		if findErr != nil {
			return serverInternalError(findErr)
		}
		consentGranted = consent != nil && serverSubset(scopes, serverStrings(consent["scopes"]))
	}
	if !consentGranted || forceConsent {
		if serverContains(prompts, "none") {
			return server.authorizationError(ctx, redirectURI, values.Get("state"), "consent_required", "End-User consent is required")
		}
		return server.authorizationPageRedirect(ctx, server.options.ConsentPage, values)
	}
	code, err := server.revoke.CreateAuthorizationCode(ctx.GoContext(), RevokeAuthorizationGrant{
		ClientID: serverRecordString(client, "clientId"), UserID: userID, SessionID: sessionID,
		RedirectURI: redirectURI, Scopes: scopes,
		CodeChallenge: values.Get("code_challenge"), CodeChallengeMethod: values.Get("code_challenge_method"),
		Nonce: values.Get("nonce"), ReferenceID: referenceID, AuthTime: authTime,
	})
	if err != nil {
		return serverInternalError(err)
	}
	location, err := server.authorizationSuccessURL(redirectURI, code, values.Get("state"), ctx.Request())
	if err != nil {
		return serverInternalError(err)
	}
	return serverRedirect(ctx, location)
}

func (server *Server) validateAuthorizationRequest(ctx *engine.Context, values url.Values) (storage.Record, []string, string, error) {
	clientID := values.Get("client_id")
	if clientID == "" {
		return nil, nil, "", contract.NewAPIError(contract.StatusBadRequest, "INVALID_CLIENT", "client_id is required")
	}
	if values.Get("response_type") == "" {
		return nil, nil, "", contract.NewAPIError(contract.StatusBadRequest, "INVALID_REQUEST", "response_type is required")
	}
	if values.Get("response_type") != "code" {
		return nil, nil, "", contract.NewAPIError(contract.StatusBadRequest, "UNSUPPORTED_RESPONSE_TYPE", "unsupported response type")
	}
	client, err := server.findClient(ctx.GoContext(), clientID)
	if err != nil {
		return nil, nil, "", err
	}
	if client == nil {
		return nil, nil, "", contract.NewAPIError(contract.StatusBadRequest, "INVALID_CLIENT", "client not found")
	}
	if serverRecordBool(client, "disabled") {
		return nil, nil, "", contract.NewAPIError(contract.StatusBadRequest, "CLIENT_DISABLED", "client is disabled")
	}
	if !revokeClientAllowsGrant(client, "authorization_code") {
		return nil, nil, "", contract.NewAPIError(contract.StatusBadRequest, "UNAUTHORIZED_CLIENT", "client is not authorized to use the authorization_code grant")
	}
	redirectURI := values.Get("redirect_uri")
	validRedirect := false
	for _, registered := range serverStrings(client["redirectUris"]) {
		if serverRedirectMatches(registered, redirectURI) {
			validRedirect = true
			break
		}
	}
	if redirectURI == "" || !validRedirect || ValidateSafeURL(redirectURI) != nil {
		return nil, nil, "", contract.NewAPIError(contract.StatusBadRequest, "INVALID_REDIRECT", "invalid redirect uri")
	}
	scopes := serverUniqueStrings(strings.Fields(values.Get("scope")))
	allowed := serverStrings(client["scopes"])
	if len(allowed) == 0 {
		allowed = server.options.Scopes
	}
	if len(scopes) == 0 {
		scopes = append([]string(nil), allowed...)
		values.Set("scope", strings.Join(scopes, " "))
	}
	if !serverSubset(scopes, allowed) {
		return nil, nil, redirectURI, contract.NewAPIError(contract.StatusBadRequest, "INVALID_SCOPE", "requested scope is not allowed for this client")
	}
	challenge := values.Get("code_challenge")
	method := values.Get("code_challenge_method")
	requirePKCE := serverRecordBool(client, "public") || serverContains(scopes, "offline_access")
	if configured, exists := client["requirePKCE"].(bool); exists {
		requirePKCE = requirePKCE || configured
	} else {
		requirePKCE = true
	}
	if requirePKCE && (challenge == "" || method == "") {
		return nil, nil, redirectURI, contract.NewAPIError(contract.StatusBadRequest, "INVALID_REQUEST", "pkce is required for this client")
	}
	if challenge != "" || method != "" {
		if challenge == "" || method == "" {
			return nil, nil, redirectURI, contract.NewAPIError(contract.StatusBadRequest, "INVALID_REQUEST", "code_challenge and code_challenge_method must both be provided")
		}
		if method != "S256" {
			return nil, nil, redirectURI, contract.NewAPIError(contract.StatusBadRequest, "INVALID_REQUEST", "invalid code_challenge method, only S256 is supported")
		}
	}
	return client, scopes, redirectURI, nil
}

func (server *Server) authorizationPageRedirect(ctx *engine.Context, page string, values url.Values) (contract.Response, error) {
	values = cloneURLValues(values)
	values.Set(SignedQueryIssuedAtParam, strconv.FormatInt(server.runtime.clock().UnixMilli(), 10))
	signed := serverSignQuery(values, server.runtime.secret)
	destination, err := serverAppendQuery(page, map[string]string{
		"oauth_query": signed, "client_id": values.Get("client_id"), "scope": values.Get("scope"),
	})
	if err != nil {
		return serverInternalError(err)
	}
	return serverRedirect(ctx, destination)
}

func (server *Server) authorizationError(ctx *engine.Context, redirectURI, state, code, description string) (contract.Response, error) {
	if redirectURI == "" {
		baseURL, err := server.runtime.resolveBaseURL(ctx.Request())
		if err != nil {
			return serverInternalError(err)
		}
		redirectURI = strings.TrimSuffix(baseURL, "/") + "/error"
	}
	return serverRedirect(ctx, serverErrorURL(redirectURI, state, server.issuer(ctx.Request()), code, description))
}

func (server *Server) authorizationSuccessURL(redirectURI, code, state string, request contract.Request) (string, error) {
	return serverAppendQuery(redirectURI, map[string]string{"code": code, "state": state, "iss": server.issuer(request)})
}

func authorizationPrompts(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	valid := map[string]struct{}{"none": {}, "consent": {}, "login": {}, "create": {}, "select_account": {}}
	result := serverUniqueStrings(strings.Fields(raw))
	for _, prompt := range result {
		if _, exists := valid[prompt]; !exists {
			return nil, errors.New("unsupported prompt type")
		}
	}
	if serverContains(result, "none") && len(result) > 1 {
		return nil, errors.New("prompt none cannot be combined with other prompts")
	}
	return result, nil
}

func authorizationSessionIdentity(session *Session, fallback time.Time) (string, string, time.Time) {
	if session == nil {
		return "", "", time.Time{}
	}
	userID := serverRecordString(session.User, "id")
	if userID == "" {
		userID = serverRecordString(session.Session, "userId")
	}
	sessionID := fmt.Sprint(session.Session["id"])
	authTime, ok := serverRecordTime(session.Session, "createdAt")
	if !ok {
		authTime = fallback
	}
	return userID, sessionID, authTime
}

func authorizationConsentWhere(client storage.Record, userID, referenceID string) []storage.Where {
	where := []storage.Where{{Field: "clientId", Value: serverRecordString(client, "clientId")}, {Field: "userId", Value: userID}}
	if referenceID != "" {
		where = append(where, storage.Where{Field: "referenceId", Value: referenceID})
	}
	return where
}

func serverRecordStringFromSession(ctx *engine.Context, resolver func(*engine.Context, bool) (*Session, error)) string {
	state, _ := resolver(ctx, false)
	if state == nil {
		return ""
	}
	return fmt.Sprint(state.Session["id"])
}
