package oidcprovider

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) authorize(ctx *engine.Context) (contract.Response, error) {
	query, err := queryMap(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	return p.authorizeQuery(ctx, query, nil)
}

func (p *plugin) authorizeQuery(
	ctx *engine.Context,
	query map[string]string,
	existingSession *SessionState,
) (contract.Response, error) {
	session := existingSession
	if session == nil {
		resolved, err := p.options.Runtime.ResolveSession(ctx, false)
		if err != nil {
			return contract.Response{}, err
		}
		session = resolved
	}
	promptSet, err := ParsePrompt(query["prompt"])
	if err != nil {
		return contract.Response{}, err
	}
	if session == nil || session.User == nil || session.Session == nil {
		if promptSet.Has(PromptNone) {
			redirectURI := query["redirect_uri"]
			if redirectURI == "" {
				return contract.Response{}, invalidRequest(
					"redirect_uri is required when prompt=none and must be usable to return errors without displaying UI",
				)
			}
			clientID := query["client_id"]
			if clientID == "" {
				return contract.Response{}, invalidClient("client_id is required")
			}
			client, err := p.findClient(ctx, clientID)
			if err != nil {
				return contract.Response{}, err
			}
			if client == nil {
				return contract.Response{}, invalidClient("client_id is required")
			}
			if !contains(client.RedirectURLs, redirectURI) {
				return contract.Response{}, invalidRequest("redirect_uri is invalid or not registered for this client")
			}
			return handleRedirect(ctx, formatErrorURL(
				redirectURI, "login_required", "Authentication required but prompt is none",
			))
		}
		encoded, err := json.Marshal(query)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		setSignedPromptCookie(ctx, "oidc_login_prompt", string(encoded), p.options.Runtime.Secret, 600)
		return handleRedirect(ctx, p.options.LoginPage+"?"+ctx.Request().RawQuery())
	}

	baseURL, err := p.options.Runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	errorURL := baseURL + "/error"
	clientID := query["client_id"]
	if clientID == "" {
		return redirect(formatErrorURL(errorURL, "invalid_client", "client_id is required")), nil
	}
	if query["response_type"] == "" {
		return redirect(formatErrorURL(errorURL, "invalid_request", "response_type is required")), nil
	}
	client, err := p.findClient(ctx, clientID)
	if err != nil {
		return contract.Response{}, err
	}
	if client == nil {
		return redirect(formatErrorURL(errorURL, "invalid_client", "client_id is required")), nil
	}
	redirectURI := query["redirect_uri"]
	if redirectURI == "" || !contains(client.RedirectURLs, redirectURI) {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", "Invalid redirect URI")
	}
	if client.Disabled {
		return redirect(formatErrorURL(errorURL, "client_disabled", "client is disabled")), nil
	}
	if query["response_type"] != "code" {
		return redirect(formatErrorURL(errorURL, "unsupported_response_type", "unsupported response type")), nil
	}

	requestedScopes := strings.Fields(query["scope"])
	if len(requestedScopes) == 0 {
		requestedScopes = strings.Fields(p.options.DefaultScope)
	}
	var invalidScopes []string
	allowedScopes := p.allScopes()
	for _, scope := range requestedScopes {
		if !contains(allowedScopes, scope) {
			invalidScopes = append(invalidScopes, scope)
		}
	}
	if len(invalidScopes) > 0 {
		return handleRedirect(ctx, formatErrorURL(
			redirectURI, "invalid_scope", "The following scopes are invalid: "+strings.Join(invalidScopes, ", "),
		))
	}

	challenge := query["code_challenge"]
	challengeMethod := query["code_challenge_method"]
	if p.options.RequirePKCE && (challenge == "" || challengeMethod == "") {
		return handleRedirect(ctx, formatErrorURL(redirectURI, "invalid_request", "pkce is required"))
	}
	if challengeMethod != "" && challenge == "" {
		return handleRedirect(ctx, formatErrorURL(
			redirectURI, "invalid_request", "code_challenge_method requires code_challenge",
		))
	}
	if challenge != "" {
		challengeMethod = strings.ToLower(challengeMethod)
		if challengeMethod == "" && p.options.AllowPlainCodeChallengeMethod {
			challengeMethod = "plain"
		}
		validMethod := challengeMethod == "s256" ||
			(p.options.AllowPlainCodeChallengeMethod && challengeMethod == "plain")
		if !validMethod {
			return handleRedirect(ctx, formatErrorURL(
				redirectURI, "invalid_request", "invalid code_challenge method",
			))
		}
		query["code_challenge_method"] = challengeMethod
	}

	code, err := p.randomString(32, "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789")
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	userID, _ := recordString(session.User, "id")
	if userID == "" {
		userID, _ = recordString(session.Session, "userId")
	}
	createdAt, _ := recordTime(session.Session, "createdAt")

	hasAlreadyConsented := false
	consent, err := p.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "oauthConsent", Where: []storage.Where{
			{Field: "clientId", Value: client.ClientID}, {Field: "userId", Value: userID},
		},
	})
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if consent != nil {
		given, _ := recordBool(consent, "consentGiven")
		consentedScopes, _ := recordString(consent, "scopes")
		if given {
			hasAlreadyConsented = true
			for _, scope := range requestedScopes {
				if !contains(strings.Fields(consentedScopes), scope) {
					hasAlreadyConsented = false
					break
				}
			}
		}
	}
	skipTrustedConsent := client.SkipConsent
	if promptSet.Has(PromptNone) && !skipTrustedConsent && !hasAlreadyConsented {
		return handleRedirect(ctx, formatErrorURL(
			redirectURI, "consent_required", "Consent required but prompt is none",
		))
	}

	requireLogin := promptSet.Has(PromptLogin)
	if rawMaxAge, exists := query["max_age"]; exists {
		maxAge, parseErr := strconv.ParseInt(rawMaxAge, 10, 64)
		if parseErr == nil && maxAge >= 0 && !createdAt.IsZero() {
			sessionAge := p.clock().Sub(createdAt).Seconds()
			if sessionAge > float64(maxAge) {
				requireLogin = true
			}
		}
	}
	requireConsent := !skipTrustedConsent && (!hasAlreadyConsented || promptSet.Has(PromptConsent))
	var state *string
	if requireConsent {
		if rawState, exists := query["state"]; exists {
			value := rawState
			state = &value
		}
	}
	value := AuthorizationCodeValue{
		ClientID: client.ClientID, RedirectURI: redirectURI, Scope: requestedScopes,
		UserID: userID, AuthTime: createdAt.UnixMilli(), RequireConsent: requireConsent,
		State: state, CodeChallenge: challenge, CodeChallengeMethod: challengeMethod,
		Nonce: query["nonce"],
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if _, err := p.createVerification(
		ctx.GoContext(), code, string(encoded), p.clock().Add(p.options.CodeExpiresIn),
	); err != nil {
		return handleRedirect(ctx, formatErrorURL(
			redirectURI, "server_error", "An error occurred while processing the request",
		))
	}

	if requireLogin {
		queryJSON, err := json.Marshal(query)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		setSignedPromptCookie(ctx, "oidc_login_prompt", string(queryJSON), p.options.Runtime.Secret, 600)
		setSignedPromptCookie(ctx, "oidc_consent_prompt", code, p.options.Runtime.Secret, 600)
		loginQuery := url.Values{
			"client_id": {client.ClientID}, "code": {code}, "state": {query["state"]},
		}
		return handleRedirect(ctx, p.options.LoginPage+"?"+loginQuery.Encode())
	}
	if !requireConsent {
		stateValue := query["state"]
		if _, exists := query["state"]; !exists {
			stateValue = "undefined"
		}
		location, err := appendURLQuery(redirectURI, map[string]string{"code": code, "state": stateValue})
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		return handleRedirect(ctx, location)
	}
	if p.options.ConsentPage != "" {
		setSignedPromptCookie(ctx, "oidc_consent_prompt", code, p.options.Runtime.Secret, 600)
		consentQuery := url.Values{
			"consent_code": {code}, "client_id": {client.ClientID},
			"scope": {strings.Join(requestedScopes, " ")},
		}
		return handleRedirect(ctx, p.options.ConsentPage+"?"+consentQuery.Encode())
	}
	if p.options.GetConsentHTML == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "No consent page provided",
		)
	}
	html, err := p.options.GetConsentHTML(ctx.GoContext(), ConsentHTMLInput{
		ClientID: client.ClientID, ClientName: client.Name, ClientIcon: client.Icon,
		ClientMetadata: cloneMap(client.Metadata), Code: code,
		Scopes: append([]string(nil), requestedScopes...),
	})
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	return contract.NewResponse(contract.StatusOK, contract.NewHeaders(
		contract.HeaderField{Name: "Content-Type", Value: "text/html"},
	), []byte(html)), nil
}
