package mcp

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) authorize(ctx *engine.Context) (contract.Response, error) {
	values, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, validationError("Invalid query")
	}
	query := make(map[string]string, len(values))
	for key, entries := range values {
		if len(entries) > 0 {
			query[key] = entries[0]
		}
	}
	return p.authorizeQuery(ctx, query, nil)
}

func (p *plugin) authorizeQuery(
	ctx *engine.Context,
	query map[string]string,
	existingSession *SessionState,
) (contract.Response, error) {
	addProtocolCORS(ctx)
	session := existingSession
	if session == nil {
		resolved, err := p.options.Runtime.ResolveSession(ctx, false)
		if err != nil {
			return contract.Response{}, err
		}
		session = resolved
	}
	if session == nil || session.User == nil || session.Session == nil {
		encoded, err := json.Marshal(query)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		setSignedPromptCookie(ctx, "oidc_login_prompt", string(encoded), p.options.Runtime.Secret, 600)
		return redirect(p.options.LoginPage + "?" + ctx.Request().RawQuery()), nil
	}

	baseURL, err := p.options.Runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	clientID := query["client_id"]
	if clientID == "" {
		return redirect(baseURL + "/error?error=invalid_client"), nil
	}
	if query["response_type"] == "" {
		return redirect(redirectErrorURL(baseURL+"/error", "invalid_request", "response_type is required")), nil
	}
	record, err := p.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "oauthApplication", Where: []storage.Where{{Field: "clientId", Value: clientID}},
	})
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if record == nil {
		return redirect(baseURL + "/error?error=invalid_client"), nil
	}
	client, err := clientFromRecord(record)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	redirectURI := query["redirect_uri"]
	if redirectURI == "" || !contains(client.RedirectURLs, redirectURI) {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", "Invalid redirect URI")
	}
	if client.Disabled {
		return redirect(baseURL + "/error?error=client_disabled"), nil
	}
	if query["response_type"] != "code" {
		return redirect(baseURL + "/error?error=unsupported_response_type"), nil
	}

	requestedScopes := strings.Fields(query["scope"])
	if len(requestedScopes) == 0 {
		requestedScopes = strings.Fields(p.options.OIDCConfig.DefaultScope)
	}
	var invalidScopes []string
	allowedScopes := p.allScopes()
	for _, scope := range requestedScopes {
		if !contains(allowedScopes, scope) {
			invalidScopes = append(invalidScopes, scope)
		}
	}
	if len(invalidScopes) > 0 {
		return redirect(redirectErrorURL(
			redirectURI, "invalid_scope",
			"The following scopes are invalid: "+strings.Join(invalidScopes, ", "),
		)), nil
	}

	challenge := query["code_challenge"]
	challengeMethod := query["code_challenge_method"]
	if p.options.OIDCConfig.RequirePKCE && (challenge == "" || challengeMethod == "") {
		return redirect(redirectErrorURL(redirectURI, "invalid_request", "pkce is required")), nil
	}
	if challengeMethod != "" && challenge == "" {
		return redirect(redirectErrorURL(
			redirectURI, "invalid_request", "code_challenge_method requires code_challenge",
		)), nil
	}
	if challenge != "" {
		challengeMethod = strings.ToLower(challengeMethod)
		if challengeMethod == "" && p.options.OIDCConfig.AllowPlainCodeChallengeMethod {
			challengeMethod = "plain"
		}
		allowed := challengeMethod == "s256" ||
			(p.options.OIDCConfig.AllowPlainCodeChallengeMethod && challengeMethod == "plain")
		if !allowed {
			return redirect(redirectErrorURL(
				redirectURI, "invalid_request", "invalid code_challenge method",
			)), nil
		}
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
	var state *string
	if query["prompt"] == "consent" {
		if rawState, exists := query["state"]; exists {
			state = &rawState
		}
	}
	value := codeVerificationValue{
		ClientID: client.ClientID, RedirectURI: redirectURI, Scope: requestedScopes,
		UserID: userID, AuthTime: createdAt.UnixMilli(),
		RequireConsent: query["prompt"] == "consent", State: state,
		CodeChallenge: challenge, CodeChallengeMethod: challengeMethod, Nonce: query["nonce"],
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if _, err := p.createVerification(
		ctx.GoContext(), code, string(encoded), p.clock().Add(p.options.OIDCConfig.CodeExpiresIn),
	); err != nil {
		return redirect(redirectErrorURL(
			redirectURI, "server_error", "An error occurred while processing the request",
		)), nil
	}

	if query["prompt"] != "consent" {
		values := map[string]string{"code": code}
		if rawState, exists := query["state"]; exists && rawState != "" {
			values["state"] = rawState
		}
		location, err := appendURLQuery(redirectURI, values)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		return redirect(location), nil
	}
	if p.options.OIDCConfig.ConsentPage != "" {
		setSignedPromptCookie(ctx, "oidc_consent_prompt", code, p.options.Runtime.Secret, 600)
		queryString := "consent_code=" + url.QueryEscape(code) +
			"&client_id=" + url.QueryEscape(client.ClientID) +
			"&scope=" + url.QueryEscape(strings.Join(requestedScopes, " "))
		return redirect(p.options.OIDCConfig.ConsentPage + "?" + queryString), nil
	}
	values := map[string]string{"code": code}
	if rawState, exists := query["state"]; exists && rawState != "" {
		values["state"] = rawState
	}
	location, err := appendURLQuery(redirectURI, values)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	return redirect(location), nil
}
