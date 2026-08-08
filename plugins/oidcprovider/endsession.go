package oidcprovider

import (
	"net/url"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) endSession(ctx *engine.Context) (contract.Response, error) {
	query, err := queryMap(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	idTokenHint := query["id_token_hint"]
	clientID := query["client_id"]
	postLogoutRedirectURI := query["post_logout_redirect_uri"]
	state := query["state"]
	validatedClientID := ""
	validatedUserID := ""

	if idTokenHint != "" {
		baseURL, resolveErr := p.options.Runtime.ResolveBaseURL(ctx.Request())
		if resolveErr == nil && p.options.UseJWTPlugin && p.options.Runtime.VerifyWithJWTPlugin != nil {
			payload, verifyErr := p.options.Runtime.VerifyWithJWTPlugin(ctx, idTokenHint, p.resolveIssuer(baseURL))
			if verifyErr == nil && payload != nil {
				validatedUserID, _ = payload["sub"].(string)
				validatedClientID = audienceString(payload["aud"])
			}
		} else if clientID != "" {
			client, findErr := p.findClient(ctx, clientID)
			if findErr == nil && client != nil && client.ClientSecret != "" {
				payload := verifyHS256(idTokenHint, client.ClientSecret, p.clock())
				if payload != nil {
					validatedUserID, _ = payload["sub"].(string)
					validatedClientID = audienceString(payload["aud"])
				}
			}
		}
	}

	if clientID != "" {
		client, err := p.findClient(ctx, clientID)
		if err != nil {
			return contract.Response{}, err
		}
		if client == nil {
			return contract.Response{}, oauthError(
				contract.StatusBadRequest, "invalid_client", "Invalid client_id",
			)
		}
		if validatedClientID != "" && validatedClientID != clientID {
			return contract.Response{}, oauthError(
				contract.StatusBadRequest, "invalid_request",
				"client_id does not match the ID Token's audience",
			)
		}
		validatedClientID = clientID
	}
	if postLogoutRedirectURI != "" {
		if validatedClientID == "" {
			return contract.Response{}, oauthError(
				contract.StatusBadRequest, "invalid_request",
				"client_id is required when using post_logout_redirect_uri without a valid id_token_hint",
			)
		}
		client, err := p.findClient(ctx, validatedClientID)
		if err != nil {
			return contract.Response{}, err
		}
		if client == nil {
			return contract.Response{}, oauthError(
				contract.StatusBadRequest, "invalid_client", "Invalid client",
			)
		}
		if !contains(client.RedirectURLs, postLogoutRedirectURI) {
			return contract.Response{}, oauthError(
				contract.StatusBadRequest, "invalid_request",
				"post_logout_redirect_uri is not registered for this client",
			)
		}
	}

	session, err := p.options.Runtime.ResolveSession(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if validatedUserID != "" || session != nil {
		fetchSite, _ := ctx.Request().Headers().Get("Sec-Fetch-Site")
		originHeader, _ := ctx.Request().Headers().Get("Origin")
		if originHeader == "" {
			originHeader, _ = ctx.Request().Headers().Get("Referer")
		}
		sameSite := fetchSite == "same-origin" || fetchSite == "same-site" || fetchSite == "none"
		if !sameSite && originHeader != "" && p.options.Runtime.IsTrustedOrigin != nil {
			trusted, trustErr := p.options.Runtime.IsTrustedOrigin(ctx.Request(), originHeader, false)
			if trustErr != nil {
				return contract.Response{}, internalError(trustErr)
			}
			sameSite = trusted
		}
		sessionUserID := ""
		if session != nil {
			sessionUserID, _ = recordString(session.User, "id")
		}
		hintMatchesSession := validatedUserID != "" && validatedUserID == sessionUserID
		if !sameSite && !hintMatchesSession {
			return contract.Response{}, oauthError(
				contract.StatusForbidden, "invalid_request",
				"Logout must be same-site or carry an id_token_hint for the current session",
			)
		}
	}

	userID := validatedUserID
	if userID == "" && session != nil {
		userID, _ = recordString(session.User, "id")
	}
	if userID != "" {
		if _, err := p.adapter(ctx.GoContext()).DeleteMany(ctx.GoContext(), storage.DeleteManyParams{
			Model: "oauthAccessToken", Where: []storage.Where{{Field: "userId", Value: userID}},
		}); err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	if session != nil {
		token, _ := recordString(session.Session, "token")
		if token != "" && p.options.Runtime.DeleteSession != nil {
			if err := p.options.Runtime.DeleteSession(ctx.GoContext(), token); err != nil {
				return contract.Response{}, internalError(err)
			}
		}
		if p.options.Runtime.SessionCookie != nil {
			name, options := p.options.Runtime.SessionCookie(ctx.Request())
			zero := 0
			options.MaxAge = &zero
			ctx.AddSetCookie(cookies.Serialize(name, "", options))
		}
	}
	if postLogoutRedirectURI != "" {
		redirectURL, err := url.Parse(postLogoutRedirectURI)
		if err != nil || !redirectURL.IsAbs() {
			return contract.Response{}, oauthError(
				contract.StatusBadRequest, "invalid_request", "Invalid post_logout_redirect_uri format",
			)
		}
		if state != "" {
			parameters := redirectURL.Query()
			parameters.Set("state", state)
			redirectURL.RawQuery = parameters.Encode()
		}
		return redirect(redirectURL.String()), nil
	}
	return jsonResponse(contract.StatusOK, map[string]any{
		"success": true, "message": "Logout successful",
	})
}

func audienceString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []string:
		if len(typed) > 0 {
			return typed[0]
		}
	case []any:
		if len(typed) > 0 {
			result, _ := typed[0].(string)
			return result
		}
	}
	return ""
}
