package oauthpopup

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/providers"
)

var internalStateKeys = map[string]struct{}{
	"callbackURL": {}, "codeVerifier": {}, "errorURL": {},
	"newUserURL": {}, "expiresAt": {}, "oauthState": {},
	"link": {}, "requestSignUp": {},
}

func (p *plugin) start(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, badRequest("Invalid query")
	}
	providerID := query.Get("provider")
	if providerID == "" {
		return contract.Response{}, badRequest("provider is required")
	}
	popupOrigin := query.Get("popupOrigin")
	if popupOrigin == "" {
		return contract.Response{}, badRequest("popupOrigin is required")
	}
	popupNonce := query.Get("popupNonce")

	trusted, err := p.runtime.IsTrustedOrigin(ctx.Request(), popupOrigin, false)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if !trusted {
		if p.runtime.Logger != nil {
			p.runtime.Logger.Error("OAuth popup origin is not a trusted origin. Add " + popupOrigin + " to trustedOrigins.")
		}
		apiErr := contract.NewAPIError(contract.StatusForbidden, "INVALID_ORIGIN", "Invalid origin")
		return contract.Response{}, apiErr
	}

	fail := func(code, description string) contract.Response {
		return p.renderCompletion(popupOrigin, popupFailure(
			popupOrigin, popupNonce, code, description,
		))
	}
	redirects := []struct {
		key  string
		code string
	}{
		{key: "callbackURL", code: "invalid_callback_url"},
		{key: "errorCallbackURL", code: "invalid_error_callback_url"},
		{key: "newUserCallbackURL", code: "invalid_new_user_callback_url"},
	}
	for _, candidate := range redirects {
		value := query.Get(candidate.key)
		if value == "" {
			continue
		}
		trusted, trustErr := p.runtime.IsTrustedOrigin(ctx.Request(), value, true)
		if trustErr != nil {
			return contract.Response{}, internalError(trustErr)
		}
		if !trusted {
			if p.runtime.Logger != nil {
				p.runtime.Logger.Error("Invalid redirect URL: " + value)
			}
			return fail(candidate.code, "Untrusted URL: "+value), nil
		}
	}

	provider := p.runtime.SocialProvider(providerID)
	if provider == nil {
		return fail("provider_not_found", "Unknown provider: "+providerID), nil
	}

	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return fail("popup_sign_in_failed", "Failed to start the OAuth flow."), nil
	}
	callbackURL := query.Get("callbackURL")
	if callbackURL == "" {
		callbackURL = baseURL
	}
	additionalData := parseAdditionalData(query.Get("additionalData"))
	requestSignUp := (*bool)(nil)
	if query.Get("requestSignUp") == "true" {
		value := true
		requestSignUp = &value
	}
	state, err := p.runtime.CreateOAuthState(ctx, singleauth.PluginOAuthStateInput{
		CallbackURL:    callbackURL,
		ErrorURL:       query.Get("errorCallbackURL"),
		NewUserURL:     query.Get("newUserCallbackURL"),
		RequestSignUp:  requestSignUp,
		AdditionalData: additionalData,
	})
	if err != nil {
		if p.runtime.Logger != nil {
			p.runtime.Logger.Error("OAuth popup failed to start", err)
		}
		return fail("popup_sign_in_failed", "Failed to start the OAuth flow."), nil
	}

	markerName, markerOptions := p.runtime.Cookie(ctx.Request(), MarkerCookie, MarkerCookie)
	maxAge := 10 * 60
	markerOptions.MaxAge = &maxAge
	markerJSON, err := json.Marshal(markerData{PopupOrigin: popupOrigin, PopupNonce: popupNonce})
	if err != nil {
		return fail("popup_sign_in_failed", "Failed to start the OAuth flow."), nil
	}
	ctx.AddSetCookie(cookies.Serialize(
		markerName, signCookie(string(markerJSON), p.runtime.Secret), markerOptions,
	))

	scopes := []string(nil)
	if rawScopes := query.Get("scopes"); rawScopes != "" {
		scopes = strings.Split(rawScopes, ",")
	}
	authorizationURL, err := provider.CreateAuthorizationURL(providers.AuthorizationInput{
		State: state.State, CodeVerifier: state.CodeVerifier,
		RedirectURI: strings.TrimRight(baseURL, "/") + "/callback/" + url.PathEscape(provider.ID),
		Scopes:      scopes,
	})
	if err != nil {
		if p.runtime.Logger != nil {
			p.runtime.Logger.Error("OAuth popup failed to start", err)
		}
		return fail("popup_sign_in_failed", "Failed to start the OAuth flow."), nil
	}
	return redirect(authorizationURL.String()), nil
}

func parseAdditionalData(raw string) map[string]any {
	if raw == "" {
		return map[string]any{}
	}
	var parsed any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&parsed) != nil {
		return map[string]any{}
	}
	result := make(map[string]any)
	switch value := parsed.(type) {
	case map[string]any:
		for key, item := range value {
			if _, internal := internalStateKeys[key]; !internal {
				result[key] = item
			}
		}
	case []any:
		for index, item := range value {
			result[strconv.Itoa(index)] = item
		}
	case string:
		for index, character := range []rune(value) {
			result[strconv.Itoa(index)] = string(character)
		}
	}
	return result
}

func (p *plugin) afterCallback(
	ctx *engine.Context,
	response contract.Response,
) (*contract.Response, error) {
	redirectTo, ok := response.Headers().Get("Location")
	if !ok || redirectTo == "" {
		return nil, nil
	}
	markerName, markerOptions := p.runtime.Cookie(ctx.Request(), MarkerCookie, MarkerCookie)
	marker, ok := readSignedCookie(ctx.Request(), markerName, p.runtime.Secret)
	if !ok {
		return nil, nil
	}
	zero := 0
	markerOptions.MaxAge = &zero
	ctx.AddSetCookie(cookies.Serialize(markerName, "", markerOptions))

	var markerValue markerData
	if json.Unmarshal([]byte(marker), &markerValue) != nil {
		return nil, nil
	}
	sessionName, _ := p.runtime.SessionCookie(ctx.Request())
	var token string
	for _, raw := range response.Headers().Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(raw) {
			if parsed.Name == sessionName {
				token = parsed.Attributes.Value
				break
			}
		}
		if token != "" {
			break
		}
	}
	if token != "" {
		replacement := p.renderCompletion(markerValue.PopupOrigin, completionData{
			Nonce: markerValue.PopupNonce, Token: token, RedirectTo: redirectTo,
		})
		return &replacement, nil
	}

	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return nil, nil
	}
	redirectURL, err := resolvedURL(redirectTo, baseURL)
	if err != nil {
		return nil, nil
	}
	errorCode := redirectURL.Query().Get("error")
	if errorCode == "" {
		return nil, nil
	}
	popupError := &PopupError{Code: errorCode}
	if descriptions, exists := redirectURL.Query()["error_description"]; exists && len(descriptions) != 0 {
		value := descriptions[0]
		popupError.Description = &value
	}
	replacement := p.renderCompletion(markerValue.PopupOrigin, completionData{
		Nonce: markerValue.PopupNonce, Error: popupError,
	})
	return &replacement, nil
}
