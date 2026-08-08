package oauthproxy

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/providers"
)

func (p *plugin) beforeSignIn(ctx *engine.Context) (*contract.Response, error) {
	if p.checkSkipProxy(ctx.Request()) {
		return nil, nil
	}
	currentURL, err := p.resolveCurrentURL(ctx.Request())
	if err != nil {
		return nil, internalError(err)
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return nil, nil
	}
	originalCallback, _ := stringValue(body["callbackURL"])
	if originalCallback == "" {
		originalCallback, err = p.runtime.ResolveBaseURL(ctx.Request())
		if err != nil {
			return nil, internalError(err)
		}
	}
	proxyCallback := stripTrailingSlash(currentURL.Scheme+"://"+currentURL.Host) +
		p.runtime.BasePath + "/oauth-proxy-callback?callbackURL=" +
		url.QueryEscape(originalCallback)
	body["callbackURL"] = proxyCallback
	replacement, err := replaceJSONBody(ctx.Request(), body)
	if err != nil {
		return nil, internalError(err)
	}
	ctx.ReplaceRequest(replacement)
	return nil, nil
}

func (p *plugin) afterSignIn(
	ctx *engine.Context,
	response contract.Response,
) (*contract.Response, error) {
	if p.checkSkipProxy(ctx.Request()) {
		return nil, nil
	}
	var object map[string]any
	if json.Unmarshal(response.Body(), &object) != nil || object == nil {
		return nil, nil
	}
	providerURL, ok := stringValue(object["url"])
	if !ok || providerURL == "" {
		return nil, nil
	}
	oauthURL, err := url.Parse(providerURL)
	if err != nil {
		return nil, nil
	}
	originalState := oauthURL.Query().Get("state")
	if originalState == "" {
		return nil, nil
	}
	plaintextState, err := p.statePlaintextFromSignIn(ctx, response, originalState)
	if err != nil {
		logError(p.runtime.Logger, "Failed to prepare OAuth proxy state:", err)
		return nil, nil
	}
	if len(plaintextState) == 0 {
		warn(p.runtime.Logger, "No OAuth state found for proxy")
		return nil, nil
	}
	stateCookie, err := p.encryptProxy(plaintextState)
	if err != nil {
		logError(p.runtime.Logger, "Failed to prepare OAuth proxy state:", err)
		return nil, nil
	}
	encodedPackage, err := json.Marshal(oauthProxyStatePackage{
		State: originalState, StateCookie: stateCookie, IsOAuthProxy: true,
	})
	if err != nil {
		return nil, nil
	}
	encryptedPackage, err := p.encryptProxy(encodedPackage)
	if err != nil {
		logError(p.runtime.Logger, "Failed to prepare OAuth proxy state:", err)
		return nil, nil
	}
	query := oauthURL.Query()
	query.Set("state", encryptedPackage)
	if p.options.ProductionURL != "" {
		providerID, _ := stringValue(object["provider"])
		if providerID == "" {
			providerID, _ = stringValueFromPath(ctx.Path(), ctx.Request().Body())
		}
		provider := p.runtime.SocialProvider(providerID)
		hasDedicatedRedirect := provider != nil && provider.Options.RedirectURI != ""
		if providerID != "" && query.Has("redirect_uri") && !hasDedicatedRedirect {
			query.Set("redirect_uri", stripTrailingSlash(p.options.ProductionURL)+
				p.runtime.BasePath+"/callback/"+url.PathEscape(providerID))
		}
	}
	oauthURL.RawQuery = query.Encode()
	object["url"] = oauthURL.String()
	body, err := json.Marshal(object)
	if err != nil {
		return nil, nil
	}
	replacement := response.WithBody(body)
	if location, exists := response.Headers().Get("Location"); exists && location == providerURL {
		replacement = replacement.WithHeader("Location", oauthURL.String())
	}
	return &replacement, nil
}

func stringValueFromPath(_ string, body []byte) (string, bool) {
	var object map[string]any
	if json.Unmarshal(body, &object) != nil {
		return "", false
	}
	return stringValue(object["provider"])
}

func (p *plugin) beforeCallback(ctx *engine.Context) (*contract.Response, error) {
	params, valid := callbackParameters(ctx.Request())
	if !valid {
		return nil, nil
	}
	state, ok := stringValue(params["state"])
	if !ok || state == "" {
		return nil, nil
	}
	decryptedPackage, err := p.decryptProxy(state)
	if err != nil {
		return nil, nil
	}
	var statePackage oauthProxyStatePackage
	if json.Unmarshal(decryptedPackage, &statePackage) != nil ||
		!statePackage.IsOAuthProxy || statePackage.State == "" || statePackage.StateCookie == "" {
		warn(p.runtime.Logger, "Invalid OAuth proxy state package")
		return nil, nil
	}
	innerState, err := p.decryptProxy(statePackage.StateCookie)
	if err != nil {
		logError(p.runtime.Logger, "Failed to decrypt OAuth proxy state cookie:", err)
		return nil, nil
	}
	stateData, err := parseStateData(innerState)
	if err != nil {
		logError(p.runtime.Logger, "Failed to decrypt OAuth proxy state cookie:", err)
		return nil, nil
	}
	errorURL := stateData.ErrorURL
	if errorURL == "" {
		errorURL = p.defaultErrorURL(ctx.Request())
	}
	if stateData.OAuthState != "" && stateData.OAuthState != statePackage.State {
		response := redirectError(errorURL, "state_mismatch", "")
		return &response, nil
	}
	if callbackError, exists := optionalStringParameter(params, "error"); exists && callbackError != "" {
		response := redirectError(errorURL, callbackError, "")
		return &response, nil
	}
	code, exists := optionalStringParameter(params, "code")
	if !exists || code == "" {
		response := redirectError(errorURL, "no_code", "")
		return &response, nil
	}
	providerID, _ := ctx.Param("id")
	provider := p.runtime.SocialProvider(providerID)
	if provider == nil {
		response := redirectError(errorURL, "oauth_provider_not_found", "")
		return &response, nil
	}
	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return nil, internalError(err)
	}
	tokens, err := provider.ValidateAuthorizationCode(ctx.GoContext(), providers.CodeInput{
		Code: code, CodeVerifier: stateData.CodeVerifier,
		RedirectURI: stripTrailingSlash(baseURL) + "/callback/" + url.PathEscape(provider.ID),
	})
	if err != nil || tokens == nil {
		response := redirectError(errorURL, "invalid_code", "")
		return &response, nil
	}
	var authorizationUser []providers.AuthorizationUser
	if rawUser, exists := optionalStringParameter(params, "user"); exists && rawUser != "" {
		if user, ok := parseAuthorizationUser(rawUser); ok {
			authorizationUser = append(authorizationUser, user)
		}
	}
	userInfo, err := provider.GetUserInfo(ctx.GoContext(), *tokens, authorizationUser...)
	if err != nil || userInfo == nil {
		response := redirectError(errorURL, "unable_to_get_user_info", "")
		return &response, nil
	}
	if userInfo.User.Email == nil || *userInfo.User.Email == "" {
		response := redirectError(errorURL, "email_not_found", "")
		return &response, nil
	}
	proxyCallbackURL, err := absoluteURL(stateData.CallbackURL)
	if err != nil {
		return nil, internalError(err)
	}
	requestSignUp := stateData.RequestSignUp != nil && *stateData.RequestSignUp
	payload := passthroughPayload{
		UserInfo: passthroughUser{
			ID: userInfo.User.ID, Email: *userInfo.User.Email,
			Name: userInfo.User.Name, Image: userInfo.User.Image,
			EmailVerified: userInfo.User.EmailVerified,
		},
		Account: passthroughAccount{
			ProviderID: provider.ID, AccountID: userInfo.User.ID,
			AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
			IDToken:               tokens.IDToken,
			AccessTokenExpiresAt:  isoTimePointer(tokens.AccessTokenExpiresAt),
			RefreshTokenExpiresAt: isoTimePointer(tokens.RefreshTokenExpiresAt),
			Scope:                 strings.Join(tokens.Scopes, ","),
		},
		State:       statePackage.State,
		CallbackURL: callbackURLFromState(stateData.CallbackURL),
		NewUserURL:  stateData.NewUserURL, ErrorURL: stateData.ErrorURL,
		DisableSignUp: (provider.Options.DisableImplicitSignUp && !requestSignUp) || provider.Options.DisableSignUp,
		Timestamp:     float64(p.runtime.Clock().UnixMilli()),
	}
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, internalError(err)
	}
	encryptedPayload, err := p.encryptProxy(encodedPayload)
	if err != nil {
		return nil, internalError(err)
	}
	query := proxyCallbackURL.Query()
	query.Set("profile", encryptedPayload)
	proxyCallbackURL.RawQuery = query.Encode()
	response := redirect(proxyCallbackURL.String())
	return &response, nil
}

func callbackParameters(request contract.Request) (map[string]any, bool) {
	result := make(map[string]any)
	if len(request.Body()) != 0 {
		body, err := decodeObjectBody(request)
		if err != nil {
			return nil, false
		}
		for key, value := range body {
			result[key] = value
		}
	}
	query, err := request.Query()
	if err != nil {
		return nil, false
	}
	for key, values := range query {
		if len(values) != 0 {
			result[key] = values[0]
		}
	}
	for _, key := range []string{"code", "error", "user"} {
		if value, exists := result[key]; exists && value != nil {
			if _, ok := value.(string); !ok {
				return nil, false
			}
		}
	}
	return result, true
}

func optionalStringParameter(values map[string]any, key string) (string, bool) {
	value, exists := values[key]
	if !exists || value == nil {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func parseAuthorizationUser(value string) (providers.AuthorizationUser, bool) {
	var object struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
		Email string `json:"email"`
	}
	if json.Unmarshal([]byte(value), &object) != nil {
		return providers.AuthorizationUser{}, false
	}
	return providers.AuthorizationUser{
		FirstName: object.Name.FirstName, LastName: object.Name.LastName,
		Email: object.Email,
	}, true
}

func (p *plugin) afterCallback(
	ctx *engine.Context,
	response contract.Response,
) (*contract.Response, error) {
	location, ok := response.Headers().Get("Location")
	if !ok || !strings.Contains(location, "/oauth-proxy-callback?callbackURL") ||
		!strings.HasPrefix(location, "http") {
		return nil, nil
	}
	productionURL := p.options.ProductionURL
	if productionURL == "" {
		productionURL = p.runtime.BaseURL
	}
	if productionURL == "" {
		productionURL, _ = p.runtime.ResolveBaseURL(ctx.Request())
	}
	locationURL, err := url.Parse(location)
	if err != nil {
		return nil, nil
	}
	if locationURL.Scheme+"://"+locationURL.Host != originOf(productionURL) {
		warn(p.runtime.Logger, "OAuth proxy: cross-origin callback reached after hook unexpectedly")
		return nil, nil
	}
	newLocation := locationURL.Query().Get("callbackURL")
	if newLocation == "" {
		return nil, nil
	}
	replacement := response.WithHeader("Location", newLocation)
	return &replacement, nil
}
