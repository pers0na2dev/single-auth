package oauthproxy

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

func (p *plugin) proxyCallback(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, badRequest("Invalid query")
	}
	callbackURL := query.Get("callbackURL")
	if callbackURL == "" {
		return contract.Response{}, badRequest("callbackURL is required")
	}
	trusted, err := p.runtime.IsTrustedOrigin(ctx.Request(), callbackURL, true)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if !trusted {
		return contract.Response{}, forbidden("INVALID_CALLBACK_URL", "Invalid callbackURL")
	}
	defaultErrorURL := p.defaultErrorURL(ctx.Request())
	encryptedProfile := query.Get("profile")
	if encryptedProfile == "" {
		logError(p.runtime.Logger, "OAuth proxy callback missing profile data")
		response := redirectError(defaultErrorURL, "missing_profile", "")
		return response, nil
	}
	plaintext, err := p.decryptProxy(encryptedProfile)
	if err != nil {
		logError(p.runtime.Logger, "Failed to decrypt OAuth proxy profile", err)
		response := redirectError(defaultErrorURL, "invalid_profile", "")
		return response, nil
	}
	payload, valid := decodePassthroughPayload(plaintext)
	if !valid {
		logError(p.runtime.Logger, "Failed to parse OAuth proxy payload")
		response := redirectError(defaultErrorURL, "invalid_payload", "")
		return response, nil
	}
	errorURL := payload.ErrorURL
	if errorURL == "" {
		errorURL = defaultErrorURL
	}
	age := p.runtime.Clock().Sub(timeFromMilliseconds(payload.Timestamp))
	if age > p.maxAge || age < -10*time.Second {
		logError(p.runtime.Logger, "OAuth proxy payload expired or invalid")
		response := redirectError(errorURL, "payload_expired", "")
		return response, nil
	}
	if !p.consumeProxyState(ctx, payload.State) {
		warn(p.runtime.Logger, "OAuth proxy state missing or invalid")
		response := redirectError(errorURL, "state_mismatch", "")
		return response, nil
	}
	provider := p.runtime.SocialProvider(payload.Account.ProviderID)
	result, err := p.runtime.HandleOAuthUser(ctx, singleauth.PluginOAuthUserInput{
		Provider: provider, ProviderID: payload.Account.ProviderID,
		User: oauth2.UserInfo{
			ID: payload.UserInfo.ID, Name: payload.UserInfo.Name,
			Email: &payload.UserInfo.Email, Image: payload.UserInfo.Image,
			EmailVerified: payload.UserInfo.EmailVerified,
		},
		Tokens: oauth2.Tokens{
			AccessToken:           payload.Account.AccessToken,
			RefreshToken:          payload.Account.RefreshToken,
			IDToken:               payload.Account.IDToken,
			AccessTokenExpiresAt:  timePointer(payload.Account.AccessTokenExpiresAt),
			RefreshTokenExpiresAt: timePointer(payload.Account.RefreshTokenExpiresAt),
			Scopes:                splitScope(payload.Account.Scope),
		},
		DisableSignUp: payload.DisableSignUp,
	})
	if err != nil {
		if apiErr, ok := contract.AsAPIError(err); ok && apiErr.Code != "" {
			response := redirectError(errorURL, apiErr.Code, apiErr.Message)
			return response, nil
		}
		return contract.Response{}, err
	}
	if result.LinkError != "" {
		logError(p.runtime.Logger, "OAuth proxy callback error", result.LinkError)
		response := redirectError(errorURL, strings.ReplaceAll(result.LinkError, " ", "_"), "")
		return response, nil
	}
	if result.State.Session == nil || result.State.User == nil {
		logError(p.runtime.Logger, "OAuth proxy callback missing session data")
		response := redirectError(errorURL, "user_creation_failed", "")
		return response, nil
	}
	if err := p.runtime.RefreshSession(ctx, result.State, false); err != nil {
		return contract.Response{}, preserveError(err)
	}
	finalURL := payload.CallbackURL
	if result.IsRegister && payload.NewUserURL != "" {
		finalURL = payload.NewUserURL
	}
	return redirect(finalURL), nil
}

func decodePassthroughPayload(plaintext []byte) (passthroughPayload, bool) {
	decoder := json.NewDecoder(strings.NewReader(string(plaintext)))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return passthroughPayload{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return passthroughPayload{}, false
	}
	timestamp, timestampOK := timestampMilliseconds(object["timestamp"])
	state, stateOK := stringValue(object["state"])
	callbackURL, callbackOK := stringValue(object["callbackURL"])
	_, userOK := object["userInfo"].(map[string]any)
	_, accountOK := object["account"].(map[string]any)
	if !timestampOK || !stateOK || state == "" || !callbackOK || callbackURL == "" || !userOK || !accountOK {
		return passthroughPayload{}, false
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return passthroughPayload{}, false
	}
	var result passthroughPayload
	if json.Unmarshal(encoded, &result) != nil {
		return passthroughPayload{}, false
	}
	result.Timestamp = timestamp
	return result, true
}

func timeFromMilliseconds(value float64) time.Time {
	seconds := int64(value / 1000)
	milliseconds := value - float64(seconds*1000)
	return time.Unix(seconds, int64(milliseconds*float64(time.Millisecond))).UTC()
}

func splitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Split(scope, ",")
}

func callbackURLFromState(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return value
	}
	if callback := parsed.Query().Get("callbackURL"); callback != "" {
		return callback
	}
	return value
}
