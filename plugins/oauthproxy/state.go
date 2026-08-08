package oauthproxy

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func parseStateData(value []byte) (oauthStateData, error) {
	decoder := json.NewDecoder(strings.NewReader(string(value)))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return oauthStateData{}, errors.New("invalid OAuth state payload")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return oauthStateData{}, errors.New("invalid OAuth state payload")
	}
	callbackURL, callbackOK := stringValue(object["callbackURL"])
	codeVerifier, verifierOK := stringValue(object["codeVerifier"])
	expiresAt, expiresOK := timestampMilliseconds(object["expiresAt"])
	if !callbackOK || callbackURL == "" || !verifierOK || codeVerifier == "" || !expiresOK || expiresAt == 0 {
		return oauthStateData{}, errors.New("invalid OAuth state payload")
	}
	result := oauthStateData{
		CallbackURL: callbackURL, CodeVerifier: codeVerifier,
		ExpiresAt: expiresAt, Raw: object,
	}
	result.ErrorURL, _ = stringValue(object["errorURL"])
	result.NewUserURL, _ = stringValue(object["newUserURL"])
	result.OAuthState, _ = stringValue(object["oauthState"])
	if requestSignUp, ok := object["requestSignUp"].(bool); ok {
		result.RequestSignUp = &requestSignUp
	}
	return result, nil
}

func verificationValue(record storage.Record) string {
	if record == nil {
		return ""
	}
	value, _ := record["value"].(string)
	return value
}

// consumeProxyState validates and consumes the state that originated in the
// preview environment. Database values are atomically consumed. Cookie-mode
// values remain bound to the OAuth state and are expired in the response.
func (p *plugin) consumeProxyState(ctx *engine.Context, state string) bool {
	if state == "" {
		return false
	}
	var plaintext []byte
	if p.runtime.StateStrategy == "cookie" {
		name, options := p.runtime.Cookie(ctx.Request(), "oauth_state", "oauth_state")
		header := strings.Join(ctx.Request().Headers().Values("Cookie"), "; ")
		encrypted, ok := cookies.Parse(header).Get(name)
		if !ok || encrypted == "" {
			return false
		}
		var err error
		plaintext, err = p.runtime.DecryptSecret(encrypted)
		if err != nil {
			return false
		}
		data, err := parseStateData(plaintext)
		if err != nil || data.OAuthState == "" || data.OAuthState != state {
			return false
		}
		zero := 0
		options.MaxAge = &zero
		ctx.AddSetCookie(cookies.Serialize(name, "", options))
		return data.ExpiresAt >= float64(p.runtime.Clock().UnixMilli())
	}

	record, err := p.runtime.FindVerification(ctx.GoContext(), state)
	if err != nil || record == nil {
		return false
	}
	plaintext = []byte(verificationValue(record))
	data, err := parseStateData(plaintext)
	if err != nil || (data.OAuthState != "" && data.OAuthState != state) {
		return false
	}
	name, options := p.runtime.Cookie(ctx.Request(), "state", "state")
	zero := 0
	options.MaxAge = &zero
	ctx.AddSetCookie(cookies.Serialize(name, "", options))
	consumed, err := p.runtime.ConsumeVerification(ctx.GoContext(), state)
	if err != nil || consumed == nil {
		return false
	}
	return data.ExpiresAt >= float64(p.runtime.Clock().UnixMilli())
}

func (p *plugin) statePlaintextFromSignIn(
	ctx *engine.Context,
	response contract.Response,
	state string,
) ([]byte, error) {
	if p.runtime.StateStrategy != "cookie" {
		verification, err := p.runtime.FindVerification(ctx.GoContext(), state)
		if err != nil || verification == nil {
			return nil, err
		}
		value := verificationValue(verification)
		if value == "" {
			return nil, nil
		}
		return []byte(value), nil
	}
	name, _ := p.runtime.Cookie(ctx.Request(), "oauth_state", "oauth_state")
	for _, header := range response.Headers().Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(header) {
			if parsed.Name != name || parsed.Attributes.Value == "" {
				continue
			}
			return p.runtime.DecryptSecret(parsed.Attributes.Value)
		}
	}
	return nil, nil
}
