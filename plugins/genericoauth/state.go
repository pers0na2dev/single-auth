package genericoauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type stateError struct {
	code     string
	errorURL string
	cause    error
}

func (err *stateError) Error() string {
	if err == nil {
		return "<nil>"
	}
	if err.cause != nil {
		return err.code + ": " + err.cause.Error()
	}
	return err.code
}

func (err *stateError) Unwrap() error { return err.cause }

func (p *plugin) parseState(ctx *engine.Context, state string) (oauthStateData, error) {
	if state == "" {
		return oauthStateData{}, &stateError{code: "state_not_found"}
	}
	if p.runtime.StateStrategy == "cookie" {
		name, options := p.runtime.Cookie(ctx.Request(), "oauth_state", "oauth_state")
		header := strings.Join(ctx.Request().Headers().Values("Cookie"), "; ")
		encrypted, ok := cookies.Parse(header).Get(name)
		if !ok || encrypted == "" {
			return oauthStateData{}, &stateError{code: "state_mismatch"}
		}
		plain, err := p.runtime.DecryptSecret(encrypted)
		if err != nil {
			return oauthStateData{}, &stateError{code: "state_invalid", cause: err}
		}
		data, err := decodeState(plain)
		if err != nil {
			return oauthStateData{}, &stateError{code: "state_invalid", cause: err}
		}
		if data.OAuthState == "" || data.OAuthState != state {
			return oauthStateData{}, &stateError{code: "state_security_mismatch", errorURL: data.ErrorURL}
		}
		expireCookie(ctx, name, options)
		if data.ExpiresAt < p.clock().UnixMilli() {
			return oauthStateData{}, &stateError{code: "state_mismatch", errorURL: data.ErrorURL}
		}
		return data, nil
	}

	record, err := p.runtime.FindVerification(ctx.GoContext(), state)
	if err != nil {
		return oauthStateData{}, &stateError{code: "internal_server_error", cause: err}
	}
	if record == nil {
		return oauthStateData{}, &stateError{code: "state_mismatch"}
	}
	data, err := decodeState([]byte(recordString(record, "value")))
	if err != nil {
		return oauthStateData{}, &stateError{code: "state_invalid", cause: err}
	}
	if data.OAuthState != "" && data.OAuthState != state {
		return oauthStateData{}, &stateError{code: "state_security_mismatch", errorURL: data.ErrorURL}
	}
	if !p.runtime.SkipStateCookieCheck {
		name, options := p.runtime.Cookie(ctx.Request(), "state", "state")
		header := strings.Join(ctx.Request().Headers().Values("Cookie"), "; ")
		signed, ok := cookies.Parse(header).Get(name)
		if !ok || !validSignedState(signed, state, p.runtime.Secret) {
			return oauthStateData{}, &stateError{code: "state_security_mismatch", errorURL: data.ErrorURL}
		}
		expireCookie(ctx, name, options)
	}
	consumed, err := p.runtime.ConsumeVerification(ctx.GoContext(), state)
	if err != nil {
		return oauthStateData{}, &stateError{code: "internal_server_error", errorURL: data.ErrorURL, cause: err}
	}
	if consumed == nil {
		return oauthStateData{}, &stateError{code: "state_mismatch", errorURL: data.ErrorURL}
	}
	if data.ExpiresAt < p.clock().UnixMilli() {
		return oauthStateData{}, &stateError{code: "state_mismatch", errorURL: data.ErrorURL}
	}
	return data, nil
}

func decodeState(raw []byte) (oauthStateData, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	object := map[string]any{}
	if err := decoder.Decode(&object); err != nil {
		return oauthStateData{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return oauthStateData{}, errors.New("invalid OAuth state payload")
	}
	result := oauthStateData{Raw: object}
	result.CallbackURL = stringValue(object["callbackURL"])
	result.CodeVerifier = stringValue(object["codeVerifier"])
	result.ErrorURL = stringValue(object["errorURL"])
	result.NewUserURL = stringValue(object["newUserURL"])
	result.OAuthState = stringValue(object["oauthState"])
	result.ExpiresAt = int64Value(object["expiresAt"])
	if value, ok := object["requestSignUp"].(bool); ok {
		result.RequestSignUp = &value
	}
	if link, ok := object["link"].(map[string]any); ok {
		parsed := &oauthLinkState{Email: stringValue(link["email"]), UserID: stringValue(link["userId"])}
		if parsed.Email != "" && parsed.UserID != "" {
			result.Link = parsed
		}
	}
	if result.CallbackURL == "" || result.CodeVerifier == "" || result.ExpiresAt == 0 {
		return oauthStateData{}, errors.New("invalid OAuth state payload")
	}
	return result, nil
}

func validSignedState(signed, state, secret string) bool {
	index := strings.LastIndexByte(signed, '.')
	if index <= 0 || signed[:index] != state {
		return false
	}
	return baCrypto.VerifySignature(state, signed[index+1:], secret)
}

func expireCookie(ctx *engine.Context, name string, options cookies.Options) {
	zero := 0
	options.MaxAge = &zero
	ctx.AddSetCookie(cookies.Serialize(name, "", options))
}

func stateFailure(err error) (code, errorURL string) {
	var typed *stateError
	if !errors.As(err, &typed) {
		return "internal_server_error", ""
	}
	code = typed.code
	if code == "state_security_mismatch" {
		code = "state_mismatch"
	}
	if code == "" {
		code = "internal_server_error"
	}
	return code, typed.errorURL
}

func redirectError(target, fallback, code, description string) contract.Response {
	if target == "" {
		target = fallback
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" && !strings.HasPrefix(target, "/") {
		parsed, _ = url.Parse(fallback)
	}
	query := parsed.Query()
	query.Set("error", code)
	if description != "" {
		query.Set("error_description", description)
	}
	parsed.RawQuery = query.Encode()
	return contract.NewResponse(contract.StatusFound, contract.NewHeaders(contract.HeaderField{Name: "Location", Value: parsed.String()}), nil)
}

func redirect(target string) contract.Response {
	return contract.NewResponse(contract.StatusFound, contract.NewHeaders(contract.HeaderField{Name: "Location", Value: target}), nil)
}

func recordString(record storage.Record, key string) string {
	if record == nil {
		return ""
	}
	return stringValue(record[key])
}

func int64Value(value any) int64 {
	switch typed := value.(type) {
	case json.Number:
		result, _ := typed.Int64()
		return result
	case float64:
		return int64(typed)
	case int64:
		return typed
	case int:
		return int64(typed)
	default:
		return 0
	}
}

func reservedAdditionalData(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		switch key {
		case "callbackURL", "codeVerifier", "errorURL", "newUserURL", "oauthState", "expiresAt", "requestSignUp", "link":
			continue
		default:
			result[key] = value
		}
	}
	return result
}

func linkAdditionalData(userID, email string) map[string]any {
	return map[string]any{"link": map[string]any{"userId": userID, "email": email}}
}

func stateErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprint(err)
}
