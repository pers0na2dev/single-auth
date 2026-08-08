package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const oauthRandomAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"

type oauthLinkState struct {
	Email  string `json:"email"`
	UserID string `json:"userId"`
}

type oauthStateData struct {
	CallbackURL   string          `json:"callbackURL"`
	CodeVerifier  string          `json:"codeVerifier"`
	ErrorURL      string          `json:"errorURL,omitempty"`
	NewUserURL    string          `json:"newUserURL,omitempty"`
	OAuthState    string          `json:"oauthState,omitempty"`
	Link          *oauthLinkState `json:"link,omitempty"`
	ExpiresAt     int64           `json:"expiresAt"`
	RequestSignUp *bool           `json:"requestSignUp,omitempty"`
	Raw           map[string]any  `json:"-"`
}

type oauthStateError struct {
	code     string
	errorURL string
	cause    error
}

func (e *oauthStateError) Error() string {
	if e.cause != nil {
		return e.code + ": " + e.cause.Error()
	}
	return e.code
}

func (e *oauthStateError) Unwrap() error { return e.cause }

func (a *Auth) generateOAuthState(
	ctx *engine.Context,
	body map[string]any,
	link *oauthLinkState,
) (oauthStateData, string, error) {
	callbackURL := ""
	if value, exists := optionalString(body, "callbackURL"); exists && value != nil && *value != "" {
		callbackURL = *value
	} else {
		callbackURL = a.baseOriginForRequest(ctx.Request())
	}
	if callbackURL == "" {
		return oauthStateData{}, "", baseError(contract.StatusBadRequest, ErrorCallbackURLRequired)
	}
	codeVerifier, err := randomStringFromAlphabet(a.options.Random, 128, oauthRandomAlphabet)
	if err != nil {
		return oauthStateData{}, "", err
	}
	state, err := randomStringFromAlphabet(a.options.Random, 32, oauthRandomAlphabet)
	if err != nil {
		return oauthStateData{}, "", err
	}
	data := oauthStateData{
		CallbackURL: callbackURL, CodeVerifier: codeVerifier, Link: link,
		ExpiresAt: a.options.Clock().Add(10 * time.Minute).UnixMilli(), OAuthState: state,
	}
	if value, exists := optionalString(body, "errorCallbackURL"); exists && value != nil {
		data.ErrorURL = *value
	}
	if value, exists := optionalString(body, "newUserCallbackURL"); exists && value != nil {
		data.NewUserURL = *value
	}
	if value, exists := optionalBool(body, "requestSignUp"); exists {
		data.RequestSignUp = value
	}
	data.Raw = make(map[string]any)
	if additional, ok := body["additionalData"].(map[string]any); ok {
		for key, value := range additional {
			data.Raw[key] = value
		}
	}
	encoded, err := marshalOAuthState(data)
	if err != nil {
		return oauthStateData{}, "", err
	}

	if a.options.Account.StoreStateStrategy == "cookie" {
		encrypted, encryptErr := a.encryptOAuthValue(encoded)
		if encryptErr != nil {
			return oauthStateData{}, "", encryptErr
		}
		config := a.cookiesForRequest(ctx.Request())
		ctx.AddSetCookie(cookies.Serialize(config.oauthStateName, encrypted, config.oauthState))
		return data, state, nil
	}

	signed := state + "." + baCrypto.MakeSignature(state, a.options.Secret)
	config := a.cookiesForRequest(ctx.Request())
	ctx.AddSetCookie(cookies.Serialize(config.stateName, signed, config.state))
	if _, err := a.createVerification(
		ctx, state, string(encoded), a.options.Clock().Add(10*time.Minute),
	); err != nil {
		return oauthStateData{}, "", contract.NewAPIError(
			contract.StatusInternalServerError,
			string(ErrorFailedToCreateVerification),
			ErrorMessage(ErrorFailedToCreateVerification),
		).WithCause(err)
	}
	return data, state, nil
}

func (a *Auth) parseOAuthState(ctx *engine.Context, state string) (oauthStateData, error) {
	if state == "" {
		return oauthStateData{}, &oauthStateError{code: "state_not_found"}
	}
	var data oauthStateData
	if a.options.Account.StoreStateStrategy == "cookie" {
		config := a.cookiesForRequest(ctx.Request())
		header := strings.Join(ctx.Request().Headers().Values("Cookie"), "; ")
		encrypted, ok := cookies.Parse(header).Get(config.oauthStateName)
		if !ok || encrypted == "" {
			return oauthStateData{}, &oauthStateError{code: "state_mismatch"}
		}
		plain, err := baCrypto.DecryptWithConfig(a.options.secretConfig, encrypted)
		if err != nil {
			return oauthStateData{}, &oauthStateError{code: "state_invalid", cause: err}
		}
		data, err = unmarshalOAuthState(plain)
		if err != nil {
			return oauthStateData{}, &oauthStateError{code: "state_invalid", cause: err}
		}
		if data.OAuthState == "" || data.OAuthState != state {
			return oauthStateData{}, &oauthStateError{
				code: "state_security_mismatch", errorURL: data.ErrorURL,
			}
		}
		a.expireOAuthCookie(ctx, config.oauthStateName, config.oauthState)
	} else {
		verification, err := a.findVerification(ctx, state)
		if err != nil {
			return oauthStateData{}, &oauthStateError{code: "internal_server_error", cause: err}
		}
		if verification == nil {
			return oauthStateData{}, &oauthStateError{code: "state_mismatch"}
		}
		value, _ := recordString(verification, "value")
		data, err = unmarshalOAuthState([]byte(value))
		if err != nil {
			return oauthStateData{}, &oauthStateError{code: "state_invalid", cause: err}
		}
		if data.OAuthState != "" && data.OAuthState != state {
			return oauthStateData{}, &oauthStateError{
				code: "state_security_mismatch", errorURL: data.ErrorURL,
			}
		}
		if !a.options.Account.SkipStateCookieCheck {
			config := a.cookiesForRequest(ctx.Request())
			persisted, ok := a.signedCookieValue(ctx.Request(), config.stateName)
			if !ok || persisted != state {
				return oauthStateData{}, &oauthStateError{
					code: "state_security_mismatch", errorURL: data.ErrorURL,
				}
			}
		}
		config := a.cookiesForRequest(ctx.Request())
		a.expireOAuthCookie(ctx, config.stateName, config.state)
		consumed, err := a.consumeStoredVerification(ctx.GoContext(), state)
		if err != nil {
			return oauthStateData{}, &oauthStateError{
				code: "internal_server_error", errorURL: data.ErrorURL, cause: err,
			}
		}
		if consumed == nil {
			return oauthStateData{}, &oauthStateError{
				code: "state_mismatch", errorURL: data.ErrorURL,
			}
		}
	}
	if data.ExpiresAt < a.options.Clock().UnixMilli() {
		return oauthStateData{}, &oauthStateError{code: "state_mismatch", errorURL: data.ErrorURL}
	}
	return data, nil
}

func marshalOAuthState(data oauthStateData) ([]byte, error) {
	object := make(map[string]any, len(data.Raw)+8)
	for key, value := range data.Raw {
		object[key] = value
	}
	object["callbackURL"] = data.CallbackURL
	object["codeVerifier"] = data.CodeVerifier
	object["expiresAt"] = data.ExpiresAt
	object["oauthState"] = data.OAuthState
	if data.ErrorURL != "" {
		object["errorURL"] = data.ErrorURL
	}
	if data.NewUserURL != "" {
		object["newUserURL"] = data.NewUserURL
	}
	if data.Link != nil {
		object["link"] = data.Link
	}
	if data.RequestSignUp != nil {
		object["requestSignUp"] = *data.RequestSignUp
	}
	return marshalJSON(object)
}

func unmarshalOAuthState(value []byte) (oauthStateData, error) {
	var object map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(value)))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		return oauthStateData{}, err
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return oauthStateData{}, err
	}
	var data oauthStateData
	if err := json.Unmarshal(encoded, &data); err != nil {
		return oauthStateData{}, err
	}
	if data.CallbackURL == "" || data.CodeVerifier == "" || data.ExpiresAt == 0 {
		return oauthStateData{}, errors.New("invalid OAuth state payload")
	}
	data.Raw = object
	return data, nil
}

func (a *Auth) encryptOAuthValue(value []byte) (string, error) {
	if len(a.options.secretConfig.Keys) == 0 {
		return baCrypto.EncryptWithReader(a.options.Secret, value, a.options.Random)
	}
	return baCrypto.EncryptWithConfigAndReader(a.options.secretConfig, value, a.options.Random)
}

func (a *Auth) expireOAuthCookie(ctx *engine.Context, name string, options cookies.Options) {
	zero := 0
	options.MaxAge = &zero
	ctx.AddSetCookie(cookies.Serialize(name, "", options))
}

func (a *Auth) oauthErrorURL(request contract.Request) string {
	if a.options.OnAPIError.ErrorURL != "" {
		return a.options.OnAPIError.ErrorURL
	}
	return a.baseURLForRequest(request) + "/error"
}

func (a *Auth) redirectOAuthError(
	request contract.Request,
	target, code, description string,
) contract.Response {
	if target == "" {
		target = a.oauthErrorURL(request)
	}
	if _, err := url.Parse(target); err != nil {
		target = a.oauthErrorURL(request)
	}
	query := url.Values{}
	query.Set("error", code)
	if description != "" {
		query.Set("error_description", description)
	}
	separator := "?"
	if strings.Contains(target, "?") {
		separator = "&"
	}
	return redirectResponse(target + separator + query.Encode())
}

func oauthStateFailure(err error) (code, errorURL string) {
	var stateErr *oauthStateError
	if !errors.As(err, &stateErr) {
		return "internal_server_error", ""
	}
	code = stateErr.code
	if code == "state_security_mismatch" {
		code = "state_mismatch"
	}
	if code == "" {
		code = "internal_server_error"
	}
	return code, stateErr.errorURL
}

func requireStringMap(value any, field string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", field)
	}
	return object, nil
}
