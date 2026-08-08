package magiclink

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) signInMagicLink(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	email, err := requiredString(body, "email")
	if err != nil {
		return contract.Response{}, err
	}
	if !validEmail(email) {
		return contract.Response{}, invalidEmail()
	}
	name, err := optionalString(body, "name")
	if err != nil {
		return contract.Response{}, err
	}
	callbackURL, err := optionalString(body, "callbackURL")
	if err != nil {
		return contract.Response{}, err
	}
	newUserCallbackURL, err := optionalString(body, "newUserCallbackURL")
	if err != nil {
		return contract.Response{}, err
	}
	errorCallbackURL, err := optionalString(body, "errorCallbackURL")
	if err != nil {
		return contract.Response{}, err
	}
	metadata, err := optionalMetadata(body)
	if err != nil {
		return contract.Response{}, err
	}

	token, err := p.generateToken(ctx.GoContext(), email)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	storedToken, err := p.storeToken(ctx.GoContext(), token)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	value, err := encodeVerificationValue(email, name)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if _, err := p.createVerification(ctx.GoContext(), storedToken, value); err != nil {
		return contract.Response{}, internalError(err)
	}
	link, err := p.verificationURL(ctx, token, callbackURL, newUserCallbackURL, errorCallbackURL)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if err := p.options.SendMagicLink(ctx.GoContext(), MagicLinkMessage{
		Email: email, URL: link, Token: token, Metadata: metadata,
	}, ctx); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{"status": true})
}

func (p *plugin) verificationURL(
	ctx *engine.Context,
	token string,
	callbackURL, newUserCallbackURL, errorCallbackURL *string,
) (string, error) {
	base, err := p.resolveBaseURL(ctx)
	if err != nil {
		return "", err
	}
	pathname := strings.TrimRight(base.Path, "/")
	if pathname == "" || pathname == "/" {
		pathname = ""
	}
	basePath := ""
	if pathname == "" {
		basePath = p.options.Runtime.BasePath
		if basePath == "/" {
			basePath = ""
		}
	}
	link := &url.URL{
		Scheme: base.Scheme,
		Host:   base.Host,
		Path:   pathname + basePath + "/magic-link/verify",
	}
	callback := "/"
	if callbackURL != nil && *callbackURL != "" {
		callback = *callbackURL
	}
	parts := []string{
		"token=" + formEscape(token),
		"callbackURL=" + formEscape(callback),
	}
	if newUserCallbackURL != nil && *newUserCallbackURL != "" {
		parts = append(parts, "newUserCallbackURL="+formEscape(*newUserCallbackURL))
	}
	if errorCallbackURL != nil && *errorCallbackURL != "" {
		parts = append(parts, "errorCallbackURL="+formEscape(*errorCallbackURL))
	}
	link.RawQuery = strings.Join(parts, "&")
	return link.String(), nil
}

func formEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "~", "%7E")
}

func (p *plugin) magicLinkVerify(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, validationError("Invalid query")
	}
	token := query.Get("token")
	if token == "" {
		return contract.Response{}, validationError("token is required")
	}
	base, err := p.resolveBaseURL(ctx)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	callbackInput, err := decodedQueryValue(query.Get("callbackURL"), "/")
	if err != nil {
		return contract.Response{}, validationError("Invalid callbackURL")
	}
	callbackURL, err := resolveReference(base, callbackInput)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	errorInput, err := decodedQueryValue(query.Get("errorCallbackURL"), callbackURL)
	if err != nil {
		return contract.Response{}, validationError("Invalid errorCallbackURL")
	}
	errorURL, err := resolveReference(base, errorInput)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	newUserInput, err := decodedQueryValue(query.Get("newUserCallbackURL"), callbackURL)
	if err != nil {
		return contract.Response{}, validationError("Invalid newUserCallbackURL")
	}
	newUserURL, err := resolveReference(base, newUserInput)
	if err != nil {
		return contract.Response{}, internalError(err)
	}

	storedToken, err := p.storeToken(ctx.GoContext(), token)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	verification, err := p.consumeVerification(ctx.GoContext(), storedToken)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if verification == nil {
		return redirectWithError(errorURL, "INVALID_TOKEN")
	}
	value, ok := recordString(verification, "value")
	if !ok {
		return contract.Response{}, internalError(errors.New("magiclink: verification value is invalid"))
	}
	var payload struct {
		Email string  `json:"email"`
		Name  *string `json:"name"`
	}
	if err := json.Unmarshal([]byte(value), &payload); err != nil || payload.Email == "" {
		if err == nil {
			err = errors.New("magiclink: verification email is invalid")
		}
		return contract.Response{}, internalError(err)
	}

	newUser := false
	user, err := p.findUserByEmail(ctx, payload.Email)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if user == nil {
		if p.options.DisableSignUp {
			return redirectWithError(errorURL, "new_user_signup_disabled")
		}
		name := ""
		if payload.Name != nil {
			name = *payload.Name
		}
		user, err = p.createUser(ctx, payload.Email, name)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		newUser = true
		if user == nil {
			return redirectWithError(errorURL, "failed_to_create_user")
		}
	}
	verified, _ := recordBool(user, "emailVerified")
	if !verified {
		userID, ok := recordString(user, "id")
		if !ok || userID == "" {
			return contract.Response{}, internalError(errors.New("magiclink: user id is invalid"))
		}
		if err := p.revokeUnprovenAccess(ctx, userID); err != nil {
			return contract.Response{}, internalError(err)
		}
		user, err = p.updateUser(ctx, userID, storage.Record{"emailVerified": true})
		if err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	state, err := p.options.Runtime.IssueSession(ctx, cloneRecord(user))
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if state == nil || state.Session == nil {
		return redirectWithError(errorURL, "failed_to_create_session")
	}
	if state.User == nil {
		state.User = cloneRecord(user)
	}
	tokenValue, ok := recordString(state.Session, "token")
	if !ok || tokenValue == "" {
		return redirectWithError(errorURL, "failed_to_create_session")
	}
	if query.Get("callbackURL") == "" {
		return contract.JSONResponse(contract.StatusOK, map[string]any{
			"token":   tokenValue,
			"user":    p.serializeUser(user),
			"session": p.serializeSession(state.Session),
		})
	}
	if newUser {
		return redirectResponse(newUserURL), nil
	}
	return redirectResponse(callbackURL), nil
}

func decodedQueryValue(value, fallback string) (string, error) {
	if value == "" {
		return fallback, nil
	}
	return url.PathUnescape(value)
}
