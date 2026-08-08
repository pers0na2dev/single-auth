package core

import (
	"context"
	"net/url"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/storage"
)

func (a *Auth) maybeSendVerification(
	ctx context.Context,
	request contract.Request,
	user storage.Record,
	body map[string]any,
	signUp bool,
) error {
	settings := a.options.EmailVerification
	shouldSend := settings.SendOnSignIn
	if signUp {
		shouldSend = a.options.EmailAndPassword.RequireEmailVerification
		if settings.SendOnSignUp != nil {
			shouldSend = *settings.SendOnSignUp
		}
	}
	if !shouldSend || settings.SendVerificationEmail == nil {
		return nil
	}
	email, ok := recordString(user, "email")
	if !ok {
		return baseError(contract.StatusBadRequest, ErrorUserEmailNotFound)
	}
	token, err := baCrypto.SignJWTAt(
		map[string]any{"email": strings.ToLower(email)},
		a.options.Secret,
		settings.ExpiresIn,
		a.options.Clock(),
	)
	if err != nil {
		return err
	}
	callback := "/"
	if value, ok := optionalString(body, "callbackURL"); ok && value != nil {
		callback = *value
	}
	verificationURL := a.baseURLForRequest(request) + "/verify-email?token=" +
		url.QueryEscape(token) + "&callbackURL=" + url.QueryEscape(callback)
	message := EmailVerificationMessage{
		User: userFromRecord(user), URL: verificationURL, Token: token,
	}
	return a.runBackground(ctx, func(callbackContext context.Context) error {
		return settings.SendVerificationEmail(callbackContext, message)
	})
}

func (a *Auth) baseURLForRequest(request contract.Request) string {
	value, err := a.resolveBaseURLForRequest(request)
	if err != nil {
		return ""
	}
	return value
}
