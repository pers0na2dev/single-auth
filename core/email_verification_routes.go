package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (a *Auth) sendVerificationEmail(ctx *engine.Context) (contract.Response, error) {
	if a.options.EmailVerification.SendVerificationEmail == nil {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorVerificationEmailNotEnabled)
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	email, ok := requiredString(body, "email")
	if !ok || !validEmail(email) {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorInvalidEmail)
	}
	callbackURL := "/"
	if callback, exists := optionalString(body, "callbackURL"); exists && callback != nil {
		callbackURL = *callback
	}
	current, err := a.optionalSession(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	if current == nil {
		started := time.Now()
		user, findErr := a.findUserByEmail(ctx.GoContext(), a.adapter, strings.ToLower(email))
		if findErr != nil {
			return contract.Response{}, internalServerError(findErr)
		}
		var sendErr error
		if user == nil {
			_, sendErr = a.createEmailToken(email, "", "", a.options.EmailVerification.ExpiresIn)
		} else if verified, _ := recordBool(user, "emailVerified"); verified {
			_, sendErr = a.createEmailToken(email, "", "", a.options.EmailVerification.ExpiresIn)
		} else {
			sendErr = a.deliverVerificationEmail(ctx, user, callbackURL, "", "")
		}
		if remaining := 500*time.Millisecond - time.Since(started); remaining > 0 {
			timer := time.NewTimer(remaining)
			select {
			case <-timer.C:
			case <-ctx.GoContext().Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return contract.Response{}, ctx.GoContext().Err()
			}
		}
		if sendErr != nil {
			return contract.Response{}, sendErr
		}
		return jsonResponse(contract.StatusOK, map[string]any{"status": true})
	}
	currentEmail, _ := recordString(current.User, "email")
	if !strings.EqualFold(currentEmail, email) {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorEmailMismatch)
	}
	if verified, _ := recordBool(current.User, "emailVerified"); verified {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorEmailAlreadyVerified)
	}
	if err := a.deliverVerificationEmail(ctx, current.User, callbackURL, "", ""); err != nil {
		return contract.Response{}, err
	}
	return jsonResponse(contract.StatusOK, map[string]any{"status": true})
}

func (a *Auth) verifyEmail(ctx *engine.Context) (contract.Response, error) {
	if !a.shouldSkipOrigin(ctx) {
		if err := a.validateRedirectFields(ctx.Request()); err != nil {
			return contract.Response{}, err
		}
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, string(ErrorValidation), ErrorMessage(ErrorValidation),
		).WithCause(err)
	}
	token := query.Get("token")
	callbackURL := query.Get("callbackURL")
	claims, err := baCrypto.VerifyJWTAt(token, a.options.Secret, a.options.Clock(), 0)
	if err != nil {
		if errors.Is(err, baCrypto.ErrExpiredJWT) {
			return a.emailVerificationError(callbackURL, ErrorTokenExpired)
		}
		return a.emailVerificationError(callbackURL, ErrorInvalidToken)
	}
	email, ok := claims["email"].(string)
	if !ok || !validEmail(email) {
		return a.emailVerificationError(callbackURL, ErrorInvalidToken)
	}
	updateTo, _ := claims["updateTo"].(string)
	requestType, _ := claims["requestType"].(string)
	user, err := a.findUserByEmail(ctx.GoContext(), a.adapter, strings.ToLower(email))
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	if user == nil {
		return a.emailVerificationError(callbackURL, ErrorUserNotFound)
	}
	if updateTo != "" {
		return a.verifyEmailChange(ctx, user, email, updateTo, requestType, callbackURL)
	}
	if verified, _ := recordBool(user, "emailVerified"); verified {
		if callbackURL != "" {
			return redirectResponse(callbackURL), nil
		}
		return jsonResponse(contract.StatusOK, map[string]any{"status": true, "user": nil})
	}
	if callback := a.options.EmailVerification.BeforeEmailVerification; callback != nil {
		if err := callback(ctx.GoContext(), userFromRecord(user)); err != nil {
			return contract.Response{}, err
		}
	}
	updated, err := a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model:  "user",
		Where:  []storage.Where{{Field: "email", Value: strings.ToLower(email), Mode: storage.Insensitive}},
		Update: storage.Record{"emailVerified": true},
	})
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	if updated == nil {
		return a.emailVerificationError(callbackURL, ErrorUserNotFound)
	}
	if err := a.refreshSecondaryUser(ctx.GoContext(), updated); err != nil {
		return contract.Response{}, internalServerError(err)
	}
	if callback := a.options.EmailVerification.AfterEmailVerification; callback != nil {
		if err := callback(ctx.GoContext(), userFromRecord(updated)); err != nil {
			return contract.Response{}, err
		}
	}
	if a.options.EmailVerification.AutoSignInAfterVerification {
		current, sessionErr := a.optionalSession(ctx)
		if sessionErr != nil {
			return contract.Response{}, sessionErr
		}
		if current == nil || !strings.EqualFold(recordText(current.User, "email"), email) {
			userID, _ := recordString(user, "id")
			session, createErr := a.createSession(ctx, a.adapter, userID, false)
			if createErr != nil || session == nil {
				return contract.Response{}, baseError(
					contract.StatusInternalServerError, ErrorFailedToCreateSession,
				).WithCause(createErr)
			}
			a.setSessionCookies(ctx, session, updated, false)
		} else {
			a.setSessionCookies(ctx, current.Session, updated, false)
		}
	}
	if callbackURL != "" {
		return redirectResponse(callbackURL), nil
	}
	return jsonResponse(contract.StatusOK, map[string]any{"status": true, "user": nil})
}

func (a *Auth) verifyEmailChange(
	ctx *engine.Context,
	user storage.Record,
	email, updateTo, requestType, callbackURL string,
) (contract.Response, error) {
	current, err := a.optionalSession(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	if current != nil && recordText(current.User, "email") != email {
		return a.emailVerificationError(callbackURL, ErrorInvalidUser)
	}
	switch requestType {
	case "change-email-confirmation":
		newToken, err := a.createEmailToken(
			email, updateTo, "change-email-verification", a.options.EmailVerification.ExpiresIn,
		)
		if err != nil {
			return contract.Response{}, err
		}
		if sender := a.options.EmailVerification.SendVerificationEmail; sender != nil {
			copyUser := cloneStorageRecord(user)
			copyUser["email"] = updateTo
			verificationURL := a.baseURLForRequest(ctx.Request()) + "/verify-email?token=" +
				percentEncodeURIComponent(newToken) + "&callbackURL=" + percentEncodeURIComponent(defaultCallback(callbackURL))
			message := EmailVerificationMessage{User: userFromRecord(copyUser), URL: verificationURL, Token: newToken}
			if err := a.runBackground(ctx.GoContext(), func(background context.Context) error {
				return sender(background, message)
			}); err != nil {
				return contract.Response{}, err
			}
		}
		if callbackURL != "" {
			return redirectResponse(callbackURL), nil
		}
		return jsonResponse(contract.StatusOK, map[string]any{"status": true})
	case "change-email-verification":
		active, err := a.ensureVerificationSession(ctx, current, user)
		if err != nil {
			return contract.Response{}, err
		}
		updated, err := a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model:  "user",
			Where:  []storage.Where{{Field: "email", Value: email, Mode: storage.Insensitive}},
			Update: storage.Record{"email": strings.ToLower(updateTo), "emailVerified": true},
		})
		if err != nil {
			return contract.Response{}, internalServerError(err)
		}
		if err := a.refreshSecondaryUser(ctx.GoContext(), updated); err != nil {
			return contract.Response{}, internalServerError(err)
		}
		if callback := a.options.EmailVerification.AfterEmailVerification; callback != nil && updated != nil {
			if err := callback(ctx.GoContext(), userFromRecord(updated)); err != nil {
				return contract.Response{}, err
			}
		}
		a.setSessionCookies(ctx, active.Session, updated, false)
		if callbackURL != "" {
			return redirectResponse(callbackURL), nil
		}
		return jsonResponse(contract.StatusOK, map[string]any{
			"status": true, "user": a.publicUser(updated),
		})
	default:
		active, err := a.ensureVerificationSession(ctx, current, user)
		if err != nil {
			return contract.Response{}, err
		}
		updated, err := a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model:  "user",
			Where:  []storage.Where{{Field: "email", Value: email, Mode: storage.Insensitive}},
			Update: storage.Record{"email": strings.ToLower(updateTo), "emailVerified": false},
		})
		if err != nil {
			return contract.Response{}, internalServerError(err)
		}
		if err := a.refreshSecondaryUser(ctx.GoContext(), updated); err != nil {
			return contract.Response{}, internalServerError(err)
		}
		if sender := a.options.EmailVerification.SendVerificationEmail; sender != nil {
			newToken, tokenErr := a.createEmailToken(updateTo, "", "", time.Hour)
			if tokenErr != nil {
				return contract.Response{}, tokenErr
			}
			verificationURL := a.baseURLForRequest(ctx.Request()) + "/verify-email?token=" +
				percentEncodeURIComponent(newToken) + "&callbackURL=" + percentEncodeURIComponent(defaultCallback(callbackURL))
			message := EmailVerificationMessage{User: userFromRecord(updated), URL: verificationURL, Token: newToken}
			if err := a.runBackground(ctx.GoContext(), func(background context.Context) error {
				return sender(background, message)
			}); err != nil {
				return contract.Response{}, err
			}
		}
		a.setSessionCookies(ctx, active.Session, updated, false)
		if callbackURL != "" {
			return redirectResponse(callbackURL), nil
		}
		return jsonResponse(contract.StatusOK, map[string]any{
			"status": true, "user": a.publicUser(updated),
		})
	}
}

func (a *Auth) ensureVerificationSession(
	ctx *engine.Context,
	current *authenticatedSession,
	user storage.Record,
) (*authenticatedSession, error) {
	if current != nil {
		return current, nil
	}
	userID, _ := recordString(user, "id")
	session, err := a.createSession(ctx, a.adapter, userID, false)
	if err != nil || session == nil {
		return nil, baseError(contract.StatusInternalServerError, ErrorFailedToCreateSession).WithCause(err)
	}
	return &authenticatedSession{Session: session, User: user}, nil
}

func (a *Auth) optionalSession(ctx *engine.Context) (*authenticatedSession, error) {
	if _, ok := a.signedSessionToken(ctx.Request()); !ok {
		return nil, nil
	}
	current, err := a.sessionForEndpoint(ctx, false)
	if err == nil {
		return current, nil
	}
	if apiError, ok := contract.AsAPIError(err); ok && apiError.Code == "UNAUTHORIZED" {
		return nil, nil
	}
	return nil, err
}

func (a *Auth) deliverVerificationEmail(
	ctx *engine.Context,
	user storage.Record,
	callbackURL, updateTo, requestType string,
) error {
	token, err := a.createEmailToken(recordText(user, "email"), updateTo, requestType, a.options.EmailVerification.ExpiresIn)
	if err != nil {
		return err
	}
	verificationURL := a.baseURLForRequest(ctx.Request()) + "/verify-email?token=" +
		percentEncodeURIComponent(token) + "&callbackURL=" + percentEncodeURIComponent(defaultCallback(callbackURL))
	message := EmailVerificationMessage{User: userFromRecord(user), URL: verificationURL, Token: token}
	return a.options.EmailVerification.SendVerificationEmail(ctx.GoContext(), message)
}

func (a *Auth) createEmailToken(email, updateTo, requestType string, expiresIn time.Duration) (string, error) {
	claims := map[string]any{"email": strings.ToLower(email)}
	if updateTo != "" {
		claims["updateTo"] = strings.ToLower(updateTo)
	}
	if requestType != "" {
		claims["requestType"] = requestType
	}
	return baCrypto.SignJWTAt(claims, a.options.Secret, expiresIn, a.options.Clock())
}

func (a *Auth) emailVerificationError(callbackURL string, code ErrorCode) (contract.Response, error) {
	if callbackURL != "" {
		separator := "?"
		if strings.Contains(callbackURL, "?") {
			separator = "&"
		}
		return redirectResponse(callbackURL + separator + "error=" + string(code)), nil
	}
	return contract.Response{}, baseError(contract.StatusUnauthorized, code)
}

func defaultCallback(value string) string {
	if value == "" {
		return "/"
	}
	return value
}

func recordText(record storage.Record, key string) string {
	value, _ := recordString(record, key)
	return value
}
