package emailotp

import (
	"errors"
	"unicode/utf16"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const sensitiveSessionContextKey = "emailotp.sensitive-session"

func (p *plugin) signInEmailOTP(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	rawEmail, err := requiredString(body, "email")
	if err != nil {
		return contract.Response{}, err
	}
	provided, err := requiredString(body, "otp")
	if err != nil {
		return contract.Response{}, err
	}
	name, err := optionalString(body, "name")
	if err != nil {
		return contract.Response{}, err
	}
	image, err := optionalString(body, "image")
	if err != nil {
		return contract.Response{}, err
	}
	email := normalizeEmail(rawEmail)
	if err := p.atomicVerifyOTP(ctx, Identifier(TypeSignIn, email), provided); err != nil {
		return contract.Response{}, err
	}

	user, err := p.findUserByEmail(ctx, email)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if user == nil {
		if p.options.DisableSignUp {
			return contract.Response{}, otpError(contract.StatusBadRequest, ErrorInvalidOTP)
		}
		additional, parseErr := p.additionalUserFields(ctx, body)
		if parseErr != nil {
			return contract.Response{}, preserveRuntimeError(parseErr)
		}
		resolvedName := ""
		if name != nil {
			resolvedName = *name
		}
		user, err = p.createUser(ctx, CreateUserInput{
			Email: email, Name: resolvedName, Image: image, Additional: additional,
		})
		if err != nil {
			return contract.Response{}, internalError(err)
		}
	} else {
		verified, _ := recordBool(user, "emailVerified")
		if !verified {
			userID, ok := recordString(user, "id")
			if !ok || userID == "" {
				return contract.Response{}, internalError(errors.New("emailotp: user id is invalid"))
			}
			if err := p.revokeUnprovenAccess(ctx, userID); err != nil {
				return contract.Response{}, internalError(err)
			}
			user, err = p.updateUser(ctx, userID, storage.Record{"emailVerified": true})
			if err != nil {
				return contract.Response{}, internalError(err)
			}
		}
	}
	issued, err := p.issueSession(ctx, user)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	token, ok := recordString(issued.Session, "token")
	if !ok || token == "" {
		return contract.Response{}, internalError(errors.New("emailotp: session token is invalid"))
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"token": token,
		"user":  p.serializeUser(user),
	})
}

func (p *plugin) requestPasswordResetEmailOTP(ctx *engine.Context) (contract.Response, error) {
	return p.requestPasswordReset(ctx)
}

func (p *plugin) forgetPasswordEmailOTP(ctx *engine.Context) (contract.Response, error) {
	p.warnOld.Do(func() {
		if p.options.Runtime.Warn != nil {
			p.options.Runtime.Warn(`The "/forget-password/email-otp" endpoint is deprecated. Please use "/email-otp/request-password-reset" instead. This endpoint will be removed in the next major version.`)
		}
	})
	return p.requestPasswordReset(ctx)
}

func (p *plugin) requestPasswordReset(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	rawEmail, err := requiredString(body, "email")
	if err != nil {
		return contract.Response{}, err
	}
	email := normalizeEmail(rawEmail)
	identifier := Identifier(TypeForgetPassword, email)
	otp, err := p.resolveOTP(ctx.GoContext(), ctx, email, TypeForgetPassword)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	user, err := p.findUserByEmail(ctx, email)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if user == nil {
		if err := p.deleteVerification(ctx.GoContext(), identifier); err != nil {
			return contract.Response{}, internalError(err)
		}
		return successResponse()
	}
	if err := p.sendMessage(ctx.GoContext(), ctx, OTPMessage{Email: email, OTP: otp, Type: TypeForgetPassword}); err != nil {
		return contract.Response{}, internalError(err)
	}
	return successResponse()
}

func (p *plugin) resetPasswordEmailOTP(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	rawEmail, err := requiredString(body, "email")
	if err != nil {
		return contract.Response{}, err
	}
	provided, err := requiredString(body, "otp")
	if err != nil {
		return contract.Response{}, err
	}
	password, err := requiredString(body, "password")
	if err != nil {
		return contract.Response{}, err
	}
	length := len(utf16.Encode([]rune(password)))
	if length < p.options.Password.MinLength {
		return contract.Response{}, apiError(contract.StatusBadRequest, "PASSWORD_TOO_SHORT", "Password too short")
	}
	if length > p.options.Password.MaxLength {
		return contract.Response{}, apiError(contract.StatusBadRequest, "PASSWORD_TOO_LONG", "Password too long")
	}
	email := normalizeEmail(rawEmail)
	if err := p.atomicVerifyOTP(ctx, Identifier(TypeForgetPassword, email), provided); err != nil {
		return contract.Response{}, err
	}
	user, err := p.findUserByEmail(ctx, email)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if user == nil {
		return contract.Response{}, userNotFound()
	}
	if err := p.updatePassword(ctx, user, password); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if callback := p.options.Password.OnReset; callback != nil {
		if err := callback(ctx.GoContext(), ctx, cloneRecord(user)); err != nil {
			return contract.Response{}, preserveRuntimeError(err)
		}
	}
	verified, _ := recordBool(user, "emailVerified")
	if !verified {
		userID, ok := recordString(user, "id")
		if !ok || userID == "" {
			return contract.Response{}, internalError(errors.New("emailotp: user id is invalid"))
		}
		if _, err := p.updateUser(ctx, userID, storage.Record{"emailVerified": true}); err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	if p.options.Password.RevokeSessions {
		userID, _ := recordString(user, "id")
		if err := p.revokeSessions(ctx, userID); err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	return successResponse()
}

func (p *plugin) requireAuthoritativeSession(ctx *engine.Context) (*SessionState, error) {
	if value, ok := ctx.Value(sensitiveSessionContextKey); ok {
		if state, valid := value.(*SessionState); valid && state != nil {
			return state, nil
		}
	}
	state, err := p.options.Runtime.ResolveSession(ctx, SessionAuthoritative)
	if err != nil {
		return nil, preserveRuntimeError(err)
	}
	if state == nil || state.User == nil {
		return nil, unauthorized()
	}
	userID, _ := recordString(state.User, "id")
	email, _ := recordString(state.User, "email")
	if userID == "" || email == "" || state.Session == nil {
		return nil, unauthorized()
	}
	return state, nil
}

func (p *plugin) sensitiveSessionMiddleware(ctx *engine.Context, next engine.Next) (contract.Response, error) {
	state, err := p.options.Runtime.ResolveSession(ctx, SessionAuthoritative)
	if err != nil {
		preserved := preserveRuntimeError(err)
		return contract.ResponseFromError(preserved), preserved
	}
	if state == nil || state.User == nil || state.Session == nil {
		err := unauthorized()
		return contract.ResponseFromError(err), err
	}
	userID, _ := recordString(state.User, "id")
	email, _ := recordString(state.User, "email")
	if userID == "" || email == "" {
		err := unauthorized()
		return contract.ResponseFromError(err), err
	}
	ctx.Set(sensitiveSessionContextKey, state)
	return next()
}

func (p *plugin) requestEmailChangeEmailOTP(ctx *engine.Context) (contract.Response, error) {
	if !p.options.ChangeEmail.Enabled {
		return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "Change email with OTP is disabled")
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	rawNewEmail, err := requiredString(body, "newEmail")
	if err != nil {
		return contract.Response{}, err
	}
	provided, err := optionalString(body, "otp")
	if err != nil {
		return contract.Response{}, err
	}
	session, err := p.requireAuthoritativeSession(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	currentEmail, _ := recordString(session.User, "email")
	currentEmail = normalizeEmail(currentEmail)
	newEmail := normalizeEmail(rawNewEmail)
	if !validEmail(newEmail) {
		return contract.Response{}, invalidEmail()
	}
	if newEmail == currentEmail {
		return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "Email is the same")
	}
	if p.options.ChangeEmail.VerifyCurrentEmail {
		if provided == nil || *provided == "" {
			return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "OTP is required to verify current email")
		}
		if err := p.atomicVerifyOTP(ctx, Identifier(TypeEmailVerification, currentEmail), *provided); err != nil {
			return contract.Response{}, err
		}
	} else if provided != nil && *provided != "" && p.options.Runtime.Warn != nil {
		p.options.Runtime.Warn("OTP provided but not required for verifying current email. Set ChangeEmail.VerifyCurrentEmail to require it")
	}

	otp, err := p.generateOTP(OTPData{Email: newEmail, Type: TypeChangeEmail}, ctx)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	stored, err := p.storeOTP(ctx.GoContext(), otp)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	identifier := Identifier(TypeChangeEmail, currentEmail+"-"+newEmail)
	if _, err := p.createVerification(ctx.GoContext(), identifier, stored+":0", p.clock().Add(p.options.ExpiresIn)); err != nil {
		return contract.Response{}, internalError(err)
	}
	existing, err := p.findUserByEmail(ctx, newEmail)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if existing != nil {
		if err := p.deleteVerification(ctx.GoContext(), identifier); err != nil {
			return contract.Response{}, internalError(err)
		}
		return successResponse()
	}
	if err := p.sendMessage(ctx.GoContext(), ctx, OTPMessage{Email: newEmail, OTP: otp, Type: TypeChangeEmail}); err != nil {
		return contract.Response{}, internalError(err)
	}
	return successResponse()
}

func (p *plugin) changeEmailEmailOTP(ctx *engine.Context) (contract.Response, error) {
	if !p.options.ChangeEmail.Enabled {
		return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "Change email with OTP is disabled")
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	rawNewEmail, err := requiredString(body, "newEmail")
	if err != nil {
		return contract.Response{}, err
	}
	provided, err := requiredString(body, "otp")
	if err != nil {
		return contract.Response{}, err
	}
	session, err := p.requireAuthoritativeSession(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	currentEmail, _ := recordString(session.User, "email")
	currentEmail = normalizeEmail(currentEmail)
	newEmail := normalizeEmail(rawNewEmail)
	if !validEmail(newEmail) {
		return contract.Response{}, invalidEmail()
	}
	if newEmail == currentEmail {
		return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "Email is the same")
	}
	identifier := Identifier(TypeChangeEmail, currentEmail+"-"+newEmail)
	if err := p.atomicVerifyOTP(ctx, identifier, provided); err != nil {
		return contract.Response{}, err
	}
	currentUser, err := p.findUserByEmail(ctx, currentEmail)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if currentUser == nil {
		return contract.Response{}, userNotFound()
	}
	existing, err := p.findUserByEmail(ctx, newEmail)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if existing != nil {
		return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "Email already in use")
	}
	if hook := p.options.Runtime.BeforeEmailVerification; hook != nil {
		if err := hook(ctx.GoContext(), ctx, cloneRecord(currentUser)); err != nil {
			return contract.Response{}, preserveRuntimeError(err)
		}
	}
	userID, ok := recordString(currentUser, "id")
	if !ok || userID == "" {
		return contract.Response{}, internalError(errors.New("emailotp: user id is invalid"))
	}
	updated, err := p.updateUser(ctx, userID, storage.Record{"email": newEmail, "emailVerified": true})
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if updated == nil {
		return contract.Response{}, internalError(errors.New("emailotp: failed to update user"))
	}
	if hook := p.options.Runtime.AfterEmailVerification; hook != nil {
		if err := hook(ctx.GoContext(), ctx, cloneRecord(updated)); err != nil {
			return contract.Response{}, preserveRuntimeError(err)
		}
	}
	session.User = cloneRecord(updated)
	if err := p.options.Runtime.RefreshSession(ctx, *session); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	return successResponse()
}
