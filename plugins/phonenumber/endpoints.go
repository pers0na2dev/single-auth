package phonenumber

import (
	"context"
	"errors"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) validatePhoneNumber(phoneNumber string) error {
	if p.options.PhoneNumberValidator == nil {
		return nil
	}
	valid, err := p.options.PhoneNumberValidator(phoneNumber)
	if err != nil {
		return internalError(err)
	}
	if !valid {
		return phoneError(contract.StatusBadRequest, CodeInvalidPhoneNumber)
	}
	return nil
}

func (p *plugin) findUser(ctx *engine.Context, phoneNumber string) (storage.Record, error) {
	return p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "phoneNumber", Value: phoneNumber}},
	})
}

func (p *plugin) findCredentialAccount(ctx *engine.Context, userID string) (storage.Record, error) {
	return p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "account", Where: []storage.Where{
			{Field: "userId", Value: userID}, {Field: "providerId", Value: "credential"},
		},
	})
}

func (p *plugin) signInPhoneNumber(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	phoneNumber, err := requiredString(body, "phoneNumber")
	if err != nil {
		return contract.Response{}, err
	}
	password, err := requiredString(body, "password")
	if err != nil {
		return contract.Response{}, err
	}
	rememberMe, err := optionalBool(body, "rememberMe")
	if err != nil {
		return contract.Response{}, err
	}
	if err := p.validatePhoneNumber(phoneNumber); err != nil {
		return contract.Response{}, err
	}
	user, err := p.findUser(ctx, phoneNumber)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if user == nil {
		return contract.Response{}, phoneError(contract.StatusUnauthorized, CodeInvalidPhoneOrPassword)
	}
	verified, _ := recordBool(user, "phoneNumberVerified")
	if p.options.RequireVerification && !verified {
		code, generateErr := randomDigits(p.random, p.options.OTPLength)
		if generateErr != nil {
			return contract.Response{}, internalError(generateErr)
		}
		if _, createErr := p.createVerification(ctx.GoContext(), phoneNumber, code); createErr != nil {
			return contract.Response{}, internalError(createErr)
		}
		if p.options.SendOTP != nil {
			message := OTPMessage{PhoneNumber: phoneNumber, Code: code}
			if runErr := p.runAwaitable(ctx, func(callbackContext context.Context) error {
				return p.options.SendOTP(callbackContext, message, ctx)
			}); runErr != nil {
				return contract.Response{}, preserveRuntimeError(runErr)
			}
		}
		return contract.Response{}, phoneError(contract.StatusUnauthorized, CodePhoneNumberNotVerified)
	}
	userID, ok := recordString(user, "id")
	if !ok || userID == "" {
		return contract.Response{}, internalError(errors.New("phonenumber: user id is invalid"))
	}
	account, err := p.findCredentialAccount(ctx, userID)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if account == nil {
		p.warn("Credential account not found")
		return contract.Response{}, phoneError(contract.StatusUnauthorized, CodeInvalidPhoneOrPassword)
	}
	currentPassword, ok := recordString(account, "password")
	if !ok || currentPassword == "" {
		p.warn("Password not found")
		return contract.Response{}, phoneError(contract.StatusUnauthorized, CodeUnexpectedError)
	}
	if !p.options.Runtime.VerifyPassword(currentPassword, password) {
		p.warn("Invalid password")
		return contract.Response{}, phoneError(contract.StatusUnauthorized, CodeInvalidPhoneOrPassword)
	}
	dontRemember := rememberMe != nil && !*rememberMe
	state, err := p.options.Runtime.IssueSession(ctx, userID, dontRemember)
	if err != nil || state == nil || state.Session == nil {
		return contract.Response{}, baseError(
			contract.StatusUnauthorized, string(singleauth.ErrorFailedToCreateSession),
			singleauth.ErrorMessage(singleauth.ErrorFailedToCreateSession),
		).WithCause(err)
	}
	token, ok := recordString(state.Session, "token")
	if !ok || token == "" {
		return contract.Response{}, baseError(
			contract.StatusUnauthorized, string(singleauth.ErrorFailedToCreateSession),
			singleauth.ErrorMessage(singleauth.ErrorFailedToCreateSession),
		)
	}
	responseUser := state.User
	if responseUser == nil {
		responseUser = user
	}
	return successResponse(map[string]any{"token": token, "user": p.serializeUser(responseUser)})
}

func (p *plugin) sendPhoneNumberOTP(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	phoneNumber, err := requiredString(body, "phoneNumber")
	if err != nil {
		return contract.Response{}, err
	}
	if p.options.SendOTP == nil {
		p.warn("sendOTP not implemented")
		return contract.Response{}, phoneError(501, CodeSendOTPNotImplemented)
	}
	if err := p.validatePhoneNumber(phoneNumber); err != nil {
		return contract.Response{}, err
	}
	code, err := randomDigits(p.random, p.options.OTPLength)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if _, err := p.createVerification(ctx.GoContext(), phoneNumber, code+":0"); err != nil {
		return contract.Response{}, internalError(err)
	}
	message := OTPMessage{PhoneNumber: phoneNumber, Code: code}
	if p.options.Runtime.BackgroundTasksEnabled {
		// single-auth invokes sendOTP first to obtain its Promise and only then
		// hands that Promise to the background handler. Invoke the Go callback
		// before the runner for the same observable ordering.
		callbackErr := p.options.SendOTP(ctx.GoContext(), message, ctx)
		err := p.options.Runtime.RunBackground(ctx.GoContext(), func(backgroundContext context.Context) error {
			_ = backgroundContext
			if callbackErr != nil {
				p.logError("Failed to run background task:", callbackErr)
			}
			return nil
		})
		if err != nil {
			p.logError("Failed to run background task:", err)
		}
	} else if err := p.options.SendOTP(ctx.GoContext(), message, ctx); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	return successResponse(map[string]any{"message": "code sent"})
}

func (p *plugin) verifyPhoneNumber(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	phoneNumber, err := requiredString(body, "phoneNumber")
	if err != nil {
		return contract.Response{}, err
	}
	code, err := requiredString(body, "code")
	if err != nil {
		return contract.Response{}, err
	}
	disableSession, err := optionalBool(body, "disableSession")
	if err != nil {
		return contract.Response{}, err
	}
	updatePhoneNumber, err := optionalBool(body, "updatePhoneNumber")
	if err != nil {
		return contract.Response{}, err
	}
	if p.options.VerifyOTP != nil {
		valid, verifyErr := p.options.VerifyOTP(
			ctx.GoContext(), OTPMessage{PhoneNumber: phoneNumber, Code: code}, ctx,
		)
		if verifyErr != nil {
			return contract.Response{}, preserveRuntimeError(verifyErr)
		}
		if !valid {
			return contract.Response{}, phoneError(contract.StatusBadRequest, CodeInvalidOTP)
		}
		if existing, findErr := p.peekVerification(ctx.GoContext(), phoneNumber); findErr != nil {
			return contract.Response{}, internalError(findErr)
		} else if existing != nil {
			if deleteErr := p.deleteVerification(ctx.GoContext(), phoneNumber); deleteErr != nil {
				return contract.Response{}, internalError(deleteErr)
			}
		}
	} else if err := p.verifyInternalOTP(ctx, phoneNumber, code); err != nil {
		return contract.Response{}, err
	}

	if updatePhoneNumber != nil && *updatePhoneNumber {
		return p.updateVerifiedPhoneNumber(ctx, phoneNumber)
	}
	return p.completeVerification(ctx, body, phoneNumber, disableSession != nil && *disableSession)
}

func (p *plugin) updateVerifiedPhoneNumber(
	ctx *engine.Context,
	phoneNumber string,
) (contract.Response, error) {
	state, err := p.options.Runtime.ResolveSession(ctx)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if state == nil || state.User == nil || state.Session == nil {
		return contract.Response{}, baseError(
			contract.StatusUnauthorized, string(singleauth.ErrorUserNotFound),
			singleauth.ErrorMessage(singleauth.ErrorUserNotFound),
		)
	}
	existing, err := p.options.Runtime.Adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "user", Where: []storage.Where{{Field: "phoneNumber", Value: phoneNumber}},
	})
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if len(existing) > 0 {
		return contract.Response{}, phoneError(contract.StatusBadRequest, CodePhoneNumberExists)
	}
	userID, ok := recordString(state.User, "id")
	if !ok || userID == "" {
		return contract.Response{}, internalError(errors.New("phonenumber: session user id is invalid"))
	}
	user, err := p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		Update: storage.Record{"phoneNumber": phoneNumber, "phoneNumberVerified": true},
	})
	if err != nil {
		if errors.Is(err, storage.ErrUniqueConstraint) {
			return contract.Response{}, phoneError(contract.StatusBadRequest, CodePhoneNumberExists)
		}
		return contract.Response{}, internalError(err)
	}
	if user == nil {
		return contract.Response{}, baseError(
			contract.StatusInternalServerError, string(singleauth.ErrorFailedToUpdateUser),
			singleauth.ErrorMessage(singleauth.ErrorFailedToUpdateUser),
		)
	}
	if err := p.runVerificationCallback(ctx, phoneNumber, user); err != nil {
		return contract.Response{}, err
	}
	token, _ := recordString(state.Session, "token")
	return successResponse(map[string]any{
		"status": true, "token": token, "user": p.serializeUser(user),
	})
}

func (p *plugin) completeVerification(
	ctx *engine.Context,
	body map[string]any,
	phoneNumber string,
	disableSession bool,
) (contract.Response, error) {
	user, err := p.findUser(ctx, phoneNumber)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if user == nil && p.options.SignUpOnVerification != nil {
		rest := cloneObject(body)
		for _, field := range []string{"phoneNumber", "code", "disableSession", "updatePhoneNumber"} {
			delete(rest, field)
		}
		additional, parseErr := p.options.Runtime.ParseUserInput(ctx, rest)
		if parseErr != nil {
			return contract.Response{}, preserveRuntimeError(parseErr)
		}
		name := phoneNumber
		if p.options.SignUpOnVerification.GetTempName != nil {
			name = p.options.SignUpOnVerification.GetTempName(phoneNumber)
		}
		input := cloneRecord(additional)
		if input == nil {
			input = storage.Record{}
		}
		input["email"] = p.options.SignUpOnVerification.GetTempEmail(phoneNumber)
		input["name"] = name
		input["phoneNumber"] = phoneNumber
		input["phoneNumberVerified"] = true
		user, err = p.options.Runtime.CreateUser(ctx, input)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		if user == nil {
			return contract.Response{}, baseError(
				contract.StatusInternalServerError, string(singleauth.ErrorFailedToCreateUser),
				singleauth.ErrorMessage(singleauth.ErrorFailedToCreateUser),
			)
		}
	} else if user != nil {
		userID, ok := recordString(user, "id")
		if !ok || userID == "" {
			return contract.Response{}, internalError(errors.New("phonenumber: user id is invalid"))
		}
		user, err = p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
			Update: storage.Record{"phoneNumberVerified": true},
		})
		if err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	if user == nil {
		return contract.Response{}, baseError(
			contract.StatusInternalServerError, string(singleauth.ErrorFailedToUpdateUser),
			singleauth.ErrorMessage(singleauth.ErrorFailedToUpdateUser),
		)
	}
	if err := p.runVerificationCallback(ctx, phoneNumber, user); err != nil {
		return contract.Response{}, err
	}
	if disableSession {
		return successResponse(map[string]any{
			"status": true, "token": nil, "user": p.serializeUser(user),
		})
	}
	userID, _ := recordString(user, "id")
	state, err := p.options.Runtime.IssueSession(ctx, userID, false)
	if err != nil || state == nil || state.Session == nil {
		return contract.Response{}, baseError(
			contract.StatusInternalServerError, string(singleauth.ErrorFailedToCreateSession),
			singleauth.ErrorMessage(singleauth.ErrorFailedToCreateSession),
		).WithCause(err)
	}
	token, ok := recordString(state.Session, "token")
	if !ok || token == "" {
		return contract.Response{}, internalError(errors.New("phonenumber: session token is invalid"))
	}
	responseUser := user
	if state.User != nil {
		responseUser = state.User
	}
	return successResponse(map[string]any{
		"status": true, "token": token, "user": p.serializeUser(responseUser),
	})
}

func (p *plugin) requestPasswordResetPhoneNumber(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	phoneNumber, err := requiredString(body, "phoneNumber")
	if err != nil {
		return contract.Response{}, err
	}
	user, err := p.findUser(ctx, phoneNumber)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	code, err := randomDigits(p.random, p.options.OTPLength)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	identifier := phoneNumber + "-request-password-reset"
	if _, err := p.createVerification(ctx.GoContext(), identifier, code+":0"); err != nil {
		return contract.Response{}, internalError(err)
	}
	if user != nil && p.options.SendPasswordResetOTP != nil {
		message := OTPMessage{PhoneNumber: phoneNumber, Code: code}
		if err := p.runAwaitable(ctx, func(callbackContext context.Context) error {
			return p.options.SendPasswordResetOTP(callbackContext, message, ctx)
		}); err != nil {
			return contract.Response{}, preserveRuntimeError(err)
		}
	}
	return successResponse(map[string]any{"status": true})
}

func (p *plugin) resetPasswordPhoneNumber(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	otp, err := requiredString(body, "otp")
	if err != nil {
		return contract.Response{}, err
	}
	phoneNumber, err := requiredString(body, "phoneNumber")
	if err != nil {
		return contract.Response{}, err
	}
	newPassword, err := requiredString(body, "newPassword")
	if err != nil {
		return contract.Response{}, err
	}
	if err := p.verifyInternalOTP(ctx, phoneNumber+"-request-password-reset", otp); err != nil {
		return contract.Response{}, err
	}
	user, err := p.findUser(ctx, phoneNumber)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if user == nil {
		return contract.Response{}, phoneError(contract.StatusBadRequest, CodeUnexpectedError)
	}
	minLength := p.options.Runtime.PasswordMinLength
	maxLength := p.options.Runtime.PasswordMaxLength
	length := utf16Length(newPassword)
	if length < minLength {
		return contract.Response{}, baseError(
			contract.StatusBadRequest, string(singleauth.ErrorPasswordTooShort),
			singleauth.ErrorMessage(singleauth.ErrorPasswordTooShort),
		)
	}
	if length > maxLength {
		return contract.Response{}, baseError(
			contract.StatusBadRequest, string(singleauth.ErrorPasswordTooLong),
			singleauth.ErrorMessage(singleauth.ErrorPasswordTooLong),
		)
	}
	hash, err := p.options.Runtime.HashPassword(ctx, newPassword)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	userID, ok := recordString(user, "id")
	if !ok || userID == "" {
		return contract.Response{}, internalError(errors.New("phonenumber: user id is invalid"))
	}
	account, err := p.findCredentialAccount(ctx, userID)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if account == nil {
		_, err = p.options.Runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{
			Model: "account", Data: storage.Record{
				"userId": userID, "providerId": "credential", "accountId": userID, "password": hash,
			},
		})
	} else {
		accountID, ok := recordString(account, "id")
		if !ok || accountID == "" {
			return contract.Response{}, internalError(errors.New("phonenumber: credential account id is invalid"))
		}
		_, err = p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "account", Where: []storage.Where{{Field: "id", Value: accountID}},
			Update: storage.Record{"password": hash},
		})
	}
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if err := p.options.Runtime.OnPasswordReset(ctx.GoContext(), ctx, cloneRecord(user)); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if p.options.Runtime.RevokeSessionsOnPasswordReset {
		if err := p.options.Runtime.RevokeSessions(ctx, userID); err != nil {
			return contract.Response{}, preserveRuntimeError(err)
		}
	}
	return successResponse(map[string]any{"status": true})
}

func (p *plugin) runVerificationCallback(ctx *engine.Context, phoneNumber string, user storage.Record) error {
	if p.options.CallbackOnVerification == nil {
		return nil
	}
	if err := p.options.CallbackOnVerification(
		ctx.GoContext(), VerificationEvent{PhoneNumber: phoneNumber, User: cloneRecord(user)}, ctx,
	); err != nil {
		return preserveRuntimeError(err)
	}
	return nil
}

func (p *plugin) runAwaitable(ctx *engine.Context, work func(context.Context) error) error {
	// runInBackgroundOrAwait receives an already-created Promise upstream and
	// catches both its rejection and background-handler failures. Invoke first,
	// then hand a non-failing task to the configured runner so delivery errors
	// never replace the endpoint's authoritative result.
	callbackErr := work(ctx.GoContext())
	if p.options.Runtime.BackgroundTasksEnabled {
		err := p.options.Runtime.RunBackground(ctx.GoContext(), func(context.Context) error {
			if callbackErr != nil {
				p.logError("Failed to run background task:", callbackErr)
			}
			return nil
		})
		if err != nil {
			p.logError("Failed to run background task:", err)
		}
		return nil
	}
	if callbackErr != nil {
		p.logError("Failed to run background task:", callbackErr)
	}
	return nil
}

func (p *plugin) warn(message string) {
	if p.options.Runtime.Warn != nil {
		p.options.Runtime.Warn(message)
	}
}

func (p *plugin) logError(message string, err error) {
	if p.options.Runtime.LogError != nil {
		p.options.Runtime.LogError(message, err)
	}
}
