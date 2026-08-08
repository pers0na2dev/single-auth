package emailotp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) resolveOTP(ctx context.Context, endpointCtx *engine.Context, email string, otpType OTPType) (string, error) {
	identifier := Identifier(otpType, email)
	if p.options.ResendStrategy == ResendReuse {
		reused, ok, err := p.tryReuseOTP(ctx, identifier)
		if err != nil {
			return "", err
		}
		if ok {
			return reused, nil
		}
	}

	otp, err := p.generateOTP(OTPData{Email: email, Type: otpType}, endpointCtx)
	if err != nil {
		return "", err
	}
	stored, err := p.storeOTP(ctx, otp)
	if err != nil {
		return "", err
	}
	expiresAt := p.clock().Add(p.options.ExpiresIn)
	if _, err = p.createVerification(ctx, identifier, stored+":0", expiresAt); err != nil {
		// single-auth retries once after removing an existing identifier. This
		// accommodates adapters with a unique verification identifier.
		if deleteErr := p.deleteVerification(ctx, identifier); deleteErr != nil {
			return "", deleteErr
		}
		if _, err = p.createVerification(ctx, identifier, stored+":0", expiresAt); err != nil {
			return "", err
		}
	}
	return otp, nil
}

func (p *plugin) tryReuseOTP(ctx context.Context, identifier string) (string, bool, error) {
	record, err := p.findVerification(ctx, identifier)
	if err != nil || record == nil {
		return "", false, err
	}
	expiresAt, ok := recordTime(record, "expiresAt")
	if !ok || expiresAt.Before(p.clock()) {
		return "", false, nil
	}
	value, ok := recordString(record, "value")
	if !ok {
		return "", false, errors.New("emailotp: verification value is invalid")
	}
	stored, attemptText := SplitStoredValue(value)
	if parseAttempts(attemptText) >= p.options.AllowedAttempts {
		return "", false, nil
	}
	otp, recoverable, err := p.retrieveOTP(ctx, stored)
	if err != nil || !recoverable {
		return "", false, err
	}
	if err := p.updateVerification(ctx, identifier, storage.Record{
		"expiresAt": p.clock().Add(p.options.ExpiresIn).UTC(),
		"updatedAt": p.clock().UTC(),
	}); err != nil {
		return "", false, err
	}
	return otp, true, nil
}

func (p *plugin) sendMessage(ctx context.Context, endpointCtx *engine.Context, message OTPMessage) error {
	work := func(workCtx context.Context) error {
		return p.options.SendVerificationOTP(workCtx, message, endpointCtx)
	}
	if runner := p.options.Runtime.RunInBackground; runner != nil {
		return runner(ctx, work)
	}
	return work(ctx)
}

func (p *plugin) sendVerificationOTP(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	rawEmail, err := requiredString(body, "email")
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	rawType, err := requiredString(body, "type")
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	otpType, ok := parseOTPType(rawType)
	if !ok {
		err = validationError("Invalid OTP type")
		return contract.ResponseFromError(err), err
	}
	email := normalizeEmail(rawEmail)
	if !validEmail(email) {
		err = invalidEmail()
		return contract.ResponseFromError(err), err
	}
	if otpType == TypeChangeEmail {
		err = apiError(contract.StatusBadRequest, "BAD_REQUEST", "Invalid OTP type")
		return contract.ResponseFromError(err), err
	}

	identifier := Identifier(otpType, email)
	otp, err := p.resolveOTP(ctx.GoContext(), ctx, email, otpType)
	if err != nil {
		err = internalError(err)
		return contract.ResponseFromError(err), err
	}
	user, findErr := p.findUserByEmail(ctx, email)
	if findErr != nil {
		err = internalError(findErr)
		return contract.ResponseFromError(err), err
	}
	shouldSend := otpType == TypeSignIn && !p.options.DisableSignUp
	if user == nil && !shouldSend {
		if deleteErr := p.deleteVerification(ctx.GoContext(), identifier); deleteErr != nil {
			err = internalError(deleteErr)
			return contract.ResponseFromError(err), err
		}
		return successResponse()
	}
	if err := p.sendMessage(ctx.GoContext(), ctx, OTPMessage{Email: email, OTP: otp, Type: otpType}); err != nil {
		err = internalError(err)
		return contract.ResponseFromError(err), err
	}
	return successResponse()
}

func (p *plugin) createVerificationOTP(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	rawEmail, err := requiredString(body, "email")
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	rawType, err := requiredString(body, "type")
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	otpType, ok := parseOTPType(rawType)
	if !ok {
		err = validationError("Invalid OTP type")
		return contract.ResponseFromError(err), err
	}
	email := normalizeEmail(rawEmail)
	otp, err := p.generateOTP(OTPData{Email: email, Type: otpType}, ctx)
	if err != nil {
		err = internalError(err)
		return contract.ResponseFromError(err), err
	}
	stored, err := p.storeOTP(ctx.GoContext(), otp)
	if err != nil {
		err = internalError(err)
		return contract.ResponseFromError(err), err
	}
	if _, err = p.createVerification(ctx.GoContext(), Identifier(otpType, email), stored+":0", p.clock().Add(p.options.ExpiresIn)); err != nil {
		err = internalError(err)
		return contract.ResponseFromError(err), err
	}
	return contract.JSONResponse(contract.StatusOK, otp)
}

func (p *plugin) getVerificationOTP(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		err = validationError("Invalid query")
		return contract.ResponseFromError(err), err
	}
	rawEmail := query.Get("email")
	rawType := query.Get("type")
	if rawEmail == "" || rawType == "" {
		err = validationError("email and type are required")
		return contract.ResponseFromError(err), err
	}
	otpType, ok := parseOTPType(rawType)
	if !ok {
		err = validationError("Invalid OTP type")
		return contract.ResponseFromError(err), err
	}
	record, err := p.findVerification(ctx.GoContext(), Identifier(otpType, normalizeEmail(rawEmail)))
	if err != nil {
		err = internalError(err)
		return contract.ResponseFromError(err), err
	}
	if record == nil {
		return contract.JSONResponse(contract.StatusOK, map[string]any{"otp": nil})
	}
	expiresAt, ok := recordTime(record, "expiresAt")
	if !ok || expiresAt.Before(p.clock()) {
		return contract.JSONResponse(contract.StatusOK, map[string]any{"otp": nil})
	}
	value, ok := recordString(record, "value")
	if !ok {
		err = internalError(errors.New("emailotp: verification value is invalid"))
		return contract.ResponseFromError(err), err
	}
	stored, _ := SplitStoredValue(value)
	otp, recoverable, retrieveErr := p.retrieveOTP(ctx.GoContext(), stored)
	if retrieveErr != nil {
		err = internalError(retrieveErr)
		return contract.ResponseFromError(err), err
	}
	if !recoverable {
		err = apiError(contract.StatusBadRequest, "BAD_REQUEST", "OTP is hashed, cannot return the plain text OTP")
		return contract.ResponseFromError(err), err
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{"otp": otp})
}

func (p *plugin) defaultVerificationHandler(ctx context.Context, email string) error {
	email = normalizeEmail(email)
	if !validEmail(email) {
		return invalidEmail()
	}
	otp, err := p.resolveOTP(ctx, nil, email, TypeEmailVerification)
	if err != nil {
		return err
	}
	user, err := p.options.Runtime.Adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: email}},
	})
	if err != nil {
		return err
	}
	if user == nil {
		return p.deleteVerification(ctx, Identifier(TypeEmailVerification, email))
	}
	return p.sendMessage(ctx, nil, OTPMessage{Email: email, OTP: otp, Type: TypeEmailVerification})
}

func (p *plugin) signUpHookMatcher(ctx *engine.Context) (bool, error) {
	return p.options.SendVerificationOnSignUp && !p.options.OverrideDefaultEmailVerification && strings.HasPrefix(ctx.Path(), "/sign-up"), nil
}

func (p *plugin) sendOnSignUp(ctx *engine.Context, response contract.Response) (*contract.Response, error) {
	if response.Status() < 200 || response.Status() >= 300 {
		return nil, nil
	}
	var payload struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := jsonUnmarshal(response.Body(), &payload); err != nil || payload.User.Email == "" {
		return nil, nil
	}
	email := payload.User.Email
	otp, err := p.generateOTP(OTPData{Email: email, Type: TypeEmailVerification}, ctx)
	if err != nil {
		return nil, internalError(err)
	}
	stored, err := p.storeOTP(ctx.GoContext(), otp)
	if err != nil {
		return nil, internalError(err)
	}
	if _, err := p.createVerification(
		ctx.GoContext(), Identifier(TypeEmailVerification, email), stored+":0", p.clock().Add(p.options.ExpiresIn),
	); err != nil {
		return nil, internalError(err)
	}
	if err := p.sendMessage(ctx.GoContext(), ctx, OTPMessage{Email: email, OTP: otp, Type: TypeEmailVerification}); err != nil {
		return nil, internalError(err)
	}
	return nil, nil
}

// jsonUnmarshal is kept tiny so hook parsing ignores unknown response fields.
func jsonUnmarshal(data []byte, target any) error {
	return json.Unmarshal(data, target)
}
