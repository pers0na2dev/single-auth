package emailotp

import (
	"errors"
	"strconv"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) checkVerificationOTP(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	rawEmail, err := requiredString(body, "email")
	if err != nil {
		return contract.Response{}, err
	}
	rawType, err := requiredString(body, "type")
	if err != nil {
		return contract.Response{}, err
	}
	provided, err := requiredString(body, "otp")
	if err != nil {
		return contract.Response{}, err
	}
	otpType, ok := parseOTPType(rawType)
	if !ok {
		return contract.Response{}, validationError("Invalid OTP type")
	}
	email := normalizeEmail(rawEmail)
	if !validEmail(email) {
		return contract.Response{}, invalidEmail()
	}
	identifier := Identifier(otpType, email)
	err = p.withIdentifierLock(identifier, func() error {
		record, findErr := p.findVerification(ctx.GoContext(), identifier)
		if findErr != nil {
			return internalError(findErr)
		}
		if record == nil {
			return otpError(contract.StatusBadRequest, ErrorInvalidOTP)
		}
		expiresAt, valid := recordTime(record, "expiresAt")
		if !valid {
			return internalError(errors.New("emailotp: verification expiry is invalid"))
		}
		if expiresAt.Before(p.clock()) {
			if deleteErr := p.deleteVerification(ctx.GoContext(), identifier); deleteErr != nil {
				return internalError(deleteErr)
			}
			return otpError(contract.StatusBadRequest, ErrorOTPExpired)
		}
		value, valid := recordString(record, "value")
		if !valid {
			return internalError(errors.New("emailotp: verification value is invalid"))
		}
		stored, attemptText := SplitStoredValue(value)
		attempts := parseAttempts(attemptText)
		if attempts >= p.options.AllowedAttempts {
			if deleteErr := p.deleteVerification(ctx.GoContext(), identifier); deleteErr != nil {
				return internalError(deleteErr)
			}
			return otpError(contract.StatusForbidden, ErrorTooManyAttempts)
		}
		verified, verifyErr := p.verifyStoredOTP(ctx.GoContext(), stored, provided)
		if verifyErr != nil {
			return internalError(verifyErr)
		}
		if !verified {
			if updateErr := p.updateVerification(ctx.GoContext(), identifier, storage.Record{
				"value":     stored + ":" + strconv.Itoa(attempts+1),
				"updatedAt": p.clock().UTC(),
			}); updateErr != nil {
				return internalError(updateErr)
			}
			return otpError(contract.StatusBadRequest, ErrorInvalidOTP)
		}
		return nil
	})
	if err != nil {
		return contract.Response{}, err
	}
	user, err := p.findUserByEmail(ctx, email)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if user == nil {
		return contract.Response{}, userNotFound()
	}
	return successResponse()
}

func (p *plugin) verifyEmailOTP(ctx *engine.Context) (contract.Response, error) {
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
	email := normalizeEmail(rawEmail)
	if !validEmail(email) {
		return contract.Response{}, invalidEmail()
	}
	if err := p.atomicVerifyOTP(ctx, Identifier(TypeEmailVerification, email), provided); err != nil {
		return contract.Response{}, err
	}
	user, err := p.findUserByEmail(ctx, email)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if user == nil {
		return contract.Response{}, userNotFound()
	}
	if hook := p.options.Runtime.BeforeEmailVerification; hook != nil {
		if err := hook(ctx.GoContext(), ctx, cloneRecord(user)); err != nil {
			return contract.Response{}, preserveRuntimeError(err)
		}
	}
	userID, ok := recordString(user, "id")
	if !ok || userID == "" {
		return contract.Response{}, internalError(errors.New("emailotp: user id is invalid"))
	}
	updated, err := p.updateUser(ctx, userID, storage.Record{"email": email, "emailVerified": true})
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

	var token any
	if p.options.AutoSignInAfterVerification {
		issued, err := p.issueSession(ctx, updated)
		if err != nil {
			return contract.Response{}, preserveRuntimeError(err)
		}
		tokenValue, ok := recordString(issued.Session, "token")
		if !ok || tokenValue == "" {
			return contract.Response{}, internalError(errors.New("emailotp: session token is invalid"))
		}
		token = tokenValue
	} else {
		token = nil
		current, resolveErr := p.options.Runtime.ResolveSession(ctx, SessionOptional)
		if resolveErr != nil {
			return contract.Response{}, preserveRuntimeError(resolveErr)
		}
		if current != nil {
			currentUserID, _ := recordString(current.User, "id")
			if currentUserID == userID {
				current.User = cloneRecord(updated)
				if refreshErr := p.options.Runtime.RefreshSession(ctx, *current); refreshErr != nil {
					return contract.Response{}, preserveRuntimeError(refreshErr)
				}
			}
		}
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"status": true,
		"token":  token,
		"user":   p.serializeUser(updated),
	})
}
