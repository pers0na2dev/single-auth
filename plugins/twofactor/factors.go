package twofactor

import (
	"errors"
	"fmt"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) verifyTOTP(ctx *engine.Context) (contract.Response, error) {
	if p.options.TOTP.Disable {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeTOTPNotConfigured)
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	code, err := requiredString(body, "code")
	if err != nil {
		return contract.Response{}, err
	}
	trustDevice, err := optionalBool(body, "trustDevice")
	if err != nil {
		return contract.Response{}, err
	}
	verification, err := p.verifyTwoFactor(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	userIDValue, err := userID(verification.session.User)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	twoFactor, err := p.findTwoFactor(ctx, userIDValue)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if twoFactor == nil {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeTOTPNotEnabled)
	}
	verified, verifiedPresent := recordBool(twoFactor, "verified")
	if verification.isSignIn && verifiedPresent && !verified {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeTOTPNotEnabled)
	}
	if verification.isSignIn {
		if err := p.assertNotLocked(ctx, twoFactor); err != nil {
			return contract.Response{}, err
		}
	}
	attempt, err := verification.beginAttempt(DefaultAllowedAttempts)
	if err != nil {
		return contract.Response{}, err
	}
	encrypted, _ := recordString(twoFactor, "secret")
	secret, err := p.options.Runtime.DecryptSecret(encrypted)
	if err != nil {
		if restoreErr := attempt.restore(); restoreErr != nil {
			return contract.Response{}, internalError(restoreErr)
		}
		return contract.Response{}, err
	}
	valid, err := VerifyTOTP(
		string(secret), code, p.clock(), p.options.TOTP.Digits, p.options.TOTP.Period,
	)
	if err != nil {
		if restoreErr := attempt.restore(); restoreErr != nil {
			return contract.Response{}, internalError(restoreErr)
		}
		return contract.Response{}, internalError(err)
	}
	if !valid {
		if err := attempt.recordFailure(); err != nil {
			return contract.Response{}, internalError(err)
		}
		if verification.isSignIn {
			if err := p.recordFailure(ctx, twoFactor); err != nil {
				return contract.Response{}, err
			}
		}
		return contract.Response{}, verification.invalid(CodeInvalidCode)
	}
	if verification.isSignIn {
		if err := p.resetFailures(ctx, twoFactor); err != nil {
			return contract.Response{}, err
		}
	}
	if !verifiedPresent || !verified {
		enabled, _ := recordBool(verification.session.User, "twoFactorEnabled")
		if !enabled {
			if verification.session.Session == nil {
				return contract.Response{}, contract.NewAPIError(
					contract.StatusBadRequest,
					"FAILED_TO_CREATE_SESSION",
					"Failed to create session",
				)
			}
			updated, updateErr := p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
				Model: "user", Where: []storage.Where{{Field: "id", Value: userIDValue}},
				Update: storage.Record{"twoFactorEnabled": true},
			})
			if updateErr != nil || updated == nil {
				return contract.Response{}, internalError(updateErr)
			}
			if err := p.replaceSession(ctx, verification.session, userIDValue); err != nil {
				return contract.Response{}, err
			}
			verification.session.User = updated
		}
		id, _ := recordString(twoFactor, "id")
		if _, err := p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "twoFactor", Where: []storage.Where{{Field: "id", Value: id}},
			Update: storage.Record{"verified": true},
		}); err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	return verification.valid(trustDevice != nil && *trustDevice)
}

func (p *plugin) sendTwoFactorOTP(ctx *engine.Context) (contract.Response, error) {
	if p.options.OTP.SendOTP == nil {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeOTPNotConfigured)
	}
	if _, err := decodeOptionalObject(ctx); err != nil {
		return contract.Response{}, err
	}
	verification, err := p.verifyTwoFactor(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	code, err := randomFromAlphabet(p.random, p.options.OTP.Digits, "0123456789")
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	stored, err := p.storedOTP(code)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if _, err := p.options.Runtime.CreateVerification(
		ctx.GoContext(), "2fa-otp-"+verification.key, stored+":0",
		p.clock().Add(p.options.OTP.Period),
	); err != nil {
		return contract.Response{}, internalError(err)
	}
	if err := p.sendOTP(ctx, verification.session.User, code); err != nil {
		return contract.Response{}, err
	}
	return successResponse(map[string]any{"status": true})
}

func (p *plugin) verifyTwoFactorOTP(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	code, err := requiredString(body, "code")
	if err != nil {
		return contract.Response{}, err
	}
	trustDevice, err := optionalBool(body, "trustDevice")
	if err != nil {
		return contract.Response{}, err
	}
	verification, err := p.verifyTwoFactor(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	userIDValue, err := userID(verification.session.User)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	var twoFactor storage.Record
	if verification.isSignIn {
		twoFactor, err = p.findTwoFactor(ctx, userIDValue)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		if twoFactor == nil {
			return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeTwoFactorNotEnabled)
		}
		if err := p.assertNotLocked(ctx, twoFactor); err != nil {
			return contract.Response{}, err
		}
	}
	consumed, err := p.options.Runtime.ConsumeVerification(
		ctx.GoContext(), "2fa-otp-"+verification.key,
	)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if consumed == nil {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeOTPHasExpired)
	}
	raw, _ := recordString(consumed, "value")
	stored, attempts := splitOTPValue(raw)
	if attempts >= p.options.OTP.AllowedAttempts {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeTooManyAttempts)
	}
	valid, err := p.compareStoredOTP(stored, code)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if valid {
		if twoFactor != nil {
			if err := p.resetFailures(ctx, twoFactor); err != nil {
				return contract.Response{}, err
			}
		}
		enabled, _ := recordBool(verification.session.User, "twoFactorEnabled")
		if !enabled {
			if verification.session.Session == nil {
				return contract.Response{}, contract.NewAPIError(
					contract.StatusBadRequest,
					"FAILED_TO_CREATE_SESSION",
					"Failed to create session",
				)
			}
			updated, updateErr := p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
				Model: "user", Where: []storage.Where{{Field: "id", Value: userIDValue}},
				Update: storage.Record{"twoFactorEnabled": true},
			})
			if updateErr != nil || updated == nil {
				return contract.Response{}, internalError(updateErr)
			}
			newSession, issueErr := p.options.Runtime.IssueSession(ctx, userIDValue, false)
			if issueErr != nil || newSession == nil || newSession.Session == nil {
				return contract.Response{}, internalError(issueErr)
			}
			oldToken, _ := recordString(verification.session.Session, "token")
			if oldToken == "" {
				return contract.Response{}, internalError(errors.New("twofactor: session token is invalid"))
			}
			if err := p.options.Runtime.DeleteSession(ctx.GoContext(), oldToken); err != nil {
				return contract.Response{}, internalError(err)
			}
			token, _ := recordString(newSession.Session, "token")
			return successResponse(map[string]any{
				"token": token, "user": p.options.Runtime.SerializeUser(updated),
			})
		}
		return verification.valid(trustDevice != nil && *trustDevice)
	}
	expiresAt, ok := recordTime(consumed, "expiresAt")
	if !ok {
		return contract.Response{}, internalError(errors.New("twofactor: OTP expiry is invalid"))
	}
	if _, err := p.options.Runtime.CreateVerification(
		ctx.GoContext(), "2fa-otp-"+verification.key,
		fmt.Sprintf("%s:%d", stored, attempts+1), expiresAt,
	); err != nil {
		return contract.Response{}, internalError(err)
	}
	if twoFactor != nil {
		if err := p.recordFailure(ctx, twoFactor); err != nil {
			return contract.Response{}, err
		}
	}
	return contract.Response{}, verification.invalid(CodeInvalidCode)
}

func (p *plugin) verifyBackupCode(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
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
	trustDevice, err := optionalBool(body, "trustDevice")
	if err != nil {
		return contract.Response{}, err
	}
	verification, err := p.verifyTwoFactor(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	userIDValue, err := userID(verification.session.User)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	twoFactor, err := p.findTwoFactor(ctx, userIDValue)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if twoFactor == nil {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeBackupCodesNotEnabled)
	}
	if verification.isSignIn {
		if err := p.assertNotLocked(ctx, twoFactor); err != nil {
			return contract.Response{}, err
		}
	}
	attempt, err := verification.beginAttempt(DefaultAllowedAttempts)
	if err != nil {
		return contract.Response{}, err
	}
	rawCodes, _ := recordString(twoFactor, "backupCodes")
	codes, err := p.decodeBackupCodes(rawCodes)
	if err != nil {
		if restoreErr := attempt.restore(); restoreErr != nil {
			return contract.Response{}, internalError(restoreErr)
		}
		return contract.Response{}, internalError(err)
	}
	remaining, found := removeBackupCode(codes, code)
	if !found {
		if err := attempt.recordFailure(); err != nil {
			return contract.Response{}, internalError(err)
		}
		if verification.isSignIn {
			if err := p.recordFailure(ctx, twoFactor); err != nil {
				return contract.Response{}, err
			}
		}
		return contract.Response{}, verification.invalid(CodeInvalidBackupCode)
	}
	encoded, err := p.encodeBackupCodes(remaining)
	if err != nil {
		if restoreErr := attempt.restore(); restoreErr != nil {
			return contract.Response{}, internalError(restoreErr)
		}
		return contract.Response{}, internalError(err)
	}
	id, _ := recordString(twoFactor, "id")
	updated, err := p.options.Runtime.Adapter.IncrementOne(ctx.GoContext(), storage.IncrementOneParams{
		Model: "twoFactor",
		Where: []storage.Where{
			{Field: "id", Value: id},
			{Field: "backupCodes", Value: rawCodes},
		},
		Set: storage.Record{"backupCodes": encoded},
	})
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if updated == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusConflict,
			"CONFLICT",
			"Failed to verify backup code. Please try again.",
		)
	}
	if verification.isSignIn {
		if err := p.resetFailures(ctx, twoFactor); err != nil {
			return contract.Response{}, err
		}
	}
	if disableSession != nil && *disableSession {
		payload := map[string]any{
			"user": p.options.Runtime.SerializeUser(verification.session.User),
		}
		if verification.session.Session != nil {
			if value, ok := recordString(verification.session.Session, "token"); ok {
				payload["token"] = value
			}
		}
		return successResponse(payload)
	}
	return verification.valid(trustDevice != nil && *trustDevice)
}
