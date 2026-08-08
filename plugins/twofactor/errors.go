package twofactor

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	CodeOTPNotEnabled            = "OTP_NOT_ENABLED"
	CodeOTPHasExpired            = "OTP_HAS_EXPIRED"
	CodeTOTPNotEnabled           = "TOTP_NOT_ENABLED"
	CodeTwoFactorNotEnabled      = "TWO_FACTOR_NOT_ENABLED"
	CodeBackupCodesNotEnabled    = "BACKUP_CODES_NOT_ENABLED"
	CodeInvalidBackupCode        = "INVALID_BACKUP_CODE"
	CodeInvalidCode              = "INVALID_CODE"
	CodeTooManyAttempts          = "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"
	CodeAccountTemporarilyLocked = "ACCOUNT_TEMPORARILY_LOCKED"
	CodeInvalidTwoFactorCookie   = "INVALID_TWO_FACTOR_COOKIE"
	CodeOTPNotConfigured         = "OTP_NOT_CONFIGURED"
	CodeTOTPNotConfigured        = "TOTP_NOT_CONFIGURED"
)

var errorMessages = map[string]string{
	CodeOTPNotEnabled:            "OTP not enabled",
	CodeOTPHasExpired:            "OTP has expired",
	CodeTOTPNotEnabled:           "TOTP not enabled",
	CodeTwoFactorNotEnabled:      "Two factor isn't enabled",
	CodeBackupCodesNotEnabled:    "Backup codes aren't enabled",
	CodeInvalidBackupCode:        "Invalid backup code",
	CodeInvalidCode:              "Invalid code",
	CodeTooManyAttempts:          "Too many attempts. Please request a new code.",
	CodeAccountTemporarilyLocked: "Too many failed verification attempts. Your account is temporarily locked. Please try again later.",
	CodeInvalidTwoFactorCookie:   "Invalid two factor cookie",
}

func pluginErrorCodes() map[string]engine.ErrorDefinition {
	result := make(map[string]engine.ErrorDefinition, len(errorMessages))
	for code, message := range errorMessages {
		result[code] = engine.ErrorDefinition{Message: message}
	}
	return result
}

func twoFactorError(status int, code string) *contract.APIError {
	message := errorMessages[code]
	if code == CodeOTPNotConfigured {
		message = "otp isn't configured"
	}
	if code == CodeTOTPNotConfigured {
		message = "totp isn't configured"
	}
	return contract.NewAPIError(status, code, message)
}

func validationError(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", message)
}

func internalError(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Internal Server Error",
	).WithCause(err)
}
