package emailotp

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	ErrorOTPExpired      = "OTP_EXPIRED"
	ErrorInvalidOTP      = "INVALID_OTP"
	ErrorTooManyAttempts = "TOO_MANY_ATTEMPTS"
)

var errorMessages = map[string]string{
	ErrorOTPExpired:      "OTP expired",
	ErrorInvalidOTP:      "Invalid OTP",
	ErrorTooManyAttempts: "Too many attempts",
}

func pluginErrorCodes() map[string]engine.ErrorDefinition {
	result := make(map[string]engine.ErrorDefinition, len(errorMessages))
	for code, message := range errorMessages {
		result[code] = engine.ErrorDefinition{Message: message}
	}
	return result
}

func otpError(status int, code string) *contract.APIError {
	return contract.NewAPIError(status, code, errorMessages[code])
}

func apiError(status int, code, message string) *contract.APIError {
	return contract.NewAPIError(status, code, message)
}

func invalidEmail() *contract.APIError {
	return apiError(contract.StatusBadRequest, "INVALID_EMAIL", "Invalid email")
}

func userNotFound() *contract.APIError {
	return apiError(contract.StatusBadRequest, "USER_NOT_FOUND", "User not found")
}

func unauthorized() *contract.APIError {
	return apiError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
}

func validationError(message string) *contract.APIError {
	return apiError(contract.StatusBadRequest, "VALIDATION_ERROR", message)
}

func internalError(err error) *contract.APIError {
	return apiError(contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Internal Server Error").WithCause(err)
}

func preserveRuntimeError(err error) error {
	if _, ok := contract.AsAPIError(err); ok {
		return err
	}
	return internalError(err)
}
