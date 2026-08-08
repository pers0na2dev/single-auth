package phonenumber

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	CodeInvalidPhoneNumber         = "INVALID_PHONE_NUMBER"
	CodePhoneNumberExists          = "PHONE_NUMBER_EXIST"
	CodePhoneNumberNotRegistered   = "PHONE_NUMBER_NOT_EXIST"
	CodeInvalidPhoneOrPassword     = "INVALID_PHONE_NUMBER_OR_PASSWORD"
	CodeUnexpectedError            = "UNEXPECTED_ERROR"
	CodeOTPNotFound                = "OTP_NOT_FOUND"
	CodeOTPExpired                 = "OTP_EXPIRED"
	CodeInvalidOTP                 = "INVALID_OTP"
	CodePhoneNumberNotVerified     = "PHONE_NUMBER_NOT_VERIFIED"
	CodePhoneNumberCannotBeUpdated = "PHONE_NUMBER_CANNOT_BE_UPDATED"
	CodeSendOTPNotImplemented      = "SEND_OTP_NOT_IMPLEMENTED"
	CodeTooManyAttempts            = "TOO_MANY_ATTEMPTS"
)

var errorMessages = map[string]string{
	CodeInvalidPhoneNumber:         "Invalid phone number",
	CodePhoneNumberExists:          "Phone number already exists",
	CodePhoneNumberNotRegistered:   "phone number isn't registered",
	CodeInvalidPhoneOrPassword:     "Invalid phone number or password",
	CodeUnexpectedError:            "Unexpected error",
	CodeOTPNotFound:                "OTP not found",
	CodeOTPExpired:                 "OTP expired",
	CodeInvalidOTP:                 "Invalid OTP",
	CodePhoneNumberNotVerified:     "Phone number not verified",
	CodePhoneNumberCannotBeUpdated: "Phone number cannot be updated",
	CodeSendOTPNotImplemented:      "sendOTP not implemented",
	CodeTooManyAttempts:            "Too many attempts",
}

func pluginErrorCodes() map[string]engine.ErrorDefinition {
	result := make(map[string]engine.ErrorDefinition, len(errorMessages))
	for code, message := range errorMessages {
		result[code] = engine.ErrorDefinition{Message: message}
	}
	return result
}

func phoneError(status int, code string) *contract.APIError {
	return contract.NewAPIError(status, code, errorMessages[code])
}

func baseError(status int, code, message string) *contract.APIError {
	return contract.NewAPIError(status, code, message)
}

func validationError(message string) *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", message)
}

func internalError(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Internal Server Error",
	).WithCause(err)
}

func preserveRuntimeError(err error) error {
	if _, ok := contract.AsAPIError(err); ok {
		return err
	}
	return internalError(err)
}
