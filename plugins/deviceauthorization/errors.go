package deviceauthorization

import (
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	MessageInvalidDeviceCode       = "Invalid device code"
	MessageExpiredDeviceCode       = "Device code has expired"
	MessageExpiredUserCode         = "User code has expired"
	MessageAuthorizationPending    = "Authorization pending"
	MessageAccessDenied            = "Access denied"
	MessageInvalidUserCode         = "Invalid user code"
	MessageAlreadyProcessed        = "Device code already processed"
	MessageDeviceCodeNotClaimed    = "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying"
	MessagePollingTooFrequently    = "Polling too frequently"
	MessageUserNotFound            = "User not found"
	MessageFailedToCreateSession   = "Failed to create session"
	MessageInvalidDeviceCodeStatus = "Invalid device code status"
	MessageAuthenticationRequired  = "Authentication required"
)

func errorDefinitions() map[string]engine.ErrorDefinition {
	return map[string]engine.ErrorDefinition{
		"INVALID_DEVICE_CODE":           {Message: MessageInvalidDeviceCode},
		"EXPIRED_DEVICE_CODE":           {Message: MessageExpiredDeviceCode},
		"EXPIRED_USER_CODE":             {Message: MessageExpiredUserCode},
		"AUTHORIZATION_PENDING":         {Message: MessageAuthorizationPending},
		"ACCESS_DENIED":                 {Message: MessageAccessDenied},
		"INVALID_USER_CODE":             {Message: MessageInvalidUserCode},
		"DEVICE_CODE_ALREADY_PROCESSED": {Message: MessageAlreadyProcessed},
		"DEVICE_CODE_NOT_CLAIMED":       {Message: MessageDeviceCodeNotClaimed},
		"POLLING_TOO_FREQUENTLY":        {Message: MessagePollingTooFrequently},
		"USER_NOT_FOUND":                {Message: MessageUserNotFound},
		"FAILED_TO_CREATE_SESSION":      {Message: MessageFailedToCreateSession},
		"INVALID_DEVICE_CODE_STATUS":    {Message: MessageInvalidDeviceCodeStatus},
		"AUTHENTICATION_REQUIRED":       {Message: MessageAuthenticationRequired},
	}
}

func oauthError(status int, code, description string) *contract.APIError {
	typedCode := strings.ToUpper(strings.ReplaceAll(code, "-", "_"))
	return contract.NewAPIError(status, typedCode, description).WithWireBody(OAuthErrorBody{
		Error: code, ErrorDescription: description,
	})
}

func badRequest(code, description string) *contract.APIError {
	return oauthError(contract.StatusBadRequest, code, description)
}

func internalProtocolError(description string, cause error) *contract.APIError {
	return oauthError(
		contract.StatusInternalServerError, "server_error", description,
	).WithCause(cause)
}

func preserveInternal(err error) error {
	if _, ok := contract.AsAPIError(err); ok {
		return err
	}
	return contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Internal Server Error",
	).WithCause(err)
}
