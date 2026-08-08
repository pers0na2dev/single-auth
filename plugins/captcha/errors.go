package captcha

import (
	"encoding/json"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	ErrorVerificationFailed = "VERIFICATION_FAILED"
	ErrorMissingResponse    = "MISSING_RESPONSE"
	ErrorUnknown            = "UNKNOWN_ERROR"

	MessageVerificationFailed = "Captcha verification failed"
	MessageMissingResponse    = "Missing CAPTCHA response"
	MessageUnknown            = "Something went wrong"

	internalMissingSecretKey   = "Missing secret key"
	internalServiceUnavailable = "CAPTCHA service unavailable"
)

func errorDefinitions() map[string]engine.ErrorDefinition {
	return map[string]engine.ErrorDefinition{
		ErrorVerificationFailed: {Message: MessageVerificationFailed},
		ErrorMissingResponse:    {Message: MessageMissingResponse},
		ErrorUnknown:            {Message: MessageUnknown},
	}
}

// middlewareError reproduces middlewareResponse rather than APIError. Its body
// is a JSON string, but the upstream Response constructor leaves Content-Type
// unset because middlewareResponse does not provide headers.
func middlewareError(status int, message, code string) contract.Response {
	body, err := json.Marshal(struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	}{Message: message, Code: code})
	if err != nil {
		body = []byte(`{"message":"Something went wrong","code":"UNKNOWN_ERROR"}`)
		status = contract.StatusInternalServerError
	}
	// Response does not infer Content-Type from a string body. The upstream
	// middleware response therefore has no content-type header at all.
	return contract.NewResponse(status, contract.Headers{}, body)
}

func missingResponse() contract.Response {
	return middlewareError(
		contract.StatusBadRequest,
		MessageMissingResponse,
		ErrorMissingResponse,
	)
}

func verificationFailed() contract.Response {
	return middlewareError(
		contract.StatusForbidden,
		MessageVerificationFailed,
		ErrorVerificationFailed,
	)
}

func unknownError() contract.Response {
	return middlewareError(
		contract.StatusInternalServerError,
		MessageUnknown,
		ErrorUnknown,
	)
}
