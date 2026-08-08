package saml

import "errors"

// APIError is the HTTP-facing validation error shape used by the reference implementation SSO
// route helpers. Cause preserves the stable SAML error code for callers that
// need protocol-level classification.
type APIError struct {
	Status     string
	StatusCode int
	Message    string
	Body       map[string]any
	Cause      error
}

func (err *APIError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return err.Message
}

func (err *APIError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

// Error is a stable SAML validation failure. Cause is intended for server logs
// and must not be copied into protocol responses.
type Error struct {
	Code    string
	Message string
	Cause   error
}

func (err *Error) Error() string {
	if err == nil {
		return "<nil>"
	}
	if err.Message != "" {
		return err.Message
	}
	return err.Code
}

func (err *Error) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

func newError(code, message string, cause ...error) *Error {
	var underlying error
	if len(cause) > 0 {
		underlying = cause[0]
	}
	return &Error{Code: code, Message: message, Cause: underlying}
}

func newBadRequest(code, message string, cause ...error) *APIError {
	return &APIError{
		Status:     "BAD_REQUEST",
		StatusCode: 400,
		Message:    message,
		Body:       map[string]any{"message": message},
		Cause:      newError(code, message, cause...),
	}
}

// IsErrorCode reports whether err contains a SAML Error with code.
func IsErrorCode(err error, code string) bool {
	for err != nil {
		var samlError *Error
		if errors.As(err, &samlError) && samlError == err && samlError.Code == code {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}
