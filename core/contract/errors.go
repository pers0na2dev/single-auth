package contract

import (
	"errors"
)

// HTTP status constants used by the transport-neutral engine.
const (
	StatusOK                  = 200
	StatusFound               = 302
	StatusBadRequest          = 400
	StatusUnauthorized        = 401
	StatusForbidden           = 403
	StatusNotFound            = 404
	StatusMethodNotAllowed    = 405
	StatusConflict            = 409
	StatusTooManyRequests     = 429
	StatusInternalServerError = 500
)

// APIError is the typed error crossing the direct API and HTTP dispatcher
// boundary. Cause is available to server code but is never serialized.
type APIError struct {
	Status  int
	Code    string
	Message string
	Headers Headers
	// WireBody overrides the default {code,message} JSON representation while
	// preserving APIError's typed status, code, message, headers, and cause.
	// Protocol endpoints use it for standardized payloads such as OAuth 2.0's
	// {error,error_description} response.
	WireBody any
	Cause    error
}

// NewAPIError creates a typed API error.
func NewAPIError(status int, code, message string) *APIError {
	if status == 0 {
		status = StatusInternalServerError
	}
	return &APIError{Status: status, Code: code, Message: message}
}

// Error implements error.
func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

// Unwrap exposes the server-side cause without serializing it.
func (e *APIError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// WithCause returns an independent error carrying cause.
func (e *APIError) WithCause(cause error) *APIError {
	if e == nil {
		return nil
	}
	clone := *e
	clone.Headers = e.Headers.Clone()
	clone.Cause = cause
	return &clone
}

// WithHeaders returns an independent error carrying headers.
func (e *APIError) WithHeaders(headers Headers) *APIError {
	if e == nil {
		return nil
	}
	clone := *e
	clone.Headers = headers.Clone()
	return &clone
}

// WithWireBody returns an independent error carrying a custom JSON wire body.
// A nil body clears the override and restores the default representation.
func (e *APIError) WithWireBody(body any) *APIError {
	if e == nil {
		return nil
	}
	clone := *e
	clone.Headers = e.Headers.Clone()
	clone.WireBody = body
	return &clone
}

// AsAPIError extracts a typed API error through wrapping layers.
func AsAPIError(err error) (*APIError, bool) {
	var apiError *APIError
	if !errors.As(err, &apiError) {
		return nil, false
	}
	return apiError, true
}

// ResponseFromError converts err to the stable wire representation. Unknown
// errors are intentionally redacted.
func ResponseFromError(err error) Response {
	apiError, ok := AsAPIError(err)
	if !ok {
		apiError = NewAPIError(
			StatusInternalServerError,
			"INTERNAL_SERVER_ERROR",
			"Internal Server Error",
		).WithCause(err)
	}

	body := apiError.WireBody
	if body == nil {
		body = struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}{
			Code:    apiError.Code,
			Message: apiError.Message,
		}
	}
	response, marshalErr := JSONResponse(apiError.Status, body)
	if marshalErr != nil {
		return TextResponse(StatusInternalServerError, "Internal Server Error")
	}
	return response.WithMergedHeaders(apiError.Headers)
}
