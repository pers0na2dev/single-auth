package scim

import (
	"strconv"

	"github.com/pers0na2dev/single-auth/core/contract"
)

// ErrorBody is the RFC 7644 error representation emitted by SCIM endpoints.
type ErrorBody struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	SCIMType string   `json:"scimType,omitempty"`
}

func scimError(status int, detail, scimType string) *contract.APIError {
	code := "INTERNAL_SERVER_ERROR"
	switch status {
	case contract.StatusBadRequest:
		code = "BAD_REQUEST"
	case contract.StatusUnauthorized:
		code = "UNAUTHORIZED"
	case contract.StatusForbidden:
		code = "FORBIDDEN"
	case contract.StatusNotFound:
		code = "NOT_FOUND"
	case contract.StatusConflict:
		code = "CONFLICT"
	case contract.StatusTooManyRequests:
		code = "TOO_MANY_REQUESTS"
	}
	body := ErrorBody{
		Schemas: []string{ErrorSchema}, Status: strconv.Itoa(status),
		Detail: detail, SCIMType: scimType,
	}
	return contract.NewAPIError(status, code, detail).WithWireBody(body)
}

func validationError(message string) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusBadRequest,
		"VALIDATION_ERROR",
		message,
	)
}
