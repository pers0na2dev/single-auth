package contract

import (
	"errors"
	"testing"
)

func TestAPIErrorDefaultWireBodyRemainsByteForByteStable(t *testing.T) {
	headers := NewHeaders(HeaderField{Name: "WWW-Authenticate", Value: "Bearer"})
	err := NewAPIError(StatusUnauthorized, "UNAUTHORIZED", "Authentication required").WithHeaders(headers)
	response := ResponseFromError(err)
	if response.Status() != StatusUnauthorized {
		t.Fatalf("status = %d", response.Status())
	}
	if got := string(response.Body()); got != `{"code":"UNAUTHORIZED","message":"Authentication required"}` {
		t.Fatalf("body = %q", got)
	}
	if got, _ := response.Headers().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("content type = %q", got)
	}
	if got, _ := response.Headers().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestAPIErrorCustomWireBodyIsOptInAndPreservesTypedFields(t *testing.T) {
	cause := errors.New("database detail")
	original := NewAPIError(StatusBadRequest, "INVALID_GRANT", "Invalid device code").
		WithHeaders(NewHeaders(HeaderField{Name: "Retry-After", Value: "5"})).
		WithCause(cause)
	err := original.WithWireBody(struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}{Error: "invalid_grant", ErrorDescription: "Invalid device code"})
	if original.WireBody != nil {
		t.Fatalf("WithWireBody mutated original: %#v", original.WireBody)
	}
	if err.Status != StatusBadRequest || err.Code != "INVALID_GRANT" || err.Message != "Invalid device code" {
		t.Fatalf("typed fields changed: %#v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("cause changed: %v", err.Cause)
	}
	response := ResponseFromError(err)
	if got := string(response.Body()); got != `{"error":"invalid_grant","error_description":"Invalid device code"}` {
		t.Fatalf("body = %q", got)
	}
	if got, _ := response.Headers().Get("Retry-After"); got != "5" {
		t.Fatalf("Retry-After = %q", got)
	}
}
