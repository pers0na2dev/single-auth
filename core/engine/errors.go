package engine

import (
	"fmt"
	"strings"
)

// RegistryErrorKind classifies initialization failures.
type RegistryErrorKind string

const (
	RegistryErrorInvalidEndpoint       RegistryErrorKind = "INVALID_ENDPOINT"
	RegistryErrorDuplicateEndpointName RegistryErrorKind = "DUPLICATE_ENDPOINT_NAME"
	RegistryErrorDuplicatePluginID     RegistryErrorKind = "DUPLICATE_PLUGIN_ID"
	RegistryErrorEndpointConflict      RegistryErrorKind = "ENDPOINT_CONFLICT"
	RegistryErrorInvalidMiddleware     RegistryErrorKind = "INVALID_MIDDLEWARE"
)

// RegistryError reports one invalid registry declaration.
type RegistryError struct {
	Kind       RegistryErrorKind
	PluginID   string
	Endpoint   string
	Middleware string
	Message    string
	Cause      error
}

func (e *RegistryError) Error() string {
	if e == nil {
		return "<nil>"
	}
	parts := []string{string(e.Kind)}
	if e.PluginID != "" {
		parts = append(parts, "plugin="+e.PluginID)
	}
	if e.Endpoint != "" {
		parts = append(parts, "endpoint="+e.Endpoint)
	}
	if e.Middleware != "" {
		parts = append(parts, "middleware="+e.Middleware)
	}
	if e.Message != "" {
		parts = append(parts, e.Message)
	}
	return strings.Join(parts, ": ")
}

// Unwrap exposes the parsing/validation cause.
func (e *RegistryError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// EndpointConflict describes an indistinguishable route/method pair.
type EndpointConflict struct {
	Path             string
	Method           string
	ExistingEndpoint string
	ExistingPlugin   string
	NewEndpoint      string
	NewPlugin        string
}

// ConflictError aggregates all endpoint conflicts discovered during registry
// construction so initialization can fail once with complete diagnostics.
type ConflictError struct {
	Conflicts []EndpointConflict
}

func (e *ConflictError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if len(e.Conflicts) == 0 {
		return string(RegistryErrorEndpointConflict)
	}
	messages := make([]string, 0, len(e.Conflicts))
	for _, conflict := range e.Conflicts {
		existing := conflict.ExistingEndpoint
		if conflict.ExistingPlugin != "" {
			existing = conflict.ExistingPlugin + "." + existing
		}
		incoming := conflict.NewEndpoint
		if conflict.NewPlugin != "" {
			incoming = conflict.NewPlugin + "." + incoming
		}
		messages = append(messages, fmt.Sprintf(
			"%s %s is declared by %s and %s",
			conflict.Method,
			conflict.Path,
			existing,
			incoming,
		))
	}
	return string(RegistryErrorEndpointConflict) + ": " + strings.Join(messages, "; ")
}
