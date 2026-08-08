package authorization

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
)

const Version = "1.6.26"

// Connector combines either resources at the outer level or actions within a
// resource. Unchecked inner connectors normalize to AND. An unchecked outer
// connector retains reference implementation's distinct fall-through behavior.
type Connector string

const (
	AND Connector = "AND"
	OR  Connector = "OR"
)

var ErrInvalidAccessControlRequest = errors.New("Invalid access control request")

// Statements maps resource names to the actions permitted by a role or known
// by an access-control declaration.
type Statements map[string][]string

// ActionRequest is the object form accepted for one resource. Actions is any
// slice or array. A missing or non-slice Actions value behaves as an empty
// action list; a connector other than OR behaves as AND.
type ActionRequest struct {
	Actions   any
	Connector Connector
}

// ResourceRequest is one entry in a JavaScript object-style authorization
// request. A slice retains insertion order so the first AND failure has the
// same deterministic error text as reference implementation's Object.entries traversal.
type ResourceRequest struct {
	Resource string
	Actions  any
}

// AuthorizeRequest is the ordered representation of a reference implementation role
// authorization object.
type AuthorizeRequest []ResourceRequest

// AuthorizeResponse is the exact success/error result returned by reference implementation.
type AuthorizeResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// Role stores the statements allowed for one role.
type Role struct {
	statements Statements
}

// AccessControl stores the globally declared statement vocabulary. Go exposes
// the declaration for inspection while role checks remain runtime-safe.
type AccessControl struct {
	statements Statements
}

// NewRole constructs a standalone role.
func NewRole(statements Statements) *Role {
	return &Role{statements: cloneStatements(statements)}
}

// CreateAccessControl constructs an access-control role factory.
func CreateAccessControl(statements Statements) *AccessControl {
	return &AccessControl{statements: cloneStatements(statements)}
}

// Statements returns an independent statement snapshot.
func (control *AccessControl) Statements() Statements {
	if control == nil {
		return nil
	}
	return cloneStatements(control.statements)
}

// NewRole constructs a role. Like the upstream runtime implementation, it
// does not reject statements outside the access-control vocabulary.
func (control *AccessControl) NewRole(statements Statements) *Role {
	return NewRole(statements)
}

// Statements returns an independent statement snapshot.
func (role *Role) Statements() Statements {
	if role == nil {
		return nil
	}
	return cloneStatements(role.statements)
}

// Authorize evaluates an insertion-ordered request. Omit connector for AND.
func (role *Role) Authorize(request AuthorizeRequest, connector ...Connector) (AuthorizeResponse, error) {
	outer := AND
	if len(connector) > 0 {
		outer = connector[0]
	}
	allowed := Statements(nil)
	if role != nil {
		allowed = role.statements
	}

	hasAuthorizedResource := false
	for _, item := range request {
		allowedActions, exists := allowed[item.Resource]
		if !exists {
			if outer == AND {
				return AuthorizeResponse{
					Success: false,
					Error:   "You are not allowed to access resource: " + item.Resource,
				}, nil
			}
			continue
		}

		normalized, err := normalizeActionRequest(item.Actions)
		if err != nil {
			return AuthorizeResponse{}, err
		}
		authorized := isResourceAuthorized(allowedActions, normalized)
		if authorized {
			hasAuthorizedResource = true
		}
		if authorized && outer == OR {
			return AuthorizeResponse{Success: true}, nil
		}
		if !authorized && outer == AND {
			return AuthorizeResponse{
				Success: false,
				Error:   fmt.Sprintf("unauthorized to access resource %q", item.Resource),
			}, nil
		}
	}
	if hasAuthorizedResource {
		return AuthorizeResponse{Success: true}, nil
	}
	return AuthorizeResponse{Success: false, Error: "Not authorized"}, nil
}

// AuthorizeMap is a convenience for ordinary Go maps. Go maps do not retain
// insertion order, so keys are sorted; use AuthorizeRequest when the first AND
// failure's resource-specific error text is part of the contract.
func (role *Role) AuthorizeMap(request map[string]any, connector ...Connector) (AuthorizeResponse, error) {
	keys := make([]string, 0, len(request))
	for resource := range request {
		keys = append(keys, resource)
	}
	sort.Strings(keys)
	ordered := make(AuthorizeRequest, 0, len(keys))
	for _, resource := range keys {
		ordered = append(ordered, ResourceRequest{Resource: resource, Actions: request[resource]})
	}
	return role.Authorize(ordered, connector...)
}

type normalizedActionRequest struct {
	actions   []any
	connector Connector
}

func normalizeConnector(connector Connector) Connector {
	if connector == OR {
		return OR
	}
	return AND
}

func normalizeActionRequest(request any) (normalizedActionRequest, error) {
	if actions, ok := actionSlice(request); ok {
		return normalizedActionRequest{actions: actions, connector: AND}, nil
	}
	if request == nil {
		return normalizedActionRequest{}, ErrInvalidAccessControlRequest
	}

	switch value := request.(type) {
	case ActionRequest:
		return normalizeActionObject(value.Actions, value.Connector), nil
	case *ActionRequest:
		if value == nil {
			return normalizedActionRequest{}, ErrInvalidAccessControlRequest
		}
		return normalizeActionObject(value.Actions, value.Connector), nil
	case map[string]any:
		connector, _ := stringAction(value["connector"])
		return normalizeActionObject(value["actions"], Connector(connector)), nil
	}

	reflected := reflect.ValueOf(request)
	if reflected.Kind() == reflect.Pointer {
		if reflected.IsNil() {
			return normalizedActionRequest{}, ErrInvalidAccessControlRequest
		}
		reflected = reflected.Elem()
	}
	if reflected.Kind() != reflect.Map && reflected.Kind() != reflect.Struct {
		return normalizedActionRequest{}, ErrInvalidAccessControlRequest
	}
	// Other object-like Go values mirror a JavaScript object without an
	// array-valued actions property and therefore normalize to an empty list.
	return normalizedActionRequest{actions: nil, connector: AND}, nil
}

func normalizeActionObject(actions any, connector Connector) normalizedActionRequest {
	list, ok := actionSlice(actions)
	if !ok {
		list = nil
	}
	return normalizedActionRequest{actions: list, connector: normalizeConnector(connector)}
}

func actionSlice(value any) ([]any, bool) {
	if value == nil {
		return nil, false
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.Slice && reflected.Kind() != reflect.Array {
		return nil, false
	}
	if reflected.Kind() == reflect.Slice && reflected.IsNil() {
		return []any{}, true
	}
	actions := make([]any, reflected.Len())
	for index := 0; index < reflected.Len(); index++ {
		actions[index] = reflected.Index(index).Interface()
	}
	return actions, true
}

func isResourceAuthorized(allowed []string, request normalizedActionRequest) bool {
	if len(request.actions) == 0 {
		return false
	}
	if request.connector == OR {
		for _, action := range request.actions {
			if hasAllowedAction(allowed, action) {
				return true
			}
		}
		return false
	}
	for _, action := range request.actions {
		if !hasAllowedAction(allowed, action) {
			return false
		}
	}
	return true
}

func hasAllowedAction(allowed []string, requested any) bool {
	value, ok := stringAction(requested)
	if !ok {
		return false
	}
	for _, action := range allowed {
		if action == value {
			return true
		}
	}
	return false
}

func stringAction(value any) (string, bool) {
	if value == nil {
		return "", false
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.String {
		return "", false
	}
	return reflected.String(), true
}

func cloneStatements(source Statements) Statements {
	if source == nil {
		return nil
	}
	clone := make(Statements, len(source))
	for resource, actions := range source {
		clone[resource] = append([]string(nil), actions...)
	}
	return clone
}
