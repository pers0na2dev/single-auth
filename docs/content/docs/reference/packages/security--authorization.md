---
title: "github.com/pers0na2dev/single-auth/security/authorization"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/security/authorization.

- Import path: `github.com/pers0na2dev/single-auth/security/authorization`
- Package name: `authorization`

Package authorization implements reference implementation 1.6.26 role-based access-control
statement evaluation. It is a pure utility package and does not register an
authentication endpoint.

## Constants

```go
const Version = "1.6.26"
```

## Variables

```go
var ErrInvalidAccessControlRequest = errors.New("Invalid access control request")
```

## Types

### `AccessControl`

AccessControl stores the globally declared statement vocabulary. Go exposes
the declaration for inspection while role checks remain runtime-safe.

```go
type AccessControl struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `AccessControl`

### `CreateAccessControl`

CreateAccessControl constructs an access-control role factory.

```go
func CreateAccessControl(statements Statements) *AccessControl
```

## Methods on `AccessControl`

### `NewRole`

NewRole constructs a role. Like the upstream runtime implementation, it
does not reject statements outside the access-control vocabulary.

```go
func (control *AccessControl) NewRole(statements Statements) *Role
```

### `Statements`

Statements returns an independent statement snapshot.

```go
func (control *AccessControl) Statements() Statements
```

### `ActionRequest`

ActionRequest is the object form accepted for one resource. Actions is any
slice or array. A missing or non-slice Actions value behaves as an empty
action list; a connector other than OR behaves as AND.

```go
type ActionRequest struct {
	Actions   any
	Connector Connector
}
```

### `AuthorizeRequest`

AuthorizeRequest is the ordered representation of a reference implementation role
authorization object.

```go
type AuthorizeRequest []ResourceRequest
```

### `AuthorizeResponse`

AuthorizeResponse is the exact success/error result returned by reference implementation.

```go
type AuthorizeResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}
```

### `Connector`

Connector combines either resources at the outer level or actions within a
resource. Unchecked inner connectors normalize to AND. An unchecked outer
connector retains reference implementation's distinct fall-through behavioral compatibility.

```go
type Connector string
```

## Constants associated with `Connector`

```go
const (
	AND Connector = "AND"
	OR  Connector = "OR"
)
```

### `ResourceRequest`

ResourceRequest is one entry in a JavaScript object-style authorization
request. A slice retains insertion order so the first AND failure has the
same deterministic error text as reference implementation's Object.entries traversal.

```go
type ResourceRequest struct {
	Resource string
	Actions  any
}
```

### `Role`

Role stores the statements allowed for one role.

```go
type Role struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Role`

### `NewRole`

NewRole constructs a standalone role.

```go
func NewRole(statements Statements) *Role
```

## Methods on `Role`

### `Authorize`

Authorize evaluates an insertion-ordered request. Omit connector for AND.

```go
func (role *Role) Authorize(request AuthorizeRequest, connector ...Connector) (AuthorizeResponse, error)
```

### `AuthorizeMap`

AuthorizeMap is a convenience for ordinary Go maps. Go maps do not retain
insertion order, so keys are sorted; use AuthorizeRequest when the first AND
failure's resource-specific error text is part of the contract.

```go
func (role *Role) AuthorizeMap(request map[string]any, connector ...Connector) (AuthorizeResponse, error)
```

### `Statements`

Statements returns an independent statement snapshot.

```go
func (role *Role) Statements() Statements
```

### `Statements`

Statements maps resource names to the actions permitted by a role or known
by an access-control declaration.

```go
type Statements map[string][]string
```

