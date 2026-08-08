---
title: "github.com/pers0na2dev/single-auth/core/model"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/core/model.

- Import path: `github.com/pers0na2dev/single-auth/core/model`
- Package name: `model`

## Types

### `Account`

Account is the reference implementation's base account model.

```go
type Account struct {
	Core
	ProviderID            string           `json:"providerId"`
	AccountID             string           `json:"accountId"`
	UserID                string           `json:"userId"`
	AccessToken           Value[string]    `json:"accessToken,omitzero"`
	RefreshToken          Value[string]    `json:"refreshToken,omitzero"`
	IDToken               Value[string]    `json:"idToken,omitzero"`
	AccessTokenExpiresAt  Value[time.Time] `json:"accessTokenExpiresAt,omitzero"`
	RefreshTokenExpiresAt Value[time.Time] `json:"refreshTokenExpiresAt,omitzero"`
	Scope                 Value[string]    `json:"scope,omitzero"`
	Password              Value[string]    `json:"password,omitzero"`
	AdditionalFields      Fields           `json:"-"`
}
```

## Methods on `Account`

### `MarshalJSON`

```go
func (a Account) MarshalJSON() ([]byte, error)
```

### `Record`

Record converts an account to the canonical dynamic storage representation.

```go
func (a Account) Record() Record
```

### `UnmarshalJSON`

```go
func (a *Account) UnmarshalJSON(data []byte) error
```

### `Core`

Core contains the columns shared by the reference implementation's user, session, account,
and verification models.

```go
type Core struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}
```

### `Fields`

Fields contains schema- or plugin-contributed fields. Map membership and
Value state are both honored so callers can retain absent/null/value exactly.

```go
type Fields map[string]Value[any]
```

## Constructors and functions for `Fields`

### `FieldsFromRecord`

FieldsFromRecord extracts every field except the supplied core field names.

```go
func FieldsFromRecord(record Record, coreFields ...string) Fields
```

## Methods on `Fields`

### `Apply`

Apply copies all set fields into dst. Explicit null becomes a nil map value;
absent fields are omitted.

```go
func (f Fields) Apply(dst Record)
```

### `Lookup`

Lookup returns the field's tri-state value. A missing key returns Absent.

```go
func (f Fields) Lookup(name string) Value[any]
```

### `Set`

Set stores a present value.

```go
func (f Fields) Set(name string, value any)
```

### `SetNull`

SetNull stores an explicit null.

```go
func (f Fields) SetNull(name string)
```

### `Unset`

Unset removes a field, returning it to the absent state.

```go
func (f Fields) Unset(name string)
```

### `RateLimit`

RateLimit is the reference implementation's optional database-backed rate-limit model.

```go
type RateLimit struct {
	Key              string `json:"key"`
	Count            int64  `json:"count"`
	LastRequest      int64  `json:"lastRequest"`
	AdditionalFields Fields `json:"-"`
}
```

## Methods on `RateLimit`

### `MarshalJSON`

```go
func (r RateLimit) MarshalJSON() ([]byte, error)
```

### `Record`

Record converts a rate-limit value to the canonical dynamic storage representation.

```go
func (r RateLimit) Record() Record
```

### `UnmarshalJSON`

```go
func (r *RateLimit) UnmarshalJSON(data []byte) error
```

### `Record`

Record is the dynamic row representation shared with storage adapters. A
missing key is absent and a present key with a nil value is explicit null.

```go
type Record map[string]any
```

### `Session`

Session is the reference implementation's base session model.

```go
type Session struct {
	Core
	UserID           string        `json:"userId"`
	ExpiresAt        time.Time     `json:"expiresAt"`
	Token            string        `json:"token"`
	IPAddress        Value[string] `json:"ipAddress,omitzero"`
	UserAgent        Value[string] `json:"userAgent,omitzero"`
	AdditionalFields Fields        `json:"-"`
}
```

## Methods on `Session`

### `MarshalJSON`

```go
func (s Session) MarshalJSON() ([]byte, error)
```

### `Record`

Record converts a session to the canonical dynamic storage representation.

```go
func (s Session) Record() Record
```

### `UnmarshalJSON`

```go
func (s *Session) UnmarshalJSON(data []byte) error
```

### `User`

User is the reference implementation's base user model. AdditionalFields holds configured or
plugin-contributed fields without losing absent/null/value semantics.

```go
type User struct {
	Core
	Name             string        `json:"name"`
	Email            string        `json:"email"`
	EmailVerified    bool          `json:"emailVerified"`
	Image            Value[string] `json:"image,omitzero"`
	AdditionalFields Fields        `json:"-"`
}
```

## Methods on `User`

### `MarshalJSON`

```go
func (u User) MarshalJSON() ([]byte, error)
```

### `Record`

Record converts a user to the canonical dynamic storage representation.

```go
func (u User) Record() Record
```

### `UnmarshalJSON`

```go
func (u *User) UnmarshalJSON(data []byte) error
```

### `Value`

Value preserves the three states used by the reference implementation's dynamic schemas:
a field can be absent, explicitly null, or contain a value. Its zero value
is Absent.

```go
type Value[T any] struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Value`

### `Absent`

Absent returns a value that was not supplied.

```go
func Absent[T any]() Value[T]
```

### `Null`

Null returns a value that was explicitly supplied as null.

```go
func Null[T any]() Value[T]
```

### `Present`

Present returns a supplied, non-null value. The contained Go value can be
its type's zero value; presence is tracked independently.

```go
func Present[T any](value T) Value[T]
```

## Methods on `Value`

### `Get`

Get returns the contained value and true only for the present state.

```go
func (v Value[T]) Get() (T, bool)
```

### `Interface`

Interface converts the value to the representation used by dynamic records.
The second return value is false only when the field is absent.

```go
func (v Value[T]) Interface() (any, bool)
```

### `IsNull`

IsNull reports whether the field was explicitly supplied as null.

```go
func (v Value[T]) IsNull() bool
```

### `IsSet`

IsSet reports whether the field was supplied, including explicit null.

```go
func (v Value[T]) IsSet() bool
```

### `IsZero`

IsZero lets encoding/json's omitzero option omit absent values.

```go
func (v Value[T]) IsZero() bool
```

### `MarshalJSON`

```go
func (v Value[T]) MarshalJSON() ([]byte, error)
```

### `Or`

Or returns the contained value, or fallback for absent and null values.

```go
func (v Value[T]) Or(fallback T) T
```

### `UnmarshalJSON`

```go
func (v *Value[T]) UnmarshalJSON(data []byte) error
```

### `Verification`

Verification is the reference implementation's single-use verification model.

```go
type Verification struct {
	Core
	Identifier       string    `json:"identifier"`
	Value            string    `json:"value"`
	ExpiresAt        time.Time `json:"expiresAt"`
	AdditionalFields Fields    `json:"-"`
}
```

## Methods on `Verification`

### `MarshalJSON`

```go
func (v Verification) MarshalJSON() ([]byte, error)
```

### `Record`

Record converts a verification to the canonical dynamic storage representation.

```go
func (v Verification) Record() Record
```

### `UnmarshalJSON`

```go
func (v *Verification) UnmarshalJSON(data []byte) error
```

