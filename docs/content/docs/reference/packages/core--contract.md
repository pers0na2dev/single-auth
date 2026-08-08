---
title: "github.com/pers0na2dev/single-auth/core/contract"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/core/contract.

- Import path: `github.com/pers0na2dev/single-auth/core/contract`
- Package name: `contract`

Package contract defines the transport-neutral request, response, header,
and error values shared by the single-auth engine and its HTTP adapters.

The package intentionally does not import net/http, fasthttp, or Fiber.

## Constants

HTTP status constants used by the transport-neutral engine.

```go
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
```

## Types

### `APIError`

APIError is the typed error crossing the direct API and HTTP dispatcher
boundary. Cause is available to server code but is never serialized.

```go
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
```

## Constructors and functions for `APIError`

### `AsAPIError`

AsAPIError extracts a typed API error through wrapping layers.

```go
func AsAPIError(err error) (*APIError, bool)
```

### `NewAPIError`

NewAPIError creates a typed API error.

```go
func NewAPIError(status int, code, message string) *APIError
```

## Methods on `APIError`

### `Error`

Error implements error.

```go
func (e *APIError) Error() string
```

### `Unwrap`

Unwrap exposes the server-side cause without serializing it.

```go
func (e *APIError) Unwrap() error
```

### `WithCause`

WithCause returns an independent error carrying cause.

```go
func (e *APIError) WithCause(cause error) *APIError
```

### `WithHeaders`

WithHeaders returns an independent error carrying headers.

```go
func (e *APIError) WithHeaders(headers Headers) *APIError
```

### `WithWireBody`

WithWireBody returns an independent error carrying a custom JSON wire body.
A nil body clears the override and restores the default representation.

```go
func (e *APIError) WithWireBody(body any) *APIError
```

### `HeaderField`

HeaderField is one header line. Repeated fields are represented by repeated
entries rather than by comma-joining their values.

```go
type HeaderField struct {
	Name  string
	Value string
}
```

### `Headers`

Headers is an ordered, case-insensitive, multi-value header collection.

Its zero value is ready for use. Copying a Headers value directly aliases
its backing storage; use Clone when the copy may be mutated independently.
Request and Response accessors always return independent clones.

```go
type Headers struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Headers`

### `NewHeaders`

NewHeaders constructs an ordered header collection. Empty field names are
ignored because they cannot be represented by any supported HTTP transport.

```go
func NewHeaders(fields ...HeaderField) Headers
```

## Methods on `Headers`

### `Add`

Add appends a header line. Empty field names are ignored.

```go
func (h *Headers) Add(name, value string)
```

### `Clone`

Clone returns an independently mutable copy.

```go
func (h Headers) Clone() Headers
```

### `Delete`

Delete removes every field with name.

```go
func (h *Headers) Delete(name string)
```

### `Fields`

Fields returns an independent copy in wire order.

```go
func (h Headers) Fields() []HeaderField
```

### `Get`

Get returns the first value for name. It deliberately does not comma-join
repeated values: callers that need all values must use Values. This is
particularly important for Set-Cookie, whose values are never joinable.

```go
func (h Headers) Get(name string) (string, bool)
```

### `Has`

Has reports whether at least one field with name exists.

```go
func (h Headers) Has(name string) bool
```

### `Len`

Len returns the number of header lines, including repeated fields.

```go
func (h Headers) Len() int
```

### `MergeResponse`

MergeResponse overlays src using the reference implementation response semantics: every
Set-Cookie line is appended, while all other names replace their previous
values. Repeated non-cookie values from src remain repeated and ordered.

```go
func (h *Headers) MergeResponse(src Headers)
```

### `Set`

Set replaces every existing field with name by one field appended at the
position where this mutation occurs.

```go
func (h *Headers) Set(name, value string)
```

### `Values`

Values returns all values for name in wire order.

```go
func (h Headers) Values(name string) []string
```

### `Request`

Request is an immutable, transport-neutral request snapshot. All byte slices
and headers are copied on construction and when returned by accessors.

```go
type Request struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Request`

### `NewRequest`

NewRequest constructs an independent request snapshot.

```go
func NewRequest(method, rawPath string, options RequestOptions) Request
```

## Methods on `Request`

### `Body`

Body returns an independent copy of the raw body.

```go
func (r Request) Body() []byte
```

### `Clone`

Clone returns an independent request snapshot.

```go
func (r Request) Clone() Request
```

### `Context`

Context returns the request cancellation context.

```go
func (r Request) Context() context.Context
```

### `Headers`

Headers returns an independent copy of all request header lines.

```go
func (r Request) Headers() Headers
```

### `Host`

Host returns the original request host, including a port when present.

```go
func (r Request) Host() string
```

### `Method`

Method returns the normalized uppercase method.

```go
func (r Request) Method() string
```

### `PeerAddress`

PeerAddress returns the transport-provided peer address.

```go
func (r Request) PeerAddress() string
```

### `Query`

Query parses the raw query without changing the stored request.

```go
func (r Request) Query() (url.Values, error)
```

### `RawPath`

RawPath returns the escaped request path without query data.

```go
func (r Request) RawPath() string
```

### `RawQuery`

RawQuery returns the unmodified query string without a leading question
mark.

```go
func (r Request) RawQuery() string
```

### `Scheme`

Scheme returns the original request scheme.

```go
func (r Request) Scheme() string
```

### `Target`

Target returns the raw path and raw query in request-target form.

```go
func (r Request) Target() string
```

### `WithAddedHeader`

WithAddedHeader returns a copy with one appended header line.

```go
func (r Request) WithAddedHeader(name, value string) Request
```

### `WithBody`

WithBody returns a copy carrying an independent raw body.

```go
func (r Request) WithBody(body []byte) Request
```

### `WithContext`

WithContext returns a copy carrying ctx.

```go
func (r Request) WithContext(ctx context.Context) Request
```

### `WithHeader`

WithHeader returns a copy with every existing field of name replaced.

```go
func (r Request) WithHeader(name, value string) Request
```

### `WithHeaders`

WithHeaders returns a copy carrying an independent header collection.

```go
func (r Request) WithHeaders(headers Headers) Request
```

### `WithMethod`

WithMethod returns a copy carrying the normalized method.

```go
func (r Request) WithMethod(method string) Request
```

### `WithTarget`

WithTarget returns a copy carrying a new raw path and query.

```go
func (r Request) WithTarget(rawPath, rawQuery string) Request
```

### `RequestOptions`

RequestOptions contains the transport data that is not part of the method
and raw path. Adapters must copy any reusable transport buffers before
calling NewRequest.

```go
type RequestOptions struct {
	Context     context.Context
	Scheme      string
	Host        string
	RawQuery    string
	Headers     Headers
	Body        []byte
	PeerAddress string
}
```

### `Response`

Response is an immutable, transport-neutral response snapshot.

```go
type Response struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Response`

### `JSONResponse`

JSONResponse encodes value as JSON and creates an application/json response.

```go
func JSONResponse(status int, value any) (Response, error)
```

### `NewResponse`

NewResponse constructs an independent response. A zero status defaults to
200; other values are retained so conformance tests can catch invalid output.

```go
func NewResponse(status int, headers Headers, body []byte) Response
```

### `ResponseFromError`

ResponseFromError converts err to the stable wire representation. Unknown
errors are intentionally redacted.

```go
func ResponseFromError(err error) Response
```

### `TextResponse`

TextResponse creates a UTF-8 plain-text response.

```go
func TextResponse(status int, body string) Response
```

## Methods on `Response`

### `Body`

Body returns an independent copy of the response body.

```go
func (r Response) Body() []byte
```

### `Clone`

Clone returns an independent response snapshot.

```go
func (r Response) Clone() Response
```

### `Headers`

Headers returns an independent copy of all response header lines.

```go
func (r Response) Headers() Headers
```

### `IsZero`

IsZero reports whether the response has never been initialized. A deliberate
200 response created with NewResponse is not zero.

```go
func (r Response) IsZero() bool
```

### `Status`

Status returns the numeric status code.

```go
func (r Response) Status() int
```

### `WithAddedHeader`

WithAddedHeader returns a copy with one appended header line.

```go
func (r Response) WithAddedHeader(name, value string) Response
```

### `WithBody`

WithBody returns a copy carrying an independent body.

```go
func (r Response) WithBody(body []byte) Response
```

### `WithHeader`

WithHeader returns a copy with every existing field of name replaced.

```go
func (r Response) WithHeader(name, value string) Response
```

### `WithHeaders`

WithHeaders returns a copy carrying an independent replacement collection.

```go
func (r Response) WithHeaders(headers Headers) Response
```

### `WithMergedHeaders`

WithMergedHeaders returns a copy with src overlaid using response-header
semantics. Set-Cookie appends; other names replace.

```go
func (r Response) WithMergedHeaders(src Headers) Response
```

### `WithStatus`

WithStatus returns a copy carrying status.

```go
func (r Response) WithStatus(status int) Response
```

