---
title: "github.com/pers0na2dev/single-auth/plugins/openapi"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/openapi.

- Import path: `github.com/pers0na2dev/single-auth/plugins/openapi`
- Package name: `openapi`

Package openapi exposes the single-auth 1.6.26 OpenAPI 3.1 generator and
its Scalar API-reference endpoints.

## Constants

```go
const MetadataKey = "openapi"
```

```go
const Version = "1.6.26"
```

## Functions

### `New`

New constructs the transport-neutral OpenAPI plugin from explicit runtime
dependencies. Root users normally use NewFactory so schema and endpoint
enumeration are bound automatically.

```go
func New(options Options, runtime Runtime) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds the generator to the final root schema, public base URL,
disabled-path configuration, and lazily finalized endpoint registry.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `WithMetadata`

WithMetadata returns an endpoint copy carrying OpenAPI metadata while
preserving unrelated annotations.

```go
func WithMetadata(endpoint engine.Endpoint, metadata Metadata) engine.Endpoint
```

## Types

### `Components`

```go
type Components struct {
	Schemas         map[string]ModelSchema    `json:"schemas"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes"`
}
```

### `Document`

Document is the generated OpenAPI 3.1 document.

```go
type Document struct {
	OpenAPI    string                `json:"openapi"`
	Info       Info                  `json:"info"`
	Components Components            `json:"components"`
	Security   []map[string][]string `json:"security"`
	Servers    []Server              `json:"servers"`
	Tags       []Tag                 `json:"tags"`
	Paths      map[string]PathItem   `json:"paths"`
}
```

### `Generator`

Generator is immutable and safe for concurrent use when its callbacks are.
Endpoint enumeration is deliberately lazy so a root plugin can be built
before Auth finalizes its registry.

```go
type Generator struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Generator`

### `NewGenerator`

```go
func NewGenerator(options GeneratorOptions) (*Generator, error)
```

## Methods on `Generator`

### `Generate`

Generate constructs a fresh OpenAPI document from the current endpoint
registry and the immutable storage schema.

```go
func (generator *Generator) Generate(request contract.Request) (Document, error)
```

### `GeneratorOptions`

```go
type GeneratorOptions struct {
	Schema         storage.Schema
	ListEndpoints  func() []engine.Endpoint
	ResolveBaseURL func(contract.Request) (string, error)
	BaseURL        string
	DisabledPaths  []string
}
```

### `Info`

```go
type Info struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Version     string `json:"version"`
}
```

### `Input`

Input is a transport-neutral request/query schema. It models the Zod
constructs used by single-auth's endpoint metadata without evaluating
runtime defaults.

```go
type Input struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Input`

### `Any`

```go
func Any() Input
```

### `Array`

```go
func Array(item Input) Input
```

### `Boolean`

```go
func Boolean() Input
```

### `Enum`

```go
func Enum(values ...string) Input
```

### `ExclusiveUnion`

```go
func ExclusiveUnion(options ...Input) Input
```

### `InputRef`

InputRef returns an independent pointer suitable for Metadata.Query or
Metadata.Body.

```go
func InputRef(value Input) *Input
```

### `Intersection`

```go
func Intersection(left, right Input) Input
```

### `Literal`

```go
func Literal(value any) Input
```

### `Null`

```go
func Null() Input
```

### `Number`

```go
func Number() Input
```

### `Object`

```go
func Object(properties ...Property) Input
```

### `Record`

```go
func Record(key, value Input) Input
```

### `String`

```go
func String() Input
```

### `Undefined`

```go
func Undefined() Input
```

### `Union`

```go
func Union(options ...Input) Input
```

## Methods on `Input`

### `AcceptsUndefined`

AcceptsUndefined reports whether a request body using this input is
optional under single-auth's wrapper semantics.

```go
func (input Input) AcceptsUndefined() bool
```

### `Default`

```go
func (input Input) Default(value any) Input
```

### `DefaultFactory`

```go
func (input Input) DefaultFactory(factory func() any) Input
```

### `Describe`

```go
func (input Input) Describe(description string) Input
```

### `Max`

```go
func (input Input) Max(length int) Input
```

### `Min`

```go
func (input Input) Min(length int) Input
```

### `NonOptional`

```go
func (input Input) NonOptional() Input
```

### `Nullable`

```go
func (input Input) Nullable() Input
```

### `OpenAPISchema`

OpenAPISchema converts this input into its OpenAPI 3.1 representation.

```go
func (input Input) OpenAPISchema() Schema
```

### `Optional`

```go
func (input Input) Optional() Input
```

### `Prefault`

```go
func (input Input) Prefault(value any) Input
```

### `MediaType`

```go
type MediaType struct {
	Schema *Schema `json:"schema,omitempty"`
}
```

### `Metadata`

Metadata is stored under engine.Endpoint.Metadata[MetadataKey]. Query and
Body use the wrapper-aware input DSL; explicitly supplied request bodies and
responses remain available for endpoints with hand-authored schemas.

```go
type Metadata struct {
	Tags        []string
	OperationID string
	Description string
	Parameters  []Parameter
	Query       *Input
	Body        *Input
	RequestBody *RequestBody
	Responses   map[string]Response
	Hidden      bool
}
```

### `ModelSchema`

```go
type ModelSchema = Schema
```

### `Operation`

```go
type Operation struct {
	Tags        []string              `json:"tags,omitempty"`
	OperationID string                `json:"operationId,omitempty"`
	Description string                `json:"description,omitempty"`
	Security    []map[string][]string `json:"security,omitempty"`
	Parameters  []Parameter           `json:"parameters"`
	RequestBody *RequestBody          `json:"requestBody,omitempty"`
	Responses   map[string]Response   `json:"responses,omitempty"`
}
```

### `Options`

```go
type Options struct {
	Path                    string
	DisableDefaultReference bool
	Theme                   string
	Nonce                   string
}
```

### `Parameter`

```go
type Parameter struct {
	Name        string  `json:"name"`
	In          string  `json:"in"`
	Required    *bool   `json:"required,omitempty"`
	Description string  `json:"description,omitempty"`
	Schema      *Schema `json:"schema,omitempty"`
}
```

### `PathItem`

```go
type PathItem struct {
	Get    *Operation `json:"get,omitempty"`
	Post   *Operation `json:"post,omitempty"`
	Put    *Operation `json:"put,omitempty"`
	Patch  *Operation `json:"patch,omitempty"`
	Delete *Operation `json:"delete,omitempty"`
}
```

### `Property`

```go
type Property struct {
	Name   string
	Schema Input
}
```

## Constructors and functions for `Property`

### `Prop`

```go
func Prop(name string, schema Input) Property
```

### `RequestBody`

```go
type RequestBody struct {
	Required *bool                `json:"required,omitempty"`
	Content  map[string]MediaType `json:"content"`
}
```

### `Response`

```go
type Response struct {
	Description string               `json:"description,omitempty"`
	Content     map[string]MediaType `json:"content,omitempty"`
}
```

### `Runtime`

```go
type Runtime struct {
	Schema         storage.Schema
	ListEndpoints  func() []engine.Endpoint
	ResolveBaseURL func(contract.Request) (string, error)
	BaseURL        string
	DisabledPaths  []string
}
```

### `Schema`

Schema is an OpenAPI 3.1 schema object. Type intentionally accepts either a
string or []string because OpenAPI 3.1 represents nullable values as a type
union instead of the deprecated nullable keyword.

```go
type Schema struct {
	Type                 any               `json:"type,omitempty"`
	Properties           map[string]Schema `json:"properties,omitempty"`
	Required             []string          `json:"required,omitempty"`
	Ref                  string            `json:"$ref,omitempty"`
	Description          string            `json:"description,omitempty"`
	Default              any               `json:"default,omitempty"`
	ReadOnly             bool              `json:"readOnly,omitempty"`
	Nullable             *bool             `json:"nullable,omitempty"`
	Format               string            `json:"format,omitempty"`
	Deprecated           bool              `json:"deprecated,omitempty"`
	Enum                 []any             `json:"enum,omitempty"`
	Items                *Schema           `json:"items,omitempty"`
	MinLength            *int              `json:"minLength,omitempty"`
	MaxLength            *int              `json:"maxLength,omitempty"`
	Minimum              *float64          `json:"minimum,omitempty"`
	Maximum              *float64          `json:"maximum,omitempty"`
	AdditionalProperties any               `json:"additionalProperties,omitempty"`
	PropertyNames        *Schema           `json:"propertyNames,omitempty"`
	AllOf                []Schema          `json:"allOf,omitempty"`
	AnyOf                []Schema          `json:"anyOf,omitempty"`
	OneOf                []Schema          `json:"oneOf,omitempty"`
	Const                any               `json:"const,omitempty"`
	Example              any               `json:"example,omitempty"`
}
```

## Methods on `Schema`

### `MarshalJSON`

MarshalJSON preserves the OpenAPI distinction between an omitted
properties member and an explicitly empty object schema. The latter is used
by single-auth for records and body-less mutation endpoints.

```go
func (schema Schema) MarshalJSON() ([]byte, error)
```

### `SecurityScheme`

```go
type SecurityScheme struct {
	Type        string `json:"type"`
	In          string `json:"in,omitempty"`
	Name        string `json:"name,omitempty"`
	Scheme      string `json:"scheme,omitempty"`
	Description string `json:"description,omitempty"`
}
```

### `Server`

```go
type Server struct {
	URL string `json:"url"`
}
```

### `Tag`

```go
type Tag struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}
```

