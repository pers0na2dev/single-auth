package openapi

import "encoding/json"

// Schema is an OpenAPI 3.1 schema object. Type intentionally accepts either a
// string or []string because OpenAPI 3.1 represents nullable values as a type
// union instead of the deprecated nullable keyword.
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

// MarshalJSON preserves the OpenAPI distinction between an omitted
// properties member and an explicitly empty object schema. The latter is used
// by single-auth for records and body-less mutation endpoints.
func (schema Schema) MarshalJSON() ([]byte, error) {
	type alias Schema
	encoded, err := json.Marshal(alias(schema))
	if err != nil || schema.Properties == nil {
		return encoded, err
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		return nil, err
	}
	object["properties"] = schema.Properties
	return json.Marshal(object)
}

type Parameter struct {
	Name        string  `json:"name"`
	In          string  `json:"in"`
	Required    *bool   `json:"required,omitempty"`
	Description string  `json:"description,omitempty"`
	Schema      *Schema `json:"schema,omitempty"`
}

type MediaType struct {
	Schema *Schema `json:"schema,omitempty"`
}

type Response struct {
	Description string               `json:"description,omitempty"`
	Content     map[string]MediaType `json:"content,omitempty"`
}

type RequestBody struct {
	Required *bool                `json:"required,omitempty"`
	Content  map[string]MediaType `json:"content"`
}

type Operation struct {
	Tags        []string              `json:"tags,omitempty"`
	OperationID string                `json:"operationId,omitempty"`
	Description string                `json:"description,omitempty"`
	Security    []map[string][]string `json:"security,omitempty"`
	Parameters  []Parameter           `json:"parameters"`
	RequestBody *RequestBody          `json:"requestBody,omitempty"`
	Responses   map[string]Response   `json:"responses,omitempty"`
}

type PathItem struct {
	Get    *Operation `json:"get,omitempty"`
	Post   *Operation `json:"post,omitempty"`
	Put    *Operation `json:"put,omitempty"`
	Patch  *Operation `json:"patch,omitempty"`
	Delete *Operation `json:"delete,omitempty"`
}

func (path *PathItem) operation(method string) **Operation {
	switch method {
	case "GET":
		return &path.Get
	case "POST":
		return &path.Post
	case "PUT":
		return &path.Put
	case "PATCH":
		return &path.Patch
	case "DELETE":
		return &path.Delete
	default:
		return nil
	}
}

type ModelSchema = Schema

type SecurityScheme struct {
	Type        string `json:"type"`
	In          string `json:"in,omitempty"`
	Name        string `json:"name,omitempty"`
	Scheme      string `json:"scheme,omitempty"`
	Description string `json:"description,omitempty"`
}

type Components struct {
	Schemas         map[string]ModelSchema    `json:"schemas"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes"`
}

type Info struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

type Server struct {
	URL string `json:"url"`
}

type Tag struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Document is the generated OpenAPI 3.1 document.
type Document struct {
	OpenAPI    string                `json:"openapi"`
	Info       Info                  `json:"info"`
	Components Components            `json:"components"`
	Security   []map[string][]string `json:"security"`
	Servers    []Server              `json:"servers"`
	Tags       []Tag                 `json:"tags"`
	Paths      map[string]PathItem   `json:"paths"`
}

// Metadata is stored under engine.Endpoint.Metadata[MetadataKey]. Query and
// Body use the wrapper-aware input DSL; explicitly supplied request bodies and
// responses remain available for endpoints with hand-authored schemas.
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

const MetadataKey = "openapi"
