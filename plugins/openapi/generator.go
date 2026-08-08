package openapi

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

type GeneratorOptions struct {
	Schema         storage.Schema
	ListEndpoints  func() []engine.Endpoint
	ResolveBaseURL func(contract.Request) (string, error)
	BaseURL        string
	DisabledPaths  []string
}

// Generator is immutable and safe for concurrent use when its callbacks are.
// Endpoint enumeration is deliberately lazy so a root plugin can be built
// before Auth finalizes its registry.
type Generator struct {
	schema         storage.Schema
	listEndpoints  func() []engine.Endpoint
	resolveBaseURL func(contract.Request) (string, error)
	baseURL        string
	disabled       map[string]struct{}
}

func NewGenerator(options GeneratorOptions) (*Generator, error) {
	if options.ListEndpoints == nil {
		return nil, fmt.Errorf("openapi: ListEndpoints is required")
	}
	if err := options.Schema.Validate(); err != nil {
		return nil, fmt.Errorf("openapi: schema: %w", err)
	}
	disabled := make(map[string]struct{}, len(options.DisabledPaths))
	for _, path := range options.DisabledPaths {
		disabled[path] = struct{}{}
	}
	return &Generator{
		schema: options.Schema.Clone(), listEndpoints: options.ListEndpoints,
		resolveBaseURL: options.ResolveBaseURL, baseURL: options.BaseURL,
		disabled: disabled,
	}, nil
}

// Generate constructs a fresh OpenAPI document from the current endpoint
// registry and the immutable storage schema.
func (generator *Generator) Generate(request contract.Request) (Document, error) {
	if generator == nil || generator.listEndpoints == nil {
		return Document{}, fmt.Errorf("openapi: generator is not initialized")
	}
	catalog, err := loadCoreCatalog()
	if err != nil {
		return Document{}, err
	}
	baseURL := strings.TrimSpace(generator.baseURL)
	if generator.resolveBaseURL != nil {
		baseURL, err = generator.resolveBaseURL(request)
		if err != nil {
			return Document{}, err
		}
	}

	document := Document{
		OpenAPI: "3.1.1",
		Info:    Info{Title: "single-auth", Description: "API Reference for your single-auth Instance", Version: "1.1.0"},
		Components: Components{
			Schemas: generator.models(),
			SecuritySchemes: map[string]SecurityScheme{
				"apiKeyCookie": {Type: "apiKey", In: "cookie", Name: "apiKeyCookie", Description: "API Key authentication via cookie"},
				"bearerAuth":   {Type: "http", Scheme: "bearer", Description: "Bearer token authentication"},
			},
		},
		Security: []map[string][]string{{"apiKeyCookie": {}, "bearerAuth": {}}},
		Servers:  []Server{{URL: baseURL}},
		Tags:     []Tag{{Name: "Default", Description: "Default endpoints that are included with single-auth by default. These endpoints are not part of any plugin."}},
		Paths:    make(map[string]PathItem),
	}

	usedOperationIDs := make(map[string]struct{})
	for _, endpoint := range generator.listEndpoints() {
		if endpoint.ServerOnly || endpoint.Path == "" || generator.isDisabled(endpoint.Path) ||
			endpoint.Name == "generateOpenAPISchema" || endpoint.Name == "openAPIReference" {
			continue
		}
		metadata := endpointMetadata(endpoint)
		if metadata.Hidden {
			continue
		}
		path := toOpenAPIPath(endpoint.Path)
		pathItem := document.Paths[path]
		for _, method := range normalizedMethods(endpoint.Methods) {
			target := pathItem.operation(method)
			if target == nil {
				continue
			}
			operation := catalogOperation(catalog.Paths, path, method)
			cataloged := operation != nil
			if !cataloged {
				resolved := generatedOperation(endpoint, method, metadata)
				operation = &resolved
			}
			if metadata.OperationID != "" {
				operation.OperationID = metadata.OperationID
			} else if operation.OperationID == "" && !cataloged {
				operation.OperationID = endpoint.OperationID
			}
			operation.OperationID = uniqueOperationID(operation.OperationID, method, usedOperationIDs)
			operation.Parameters = appendPathParameters(endpoint.Path, operation.Parameters)
			if method == http.MethodPost && (endpoint.Path == "/sign-up/email" || endpoint.Path == "/update-user") {
				operation.RequestBody = generator.applyUserInputFields(endpoint.Path, operation.RequestBody)
			}
			*target = operation
		}
		document.Paths[path] = pathItem
	}
	return document, nil
}

func (generator *Generator) isDisabled(path string) bool {
	_, disabled := generator.disabled[path]
	return disabled
}

func normalizedMethods(methods []string) []string {
	result := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.ToUpper(method)
		switch method {
		case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			result = append(result, method)
		}
	}
	return result
}

func catalogOperation(paths map[string]PathItem, path, method string) *Operation {
	item, exists := paths[path]
	if !exists {
		return nil
	}
	var operation *Operation
	switch method {
	case http.MethodGet:
		operation = item.Get
	case http.MethodPost:
		operation = item.Post
	case http.MethodPut:
		operation = item.Put
	case http.MethodPatch:
		operation = item.Patch
	case http.MethodDelete:
		operation = item.Delete
	}
	if operation == nil {
		return nil
	}
	clone := cloneJSON(*operation)
	return &clone
}

func endpointMetadata(endpoint engine.Endpoint) Metadata {
	metadata := builtInPluginMetadata(endpoint)
	if endpoint.Metadata == nil {
		return metadata
	}
	switch value := endpoint.Metadata[MetadataKey].(type) {
	case Metadata:
		return mergeMetadata(metadata, value)
	case *Metadata:
		if value != nil {
			return mergeMetadata(metadata, *value)
		}
	}
	return metadata
}

// WithMetadata returns an endpoint copy carrying OpenAPI metadata while
// preserving unrelated annotations.
func WithMetadata(endpoint engine.Endpoint, metadata Metadata) engine.Endpoint {
	clone := endpoint
	clone.Methods = append([]string(nil), endpoint.Methods...)
	clone.Metadata = make(map[string]any, len(endpoint.Metadata)+1)
	for key, value := range endpoint.Metadata {
		clone.Metadata[key] = value
	}
	clone.Metadata[MetadataKey] = metadata
	return clone
}

func mergeMetadata(base, override Metadata) Metadata {
	result := base
	if len(override.Tags) != 0 {
		result.Tags = append([]string(nil), override.Tags...)
	}
	if override.OperationID != "" {
		result.OperationID = override.OperationID
	}
	if override.Description != "" {
		result.Description = override.Description
	}
	if override.Parameters != nil {
		result.Parameters = cloneJSON(override.Parameters)
	}
	if override.Query != nil {
		value := *override.Query
		result.Query = &value
	}
	if override.Body != nil {
		value := *override.Body
		result.Body = &value
	}
	if override.RequestBody != nil {
		value := cloneJSON(*override.RequestBody)
		result.RequestBody = &value
	}
	if override.Responses != nil {
		result.Responses = cloneJSON(override.Responses)
	}
	if override.Hidden {
		result.Hidden = true
	}
	return result
}

func generatedOperation(endpoint engine.Endpoint, method string, metadata Metadata) Operation {
	tags := append([]string(nil), metadata.Tags...)
	if len(tags) == 0 {
		tags = []string{"Default"}
	}
	parameters := cloneJSON(metadata.Parameters)
	if metadata.Parameters == nil && metadata.Query != nil && metadata.Query.kind == inputObject {
		parameters = make([]Parameter, 0, len(metadata.Query.properties))
		for _, property := range metadata.Query.properties {
			schema := toSchema(property.Schema)
			parameters = append(parameters, Parameter{Name: property.Name, In: "query", Schema: &schema})
		}
	}
	responses := standardResponses()
	for status, response := range metadata.Responses {
		responses[status] = cloneJSON(response)
	}
	operation := Operation{
		Tags: tags, OperationID: metadata.OperationID, Description: metadata.Description,
		Security: []map[string][]string{{"bearerAuth": {}}}, Parameters: parameters,
		Responses: responses,
	}
	if operation.OperationID == "" {
		operation.OperationID = endpoint.OperationID
	}
	if method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut {
		switch {
		case metadata.RequestBody != nil:
			value := cloneJSON(*metadata.RequestBody)
			operation.RequestBody = &value
		case metadata.Body != nil:
			required := !acceptsUndefined(*metadata.Body)
			schema := toSchema(*metadata.Body)
			operation.RequestBody = jsonRequestBody(schema, required)
		default:
			operation.RequestBody = jsonRequestBody(Schema{Type: "object", Properties: map[string]Schema{}}, false)
		}
	}
	return operation
}

func jsonRequestBody(schema Schema, required bool) *RequestBody {
	return &RequestBody{
		Required: boolPointer(required),
		Content:  map[string]MediaType{"application/json": {Schema: &schema}},
	}
}

func standardResponses() map[string]Response {
	message := func(required bool) Schema {
		schema := Schema{Type: "object", Properties: map[string]Schema{"message": {Type: "string"}}}
		if required {
			schema.Required = []string{"message"}
		}
		return schema
	}
	jsonResponse := func(description string, schema Schema) Response {
		return Response{Description: description, Content: map[string]MediaType{"application/json": {Schema: &schema}}}
	}
	return map[string]Response{
		"400": jsonResponse("Bad Request. Usually due to missing parameters, or invalid parameters.", message(true)),
		"401": jsonResponse("Unauthorized. Due to missing or invalid authentication.", message(true)),
		"403": jsonResponse("Forbidden. You do not have permission to access this resource or to perform this action.", message(false)),
		"404": jsonResponse("Not Found. The requested resource was not found.", message(false)),
		"429": jsonResponse("Too Many Requests. You have exceeded the rate limit. Try again later.", message(false)),
		"500": jsonResponse("Internal Server Error. This is a problem with the server that you cannot fix.", message(false)),
	}
}

func uniqueOperationID(base, method string, used map[string]struct{}) string {
	if base == "" {
		return ""
	}
	if _, exists := used[base]; !exists {
		used[base] = struct{}{}
		return base
	}
	suffix := strings.ToUpper(method[:1]) + strings.ToLower(method[1:])
	candidate := base + suffix
	for index := 2; ; index++ {
		if _, exists := used[candidate]; !exists {
			used[candidate] = struct{}{}
			return candidate
		}
		candidate = fmt.Sprintf("%s%s%d", base, suffix, index)
	}
}

func toOpenAPIPath(path string) string {
	parts := strings.Split(path, "/")
	for index, part := range parts {
		if strings.HasPrefix(part, ":") {
			parts[index] = "{" + strings.TrimPrefix(part, ":") + "}"
		}
	}
	return strings.Join(parts, "/")
}

func appendPathParameters(path string, parameters []Parameter) []Parameter {
	result := cloneJSON(parameters)
	existing := make(map[string]struct{}, len(result))
	for _, parameter := range result {
		existing[parameter.In+":"+parameter.Name] = struct{}{}
	}
	for _, part := range strings.Split(path, "/") {
		if !strings.HasPrefix(part, ":") {
			continue
		}
		name := strings.TrimPrefix(part, ":")
		if _, exists := existing["path:"+name]; exists {
			continue
		}
		required := true
		schema := Schema{Type: "string"}
		result = append(result, Parameter{Name: name, In: "path", Required: &required, Schema: &schema})
	}
	if result == nil {
		return []Parameter{}
	}
	return result
}

func boolPointer(value bool) *bool { return &value }

func (generator *Generator) models() map[string]ModelSchema {
	models := make(map[string]ModelSchema, len(generator.schema.Models))
	names := make([]string, 0, len(generator.schema.Models))
	for name := range generator.schema.Models {
		names = append(names, name)
	}
	sort.Slice(names, func(left, right int) bool {
		a, b := generator.schema.Models[names[left]], generator.schema.Models[names[right]]
		if a.Order != b.Order {
			return a.Order < b.Order
		}
		return names[left] < names[right]
	})
	for _, canonical := range names {
		model := generator.schema.Models[canonical]
		properties := map[string]Schema{"id": {Type: "string", ReadOnly: true}}
		required := []string{"id"}
		for _, fieldName := range orderedFields(canonical, model.Fields) {
			field := model.Fields[fieldName]
			properties[fieldName] = modelFieldSchema(canonical, fieldName, field)
			if field.IsRequired() && field.IsReturned() {
				required = append(required, fieldName)
			}
		}
		name := strings.ToUpper(canonical[:1]) + canonical[1:]
		models[name] = Schema{Type: "object", Properties: properties, Required: required}
	}
	return models
}

var frozenFieldOrder = map[string][]string{
	"user":         {"name", "email", "emailVerified", "image", "createdAt", "updatedAt"},
	"session":      {"expiresAt", "token", "createdAt", "updatedAt", "ipAddress", "userAgent", "userId"},
	"account":      {"accountId", "providerId", "userId", "accessToken", "refreshToken", "idToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "scope", "password", "createdAt", "updatedAt"},
	"verification": {"identifier", "value", "expiresAt", "createdAt", "updatedAt"},
}

func orderedFields(model string, fields map[string]storage.FieldAttribute) []string {
	result := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, name := range frozenFieldOrder[model] {
		if _, exists := fields[name]; exists {
			result = append(result, name)
			seen[name] = struct{}{}
		}
	}
	rest := make([]string, 0, len(fields)-len(result))
	for name := range fields {
		if _, exists := seen[name]; !exists {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	return append(result, rest...)
}

func modelFieldSchema(model, name string, field storage.FieldAttribute) Schema {
	schema := fieldSchema(field)
	if !field.IsInput() {
		schema.ReadOnly = true
	}
	if model == "user" && name == "emailVerified" {
		schema.Default = false
	}
	if field.DefaultValue != nil && field.Type != storage.FieldDate && !(model == "user" && name == "emailVerified") {
		// Go function values cannot expose whether they close over a static value.
		// Additional fields conventionally use storage.StaticValue; use a fixed
		// context and ignore failures while never invoking date/runtime defaults.
		if value, err := field.DefaultValue(storage.ValueContext{Now: func() time.Time { return time.Time{} }}); err == nil {
			schema.Default = value
		}
	}
	return schema
}

func fieldSchema(field storage.FieldAttribute) Schema {
	switch field.Type {
	case storage.FieldDate:
		return Schema{Type: "string", Format: "date-time"}
	case storage.FieldJSON:
		return Schema{Type: "object", AdditionalProperties: true}
	case storage.FieldStringArray:
		item := Schema{Type: "string"}
		return Schema{Type: "array", Items: &item}
	case storage.FieldNumberArray:
		item := Schema{Type: "number"}
		return Schema{Type: "array", Items: &item}
	case storage.FieldEnum:
		values := make([]any, len(field.Enum))
		for index, value := range field.Enum {
			values[index] = value
		}
		return Schema{Type: "string", Enum: values}
	default:
		return Schema{Type: string(field.Type)}
	}
}

func requestFieldSchema(field storage.FieldAttribute) Schema {
	schema := fieldSchema(field)
	if field.DefaultValue != nil && field.Type != storage.FieldDate {
		if value, err := field.DefaultValue(storage.ValueContext{Now: func() time.Time { return time.Time{} }}); err == nil {
			schema.Default = value
		}
	}
	return schema
}

func (generator *Generator) applyUserInputFields(path string, body *RequestBody) *RequestBody {
	model, exists := generator.schema.Models["user"]
	if !exists {
		return body
	}
	core := storage.CoreSchema().Models["user"].Fields
	additional := make([]string, 0)
	for name, field := range model.Fields {
		if _, builtIn := core[name]; !builtIn && field.IsInput() {
			additional = append(additional, name)
		}
	}
	if len(additional) == 0 {
		return body
	}
	sort.Strings(additional)
	if body == nil {
		body = jsonRequestBody(Schema{Type: "object", Properties: map[string]Schema{}}, false)
	} else {
		value := cloneJSON(*body)
		body = &value
	}
	media := body.Content["application/json"]
	schema := Schema{Type: "object", Properties: map[string]Schema{}}
	if media.Schema != nil {
		schema = cloneJSON(*media.Schema)
	}
	if schema.Properties == nil {
		schema.Properties = make(map[string]Schema)
	}
	for _, name := range additional {
		field := model.Fields[name]
		if _, exists := schema.Properties[name]; !exists {
			schema.Properties[name] = requestFieldSchema(field)
		}
		if path == "/sign-up/email" && field.Required != nil && *field.Required && field.DefaultValue == nil && !contains(schema.Required, name) {
			schema.Required = append(schema.Required, name)
		}
	}
	media.Schema = &schema
	body.Content["application/json"] = media
	return body
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
