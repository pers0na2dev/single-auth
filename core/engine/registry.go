package engine

import (
	"sort"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
)

const anyMethod = "*"

type registeredRoute struct {
	endpoint Endpoint
	pattern  routePattern
	methods  []string
	order    int
}

// Registry is an immutable collection of direct endpoints and routable HTTP
// endpoints. It is safe for concurrent reads.
type Registry struct {
	endpoints  []Endpoint
	byName     map[string]Endpoint
	routes     []registeredRoute
	plugins    []Plugin
	errorCodes map[string]ErrorDefinition
}

// RouteMatch is one deterministic route result.
type RouteMatch struct {
	Endpoint Endpoint
	Params   map[string]string
}

// NewRegistry validates and snapshots core endpoints followed by plugins in
// registration order. Conflicting dynamic parameter names are treated as the
// same route shape: /users/:id conflicts with /users/:userID for an overlapping
// method.
func NewRegistry(core []Endpoint, plugins ...Plugin) (*Registry, error) {
	registry := &Registry{
		byName:     make(map[string]Endpoint),
		errorCodes: make(map[string]ErrorDefinition),
	}
	pluginIDs := make(map[string]struct{}, len(plugins))
	for _, plugin := range plugins {
		if plugin.ID == "" {
			return nil, &RegistryError{
				Kind:    RegistryErrorDuplicatePluginID,
				Message: "plugin id must not be empty",
			}
		}
		if _, exists := pluginIDs[plugin.ID]; exists {
			return nil, &RegistryError{
				Kind:     RegistryErrorDuplicatePluginID,
				PluginID: plugin.ID,
				Message:  "plugin id is already registered",
			}
		}
		pluginIDs[plugin.ID] = struct{}{}
		registry.plugins = append(registry.plugins, clonePlugin(plugin))
		for code, definition := range plugin.ErrorCodes {
			if definition.Code == "" {
				definition.Code = code
			}
			registry.errorCodes[code] = definition
		}
	}

	declarations := make([]Endpoint, 0, len(core))
	declarationIndex := make(map[string]int, len(core))
	for _, endpoint := range core {
		if endpoint.Override {
			return nil, &RegistryError{
				Kind: RegistryErrorInvalidEndpoint, Endpoint: endpoint.Name,
				Message: "core endpoint must not declare override",
			}
		}
		if _, duplicate := declarationIndex[endpoint.Name]; !duplicate {
			declarationIndex[endpoint.Name] = len(declarations)
		}
		declarations = append(declarations, cloneEndpoint(endpoint))
	}
	for _, plugin := range registry.plugins {
		for _, endpoint := range plugin.Endpoints {
			endpoint.pluginID = plugin.ID
			if !endpoint.Override {
				if _, duplicate := declarationIndex[endpoint.Name]; !duplicate {
					declarationIndex[endpoint.Name] = len(declarations)
				}
				declarations = append(declarations, endpoint)
				continue
			}
			index, exists := declarationIndex[endpoint.Name]
			if !exists {
				return nil, invalidEndpointOverride(endpoint, "override target is not registered")
			}
			if err := validateEndpointOverride(declarations[index], endpoint); err != nil {
				return nil, err
			}
			declarations[index] = endpoint
		}
	}

	var conflicts []EndpointConflict
	for _, declaration := range declarations {
		endpoint, pattern, methods, err := validateEndpoint(declaration)
		if err != nil {
			return nil, err
		}
		if _, exists := registry.byName[endpoint.Name]; exists {
			return nil, &RegistryError{
				Kind:     RegistryErrorDuplicateEndpointName,
				PluginID: endpoint.pluginID,
				Endpoint: endpoint.Name,
				Message:  "endpoint name is already registered",
			}
		}
		registry.byName[endpoint.Name] = cloneEndpoint(endpoint)
		registry.endpoints = append(registry.endpoints, cloneEndpoint(endpoint))

		// SERVER_ONLY is defense in depth: even a declaration that accidentally
		// carries a path never occupies or conflicts with an HTTP route.
		if endpoint.ServerOnly {
			continue
		}

		incoming := registeredRoute{
			endpoint: endpoint,
			pattern:  pattern,
			methods:  methods,
			order:    len(registry.routes),
		}
		for _, existing := range registry.routes {
			if existing.pattern.shape != incoming.pattern.shape {
				continue
			}
			for _, method := range intersectMethods(existing.methods, incoming.methods) {
				conflicts = append(conflicts, EndpointConflict{
					Path:             endpoint.Path,
					Method:           method,
					ExistingEndpoint: existing.endpoint.Name,
					ExistingPlugin:   existing.endpoint.pluginID,
					NewEndpoint:      endpoint.Name,
					NewPlugin:        endpoint.pluginID,
				})
			}
		}
		registry.routes = append(registry.routes, incoming)
	}
	if len(conflicts) > 0 {
		return nil, &ConflictError{Conflicts: conflicts}
	}

	return registry, nil
}

func invalidEndpointOverride(endpoint Endpoint, message string) *RegistryError {
	return &RegistryError{
		Kind: RegistryErrorInvalidEndpoint, PluginID: endpoint.pluginID,
		Endpoint: endpoint.Name, Message: message,
	}
}

func validateEndpointOverride(existing, replacement Endpoint) error {
	existingEndpoint, _, existingMethods, err := validateEndpoint(existing)
	if err != nil {
		return err
	}
	replacementEndpoint, _, replacementMethods, err := validateEndpoint(replacement)
	if err != nil {
		return err
	}
	if existingEndpoint.ServerOnly != replacementEndpoint.ServerOnly {
		return invalidEndpointOverride(replacement, "override must retain server-only routing mode")
	}
	if existingEndpoint.Path != replacementEndpoint.Path {
		return invalidEndpointOverride(replacement, "override must retain endpoint path")
	}
	for _, method := range replacementMethods {
		if containsMethod(existingMethods, anyMethod) {
			continue
		}
		if method == anyMethod || !containsMethod(existingMethods, method) {
			return invalidEndpointOverride(replacement, "override methods must be a subset of the original endpoint methods")
		}
	}
	return nil
}

func validateEndpoint(declaration Endpoint) (Endpoint, routePattern, []string, error) {
	endpoint := cloneEndpoint(declaration)
	if marked, ok := endpoint.Metadata[ServerOnlyMetadataKey].(bool); ok && marked {
		endpoint.ServerOnly = true
	}
	if endpoint.ServerOnly {
		if endpoint.Metadata == nil {
			endpoint.Metadata = make(map[string]any, 1)
		}
		endpoint.Metadata[ServerOnlyMetadataKey] = true
	}
	if endpoint.Name == "" {
		return Endpoint{}, routePattern{}, nil, &RegistryError{
			Kind:     RegistryErrorInvalidEndpoint,
			PluginID: endpoint.pluginID,
			Message:  "endpoint name must not be empty",
		}
	}
	if endpoint.Handler == nil {
		return Endpoint{}, routePattern{}, nil, &RegistryError{
			Kind:     RegistryErrorInvalidEndpoint,
			PluginID: endpoint.pluginID,
			Endpoint: endpoint.Name,
			Message:  "endpoint handler must not be nil",
		}
	}
	for _, middleware := range endpoint.Use {
		if middleware == nil {
			return Endpoint{}, routePattern{}, nil, &RegistryError{
				Kind:     RegistryErrorInvalidEndpoint,
				PluginID: endpoint.pluginID,
				Endpoint: endpoint.Name,
				Message:  "endpoint middleware must not be nil",
			}
		}
	}
	if endpoint.Path == "" {
		if !endpoint.ServerOnly {
			return Endpoint{}, routePattern{}, nil, &RegistryError{
				Kind:     RegistryErrorInvalidEndpoint,
				PluginID: endpoint.pluginID,
				Endpoint: endpoint.Name,
				Message:  "pathless endpoint must be server-only",
			}
		}
		methods, err := normalizeMethods(endpoint.Methods)
		if err != nil {
			return Endpoint{}, routePattern{}, nil, &RegistryError{
				Kind:     RegistryErrorInvalidEndpoint,
				PluginID: endpoint.pluginID,
				Endpoint: endpoint.Name,
				Message:  err.Error(),
				Cause:    err,
			}
		}
		endpoint.Methods = methods
		return endpoint, routePattern{}, methods, nil
	}

	pattern, err := compileRoutePattern(endpoint.Path)
	if err != nil {
		return Endpoint{}, routePattern{}, nil, &RegistryError{
			Kind:     RegistryErrorInvalidEndpoint,
			PluginID: endpoint.pluginID,
			Endpoint: endpoint.Name,
			Message:  "invalid endpoint path",
			Cause:    err,
		}
	}
	methods, err := normalizeMethods(endpoint.Methods)
	if err != nil {
		return Endpoint{}, routePattern{}, nil, &RegistryError{
			Kind:     RegistryErrorInvalidEndpoint,
			PluginID: endpoint.pluginID,
			Endpoint: endpoint.Name,
			Message:  err.Error(),
			Cause:    err,
		}
	}
	endpoint.Methods = methods
	return endpoint, pattern, methods, nil
}

func normalizeMethods(methods []string) ([]string, error) {
	if len(methods) == 0 {
		return []string{anyMethod}, nil
	}
	normalized := make([]string, 0, len(methods))
	seen := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			return nil, &methodValidationError{message: "endpoint method must not be empty"}
		}
		if _, duplicate := seen[method]; duplicate {
			return nil, &methodValidationError{message: "endpoint method is declared more than once: " + method}
		}
		if method == anyMethod && len(methods) != 1 {
			return nil, &methodValidationError{message: "wildcard method must be the only declared method"}
		}
		seen[method] = struct{}{}
		normalized = append(normalized, method)
	}
	return normalized, nil
}

type methodValidationError struct{ message string }

func (e *methodValidationError) Error() string { return e.message }

func intersectMethods(left, right []string) []string {
	leftAny := containsMethod(left, anyMethod)
	rightAny := containsMethod(right, anyMethod)
	switch {
	case leftAny && rightAny:
		return []string{anyMethod}
	case leftAny:
		return append([]string(nil), right...)
	case rightAny:
		return append([]string(nil), left...)
	}
	var intersection []string
	for _, method := range left {
		if containsMethod(right, method) {
			intersection = append(intersection, method)
		}
	}
	return intersection
}

func containsMethod(methods []string, target string) bool {
	for _, method := range methods {
		if method == target {
			return true
		}
	}
	return false
}

// Endpoint returns a cloned endpoint descriptor by direct API name.
func (r *Registry) Endpoint(name string) (Endpoint, bool) {
	if r == nil {
		return Endpoint{}, false
	}
	endpoint, ok := r.byName[name]
	if !ok {
		return Endpoint{}, false
	}
	return cloneEndpoint(endpoint), true
}

// Endpoints returns all direct endpoints, including server-only entries, in
// deterministic registration order.
func (r *Registry) Endpoints() []Endpoint {
	if r == nil {
		return nil
	}
	endpoints := make([]Endpoint, len(r.endpoints))
	for index, endpoint := range r.endpoints {
		endpoints[index] = cloneEndpoint(endpoint)
	}
	return endpoints
}

// ErrorCodes returns a copy of all plugin error definitions. Later plugins
// override earlier definitions, matching the reference implementation's object-spread behavior.
func (r *Registry) ErrorCodes() map[string]ErrorDefinition {
	if r == nil || len(r.errorCodes) == 0 {
		return nil
	}
	codes := make(map[string]ErrorDefinition, len(r.errorCodes))
	for code, definition := range r.errorCodes {
		codes[code] = definition
	}
	return codes
}

// Match resolves a non-server-only endpoint and decoded parameters.
func (r *Registry) Match(method, rawPath string) (RouteMatch, error) {
	return r.match(method, rawPath, false)
}

func (r *Registry) match(
	method,
	rawPath string,
	skipTrailingSlashes bool,
) (RouteMatch, error) {
	if r == nil {
		return RouteMatch{}, contract.NewAPIError(
			contract.StatusInternalServerError,
			"REGISTRY_NOT_INITIALIZED",
			"Endpoint registry is not initialized",
		)
	}
	segments, err := decodeRequestPath(rawPath)
	if err != nil {
		return RouteMatch{}, contract.NewAPIError(
			contract.StatusBadRequest,
			"INVALID_PATH",
			"Invalid request path",
		).WithCause(err)
	}
	method = strings.ToUpper(method)

	type candidate struct {
		route  registeredRoute
		params map[string]string
	}
	var candidates []candidate
	allowed := make([]string, 0)
	for _, route := range r.routes {
		params, matches := route.pattern.matchRequest(segments, skipTrailingSlashes)
		if !matches {
			continue
		}
		if containsMethod(route.methods, anyMethod) || containsMethod(route.methods, method) {
			candidates = append(candidates, candidate{route: route, params: params})
			continue
		}
		for _, allowedMethod := range route.methods {
			if allowedMethod != anyMethod && !containsMethod(allowed, allowedMethod) {
				allowed = append(allowed, allowedMethod)
			}
		}
	}
	if len(candidates) == 0 {
		if len(allowed) > 0 {
			headers := contract.NewHeaders(contract.HeaderField{
				Name:  "Allow",
				Value: strings.Join(allowed, ", "),
			})
			return RouteMatch{}, contract.NewAPIError(
				contract.StatusMethodNotAllowed,
				"METHOD_NOT_ALLOWED",
				"Method Not Allowed",
			).WithHeaders(headers)
		}
		return RouteMatch{}, contract.NewAPIError(
			contract.StatusNotFound,
			"NOT_FOUND",
			"Not Found",
		)
	}

	sort.SliceStable(candidates, func(left, right int) bool {
		comparison := comparePatternSpecificity(
			candidates[left].route.pattern,
			candidates[right].route.pattern,
		)
		if comparison == 0 {
			return candidates[left].route.order < candidates[right].route.order
		}
		return comparison > 0
	})
	selected := candidates[0]
	return RouteMatch{
		Endpoint: cloneEndpoint(selected.route.endpoint),
		Params:   cloneStringMap(selected.params),
	}, nil
}

func clonePlugin(plugin Plugin) Plugin {
	clone := plugin
	clone.Schema = plugin.Schema.Clone()
	clone.TrustedOrigins = append([]string(nil), plugin.TrustedOrigins...)
	clone.SkipOriginCheckPaths = append([]string(nil), plugin.SkipOriginCheckPaths...)
	clone.Endpoints = make([]Endpoint, len(plugin.Endpoints))
	for index, endpoint := range plugin.Endpoints {
		clone.Endpoints[index] = cloneEndpoint(endpoint)
	}
	clone.Middleware = cloneMiddleware(plugin.Middleware)
	clone.RateLimit = append([]ratelimit.MatcherRule(nil), plugin.RateLimit...)
	clone.Hooks = Hooks{
		Before: cloneBeforeHooks(plugin.Hooks.Before),
		After:  cloneAfterHooks(plugin.Hooks.After),
	}
	if plugin.ErrorCodes != nil {
		clone.ErrorCodes = make(map[string]ErrorDefinition, len(plugin.ErrorCodes))
		for code, definition := range plugin.ErrorCodes {
			clone.ErrorCodes[code] = definition
		}
	}
	return clone
}
