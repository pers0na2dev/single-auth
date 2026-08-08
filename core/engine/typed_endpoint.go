package engine

// EndpointMethodSpec is the sealed compile-time description of one or more
// HTTP methods accepted by a TypedEndpoint. The concrete marker is retained in
// the generic endpoint type while the production router receives a mutable
// []string snapshot through Endpoint.
type EndpointMethodSpec interface {
	endpointMethods() []string
}

// GET, POST, PUT, PATCH, DELETE, HEAD, and OPTIONS are zero-sized literal
// method markers. Their concrete Go type is the analogue of a TypeScript
// string-literal method type.
type GET struct{}
type POST struct{}
type PUT struct{}
type PATCH struct{}
type DELETE struct{}
type HEAD struct{}
type OPTIONS struct{}

func (GET) endpointMethods() []string     { return []string{"GET"} }
func (POST) endpointMethods() []string    { return []string{"POST"} }
func (PUT) endpointMethods() []string     { return []string{"PUT"} }
func (PATCH) endpointMethods() []string   { return []string{"PATCH"} }
func (DELETE) endpointMethods() []string  { return []string{"DELETE"} }
func (HEAD) endpointMethods() []string    { return []string{"HEAD"} }
func (OPTIONS) endpointMethods() []string { return []string{"OPTIONS"} }

// MethodSet2 preserves a two-method union in its concrete generic type. The
// contained values are retained so future method markers can carry immutable
// declaration data without changing the constructor contract.
type MethodSet2[First, Second EndpointMethodSpec] struct {
	first  First
	second Second
}

// Methods2 constructs a statically typed two-method set. The returned
// endpoint's Methods method still exposes an ordinary independently mutable
// []string, matching the reference implementation's mutable union-array normalization.
func Methods2[First, Second EndpointMethodSpec](first First, second Second) MethodSet2[First, Second] {
	return MethodSet2[First, Second]{first: first, second: second}
}

func (methods MethodSet2[First, Second]) endpointMethods() []string {
	result := methods.first.endpointMethods()
	return append(result, methods.second.endpointMethods()...)
}

// MethodSet3 preserves a three-method union for integrations whose endpoint
// accepts more than the two-method combination exercised upstream.
type MethodSet3[First, Second, Third EndpointMethodSpec] struct {
	first  First
	second Second
	third  Third
}

// Methods3 constructs a statically typed three-method set.
func Methods3[First, Second, Third EndpointMethodSpec](
	first First,
	second Second,
	third Third,
) MethodSet3[First, Second, Third] {
	return MethodSet3[First, Second, Third]{first: first, second: second, third: third}
}

func (methods MethodSet3[First, Second, Third]) endpointMethods() []string {
	result := methods.first.endpointMethods()
	result = append(result, methods.second.endpointMethods()...)
	return append(result, methods.third.endpointMethods()...)
}

// TypedEndpoint retains its method declaration as a static type while wrapping
// the exact production Endpoint consumed by Registry and Dispatcher.
type TypedEndpoint[Methods EndpointMethodSpec] struct {
	methods  Methods
	endpoint Endpoint
}

// NewTypedEndpoint constructs a routable endpoint without erasing its method
// marker type. Runtime validation remains centralized in NewRegistry.
func NewTypedEndpoint[Methods EndpointMethodSpec](
	name,
	path string,
	methods Methods,
	handler HandlerFunc,
) TypedEndpoint[Methods] {
	return TypedEndpoint[Methods]{
		methods: methods,
		endpoint: Endpoint{
			Name: name, Path: path, Methods: cloneMethodStrings(methods.endpointMethods()), Handler: handler,
		},
	}
}

// NewTypedPathlessEndpoint is the direct/server-only overload. Pathlessness is
// preserved at runtime and the method marker remains part of the static type.
func NewTypedPathlessEndpoint[Methods EndpointMethodSpec](
	name string,
	methods Methods,
	handler HandlerFunc,
) TypedEndpoint[Methods] {
	return TypedEndpoint[Methods]{
		methods: methods,
		endpoint: Endpoint{
			Name: name, Methods: cloneMethodStrings(methods.endpointMethods()),
			ServerOnly: true, Metadata: map[string]any{ServerOnlyMetadataKey: true}, Handler: handler,
		},
	}
}

// Methods returns an independently mutable method slice. Mutating it cannot
// alter the typed declaration or a previously returned Endpoint snapshot.
func (endpoint TypedEndpoint[Methods]) Methods() []string {
	return cloneMethodStrings(endpoint.methods.endpointMethods())
}

// Endpoint returns an independent production endpoint declaration suitable
// for Options.Endpoints or Plugin.Endpoints.
func (endpoint TypedEndpoint[Methods]) Endpoint() Endpoint {
	return cloneEndpoint(endpoint.endpoint)
}

func cloneMethodStrings(methods []string) []string {
	return append([]string(nil), methods...)
}

const (
	// EndpointScopeMetadataKey and EndpointActionMetadataKey are the runtime
	// metadata keys the reference implementation uses while deriving its server-side API type.
	EndpointScopeMetadataKey  = "scope"
	EndpointActionMetadataKey = "isAction"
	EndpointScopeServer       = "server"
	EndpointScopeHTTP         = "http"
)

// ServerVisibleEndpoint is implemented only by typed declarations that Better
// Auth includes in auth.api: pathless virtual endpoints and endpoints whose
// metadata scope is server. HTTP-scoped and non-action declarations expose
// their runtime Endpoint but intentionally do not implement this interface.
type ServerVisibleEndpoint interface {
	Endpoint() Endpoint
	serverVisibleEndpoint()
}

// TypedVirtualEndpoint is a pathless direct/server-only endpoint.
type TypedVirtualEndpoint[Methods EndpointMethodSpec] struct {
	TypedEndpoint[Methods]
}

func NewTypedVirtualEndpoint[Methods EndpointMethodSpec](
	name string,
	methods Methods,
	handler HandlerFunc,
) TypedVirtualEndpoint[Methods] {
	return TypedVirtualEndpoint[Methods]{
		TypedEndpoint: NewTypedPathlessEndpoint(name, methods, handler),
	}
}

func (TypedVirtualEndpoint[Methods]) serverVisibleEndpoint() {}

// TypedServerScopedEndpoint is routable over HTTP and is also retained in the
// typed direct/server API because its metadata scope is server.
type TypedServerScopedEndpoint[Methods EndpointMethodSpec] struct {
	TypedEndpoint[Methods]
}

func NewTypedServerScopedEndpoint[Methods EndpointMethodSpec](
	name,
	path string,
	methods Methods,
	handler HandlerFunc,
) TypedServerScopedEndpoint[Methods] {
	endpoint := NewTypedEndpoint(name, path, methods, handler)
	endpoint.endpoint.Metadata = map[string]any{EndpointScopeMetadataKey: EndpointScopeServer}
	return TypedServerScopedEndpoint[Methods]{TypedEndpoint: endpoint}
}

func (TypedServerScopedEndpoint[Methods]) serverVisibleEndpoint() {}

// TypedHTTPScopedEndpoint remains routable but is intentionally omitted from
// the server-side typed API.
type TypedHTTPScopedEndpoint[Methods EndpointMethodSpec] struct {
	TypedEndpoint[Methods]
}

func NewTypedHTTPScopedEndpoint[Methods EndpointMethodSpec](
	name,
	path string,
	methods Methods,
	handler HandlerFunc,
) TypedHTTPScopedEndpoint[Methods] {
	endpoint := NewTypedEndpoint(name, path, methods, handler)
	endpoint.endpoint.Metadata = map[string]any{EndpointScopeMetadataKey: EndpointScopeHTTP}
	return TypedHTTPScopedEndpoint[Methods]{TypedEndpoint: endpoint}
}

// TypedNonActionEndpoint remains available to the runtime registry but is
// omitted from the typed direct API when isAction is false.
type TypedNonActionEndpoint[Methods EndpointMethodSpec] struct {
	TypedEndpoint[Methods]
}

func NewTypedNonActionEndpoint[Methods EndpointMethodSpec](
	name,
	path string,
	methods Methods,
	handler HandlerFunc,
) TypedNonActionEndpoint[Methods] {
	endpoint := NewTypedEndpoint(name, path, methods, handler)
	endpoint.endpoint.Metadata = map[string]any{EndpointActionMetadataKey: false}
	return TypedNonActionEndpoint[Methods]{TypedEndpoint: endpoint}
}

// ServerAPI2 is a compile-time filtered pair of server-visible endpoints. The
// generic constraints make it impossible to add TypedHTTPScopedEndpoint or
// TypedNonActionEndpoint accidentally.
type ServerAPI2[First, Second ServerVisibleEndpoint] struct {
	first  First
	second Second
}

func NewServerAPI2[First, Second ServerVisibleEndpoint](first First, second Second) ServerAPI2[First, Second] {
	return ServerAPI2[First, Second]{first: first, second: second}
}

func (api ServerAPI2[First, Second]) First() First   { return api.first }
func (api ServerAPI2[First, Second]) Second() Second { return api.second }
