package customsession

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

// SessionData is the serialized session/user pair supplied to Enrich. The
// records already passed through the host's public output serializers.
type SessionData struct {
	User    storage.Record `json:"user"`
	Session storage.Record `json:"session"`
}

// EnrichFunc projects one public single-auth session into the response shape
// returned by get-session. The callback receives the active endpoint context,
// matching GenericEndpointContext in the upstream plugin.
type EnrichFunc func(SessionData, *engine.Context) (any, error)

// GetSessionFunc invokes the unmodified core get-session implementation in an
// isolated response context. Its returned headers are copied to the outer
// custom-session response only after Enrich succeeds.
type GetSessionFunc func(*engine.Context) (contract.Response, error)

// Runtime contains the one core service that single-auth injects implicitly.
// NewFactory supplies it from PluginHost; standalone descriptors provide it
// explicitly for deterministic transport-neutral use.
type Runtime struct {
	GetSession GetSessionFunc
}

// Options configures the single-auth-compatible custom-session plugin.
type Options struct {
	Enrich EnrichFunc

	// ShouldMutateListDeviceSessionsEndpoint applies Enrich concurrently to
	// every successful multi-session list-device-sessions result.
	ShouldMutateListDeviceSessionsEndpoint bool

	Runtime Runtime
}
