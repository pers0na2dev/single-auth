// Package apikey implements the single-auth API-key plugin contract.
package apikey

import (
	"context"
	"io"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

// ReferenceType determines whether a configuration's keys belong to a user
// or to an organization.
type ReferenceType string

const (
	ReferenceUser         ReferenceType = "user"
	ReferenceOrganization ReferenceType = "organization"
)

// Bool returns a pointer suitable for tri-state configuration fields where nil
// means to use single-auth's default.
func Bool(value bool) *bool { return &value }

// PermissionAction is the organization permission checked for an API-key
// operation.
type PermissionAction string

const (
	PermissionCreate PermissionAction = "create"
	PermissionRead   PermissionAction = "read"
	PermissionUpdate PermissionAction = "update"
	PermissionDelete PermissionAction = "delete"
)

// Configuration is one named API-key configuration. ConfigID is required
// when more than one configuration is installed.
type Configuration struct {
	ConfigID                 string
	References               ReferenceType
	DefaultPrefix            string
	DefaultKeyLength         int
	MinimumPrefixLength      int
	MaximumPrefixLength      int
	MinimumNameLength        int
	MaximumNameLength        int
	RequireName              bool
	EnableMetadata           bool
	DisableKeyHashing        bool
	StoreStartingCharacters  *bool
	StartingCharactersLength int
	RateLimitEnabled         *bool
	RateLimitTimeWindow      time.Duration
	RateLimitMax             int64
	DefaultExpiresIn         time.Duration
	DisableCustomExpiresTime bool
	MinimumExpiresIn         time.Duration
	MaximumExpiresIn         time.Duration
	DefaultPermissions       map[string][]string
	EnableSessionForAPIKeys  bool
	APIKeyHeaders            []string
}

// OrganizationAuthorization configures the organization role vocabulary used
// by this plugin. The creator role always receives all API-key permissions,
// matching single-auth's allowCreatorAllPermissions behavior.
type OrganizationAuthorization struct {
	CreatorRole string
	Roles       map[string]authorization.Statements
}

// SessionState is the request's authoritative user/session pair.
type SessionState struct {
	Session storage.Record
	User    storage.Record
}

// ResolveSessionFunc resolves a session for a plugin endpoint. A nil state is
// treated as an unauthorized request.
type ResolveSessionFunc func(*engine.Context) (*SessionState, error)

// Runtime contains host-provided services. It is public so applications can
// construct the production service without the root plugin registry.
type Runtime struct {
	Adapter                     storage.Adapter
	Clock                       func() time.Time
	Random                      io.Reader
	KeyGenerator                func(context.Context, int, string) (string, error)
	ResolveSession              ResolveSessionFunc
	ResolveAuthoritativeSession ResolveSessionFunc
	HasPlugin                   func(string) bool
	SerializeUser               func(storage.Record) any
	SerializeSession            func(storage.Record) any
}

// Options configures the API-key service and root plugin factory.
type Options struct {
	Configurations       []Configuration
	Organization         OrganizationAuthorization
	Schema               storage.Schema
	Runtime              Runtime
	DeleteExpiredOnWrite bool
}

// APIKey is the complete persisted API-key record. Key contains the plaintext
// credential only in Create's return value and is omitted from read/list/verify
// responses.
type APIKey struct {
	ID                  string              `json:"id"`
	ConfigID            string              `json:"configId"`
	Name                *string             `json:"name"`
	Start               *string             `json:"start"`
	Prefix              *string             `json:"prefix"`
	Key                 string              `json:"key,omitempty"`
	ReferenceID         string              `json:"referenceId"`
	RefillInterval      *int64              `json:"refillInterval"`
	RefillAmount        *int64              `json:"refillAmount"`
	LastRefillAt        *time.Time          `json:"lastRefillAt"`
	Enabled             bool                `json:"enabled"`
	RateLimitEnabled    bool                `json:"rateLimitEnabled"`
	RateLimitTimeWindow *int64              `json:"rateLimitTimeWindow"`
	RateLimitMax        *int64              `json:"rateLimitMax"`
	RequestCount        int64               `json:"requestCount"`
	Remaining           *int64              `json:"remaining"`
	LastRequest         *time.Time          `json:"lastRequest"`
	ExpiresAt           *time.Time          `json:"expiresAt"`
	CreatedAt           time.Time           `json:"createdAt"`
	UpdatedAt           time.Time           `json:"updatedAt"`
	Metadata            any                 `json:"metadata"`
	Permissions         map[string][]string `json:"permissions"`
}

// CreateInput contains both trusted server ownership and request actor fields.
// ActorUserID represents the authenticated session user; UserID is accepted by
// direct server calls.
type CreateInput struct {
	ConfigID            string
	Name                *string
	Prefix              string
	ExpiresIn           *time.Duration
	Remaining           *int64
	RefillAmount        *int64
	RefillInterval      *time.Duration
	Metadata            any
	Permissions         map[string][]string
	RateLimitMax        *int64
	RateLimitTimeWindow *time.Duration
	RateLimitEnabled    *bool
	UserID              string
	OrganizationID      string
	ActorUserID         string
}

type GetInput struct {
	ID          string
	ConfigID    string
	ActorUserID string
}

type ListInput struct {
	ConfigID       string
	OrganizationID string
	ActorUserID    string
	Limit          *int
	Offset         *int
}

type ListResult struct {
	APIKeys []APIKey `json:"apiKeys"`
	Total   int      `json:"total"`
	Limit   *int     `json:"limit,omitempty"`
	Offset  *int     `json:"offset,omitempty"`
}

type UpdateInput struct {
	KeyID               string
	ConfigID            string
	ActorUserID         string
	Name                *string
	Enabled             *bool
	ExpiresIn           *time.Duration
	ExpiresInSet        bool
	Remaining           *int64
	RefillAmount        *int64
	RefillInterval      *time.Duration
	Metadata            any
	MetadataSet         bool
	RateLimitEnabled    *bool
	RateLimitTimeWindow *time.Duration
	RateLimitMax        *int64
	Permissions         map[string][]string
	PermissionsSet      bool
}

type DeleteInput struct {
	KeyID       string
	ConfigID    string
	ActorUserID string
}

type VerifyInput struct {
	Key         string
	ConfigID    string
	Permissions map[string][]string
}

type VerifyResult struct {
	Valid bool       `json:"valid"`
	Error *ErrorBody `json:"error"`
	Key   *APIKey    `json:"key"`
}

// Service implements the database-backed API-key operations shared by direct
// calls and transport endpoints.
type Service struct {
	options        Options
	configurations []Configuration
	byID           map[string]Configuration
	defaultConfig  Configuration
	adapter        storage.Adapter
	clock          func() time.Time
	keyGenerator   func(context.Context, int, string) (string, error)
	hasPlugin      func(string) bool
	organization   OrganizationAuthorization
}

// Plugin is a reusable factory plus the bound direct API. A Plugin instance
// belongs to one single-auth runtime.
type Plugin struct {
	options Options
	mu      sync.RWMutex
	service *Service
}

var _ singleauth.PluginFactory = (*Plugin)(nil)
