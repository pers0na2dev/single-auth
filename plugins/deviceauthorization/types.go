package deviceauthorization

import (
	"context"
	"io"
	"time"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	PluginID = "device-authorization"
	Version  = "1.6.26"

	DeviceCodePath    = "/device/code"
	DeviceTokenPath   = "/device/token"
	DeviceVerifyPath  = "/device"
	DeviceApprovePath = "/device/approve"
	DeviceDenyPath    = "/device/deny"

	DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

const (
	defaultExpiresIn        = 30 * time.Minute
	defaultPollingInterval  = 5 * time.Second
	defaultDeviceCodeLength = 40
	defaultUserCodeLength   = 8
)

type GenerateCodeFunc func(context.Context) (string, error)
type ValidateClientFunc func(context.Context, string) (bool, error)
type DeviceAuthRequestFunc func(context.Context, string, *string) error

type SessionState struct {
	Session storage.Record
	User    storage.Record
}

type ResolveSessionFunc func(*engine.Context, bool) (*SessionState, error)
type CreateSessionFunc func(*engine.Context, string, bool) (*SessionState, error)
type SetNewSessionFunc func(*engine.Context, *SessionState)
type BaseURLResolver func(*engine.Context) (string, error)
type ContextAdapterResolver func(context.Context) storage.TransactionAdapter

// Runtime contains dependencies that single-auth injects into endpoint
// context. NewFactory supplies the root session, secondary-storage, dynamic
// URL, and transaction-aware adapter behavior.
type Runtime struct {
	Adapter           storage.Adapter
	AdapterForContext ContextAdapterResolver
	Clock             func() time.Time
	Random            io.Reader
	BaseURL           string
	ResolveBaseURL    BaseURLResolver
	ResolveSession    ResolveSessionFunc
	CreateSession     CreateSessionFunc
	SetNewSession     SetNewSessionFunc
}

// Options configures single-auth's device-authorization plugin. Zero duration
// and length values select the upstream defaults.
type Options struct {
	ExpiresIn        time.Duration
	Interval         time.Duration
	DeviceCodeLength int
	UserCodeLength   int

	GenerateDeviceCode  GenerateCodeFunc
	GenerateUserCode    GenerateCodeFunc
	ValidateClient      ValidateClientFunc
	OnDeviceAuthRequest DeviceAuthRequestFunc
	VerificationURI     string

	Schema  storage.Schema
	Runtime Runtime
}

// DeviceCode is the persisted RFC 8628 authorization state.
type DeviceCode struct {
	ID              string
	DeviceCode      string
	UserCode        string
	UserID          *string
	ExpiresAt       time.Time
	Status          string
	LastPolledAt    *time.Time
	PollingInterval int64
	ClientID        string
	Scope           *string
}

// DeviceCodeResponse is returned from POST /device/code.
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// TokenResponse is the OAuth 2.0 token response for an approved code.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// VerifyResponse is returned while displaying device authorization state.
type VerifyResponse struct {
	UserCode string `json:"user_code"`
	Status   string `json:"status"`
}

// OAuthErrorBody is the RFC-compatible error representation.
type OAuthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
