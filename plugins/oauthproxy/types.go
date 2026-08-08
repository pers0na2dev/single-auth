package oauthproxy

import (
	"context"
	"encoding/json"
	"io"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

const defaultMaxAge = time.Minute

// Options mirrors the server options of single-auth's oAuthProxy plugin.
// MaxAge is a Go duration; zero preserves single-auth's 60-second default.
// Secret selects a dedicated legacy-compatible proxy key. SecretConfig is the
// rotation-aware equivalent and takes precedence when both are provided.
type Options struct {
	CurrentURL    string
	ProductionURL string
	MaxAge        time.Duration
	Secret        string
	SecretConfig  *baCrypto.SecretConfig
	Runtime       Runtime
}

// Runtime is the transport-neutral host surface required by a standalone
// plugin. NewFactory binds every field to the root singleauth.Auth runtime.
type Runtime struct {
	BaseURL       string
	BasePath      string
	ErrorURL      string
	StateStrategy string

	Clock  func() time.Time
	Random io.Reader
	Logger *logger.Logger

	ResolveBaseURL  func(contract.Request) (string, error)
	IsTrustedOrigin func(contract.Request, string, bool) (bool, error)
	Cookie          func(contract.Request, string, string) (string, cookies.Options)

	EncryptSecret func([]byte) (string, error)
	DecryptSecret func(string) ([]byte, error)

	SocialProvider  func(string) *providers.Provider
	HandleOAuthUser func(*engine.Context, singleauth.PluginOAuthUserInput) (singleauth.PluginOAuthUserResult, error)
	RefreshSession  func(*engine.Context, singleauth.PluginSessionState, bool) error

	FindVerification    func(context.Context, string) (storage.Record, error)
	ConsumeVerification func(context.Context, string) (storage.Record, error)
}

type oauthProxyStatePackage struct {
	State        string `json:"state"`
	StateCookie  string `json:"stateCookie"`
	IsOAuthProxy bool   `json:"isOAuthProxy"`
}

type oauthStateData struct {
	CallbackURL   string         `json:"callbackURL"`
	CodeVerifier  string         `json:"codeVerifier"`
	ErrorURL      string         `json:"errorURL,omitempty"`
	NewUserURL    string         `json:"newUserURL,omitempty"`
	OAuthState    string         `json:"oauthState,omitempty"`
	ExpiresAt     float64        `json:"expiresAt"`
	RequestSignUp *bool          `json:"requestSignUp,omitempty"`
	Raw           map[string]any `json:"-"`
}

type passthroughUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	Image         string `json:"image,omitempty"`
	EmailVerified bool   `json:"emailVerified"`
}

type passthroughAccount struct {
	ProviderID            string   `json:"providerId"`
	AccountID             string   `json:"accountId"`
	AccessToken           string   `json:"accessToken,omitempty"`
	RefreshToken          string   `json:"refreshToken,omitempty"`
	IDToken               string   `json:"idToken,omitempty"`
	AccessTokenExpiresAt  *isoTime `json:"accessTokenExpiresAt,omitempty"`
	RefreshTokenExpiresAt *isoTime `json:"refreshTokenExpiresAt,omitempty"`
	Scope                 string   `json:"scope,omitempty"`
}

type passthroughPayload struct {
	UserInfo      passthroughUser    `json:"userInfo"`
	Account       passthroughAccount `json:"account"`
	State         string             `json:"state"`
	CallbackURL   string             `json:"callbackURL"`
	NewUserURL    string             `json:"newUserURL,omitempty"`
	ErrorURL      string             `json:"errorURL,omitempty"`
	DisableSignUp bool               `json:"disableSignUp"`
	Timestamp     float64            `json:"timestamp"`
}

// isoTime preserves JavaScript Date#toJSON's millisecond UTC representation
// so proxy payloads interoperate in both Go -> TypeScript and TypeScript -> Go
// directions.
type isoTime time.Time

func isoTimePointer(value *time.Time) *isoTime {
	if value == nil {
		return nil
	}
	converted := isoTime(value.UTC())
	return &converted
}

func timePointer(value *isoTime) *time.Time {
	if value == nil {
		return nil
	}
	converted := time.Time(*value)
	return &converted
}

func (value isoTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(value).UTC().Format("2006-01-02T15:04:05.000Z"))
}

func (value *isoTime) UnmarshalJSON(encoded []byte) error {
	var text string
	if err := json.Unmarshal(encoded, &text); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return err
	}
	*value = isoTime(parsed.UTC())
	return nil
}
