package ratelimit

import (
	"context"
	"time"
)

const (
	// DefaultWindow is reference implementation's default rolling window, in seconds.
	DefaultWindow int64 = 10
	// DefaultMax is reference implementation's default number of requests per window.
	DefaultMax int64 = 100
	// NoTrustedIPKey is the non-IP bucket used when production requests do not
	// contain a trustworthy client address.
	NoTrustedIPKey = "no-trusted-ip"
	// TooManyRequestsMessage is the exact reference implementation response message.
	TooManyRequestsMessage = "Too many requests. Please try again later."
	// TooManyRequestsBody is the exact JSON body emitted by all server
	// transport adapters when a request is rate limited.
	TooManyRequestsBody = `{"message":"Too many requests. Please try again later."}`
)

// Rule is a rate-limit window. Window is measured in whole seconds.
type Rule struct {
	Window int64
	Max    int64
}

// Record is the persisted reference implementation rateLimit row. LastRequest is Unix time
// in milliseconds.
type Record struct {
	Key         string `json:"key"`
	Count       int64  `json:"count"`
	LastRequest int64  `json:"lastRequest"`
}

// ConsumeResult is returned by an atomic storage backend.
type ConsumeResult struct {
	Allowed    bool
	RetryAfter *int64
}

// Storage is the backward-compatible reference implementation storage contract. Set's
// update argument is false when the key is first created and true thereafter.
// ttlSeconds is the rule window selected for this request.
type Storage interface {
	Get(context.Context, string) (*Record, error)
	Set(context.Context, string, Record, bool, int64) error
}

// AtomicStorage performs check-and-increment as one indivisible operation.
// Strict enforcement under concurrency requires this interface.
type AtomicStorage interface {
	Storage
	Consume(context.Context, string, Rule) (ConsumeResult, error)
}

// HeaderGetter exposes the only header operation needed by the limiter.
// Concrete transports adapt their native header collections to this
// interface without copying the full request.
type HeaderGetter interface {
	Get(string) string
}

// HeaderGetterFunc adapts a function to HeaderGetter.
type HeaderGetterFunc func(string) string

// Get implements HeaderGetter.
func (f HeaderGetterFunc) Get(name string) string { return f(name) }

// RequestInfo is the transport-neutral request shape used by the limiter.
type RequestInfo struct {
	URL     string
	Headers HeaderGetter
}

// IPOptions controls trusted-client-IP resolution.
type IPOptions struct {
	DisableTracking bool
	Headers         []string
	TrustedProxies  []string
	// IPv6Subnet defaults to 64. A non-nil value, including zero, is honored.
	IPv6Subnet *int
	// Development and Test enable reference implementation's 127.0.0.1 fallback.
	Development bool
	Test        bool
}

// MatcherRule is one plugin-provided rule. Plugin rule groups are evaluated
// in plugin order; the first matching rule in the first matching group wins.
type MatcherRule struct {
	Match func(string) bool
	Rule  Rule
}

// CustomRule is an ordered reference implementation custom rule. Pattern is exact unless it
// contains '*', in which case reference implementation wildcard matching is used.
type CustomRule struct {
	Pattern  string
	Rule     Rule
	Disabled bool
	Resolve  func(context.Context, RequestInfo, Rule) (Rule, bool, error)
}

// Config configures a Limiter. A nil Enabled value follows reference implementation's
// production default: enabled in production and disabled otherwise.
type Config struct {
	Enabled     *bool
	Production  bool
	BasePath    string
	DefaultRule Rule
	PluginRules [][]MatcherRule
	CustomRules []CustomRule
	IP          IPOptions
	Warn        func(string)
	Now         func() time.Time
}

// Result describes a rate-limit check. Applied is false when limiting is
// disabled globally, for a custom rule, or by DisableTracking.
type Result struct {
	Applied    bool
	Allowed    bool
	Key        string
	Path       string
	Rule       Rule
	RetryAfter int64
}
