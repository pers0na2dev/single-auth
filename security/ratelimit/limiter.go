package ratelimit

import (
	"context"
	"errors"
	"strings"
	"sync"
)

var ErrNilRequest = errors.New("ratelimit: request is nil")

const missingIPWarning = "Rate limiting could not determine a client IP and is falling back to a single shared per-path bucket. Ensure your runtime forwards a trusted client IP header, then set `advanced.ipAddress.ipAddressHeaders` or `advanced.ipAddress.trustedProxies` so the address can be resolved."
const legacyStorageWarning = "Rate limiting is best-effort: the configured storage has no atomic `consume`, so concurrent requests may bypass the limit. Provide a storage that implements `consume` for strict enforcement."

// Limiter resolves reference implementation rules and consumes their storage counters.
type Limiter struct {
	config      Config
	storage     Storage
	enabled     bool
	defaultRule Rule
	missingIP   sync.Once
	legacy      sync.Once
}

// New constructs a limiter. A nil store selects an isolated memory backend.
func New(config Config, store Storage) *Limiter {
	if config.IP.Headers != nil {
		headers := make([]string, len(config.IP.Headers))
		copy(headers, config.IP.Headers)
		config.IP.Headers = headers
	}
	config.IP.TrustedProxies = append([]string(nil), config.IP.TrustedProxies...)
	config.CustomRules = append([]CustomRule(nil), config.CustomRules...)
	if config.PluginRules != nil {
		plugins := make([][]MatcherRule, len(config.PluginRules))
		for index := range config.PluginRules {
			plugins[index] = append([]MatcherRule(nil), config.PluginRules[index]...)
		}
		config.PluginRules = plugins
	}
	enabled := config.Production
	if config.Enabled != nil {
		enabled = *config.Enabled
	}
	rule := config.DefaultRule
	if rule.Window == 0 {
		rule.Window = DefaultWindow
	}
	if rule.Max == 0 {
		rule.Max = DefaultMax
	}
	if store == nil {
		store = NewMemoryStore(MemoryOptions{Now: config.Now})
	}
	return &Limiter{config: config, storage: store, enabled: enabled, defaultRule: rule}
}

// Check resolves and consumes the rate-limit bucket for a transport-neutral
// request.
func (limiter *Limiter) Check(ctx context.Context, request RequestInfo) (Result, error) {
	if limiter == nil || !limiter.enabled {
		return Result{Allowed: true}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	path := NormalizePathname(request.URL, limiter.config.BasePath)
	ipOptions := limiter.config.IP
	ip := GetIP(request.Headers, ipOptions)
	if ip == "" && ipOptions.DisableTracking {
		return Result{Allowed: true, Path: path}, nil
	}
	if ip == "" {
		limiter.missingIP.Do(func() { limiter.warn(missingIPWarning) })
		ip = NoTrustedIPKey
	}
	rule := limiter.resolveBuiltInAndPlugin(path)
	for _, custom := range limiter.config.CustomRules {
		matched := custom.Pattern == path
		if strings.Contains(custom.Pattern, "*") {
			matched = WildcardMatch(custom.Pattern, path)
		}
		if !matched {
			continue
		}
		if custom.Disabled {
			return Result{Allowed: true, Path: path, Rule: rule}, nil
		}
		if custom.Resolve != nil {
			resolved, active, err := custom.Resolve(ctx, request, rule)
			if err != nil {
				return Result{}, err
			}
			if !active {
				return Result{Allowed: true, Path: path, Rule: rule}, nil
			}
			rule = resolved
		} else {
			rule = custom.Rule
		}
		break
	}

	key := CreateKey(ip, path)
	var consumed ConsumeResult
	var err error
	if atomic, ok := limiter.storage.(AtomicStorage); ok {
		consumed, err = atomic.Consume(ctx, key, rule)
	} else {
		limiter.legacy.Do(func() { limiter.warn(legacyStorageWarning) })
		consumed, err = limiter.legacyConsume(ctx, key, rule)
	}
	if err != nil {
		return Result{}, err
	}
	result := Result{Applied: true, Allowed: consumed.Allowed, Key: key, Path: path, Rule: rule}
	if !consumed.Allowed {
		result.RetryAfter = rule.Window
		if consumed.RetryAfter != nil {
			result.RetryAfter = *consumed.RetryAfter
		}
	}
	return result, nil
}

func (limiter *Limiter) resolveBuiltInAndPlugin(path string) Rule {
	rule := limiter.defaultRule
	if strings.HasPrefix(path, "/sign-in") ||
		strings.HasPrefix(path, "/sign-up") ||
		strings.HasPrefix(path, "/change-password") ||
		strings.HasPrefix(path, "/change-email") {
		rule = Rule{Window: 10, Max: 3}
	} else if path == "/request-password-reset" ||
		path == "/send-verification-email" ||
		strings.HasPrefix(path, "/forget-password") ||
		path == "/email-otp/send-verification-otp" ||
		path == "/email-otp/request-password-reset" {
		rule = Rule{Window: 60, Max: 3}
	}
	for _, plugin := range limiter.config.PluginRules {
		matched := false
		for _, candidate := range plugin {
			if candidate.Match != nil && candidate.Match(path) {
				rule = candidate.Rule
				matched = true
				break
			}
		}
		if matched {
			break
		}
	}
	return rule
}

func (limiter *Limiter) legacyConsume(ctx context.Context, key string, rule Rule) (ConsumeResult, error) {
	data, err := limiter.storage.Get(ctx, key)
	if err != nil {
		return ConsumeResult{}, err
	}
	decision := decideConsume(data, rule, unixMillis(limiter.config.Now))
	if !decision.allowed {
		return ConsumeResult{Allowed: false, RetryAfter: decision.retryAfter}, nil
	}
	decision.next.Key = key
	if err := limiter.storage.Set(ctx, key, decision.next, decision.update, rule.Window); err != nil {
		return ConsumeResult{}, err
	}
	return ConsumeResult{Allowed: true}, nil
}

func (limiter *Limiter) warn(message string) {
	if limiter.config.Warn != nil {
		limiter.config.Warn(message)
	}
}
