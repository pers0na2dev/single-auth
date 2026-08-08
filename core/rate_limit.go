package core

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	secondaryruntime "github.com/pers0na2dev/single-auth/internal/secondary"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage"
)

const rateLimitResponseBody = `{"message":"Too many requests. Please try again later."}`

func rateLimitStorageMode(options runtimeOptions) string {
	if options.RateLimit.Storage != "" {
		return options.RateLimit.Storage
	}
	if options.SecondaryStorage != nil || options.SecondaryValueStorage != nil {
		return "secondary-storage"
	}
	return "memory"
}

func configuredRateLimitSchema(options RateLimitOptions) storage.Schema {
	schema := ratelimit.SchemaWithModelName(options.ModelName)
	model := schema.Models["rateLimit"]
	for canonical, physical := range options.Fields {
		field := model.Fields[canonical]
		field.FieldName = physical
		model.Fields[canonical] = field
	}
	schema.Models["rateLimit"] = model
	return schema
}

type secondaryRateLimitStore struct {
	runtime *secondaryruntime.Runtime
}

func (store *secondaryRateLimitStore) Get(ctx context.Context, key string) (string, error) {
	value, err := store.runtime.Get(ctx, key)
	if err != nil || secondaryValueMissing(value) {
		return "", err
	}
	switch typed := value.(type) {
	case string:
		return typed, nil
	case []byte:
		return string(typed), nil
	default:
		return encodeSecondary(typed)
	}
}

func (store *secondaryRateLimitStore) Set(
	ctx context.Context,
	key, value string,
	ttl int64,
) error {
	return store.runtime.Set(ctx, key, value, ttl)
}

type atomicSecondaryRateLimitStore struct {
	*secondaryRateLimitStore
	increment ratelimit.SecondaryIncrementer
}

func (store *atomicSecondaryRateLimitStore) Increment(
	ctx context.Context,
	key string,
	ttl int64,
) (int64, error) {
	return store.increment.Increment(ctx, key, ttl)
}

func rateLimitSecondaryStore(runtime *secondaryruntime.Runtime) ratelimit.SecondaryStorage {
	base := &secondaryRateLimitStore{runtime: runtime}
	source := runtime.Source()
	if increment, ok := source.(ratelimit.SecondaryIncrementer); ok {
		return &atomicSecondaryRateLimitStore{
			secondaryRateLimitStore: base,
			increment:               increment,
		}
	}
	return base
}

func buildRateLimiter(
	options runtimeOptions,
	adapter storage.Adapter,
	secondary *secondaryruntime.Runtime,
) (*ratelimit.Limiter, error) {
	settings := options.RateLimit
	if settings.Warn == nil && options.logger != nil {
		settings.Warn = func(message string) { options.logger.Warn(message) }
	}
	if settings.Error == nil && options.logger != nil {
		settings.Error = func(message string, err error) {
			options.logger.Error(message, err)
		}
	}
	mode := rateLimitStorageMode(options)
	var store ratelimit.Storage
	if settings.CustomStorage != nil {
		store = settings.CustomStorage
	} else {
		switch mode {
		case "memory":
			// ratelimit.New creates one isolated, bounded memory store.
		case "database":
			store = ratelimit.NewDatabaseStore(adapter, ratelimit.DatabaseOptions{
				Model:        "rateLimit",
				GlobalWindow: settings.Window,
				Now:          options.Clock,
				Error:        settings.Error,
			})
		case "secondary-storage":
			if secondary == nil {
				return nil, fmt.Errorf(
					"single-auth: secondary-storage rate limiting requires SecondaryStorage or SecondaryValueStorage",
				)
			}
			store = ratelimit.NewSecondaryStore(rateLimitSecondaryStore(secondary), ratelimit.SecondaryOptions{
				Error: settings.Error,
			})
		default:
			return nil, fmt.Errorf("single-auth: unsupported rate limit storage %q", mode)
		}
	}

	pluginRules := make([][]ratelimit.MatcherRule, 0, len(options.Plugins))
	for _, plugin := range options.Plugins {
		if len(plugin.RateLimit) != 0 {
			pluginRules = append(pluginRules, append([]ratelimit.MatcherRule(nil), plugin.RateLimit...))
		}
	}
	environment := strings.ToLower(strings.TrimSpace(options.Environment))
	ip := options.Advanced.IPAddress
	// RateLimit.IP predates the root Advanced.IPAddress surface in single-auth.
	// Preserve it as an explicit compatibility override while using the
	// upstream shared resolver by default.
	if ipOptionsConfigured(settings.IP) {
		ip = settings.IP
	}
	ip.Development = ip.Development || environment == "development"
	ip.Test = ip.Test || environment == "test"
	limiter := ratelimit.New(ratelimit.Config{
		Enabled:     settings.Enabled,
		Production:  environment == "production",
		BasePath:    options.BasePath,
		DefaultRule: ratelimit.Rule{Window: settings.Window, Max: settings.Max},
		PluginRules: pluginRules,
		CustomRules: settings.CustomRules,
		IP:          ip,
		Warn:        settings.Warn,
		Now:         options.Clock,
	}, store)
	return limiter, nil
}

func ipOptionsConfigured(options ratelimit.IPOptions) bool {
	return options.DisableTracking || options.Headers != nil || options.TrustedProxies != nil ||
		options.IPv6Subnet != nil || options.Development || options.Test
}

func (a *Auth) rateLimitOnRequest(ctx *engine.Context) (engine.OnRequestResult, error) {
	if a == nil || a.rateLimiter == nil {
		return engine.OnRequestResult{}, nil
	}
	request := ctx.Request()
	host := request.Host()
	if host == "" {
		host = "localhost"
	}
	scheme := request.Scheme()
	if scheme != "http" && scheme != "https" {
		scheme = "http"
	}
	result, err := a.rateLimiter.Check(ctx.GoContext(), ratelimit.RequestInfo{
		URL: scheme + "://" + host + request.Target(),
		Headers: ratelimit.HeaderGetterFunc(func(name string) string {
			return strings.Join(request.Headers().Values(name), ", ")
		}),
	})
	if err != nil {
		return engine.OnRequestResult{}, err
	}
	if !result.Applied || result.Allowed {
		return engine.OnRequestResult{}, nil
	}
	headers := contract.NewHeaders(
		contract.HeaderField{Name: "X-Retry-After", Value: strconv.FormatInt(result.RetryAfter, 10)},
		contract.HeaderField{Name: "Content-Type", Value: "text/plain;charset=UTF-8"},
	)
	response := contract.NewResponse(contract.StatusTooManyRequests, headers, []byte(rateLimitResponseBody))
	return engine.OnRequestResult{Response: &response}, nil
}
