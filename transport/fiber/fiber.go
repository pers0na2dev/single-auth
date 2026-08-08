package fiber

import (
	"context"

	fiberframework "github.com/gofiber/fiber/v3"

	"github.com/pers0na2dev/single-auth/core/engine"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
)

// ErrorHandler observes dispatcher errors after their stable wire response has
// been written. It must be safe for concurrent use.
type ErrorHandler func(context.Context, error)

// Option configures an Adapter once during construction.
type Option func(*config)

type config struct {
	maxBodyBytes int
	onError      ErrorHandler
}

// WithMaxBodyBytes rejects bodies larger than limit with a stable 413
// response. A non-positive value leaves enforcement to Fiber's BodyLimit.
func WithMaxBodyBytes(limit int) Option {
	return func(config *config) {
		config.maxBodyBytes = limit
	}
}

// WithErrorHandler installs a non-mutating error observer.
func WithErrorHandler(handler ErrorHandler) Option {
	return func(config *config) {
		config.onError = handler
	}
}

// Adapter is an immutable Fiber v3 bridge around the direct fasthttp adapter.
// It performs no conversion through net/http.
type Adapter struct {
	fast *fasthttptransport.Adapter
}

// New constructs an immutable Fiber v3 adapter.
func New(dispatcher *engine.Dispatcher, options ...Option) *Adapter {
	configuration := config{}
	for _, option := range options {
		if option != nil {
			option(&configuration)
		}
	}

	fastOptions := make([]fasthttptransport.Option, 0, 2)
	if configuration.maxBodyBytes > 0 {
		fastOptions = append(
			fastOptions,
			fasthttptransport.WithMaxBodyBytes(configuration.maxBodyBytes),
		)
	}
	if configuration.onError != nil {
		fastOptions = append(
			fastOptions,
			fasthttptransport.WithErrorHandler(
				func(ctx context.Context, err error) {
					configuration.onError(ctx, err)
				},
			),
		)
	}
	return &Adapter{fast: fasthttptransport.New(dispatcher, fastOptions...)}
}

// NewHandler constructs a Fiber v3 handler. It is a convenience wrapper for
// New.
func NewHandler(dispatcher *engine.Dispatcher, options ...Option) fiberframework.Handler {
	return New(dispatcher, options...).Handler()
}

// Handler returns the adapter as a Fiber v3 handler.
func (adapter *Adapter) Handler() fiberframework.Handler {
	return adapter.Serve
}

// Serve dispatches one Fiber v3 request. Fiber's user context is the
// authoritative request context; applications can derive it from a stable
// server-lifecycle context when shutdown cancellation is required.
func (adapter *Adapter) Serve(ctx fiberframework.Ctx) error {
	if ctx == nil {
		return nil
	}
	if adapter == nil || adapter.fast == nil {
		fasthttptransport.New(nil).ServeContext(ctx.Context(), ctx.RequestCtx())
		return nil
	}
	adapter.fast.ServeContext(ctx.Context(), ctx.RequestCtx())
	return nil
}
