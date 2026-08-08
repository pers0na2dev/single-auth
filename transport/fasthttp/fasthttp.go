package fasthttp

import (
	"context"

	fasthttpserver "github.com/valyala/fasthttp"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const statusRequestEntityTooLarge = 413

// ErrorHandler observes dispatcher errors after their stable wire response has
// been written. It must be safe for concurrent use.
type ErrorHandler func(context.Context, error)

// ContextProvider returns an authoritative request-scoped context supplied by
// the host. When present, the adapter does not also retain RequestCtx as a
// cancellation source: fasthttp mutates its server-wide shutdown channel while
// shutting down, so asynchronous users of RequestCtx.Done can otherwise race
// with Server.Shutdown. Hosts that need shutdown cancellation should derive the
// provided context from their own stable server-lifecycle context.
type ContextProvider func(*fasthttpserver.RequestCtx) context.Context

// Option configures an Adapter once during construction.
type Option func(*config)

type config struct {
	maxBodyBytes    int
	onError         ErrorHandler
	contextProvider ContextProvider
}

// WithMaxBodyBytes rejects already-buffered bodies larger than limit. A
// non-positive value leaves size enforcement to fasthttp.Server's
// MaxRequestBodySize.
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

// WithContextProvider installs the bridge used for request deadlines and
// cancellation managed by the host application.
func WithContextProvider(provider ContextProvider) Option {
	return func(config *config) {
		config.contextProvider = provider
	}
}

// Adapter is an immutable fasthttp bridge around one dispatcher.
type Adapter struct {
	dispatcher      *engine.Dispatcher
	maxBodyBytes    int
	onError         ErrorHandler
	contextProvider ContextProvider
}

// New constructs an immutable adapter.
func New(dispatcher *engine.Dispatcher, options ...Option) *Adapter {
	configuration := config{}
	for _, option := range options {
		if option != nil {
			option(&configuration)
		}
	}
	return &Adapter{
		dispatcher:      dispatcher,
		maxBodyBytes:    configuration.maxBodyBytes,
		onError:         configuration.onError,
		contextProvider: configuration.contextProvider,
	}
}

// NewHandler constructs a fasthttp request handler. It is a convenience
// wrapper for New.
func NewHandler(
	dispatcher *engine.Dispatcher,
	options ...Option,
) fasthttpserver.RequestHandler {
	return New(dispatcher, options...).Handler()
}

// Handler returns the adapter as a fasthttp.RequestHandler.
func (adapter *Adapter) Handler() fasthttpserver.RequestHandler {
	return adapter.Serve
}

// Serve dispatches one fasthttp request. By default RequestCtx is used as the
// Go context, which propagates server shutdown. Use WithContextProvider when
// the host has a stable, finer-grained request or server-lifecycle context.
func (adapter *Adapter) Serve(ctx *fasthttpserver.RequestCtx) {
	var requestContext context.Context
	if adapter != nil && adapter.contextProvider != nil {
		requestContext = adapter.contextProvider(ctx)
	}
	adapter.ServeContext(requestContext, ctx)
}

// ServeContext dispatches one fasthttp request with an explicit host context.
// Fiber uses this method with fiber.Ctx.Context; it still performs no net/http
// conversion.
func (adapter *Adapter) ServeContext(
	requestContext context.Context,
	ctx *fasthttpserver.RequestCtx,
) {
	if ctx == nil {
		return
	}

	goContext, release := requestGoContext(requestContext, ctx)
	defer release()

	body := ctx.PostBody()
	if adapter != nil && adapter.maxBodyBytes > 0 && len(body) > adapter.maxBodyBytes {
		err := contract.NewAPIError(
			statusRequestEntityTooLarge,
			"PAYLOAD_TOO_LARGE",
			"Request body is too large",
		)
		writeResponse(ctx, contract.ResponseFromError(err))
		adapter.observe(goContext, err)
		return
	}

	var dispatcher *engine.Dispatcher
	if adapter != nil {
		dispatcher = adapter.dispatcher
	}
	response, dispatchErr := dispatcher.Dispatch(contract.NewRequest(
		string(ctx.Method()),
		rawPath(ctx),
		contract.RequestOptions{
			Context:     goContext,
			Scheme:      string(ctx.URI().Scheme()),
			Host:        string(ctx.URI().Host()),
			RawQuery:    string(ctx.URI().QueryString()),
			Headers:     requestHeaders(&ctx.Request.Header),
			Body:        body,
			PeerAddress: ctx.RemoteAddr().String(),
		},
	))
	writeResponse(ctx, response)
	adapter.observe(goContext, dispatchErr)
}

func (adapter *Adapter) observe(ctx context.Context, err error) {
	if err == nil || adapter == nil || adapter.onError == nil {
		return
	}
	adapter.onError(ctx, err)
}

func requestGoContext(
	requestContext context.Context,
	serverContext context.Context,
) (context.Context, func()) {
	if requestContext != nil {
		return requestContext, func() {}
	}
	if serverContext != nil {
		return serverContext, func() {}
	}
	return context.Background(), func() {}
}

func rawPath(ctx *fasthttpserver.RequestCtx) string {
	path := ctx.URI().PathOriginal()
	if len(path) == 0 {
		return "/"
	}
	return string(path)
}

func requestHeaders(source *fasthttpserver.RequestHeader) contract.Headers {
	headers := contract.Headers{}
	if source == nil {
		return headers
	}

	// Real server requests retain their raw field order. Programmatically built
	// requests may not have raw headers, so fall back to VisitAll.
	source.VisitAllInOrder(func(name, value []byte) {
		headers.Add(string(name), string(value))
	})
	if headers.Len() == 0 {
		source.VisitAll(func(name, value []byte) {
			headers.Add(string(name), string(value))
		})
	}
	return headers
}

func writeResponse(ctx *fasthttpserver.RequestCtx, response contract.Response) {
	for _, field := range response.Headers().Fields() {
		ctx.Response.Header.Add(field.Name, field.Value)
	}
	ctx.Response.SetStatusCode(response.Status())
	body := response.Body()
	ctx.Response.SetBody(body)
}
