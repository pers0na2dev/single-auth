package nethttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sort"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const statusRequestEntityTooLarge = http.StatusRequestEntityTooLarge

// ErrorHandler observes dispatcher and response-write errors after their
// stable wire response has been selected. It must be safe for concurrent use.
type ErrorHandler func(context.Context, error)

// Option configures an Adapter. Options are applied once by New, so the
// resulting handler is immutable and safe for concurrent use.
type Option func(*config)

type config struct {
	maxBodyBytes int64
	onError      ErrorHandler
}

// WithMaxBodyBytes rejects request bodies larger than limit with a stable 413
// response. A non-positive limit leaves body size enforcement to net/http and
// the hosting server.
func WithMaxBodyBytes(limit int64) Option {
	return func(config *config) {
		config.maxBodyBytes = limit
	}
}

// WithErrorHandler installs a non-mutating error observer. The adapter always
// writes the response returned by the dispatcher; the observer cannot replace
// it.
func WithErrorHandler(handler ErrorHandler) Option {
	return func(config *config) {
		config.onError = handler
	}
}

// Adapter is an immutable net/http bridge around one dispatcher.
type Adapter struct {
	dispatcher   *engine.Dispatcher
	maxBodyBytes int64
	onError      ErrorHandler
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
		dispatcher:   dispatcher,
		maxBodyBytes: configuration.maxBodyBytes,
		onError:      configuration.onError,
	}
}

// NewHandler constructs a standard-library handler. It is a convenience
// wrapper for New.
func NewHandler(dispatcher *engine.Dispatcher, options ...Option) http.Handler {
	return New(dispatcher, options...)
}

// ServeHTTP implements http.Handler.
func (adapter *Adapter) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request == nil {
		response := transportErrorResponse(
			http.StatusBadRequest,
			"INVALID_REQUEST",
			"Invalid request",
		)
		_ = writeResponse(writer, response)
		return
	}

	body, err := adapter.readBody(writer, request)
	if err != nil {
		response := bodyReadErrorResponse(err)
		writeErr := writeResponse(writer, response)
		adapter.observe(request.Context(), errors.Join(err, writeErr))
		return
	}

	var dispatcher *engine.Dispatcher
	if adapter != nil {
		dispatcher = adapter.dispatcher
	}
	rawQuery := ""
	if request.URL != nil {
		rawQuery = request.URL.RawQuery
	}
	response, dispatchErr := dispatcher.Dispatch(contract.NewRequest(
		request.Method,
		rawPath(request),
		contract.RequestOptions{
			Context:     request.Context(),
			Scheme:      requestScheme(request),
			Host:        request.Host,
			RawQuery:    rawQuery,
			Headers:     requestHeaders(request.Header),
			Body:        body,
			PeerAddress: request.RemoteAddr,
		},
	))
	writeErr := writeResponse(writer, response)
	adapter.observe(request.Context(), errors.Join(dispatchErr, writeErr))
}

func (adapter *Adapter) readBody(writer http.ResponseWriter, request *http.Request) ([]byte, error) {
	if request.Body == nil {
		return nil, nil
	}
	reader := io.Reader(request.Body)
	if adapter != nil && adapter.maxBodyBytes > 0 {
		reader = http.MaxBytesReader(writer, request.Body, adapter.maxBodyBytes)
	}
	return io.ReadAll(reader)
}

func (adapter *Adapter) observe(ctx context.Context, err error) {
	if err == nil || adapter == nil || adapter.onError == nil {
		return
	}
	adapter.onError(ctx, err)
}

func rawPath(request *http.Request) string {
	if request.URL == nil {
		return "/"
	}
	path := request.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func requestScheme(request *http.Request) string {
	if request.URL != nil && request.URL.Scheme != "" {
		return request.URL.Scheme
	}
	if request.TLS != nil {
		return "https"
	}
	return "http"
}

func requestHeaders(source http.Header) contract.Headers {
	// net/http preserves value order for a field but represents field names in
	// a map. Sorting names makes the necessarily reconstructed global order
	// deterministic.
	names := make([]string, 0, len(source))
	for name := range source {
		names = append(names, name)
	}
	sort.Strings(names)

	headers := contract.Headers{}
	for _, name := range names {
		for _, value := range source[name] {
			headers.Add(name, value)
		}
	}
	return headers
}

func writeResponse(writer http.ResponseWriter, response contract.Response) error {
	for _, field := range response.Headers().Fields() {
		writer.Header().Add(field.Name, field.Value)
	}
	writer.WriteHeader(response.Status())
	body := response.Body()
	if len(body) == 0 {
		return nil
	}
	_, err := writer.Write(body)
	return err
}

func bodyReadErrorResponse(err error) contract.Response {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		return transportErrorResponse(
			statusRequestEntityTooLarge,
			"PAYLOAD_TOO_LARGE",
			"Request body is too large",
		)
	}
	return transportErrorResponse(
		http.StatusBadRequest,
		"BODY_READ_ERROR",
		"Unable to read request body",
	)
}

func transportErrorResponse(status int, code, message string) contract.Response {
	return contract.ResponseFromError(contract.NewAPIError(status, code, message))
}
