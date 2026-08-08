package contract

import (
	"context"
	"net/url"
	"strings"
)

// RequestOptions contains the transport data that is not part of the method
// and raw path. Adapters must copy any reusable transport buffers before
// calling NewRequest.
type RequestOptions struct {
	Context     context.Context
	Scheme      string
	Host        string
	RawQuery    string
	Headers     Headers
	Body        []byte
	PeerAddress string
}

// Request is an immutable, transport-neutral request snapshot. All byte slices
// and headers are copied on construction and when returned by accessors.
type Request struct {
	ctx         context.Context
	method      string
	scheme      string
	host        string
	rawPath     string
	rawQuery    string
	headers     Headers
	body        []byte
	peerAddress string
}

// NewRequest constructs an independent request snapshot.
func NewRequest(method, rawPath string, options RequestOptions) Request {
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if rawPath == "" {
		rawPath = "/"
	}
	return Request{
		ctx:         ctx,
		method:      strings.ToUpper(method),
		scheme:      options.Scheme,
		host:        options.Host,
		rawPath:     rawPath,
		rawQuery:    options.RawQuery,
		headers:     options.Headers.Clone(),
		body:        cloneBytes(options.Body),
		peerAddress: options.PeerAddress,
	}
}

// Context returns the request cancellation context.
func (r Request) Context() context.Context {
	if r.ctx == nil {
		return context.Background()
	}
	return r.ctx
}

// Method returns the normalized uppercase method.
func (r Request) Method() string { return r.method }

// Scheme returns the original request scheme.
func (r Request) Scheme() string { return r.scheme }

// Host returns the original request host, including a port when present.
func (r Request) Host() string { return r.host }

// RawPath returns the escaped request path without query data.
func (r Request) RawPath() string {
	if r.rawPath == "" {
		return "/"
	}
	return r.rawPath
}

// RawQuery returns the unmodified query string without a leading question
// mark.
func (r Request) RawQuery() string { return r.rawQuery }

// Target returns the raw path and raw query in request-target form.
func (r Request) Target() string {
	if r.rawQuery == "" {
		return r.RawPath()
	}
	return r.RawPath() + "?" + r.rawQuery
}

// Headers returns an independent copy of all request header lines.
func (r Request) Headers() Headers { return r.headers.Clone() }

// Body returns an independent copy of the raw body.
func (r Request) Body() []byte { return cloneBytes(r.body) }

// PeerAddress returns the transport-provided peer address.
func (r Request) PeerAddress() string { return r.peerAddress }

// Query parses the raw query without changing the stored request.
func (r Request) Query() (url.Values, error) {
	return url.ParseQuery(r.rawQuery)
}

// Clone returns an independent request snapshot.
func (r Request) Clone() Request {
	return NewRequest(r.method, r.RawPath(), RequestOptions{
		Context:     r.Context(),
		Scheme:      r.scheme,
		Host:        r.host,
		RawQuery:    r.rawQuery,
		Headers:     r.headers,
		Body:        r.body,
		PeerAddress: r.peerAddress,
	})
}

// WithContext returns a copy carrying ctx.
func (r Request) WithContext(ctx context.Context) Request {
	clone := r.Clone()
	if ctx == nil {
		ctx = context.Background()
	}
	clone.ctx = ctx
	return clone
}

// WithMethod returns a copy carrying the normalized method.
func (r Request) WithMethod(method string) Request {
	clone := r.Clone()
	clone.method = strings.ToUpper(method)
	return clone
}

// WithTarget returns a copy carrying a new raw path and query.
func (r Request) WithTarget(rawPath, rawQuery string) Request {
	clone := r.Clone()
	if rawPath == "" {
		rawPath = "/"
	}
	clone.rawPath = rawPath
	clone.rawQuery = rawQuery
	return clone
}

// WithHeaders returns a copy carrying an independent header collection.
func (r Request) WithHeaders(headers Headers) Request {
	clone := r.Clone()
	clone.headers = headers.Clone()
	return clone
}

// WithAddedHeader returns a copy with one appended header line.
func (r Request) WithAddedHeader(name, value string) Request {
	clone := r.Clone()
	clone.headers.Add(name, value)
	return clone
}

// WithHeader returns a copy with every existing field of name replaced.
func (r Request) WithHeader(name, value string) Request {
	clone := r.Clone()
	clone.headers.Set(name, value)
	return clone
}

// WithBody returns a copy carrying an independent raw body.
func (r Request) WithBody(body []byte) Request {
	clone := r.Clone()
	clone.body = cloneBytes(body)
	return clone
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	clone := make([]byte, len(value))
	copy(clone, value)
	return clone
}
