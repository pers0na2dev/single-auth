package providers

import (
	"context"
	"net/http"
)

// VerifyIDTokenRequestContext is the transport-neutral request metadata made
// available to a custom ID-token verifier. It is the Go counterpart of the
// GenericEndpointContext argument passed by the reference implementation 1.6.26.
type VerifyIDTokenRequestContext struct {
	Headers http.Header
}

type verifyIDTokenRequestContextKey struct{}

// WithVerifyIDTokenRequestContext returns a context carrying an independent
// copy of the request metadata supplied to a custom ID-token verifier.
func WithVerifyIDTokenRequestContext(ctx context.Context, requestContext VerifyIDTokenRequestContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	requestContext.Headers = requestContext.Headers.Clone()
	return context.WithValue(ctx, verifyIDTokenRequestContextKey{}, requestContext)
}

// VerifyIDTokenRequestContextFrom returns the request metadata forwarded to a
// custom ID-token verifier. The returned headers may be mutated independently.
func VerifyIDTokenRequestContextFrom(ctx context.Context) (VerifyIDTokenRequestContext, bool) {
	if ctx == nil {
		return VerifyIDTokenRequestContext{}, false
	}
	requestContext, ok := ctx.Value(verifyIDTokenRequestContextKey{}).(VerifyIDTokenRequestContext)
	if !ok {
		return VerifyIDTokenRequestContext{}, false
	}
	requestContext.Headers = requestContext.Headers.Clone()
	return requestContext, true
}

// VerifyIDTokenWithRequestContext verifies an ID token while forwarding the
// endpoint request metadata to a custom VerifyIDToken callback.
func (p *Provider) VerifyIDTokenWithRequestContext(
	ctx context.Context,
	token string,
	nonce string,
	requestContext VerifyIDTokenRequestContext,
) (bool, error) {
	return p.VerifyIDToken(WithVerifyIDTokenRequestContext(ctx, requestContext), token, nonce)
}
