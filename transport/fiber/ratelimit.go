package fiber

import (
	"context"

	fiberframework "github.com/gofiber/fiber/v3"

	"github.com/pers0na2dev/single-auth/security/ratelimit"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
)

// CheckRateLimit adapts one Fiber request to the transport-neutral limiter.
func CheckRateLimit(
	requestContext context.Context,
	limiter *ratelimit.Limiter,
	request fiberframework.Ctx,
) (ratelimit.Result, error) {
	if request == nil {
		return ratelimit.Result{}, ratelimit.ErrNilRequest
	}
	if requestContext == nil {
		requestContext = request.Context()
	}
	return fasthttptransport.CheckRateLimit(requestContext, limiter, request.RequestCtx())
}

// WriteRateLimit writes the stable 429 response used by single-auth.
func WriteRateLimit(request fiberframework.Ctx, retryAfter int64) error {
	if request == nil {
		return ratelimit.ErrNilRequest
	}
	fasthttptransport.WriteRateLimit(request.RequestCtx(), retryAfter)
	return nil
}

// RateLimitMiddleware enforces limiter before continuing the Fiber chain.
func RateLimitMiddleware(
	limiter *ratelimit.Limiter,
	onError func(fiberframework.Ctx, error) error,
) fiberframework.Handler {
	return func(request fiberframework.Ctx) error {
		if request == nil {
			return nil
		}
		result, err := CheckRateLimit(request.Context(), limiter, request)
		if err != nil {
			if onError != nil {
				return onError(request, err)
			}
			return err
		}
		if result.Applied && !result.Allowed {
			return WriteRateLimit(request, result.RetryAfter)
		}
		return request.Next()
	}
}
