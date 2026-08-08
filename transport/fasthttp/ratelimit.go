package fasthttp

import (
	"context"
	"strconv"
	"strings"

	fasthttpserver "github.com/valyala/fasthttp"

	"github.com/pers0na2dev/single-auth/security/ratelimit"
)

// CheckRateLimit adapts one native fasthttp request to the transport-neutral
// limiter. requestContext may be nil.
func CheckRateLimit(
	requestContext context.Context,
	limiter *ratelimit.Limiter,
	request *fasthttpserver.RequestCtx,
) (ratelimit.Result, error) {
	if request == nil {
		return ratelimit.Result{}, ratelimit.ErrNilRequest
	}
	if requestContext == nil {
		requestContext = request
	}
	return limiter.Check(requestContext, ratelimit.RequestInfo{
		URL: string(request.URI().FullURI()),
		Headers: ratelimit.HeaderGetterFunc(func(name string) string {
			values := request.Request.Header.PeekAll(name)
			if len(values) == 0 {
				return ""
			}
			parts := make([]string, len(values))
			for index := range values {
				parts[index] = string(values[index])
			}
			return strings.Join(parts, ", ")
		}),
	})
}

// WriteRateLimit writes the stable 429 response used by single-auth.
func WriteRateLimit(request *fasthttpserver.RequestCtx, retryAfter int64) {
	request.Response.Header.Set("X-Retry-After", strconv.FormatInt(retryAfter, 10))
	request.Response.Header.SetContentType("text/plain;charset=UTF-8")
	request.SetStatusCode(fasthttpserver.StatusTooManyRequests)
	request.SetBodyString(ratelimit.TooManyRequestsBody)
}

// RateLimitMiddleware enforces limiter before invoking a native fasthttp
// handler.
func RateLimitMiddleware(
	limiter *ratelimit.Limiter,
	next fasthttpserver.RequestHandler,
	onError func(*fasthttpserver.RequestCtx, error),
) fasthttpserver.RequestHandler {
	return func(request *fasthttpserver.RequestCtx) {
		result, err := CheckRateLimit(request, limiter, request)
		if err != nil {
			if onError != nil {
				onError(request, err)
			} else if request != nil {
				request.Error(
					fasthttpserver.StatusMessage(fasthttpserver.StatusInternalServerError),
					fasthttpserver.StatusInternalServerError,
				)
			}
			return
		}
		if result.Applied && !result.Allowed {
			WriteRateLimit(request, result.RetryAfter)
			return
		}
		if next != nil {
			next(request)
		}
	}
}
