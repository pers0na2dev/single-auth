package nethttp

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/pers0na2dev/single-auth/security/ratelimit"
)

// CheckRateLimit adapts one net/http request to the transport-neutral limiter.
func CheckRateLimit(
	ctx context.Context,
	limiter *ratelimit.Limiter,
	request *http.Request,
) (ratelimit.Result, error) {
	if request == nil {
		return ratelimit.Result{}, ratelimit.ErrNilRequest
	}
	if ctx == nil {
		ctx = request.Context()
	}
	return limiter.Check(ctx, ratelimit.RequestInfo{
		URL: absoluteRequestURL(request),
		Headers: ratelimit.HeaderGetterFunc(func(name string) string {
			return strings.Join(request.Header.Values(name), ", ")
		}),
	})
}

// WriteRateLimit writes the stable 429 response used by single-auth.
func WriteRateLimit(writer http.ResponseWriter, retryAfter int64) {
	writer.Header().Set("X-Retry-After", strconv.FormatInt(retryAfter, 10))
	writer.Header().Set("Content-Type", "text/plain;charset=UTF-8")
	writer.WriteHeader(http.StatusTooManyRequests)
	_, _ = writer.Write([]byte(ratelimit.TooManyRequestsBody))
}

// RateLimitMiddleware enforces limiter before invoking next. Storage and rule
// resolution errors are delegated to onError; when it is nil they receive a
// stable 500 response.
func RateLimitMiddleware(
	limiter *ratelimit.Limiter,
	next http.Handler,
	onError func(http.ResponseWriter, *http.Request, error),
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		result, err := CheckRateLimit(requestContext(request), limiter, request)
		if err != nil {
			if onError != nil {
				onError(writer, request, err)
			} else {
				http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			return
		}
		if result.Applied && !result.Allowed {
			WriteRateLimit(writer, result.RetryAfter)
			return
		}
		if next != nil {
			next.ServeHTTP(writer, request)
		}
	})
}

func requestContext(request *http.Request) context.Context {
	if request == nil {
		return nil
	}
	return request.Context()
}

func absoluteRequestURL(request *http.Request) string {
	if request.URL != nil && request.URL.IsAbs() {
		return request.URL.String()
	}
	scheme := requestScheme(request)
	host := request.Host
	if host == "" && request.URL != nil {
		host = request.URL.Host
	}
	if host == "" {
		host = "localhost"
	}
	result := &url.URL{Scheme: scheme, Host: host}
	if request.URL != nil {
		result.Path = request.URL.Path
		result.RawPath = request.URL.RawPath
		result.RawQuery = request.URL.RawQuery
	}
	return result.String()
}
