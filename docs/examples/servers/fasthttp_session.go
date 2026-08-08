package servers

import (
	"bytes"
	"encoding/json"

	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
)

type fastHTTPSessionKey struct{}

// RequireFastHTTPSession resolves the current single-auth session before
// invoking next. A missing or invalid session becomes a stable 401 response.
func RequireFastHTTPSession(
	auth *singleauth.Auth,
	next fasthttpserver.RequestHandler,
) fasthttpserver.RequestHandler {
	api := auth.API()

	return func(request *fasthttpserver.RequestCtx) {
		headers := fastHTTPRequestHeaders(&request.Request.Header)
		current, err := api.GetSession(request, singleauth.GetSessionInput{
			Headers: headers,
		})
		if err != nil {
			writeFastHTTPSessionError(
				request,
				fasthttpserver.StatusInternalServerError,
				"SESSION_LOOKUP_FAILED",
				"Failed to resolve session",
			)
			return
		}
		if current == nil {
			writeFastHTTPSessionError(
				request,
				fasthttpserver.StatusUnauthorized,
				"UNAUTHORIZED",
				"Authentication required",
			)
			return
		}

		request.SetUserValue(fastHTTPSessionKey{}, current)
		if next != nil {
			next(request)
		}

		// Append after the application handler so a downstream response reset
		// cannot erase rolling session or cookie-cache refreshes.
		for _, cookie := range current.Headers.Values("Set-Cookie") {
			request.Response.Header.Add("Set-Cookie", cookie)
		}
	}
}

// CurrentFastHTTPSession returns the session installed by
// RequireFastHTTPSession. It returns nil outside a protected handler.
func CurrentFastHTTPSession(request *fasthttpserver.RequestCtx) *singleauth.SessionResult {
	if request == nil {
		return nil
	}
	current, _ := request.UserValue(fastHTTPSessionKey{}).(*singleauth.SessionResult)
	return current
}

// FastHTTPWithProtectedRoute returns a complete example with auth routes and
// one application route protected by RequireFastHTTPSession.
func FastHTTPWithProtectedRoute(secret string) (fasthttpserver.RequestHandler, error) {
	auth, err := newAuth(secret)
	if err != nil {
		return nil, err
	}
	return protectedFastHTTPHandler(auth), nil
}

func protectedFastHTTPHandler(auth *singleauth.Auth) fasthttpserver.RequestHandler {
	authHandler := fasthttptransport.NewHandler(auth.Dispatcher())
	privateHandler := RequireFastHTTPSession(auth, func(request *fasthttpserver.RequestCtx) {
		current := CurrentFastHTTPSession(request)
		body, _ := json.Marshal(map[string]string{
			"id":    current.User.ID,
			"email": current.User.Email,
		})
		request.Success("application/json", body)
	})

	return func(request *fasthttpserver.RequestCtx) {
		path := request.Path()
		switch {
		case bytes.Equal(path, []byte("/api/auth")),
			bytes.HasPrefix(path, []byte("/api/auth/")):
			authHandler(request)
		case request.IsGet() && bytes.Equal(path, []byte("/api/private/me")):
			privateHandler(request)
		default:
			request.SetStatusCode(fasthttpserver.StatusNotFound)
		}
	}
}

func fastHTTPRequestHeaders(source *fasthttpserver.RequestHeader) contract.Headers {
	headers := contract.Headers{}
	if source == nil {
		return headers
	}

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

func writeFastHTTPSessionError(
	request *fasthttpserver.RequestCtx,
	status int,
	code string,
	message string,
) {
	body, _ := json.Marshal(map[string]string{
		"code":    code,
		"message": message,
	})
	request.Response.Header.SetContentType("application/json")
	request.SetStatusCode(status)
	request.SetBody(body)
}
