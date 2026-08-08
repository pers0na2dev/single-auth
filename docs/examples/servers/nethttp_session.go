package servers

import (
	"context"
	"encoding/json"
	"net/http"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

type netHTTPSessionKey struct{}

// RequireNetHTTPSession resolves the current single-auth session before
// invoking next. A missing or invalid session becomes a stable 401 response.
func RequireNetHTTPSession(auth *singleauth.Auth, next http.Handler) http.Handler {
	api := auth.API()

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		headers := contract.Headers{}
		for name, values := range request.Header {
			for _, value := range values {
				headers.Add(name, value)
			}
		}

		current, err := api.GetSession(request.Context(), singleauth.GetSessionInput{
			Headers: headers,
		})
		if err != nil {
			writeNetHTTPSessionError(
				writer,
				http.StatusInternalServerError,
				"SESSION_LOOKUP_FAILED",
				"Failed to resolve session",
			)
			return
		}
		if current == nil {
			writeNetHTTPSessionError(
				writer,
				http.StatusUnauthorized,
				"UNAUTHORIZED",
				"Authentication required",
			)
			return
		}

		for _, cookie := range current.Headers.Values("Set-Cookie") {
			writer.Header().Add("Set-Cookie", cookie)
		}

		if next != nil {
			ctx := context.WithValue(request.Context(), netHTTPSessionKey{}, current)
			next.ServeHTTP(writer, request.WithContext(ctx))
		}
	})
}

// CurrentNetHTTPSession returns the session installed by
// RequireNetHTTPSession. It returns nil outside a protected handler.
func CurrentNetHTTPSession(request *http.Request) *singleauth.SessionResult {
	if request == nil {
		return nil
	}
	current, _ := request.Context().Value(netHTTPSessionKey{}).(*singleauth.SessionResult)
	return current
}

// NetHTTPWithProtectedRoute returns a complete example with auth routes and
// one application route protected by RequireNetHTTPSession.
func NetHTTPWithProtectedRoute(secret string) (http.Handler, error) {
	auth, err := newAuth(secret)
	if err != nil {
		return nil, err
	}
	return protectedNetHTTPHandler(auth), nil
}

func protectedNetHTTPHandler(auth *singleauth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", nethttptransport.NewHandler(auth.Dispatcher()))

	private := http.NewServeMux()
	private.HandleFunc("GET /api/private/me", func(writer http.ResponseWriter, request *http.Request) {
		current := CurrentNetHTTPSession(request)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{
			"id":    current.User.ID,
			"email": current.User.Email,
		})
	})
	mux.Handle("/api/private/", RequireNetHTTPSession(auth, private))

	return mux
}

func writeNetHTTPSessionError(
	writer http.ResponseWriter,
	status int,
	code string,
	message string,
) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{
		"code":    code,
		"message": message,
	})
}
