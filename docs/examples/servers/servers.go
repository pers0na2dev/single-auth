// Package servers contains compile-checked transport setup examples used by
// the single-auth documentation.
package servers

import (
	"net/http"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

func newAuth(secret string) (*singleauth.Auth, error) {
	return singleauth.New(singleauth.Options{
		BaseURL: "https://auth.example.com",
		Secret:  secret,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
		},
		TrustedOrigins: []string{"https://app.example.com"},
	})
}

// NetHTTP returns a standard-library handler with a one-megabyte request-body
// limit. Mount the result below the configured /api/auth base path.
func NetHTTP(secret string) (http.Handler, error) {
	auth, err := newAuth(secret)
	if err != nil {
		return nil, err
	}
	return nethttptransport.NewHandler(
		auth.Dispatcher(),
		nethttptransport.WithMaxBodyBytes(1<<20),
	), nil
}

// FastHTTP returns a native fasthttp handler without converting through
// net/http.
func FastHTTP(secret string) (fasthttpserver.RequestHandler, error) {
	auth, err := newAuth(secret)
	if err != nil {
		return nil, err
	}
	return fasthttptransport.NewHandler(
		auth.Dispatcher(),
		fasthttptransport.WithMaxBodyBytes(1<<20),
	), nil
}

// Fiber returns a Fiber v3 application with the native fasthttp adapter mounted
// at the default auth base path.
func Fiber(secret string) (*fiberframework.App, error) {
	auth, err := newAuth(secret)
	if err != nil {
		return nil, err
	}
	app := fiberframework.New()
	app.Use(
		"/api/auth",
		fibertransport.NewHandler(
			auth.Dispatcher(),
			fibertransport.WithMaxBodyBytes(1<<20),
		),
	)
	return app, nil
}
