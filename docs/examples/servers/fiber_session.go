package servers

import (
	fiberframework "github.com/gofiber/fiber/v3"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

type fiberSessionKey struct{}

// RequireSession resolves the current single-auth session before continuing
// the Fiber chain. A missing or invalid session becomes a stable 401 response.
func RequireSession(auth *singleauth.Auth) fiberframework.Handler {
	api := auth.API()

	return func(ctx fiberframework.Ctx) error {
		headers := contract.Headers{}
		ctx.Request().Header.VisitAllInOrder(func(name, value []byte) {
			headers.Add(string(name), string(value))
		})
		if headers.Len() == 0 {
			ctx.Request().Header.VisitAll(func(name, value []byte) {
				headers.Add(string(name), string(value))
			})
		}

		current, err := api.GetSession(ctx.Context(), singleauth.GetSessionInput{
			Headers: headers,
		})
		if err != nil {
			return fiberframework.NewError(
				fiberframework.StatusInternalServerError,
				"failed to resolve session",
			)
		}
		if current == nil {
			return ctx.Status(fiberframework.StatusUnauthorized).JSON(fiberframework.Map{
				"code":    "UNAUTHORIZED",
				"message": "Authentication required",
			})
		}

		fiberframework.Locals(ctx, fiberSessionKey{}, current)
		nextErr := ctx.Next()

		// Append after the application handler so a downstream response reset
		// cannot erase rolling session or cookie-cache refreshes.
		for _, cookie := range current.Headers.Values("Set-Cookie") {
			ctx.Response().Header.Add("Set-Cookie", cookie)
		}
		return nextErr
	}
}

// CurrentSession returns the session installed by RequireSession. It returns
// nil when called outside a protected Fiber chain.
func CurrentSession(ctx fiberframework.Ctx) *singleauth.SessionResult {
	return fiberframework.Locals[*singleauth.SessionResult](ctx, fiberSessionKey{})
}

// FiberWithProtectedRoute returns a complete example with auth routes and one
// application route protected by RequireSession.
func FiberWithProtectedRoute(secret string) (*fiberframework.App, error) {
	auth, err := newAuth(secret)
	if err != nil {
		return nil, err
	}
	return protectedFiberApp(auth), nil
}

func protectedFiberApp(auth *singleauth.Auth) *fiberframework.App {
	app := fiberframework.New()
	app.Use("/api/auth", fibertransport.NewHandler(auth.Dispatcher()))

	protected := app.Group("/api/private", RequireSession(auth))
	protected.Get("/me", func(ctx fiberframework.Ctx) error {
		current := CurrentSession(ctx)
		return ctx.JSON(fiberframework.Map{
			"id":    current.User.ID,
			"email": current.User.Email,
		})
	})

	return app
}
