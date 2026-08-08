package fiber_test

import (
	"net/http"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"

	"github.com/pers0na2dev/single-auth/security/ratelimit"
	transport "github.com/pers0na2dev/single-auth/transport/fiber"
)

func enabledRateLimiter(maximum int64) *ratelimit.Limiter {
	enabled := true
	now := time.Unix(1_700_000_000, 0)
	return ratelimit.New(ratelimit.Config{
		Enabled:     &enabled,
		Production:  true,
		DefaultRule: ratelimit.Rule{Window: 10, Max: maximum},
		Now:         func() time.Time { return now },
	}, ratelimit.NewMemoryStore(ratelimit.MemoryOptions{Now: func() time.Time { return now }}))
}

func rateLimitRequest(target string) *http.Request {
	request, _ := http.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("X-Forwarded-For", "198.51.100.10")
	return request
}

func TestRateLimitMiddlewareStopsBlockedRequest(t *testing.T) {
	limiter := enabledRateLimiter(1)
	app := fiberframework.New()
	app.Use(transport.RateLimitMiddleware(limiter, nil))
	app.Get("/get-session", func(ctx fiberframework.Ctx) error { return ctx.SendString("ok") })

	for index := 0; index < 2; index++ {
		response, err := app.Test(
			rateLimitRequest("http://example.com/get-session"),
			fiberframework.TestConfig{Timeout: 0},
		)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		want := http.StatusOK
		if index == 1 {
			want = http.StatusTooManyRequests
		}
		if response.StatusCode != want {
			t.Fatalf("request %d status = %d, want %d", index, response.StatusCode, want)
		}
		if index == 1 {
			if got := response.Header.Get("X-Retry-After"); got != "10" {
				t.Fatalf("retry header = %q", got)
			}
		}
	}
}

func TestCheckAndWriteRateLimitUseFiberContext(t *testing.T) {
	limiter := enabledRateLimiter(1)
	app := fiberframework.New()
	app.Get("/probe", func(ctx fiberframework.Ctx) error {
		result, err := transport.CheckRateLimit(nil, limiter, ctx)
		if err != nil {
			return err
		}
		if !result.Allowed || result.Key != "198.51.100.10|/probe" {
			t.Fatalf("result = %#v", result)
		}
		return transport.WriteRateLimit(ctx, 7)
	})

	response, err := app.Test(
		rateLimitRequest("http://example.com/probe"),
		fiberframework.TestConfig{Timeout: 0},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if got := response.Header.Get("X-Retry-After"); got != "7" {
		t.Fatalf("retry header = %q", got)
	}
}
