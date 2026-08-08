package core

import (
	"context"
	"strings"
	"testing"

	authlogger "github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
)

func TestRootLoggerConfigAndRateLimitDiagnostics(t *testing.T) {
	type entry struct {
		level   authlogger.Level
		message string
	}
	var entries []entry
	auth := MustNew(Options{
		Environment: "production",
		Secret:      "0123456789abcdef0123456789abcdef",
		Logger: authlogger.Options{
			Level: authlogger.Debug,
			Log: func(level authlogger.Level, message string, _ ...any) {
				entries = append(entries, entry{level: level, message: message})
			},
		},
	})
	if auth.Logger() == nil || auth.Logger().Level() != authlogger.Debug {
		t.Fatalf("logger = %#v", auth.Logger())
	}
	for range 2 {
		if _, err := auth.RateLimiter().Check(context.Background(), ratelimit.RequestInfo{
			URL: "https://auth.example/api/auth/sign-in/email",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(entries) != 1 || entries[0].level != authlogger.Warn ||
		!strings.Contains(entries[0].message, "client IP") {
		t.Fatalf("rate-limit diagnostics = %#v", entries)
	}

	snapshot := auth.Options()
	if snapshot.Logger.Level != authlogger.Debug || snapshot.Logger.DisableColors != nil {
		t.Fatalf("logger snapshot = %#v", snapshot.Logger)
	}
}

func TestRootRejectsInvalidLoggerLevel(t *testing.T) {
	if _, err := New(Options{Logger: authlogger.Options{Level: "trace"}}); err == nil ||
		!strings.Contains(err.Error(), "invalid configured level") {
		t.Fatalf("invalid logger error = %v", err)
	}
}
