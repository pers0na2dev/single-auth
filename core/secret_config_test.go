package core

import (
	"strings"
	"testing"

	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	authlogger "github.com/pers0na2dev/single-auth/observability/logger"
)

func TestSecretEnvironmentPrecedenceAndRotation(t *testing.T) {
	t.Setenv("SINGLE_AUTH_SECRETS", "")
	t.Setenv("SINGLE_AUTH_SECRET", "single-auth-env-secret-0123456789abcdef")
	t.Setenv("AUTH_SECRET", "auth-env-secret-0123456789abcdef0123")

	auth := MustNew(Options{Secret: "explicit-secret-0123456789abcdef012345"})
	if auth.Options().Secret != "explicit-secret-0123456789abcdef012345" {
		t.Fatalf("explicit secret = %q", auth.Options().Secret)
	}
	auth = MustNew(Options{})
	if auth.Options().Secret != "single-auth-env-secret-0123456789abcdef" {
		t.Fatalf("SINGLE_AUTH_SECRET = %q", auth.Options().Secret)
	}

	t.Setenv("SINGLE_AUTH_SECRET", "")
	auth = MustNew(Options{})
	if auth.Options().Secret != "auth-env-secret-0123456789abcdef0123" {
		t.Fatalf("AUTH_SECRET = %q", auth.Options().Secret)
	}

	t.Setenv("SINGLE_AUTH_SECRETS", "2: current-secret-0123456789abcdef012345, 1: old-secret-0123456789abcdef01234567")
	auth = MustNew(Options{})
	if auth.Options().Secret != "current-secret-0123456789abcdef012345" ||
		auth.options.secretConfig.CurrentVersion != 2 || len(auth.options.secretConfig.Keys) != 2 {
		t.Fatalf("environment rotation options=%#v config=%#v", auth.Options(), auth.options.secretConfig)
	}
	if len(auth.Options().Secrets) != 0 {
		t.Fatalf("environment secrets leaked into public options: %#v", auth.Options().Secrets)
	}
}

func TestSecretValidationAndDiagnostics(t *testing.T) {
	t.Setenv("SINGLE_AUTH_SECRETS", "")
	t.Setenv("SINGLE_AUTH_SECRET", "")
	t.Setenv("AUTH_SECRET", "")
	if _, err := New(Options{Environment: "production"}); err == nil ||
		!strings.Contains(err.Error(), "You are using the default secret") {
		t.Fatalf("production default secret error = %v", err)
	}

	var messages []string
	_, err := New(Options{
		Environment: "development", Secret: "short",
		Logger: authlogger.Options{Log: func(level authlogger.Level, message string, _ ...any) {
			if level == authlogger.Warn {
				messages = append(messages, message)
			}
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || !strings.Contains(messages[0], "at least 32") ||
		!strings.Contains(messages[1], "low-entropy") {
		t.Fatalf("secret warnings = %#v", messages)
	}

	messages = nil
	_, err = New(Options{
		Environment: "development",
		Secrets:     []baCrypto.SecretEntry{{Version: 7, Value: "short"}},
		Logger: authlogger.Options{Log: func(level authlogger.Level, message string, _ ...any) {
			if level == authlogger.Warn {
				messages = append(messages, message)
			}
		}},
	})
	if err != nil || len(messages) != 2 || !strings.Contains(messages[0], "version 7") {
		t.Fatalf("rotation warnings=%#v err=%v", messages, err)
	}
}

func TestInvalidEnvironmentSecretListFailsInitialization(t *testing.T) {
	t.Setenv("SINGLE_AUTH_SECRETS", "invalid")
	if _, err := New(Options{}); err == nil || !strings.Contains(err.Error(), "Expected format") {
		t.Fatalf("invalid SINGLE_AUTH_SECRETS error = %v", err)
	}
}
