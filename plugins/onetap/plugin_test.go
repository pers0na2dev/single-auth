package onetap

import (
	"context"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestDescriptorMatchesFrozenPluginContract(t *testing.T) {
	provider := googleProvider(t, providers.Options{})
	descriptor, err := New(Options{Runtime: Runtime{
		SocialProvider: func(id string) *providers.Provider {
			if id == "google" {
				return provider
			}
			return nil
		},
		HandleOAuthUser: func(*engine.Context, singleauth.PluginOAuthUserInput) (singleauth.PluginOAuthUserResult, error) {
			return singleauth.PluginOAuthUserResult{}, nil
		},
		RefreshSession: func(*engine.Context, singleauth.PluginSessionState, bool) error { return nil },
		SerializeUser:  func(record map[string]any) any { return record },
	}})
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.ID != "one-tap" || descriptor.Version != Version || len(descriptor.Endpoints) != 1 {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	endpoint := descriptor.Endpoints[0]
	if endpoint.Name != "oneTapCallback" || endpoint.OperationID != "oneTapCallback" ||
		endpoint.Path != "/one-tap/callback" || len(endpoint.Methods) != 1 || endpoint.Methods[0] != "POST" {
		t.Fatalf("endpoint = %#v", endpoint)
	}
	if len(descriptor.Schema.Models) != 0 || descriptor.Schema.UsePlural || len(descriptor.Middleware) != 0 ||
		len(descriptor.Hooks.Before) != 0 || len(descriptor.Hooks.After) != 0 ||
		len(descriptor.RateLimit) != 0 || len(descriptor.ErrorCodes) != 0 {
		t.Fatalf("unexpected descriptor extensions: %#v", descriptor)
	}
}

func TestStandaloneRuntimeRequirements(t *testing.T) {
	tests := []struct {
		name    string
		runtime Runtime
		missing string
	}{
		{name: "social provider", missing: "Runtime.SocialProvider"},
		{name: "OAuth user handler", runtime: Runtime{SocialProvider: func(string) *providers.Provider { return nil }}, missing: "Runtime.HandleOAuthUser"},
		{name: "session refresh", runtime: Runtime{
			SocialProvider: func(string) *providers.Provider { return nil },
			HandleOAuthUser: func(*engine.Context, singleauth.PluginOAuthUserInput) (singleauth.PluginOAuthUserResult, error) {
				return singleauth.PluginOAuthUserResult{}, nil
			},
		}, missing: "Runtime.RefreshSession"},
		{name: "user serializer", runtime: Runtime{
			SocialProvider: func(string) *providers.Provider { return nil },
			HandleOAuthUser: func(*engine.Context, singleauth.PluginOAuthUserInput) (singleauth.PluginOAuthUserResult, error) {
				return singleauth.PluginOAuthUserResult{}, nil
			},
			RefreshSession: func(*engine.Context, singleauth.PluginSessionState, bool) error { return nil },
		}, missing: "Runtime.SerializeUser"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(Options{Runtime: test.runtime})
			if err == nil || !strings.Contains(err.Error(), test.missing) {
				t.Fatalf("error = %v, want %q", err, test.missing)
			}
		})
	}
	if got := NewFactory(Options{}).PluginID(); got != "one-tap" {
		t.Fatalf("factory ID = %q", got)
	}
}

func TestMalformedTokensAndMissingEmailFailExactly(t *testing.T) {
	t.Run("missing idToken", func(t *testing.T) {
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: claimsVerifier(defaultClaims(), nil),
		}, singleauth.AccountLinkingOptions{})
		response, _ := callOneTap(t, auth, map[string]any{})
		if response.Code != 400 || !strings.Contains(response.Body.String(), "idToken is required") {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("verification failure", func(t *testing.T) {
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: func(context.Context, VerifyIDTokenInput) (map[string]any, error) {
				return nil, context.Canceled
			},
		}, singleauth.AccountLinkingOptions{})
		response, _ := callOneTap(t, auth, map[string]any{"idToken": "bad"})
		if response.Code != 400 || !strings.Contains(response.Body.String(), invalidIDTokenError) {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("missing sub", func(t *testing.T) {
		claims := defaultClaims()
		delete(claims, "sub")
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: claimsVerifier(claims, nil),
		}, singleauth.AccountLinkingOptions{})
		response, _ := callOneTap(t, auth, map[string]any{"idToken": "bad"})
		if response.Code != 400 || !strings.Contains(response.Body.String(), invalidIDTokenError) {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("missing email is a successful error payload", func(t *testing.T) {
		claims := defaultClaims()
		delete(claims, "email")
		auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
			VerifyIDToken: claimsVerifier(claims, nil),
		}, singleauth.AccountLinkingOptions{})
		response, body := callOneTap(t, auth, map[string]any{"idToken": "valid"})
		if response.Code != 200 || body["error"] != missingEmailError {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
	})
}

func TestEmailAndBooleanCoercionMatchesUpstream(t *testing.T) {
	claims := defaultClaims()
	claims["email"] = "MIXED@EXAMPLE.COM"
	claims["email_verified"] = "true"
	auth := newTestAuth(t, googleProvider(t, providers.Options{}), Options{
		VerifyIDToken: claimsVerifier(claims, nil),
	}, singleauth.AccountLinkingOptions{})
	response, body := callOneTap(t, auth, map[string]any{"idToken": "valid"})
	assertSuccessfulUser(t, response, body, "")
	users := findRecords(t, auth, "user", []storage.Where{{Field: "email", Value: "mixed@example.com"}})
	if len(users) != 1 || users[0]["emailVerified"] != true {
		t.Fatalf("stored users = %#v", users)
	}
}
