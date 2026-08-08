package lastloginmethod

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
)

func TestConcurrentDirectSignInIsRequestLocal(t *testing.T) {
	const calls = 32
	var resolveCount atomic.Int64
	var consentCount atomic.Int64
	auth, err := singleauth.New(singleauth.Options{
		BaseURL:          "http://auth.example.test",
		Secret:           integrationSecret,
		EmailAndPassword: fastEmailPasswordOptions(),
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{
			CustomResolveMethod: func(ctx HookContext) (*string, error) {
				if ctx.Path == "/sign-up/email" {
					return Method(""), nil
				}
				if ctx.Path != "/sign-in/email" {
					return nil, fmt.Errorf("unexpected path %q", ctx.Path)
				}
				resolveCount.Add(1)
				return nil, nil
			},
			BeforeStoreCookie: func(ctx HookContext, method string) (bool, error) {
				if ctx.Path != "/sign-in/email" || method != "email" {
					return false, fmt.Errorf("unexpected callback values %q %q", ctx.Path, method)
				}
				consentCount.Add(1)
				return true, nil
			},
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "Race User", Email: "race@example.com", Password: "password123",
	}); err != nil {
		t.Fatal(err)
	}
	// Exclude the sign-up after hook from the sign-in counters.
	resolveCount.Store(0)
	consentCount.Store(0)

	var wait sync.WaitGroup
	errorsByCall := make(chan error, calls)
	wait.Add(calls)
	for index := 0; index < calls; index++ {
		go func() {
			defer wait.Done()
			result, callErr := auth.API().SignInEmail(t.Context(), singleauth.SignInEmailInput{
				Email: "race@example.com", Password: "password123",
			})
			if callErr != nil {
				errorsByCall <- callErr
				return
			}
			response := contract.NewResponse(contract.StatusOK, result.Headers, nil)
			cookie, exists := responseCookie(response, DefaultCookieName)
			if !exists || cookie.Attributes.Value != "email" {
				errorsByCall <- fmt.Errorf("method cookie = %#v", cookie)
			}
		}()
	}
	wait.Wait()
	close(errorsByCall)
	for callErr := range errorsByCall {
		t.Error(callErr)
	}
	if got := resolveCount.Load(); got != calls {
		t.Fatalf("resolver calls = %d, want %d", got, calls)
	}
	if got := consentCount.Load(); got != calls {
		t.Fatalf("consent calls = %d, want %d", got, calls)
	}
}
