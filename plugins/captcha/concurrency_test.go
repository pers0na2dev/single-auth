package captcha

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCaptchaDescriptorIsConcurrentAndDoesNotAliasOptions(t *testing.T) {
	endpoints := []string{"/sign-in/email"}
	hostnames := []string{"allowed.test"}
	minScore := 0.5
	var providerCalls atomic.Int64
	dispatcher := testDispatcher(t, Options{
		Provider: CloudflareTurnstile, SecretKey: "secret",
		Endpoints: endpoints, AllowedHostnames: hostnames, MinScore: &minScore,
		Runtime: Runtime{HTTPClient: doerFunc(func(*http.Request) (*http.Response, error) {
			providerCalls.Add(1)
			return jsonProviderResponse(http.StatusOK, `{"success":true,"hostname":"allowed.test"}`), nil
		})},
	})

	const requestCount = 128
	errorsSeen := make(chan string, requestCount)
	start := make(chan struct{})
	var requests sync.WaitGroup
	requests.Add(requestCount)
	for index := 0; index < requestCount; index++ {
		go func() {
			defer requests.Done()
			<-start
			response := dispatchCaptcha(
				t, dispatcher, context.Background(), http.MethodPost,
				"/api/auth/sign-in/email", captchaHeaders("token"),
			)
			if response.Status() != http.StatusNoContent {
				errorsSeen <- string(response.Body())
			}
		}()
	}

	var mutate sync.WaitGroup
	mutate.Add(1)
	go func() {
		defer mutate.Done()
		<-start
		for index := 0; index < 10_000; index++ {
			endpoints[0] = "/mutated"
			hostnames[0] = "mutated.test"
			minScore = float64(index)
		}
	}()
	close(start)
	requests.Wait()
	mutate.Wait()
	close(errorsSeen)
	for failure := range errorsSeen {
		t.Fatalf("concurrent request failed: %s", failure)
	}
	if calls := providerCalls.Load(); calls != requestCount {
		t.Fatalf("provider calls = %d, want %d", calls, requestCount)
	}
}
