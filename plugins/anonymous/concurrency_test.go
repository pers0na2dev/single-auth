package anonymous

import (
	"crypto/rand"
	"net/http"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestConcurrentAnonymousSignInsAreIsolatedAndRaceSafe(t *testing.T) {
	harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
		options.Runtime.Random = rand.Reader
	})
	const requests = 64
	var wait sync.WaitGroup
	errors := make(chan error, requests)
	for index := 0; index < requests; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response, err := harness.call(t, http.MethodPost, "/sign-in/anonymous", contract.NewHeaders())
			if err != nil {
				errors <- err
				return
			}
			if response.Status() != http.StatusOK {
				errors <- &unexpectedStatusError{status: response.Status()}
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	users, err := harness.adapter.FindMany(t.Context(), storage.FindManyParams{Model: "user"})
	if err != nil || len(users) != requests {
		t.Fatalf("concurrent users=%d err=%v", len(users), err)
	}
	sessions, err := harness.adapter.FindMany(t.Context(), storage.FindManyParams{Model: "session"})
	if err != nil || len(sessions) != requests {
		t.Fatalf("concurrent sessions=%d err=%v", len(sessions), err)
	}
	emails := make(map[string]struct{}, requests)
	for _, user := range users {
		email, _ := recordString(user, "email")
		if _, duplicate := emails[email]; duplicate {
			t.Fatalf("duplicate concurrent email %q", email)
		}
		emails[email] = struct{}{}
	}
}

type unexpectedStatusError struct{ status int }

func (err *unexpectedStatusError) Error() string {
	return http.StatusText(err.status)
}
