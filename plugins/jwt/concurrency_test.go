package jwt

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestConcurrentSigningAndVerificationIsRaceSafe(t *testing.T) {
	clock := &testClock{now: time.Now()}
	store := &keyStore{}
	options := baseTestOptions(store, clock)
	options.Token.Issuer = String("http://localhost:3000")
	options.Token.Audience = "http://localhost:3000"
	implementation, err := normalize(options, false)
	if err != nil {
		t.Fatal(err)
	}
	// Seed one key before the concurrent phase; upstream permits duplicate first
	// keys under a true cold-start race, which is not the property under test.
	if _, err := implementation.signJWT(nil, map[string]any{"sub": "seed"}); err != nil {
		t.Fatal(err)
	}
	const workers = 24
	var wait sync.WaitGroup
	errorsChannel := make(chan error, workers)
	for index := 0; index < workers; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			subject := fmt.Sprintf("user-%d", index)
			token, signErr := implementation.signJWT(nil, map[string]any{"sub": subject})
			if signErr != nil {
				errorsChannel <- signErr
				return
			}
			payload := implementation.verifyJWT(nil, token)
			if payload == nil || payload["sub"] != subject {
				errorsChannel <- fmt.Errorf("payload = %#v, want subject %s", payload, subject)
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}
