package passkey

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/protocol/webauthn"
)

func TestCeremonyTaggedChallengesCannotCrossFlows(t *testing.T) {
	t.Run("authentication challenge rejected by registration", func(t *testing.T) {
		harness := newHarness(t, nil)
		harness.seedUser(t, "user-a", "a@example.com")
		headers := contract.NewHeaders(
			contract.HeaderField{Name: "X-Test-User", Value: "user-a"},
			contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"},
		)
		generated, err := harness.call(t, "GET", "/passkey/generate-authenticate-options", nil, headers, nil)
		if err != nil {
			t.Fatal(err)
		}
		applyResponseCookies(&headers, generated)
		_, err = harness.call(t, "POST", "/passkey/verify-registration", nil, headers, map[string]any{
			"response": registrationResponse("credential-cross-flow"),
		})
		assertAPIError(t, err, contract.StatusBadRequest, ErrorChallengeNotFound)
		if harness.registrationCalls.Load() != 0 {
			t.Fatalf("registration verifier called for authentication challenge")
		}
	})

	t.Run("registration challenge rejected by authentication", func(t *testing.T) {
		harness := newHarness(t, nil)
		harness.seedUser(t, "user-a", "a@example.com")
		harness.seedPasskey(t, "user-a", "credential-a", "Laptop")
		headers := contract.NewHeaders(
			contract.HeaderField{Name: "X-Test-User", Value: "user-a"},
			contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"},
		)
		generated, err := harness.call(t, "GET", "/passkey/generate-register-options", nil, headers, nil)
		if err != nil {
			t.Fatal(err)
		}
		applyResponseCookies(&headers, generated)
		_, err = harness.call(t, "POST", "/passkey/verify-authentication", nil, headers, map[string]any{
			"response": authenticationResponse("credential-a"),
		})
		assertAPIError(t, err, contract.StatusBadRequest, ErrorChallengeNotFound)
		if harness.authenticationCalls.Load() != 0 {
			t.Fatalf("authentication verifier called for registration challenge")
		}
	})
}

func TestLegacyUntaggedChallengeSurvivesUpgrade(t *testing.T) {
	harness := newHarness(t, nil)
	harness.seedUser(t, "user-a", "a@example.com")
	harness.seedPasskey(t, "user-a", "credential-a", "Laptop")
	harness.authenticationVerifier = func(webauthn.VerifyAuthenticationOptions) (webauthn.VerifiedAuthenticationResponse, error) {
		return webauthn.VerifiedAuthenticationResponse{
			Verified: true, AuthenticationInfo: webauthn.AuthenticationInfo{NewCounter: 1},
		}, nil
	}
	headers := contract.NewHeaders(contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"})
	generated, err := harness.call(t, "GET", "/passkey/generate-authenticate-options", nil, contract.Headers{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	applyResponseCookies(&headers, generated)
	rows, err := harness.adapter.FindMany(t.Context(), storage.FindManyParams{Model: "verification"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("verification rows = %#v, err=%v", rows, err)
	}
	raw, _ := recordString(rows[0], "value")
	var challenge storedChallenge
	if err := json.Unmarshal([]byte(raw), &challenge); err != nil {
		t.Fatal(err)
	}
	challenge.Type = ""
	legacy, err := json.Marshal(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.adapter.Update(t.Context(), storage.UpdateParams{
		Model: "verification", Where: []storage.Where{{Field: "id", Value: rows[0]["id"]}},
		Update: storage.Record{"value": string(legacy)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.call(t, "POST", "/passkey/verify-authentication", nil, headers, map[string]any{
		"response": authenticationResponse("credential-a"),
	}); err != nil {
		t.Fatalf("legacy challenge rejected: %v", err)
	}
}

func TestExpiredChallengeIsConsumedAndRejected(t *testing.T) {
	harness := newHarness(t, nil)
	harness.seedUser(t, "user-a", "a@example.com")
	harness.seedPasskey(t, "user-a", "credential-a", "Laptop")
	headers := contract.NewHeaders(contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"})
	generated, err := harness.call(t, "GET", "/passkey/generate-authenticate-options", nil, contract.Headers{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	applyResponseCookies(&headers, generated)
	harness.clock.Set(harness.clock.Now().Add(defaultChallengeAge + time.Nanosecond))
	for attempt := 0; attempt < 2; attempt++ {
		_, err = harness.call(t, "POST", "/passkey/verify-authentication", nil, headers, map[string]any{
			"response": authenticationResponse("credential-a"),
		})
		assertAPIError(t, err, contract.StatusBadRequest, ErrorChallengeNotFound)
	}
	if harness.authenticationCalls.Load() != 0 {
		t.Fatalf("expired challenge reached verifier")
	}
}

func TestAuthenticationRejectsAChallengeThatCannotBeAtomicallyConsumed(t *testing.T) {
	harness := newHarness(t, func(options *Options, _ *testHarness) {
		options.Runtime.ConsumeChallenge = func(context.Context, string) (storage.Record, error) {
			return nil, nil
		}
	})
	harness.seedUser(t, "user-a", "a@example.com")
	harness.seedPasskey(t, "user-a", "credential-a", "Laptop")
	headers := contract.NewHeaders(contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"})
	generated, err := harness.call(t, "GET", "/passkey/generate-authenticate-options", nil, contract.Headers{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	applyResponseCookies(&headers, generated)
	_, err = harness.call(t, "POST", "/passkey/verify-authentication", nil, headers, map[string]any{
		"response": authenticationResponse("credential-a"),
	})
	assertAPIError(t, err, contract.StatusBadRequest, ErrorChallengeNotFound)
	if harness.authenticationCalls.Load() != 0 || harness.issuedSessions.Load() != 0 {
		t.Fatalf("unconsumed challenge reached verifier/session: verifier=%d sessions=%d", harness.authenticationCalls.Load(), harness.issuedSessions.Load())
	}
}

func TestConcurrentRegistrationConsumesChallengeOnce(t *testing.T) {
	harness := newHarness(t, nil)
	harness.seedUser(t, "user-a", "a@example.com")
	harness.registrationVerifier = func(webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error) {
		return successfulRegistration("credential-race"), nil
	}
	headers := contract.NewHeaders(
		contract.HeaderField{Name: "X-Test-User", Value: "user-a"},
		contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"},
	)
	generated, err := harness.call(t, "GET", "/passkey/generate-register-options", nil, headers, nil)
	if err != nil {
		t.Fatal(err)
	}
	applyResponseCookies(&headers, generated)

	const requests = 16
	errorsByRequest := make([]error, requests)
	var group sync.WaitGroup
	group.Add(requests)
	for index := range requests {
		go func() {
			defer group.Done()
			_, errorsByRequest[index] = harness.call(t, "POST", "/passkey/verify-registration", nil, headers.Clone(), map[string]any{
				"response": registrationResponse("credential-race"),
			})
		}()
	}
	group.Wait()
	successes := 0
	for _, callErr := range errorsByRequest {
		if callErr == nil {
			successes++
			continue
		}
		apiError, ok := contract.AsAPIError(callErr)
		if !ok || apiError.Code != ErrorChallengeNotFound {
			t.Fatalf("concurrent error = %T %v", callErr, callErr)
		}
	}
	rows, findErr := harness.adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "passkey", Where: []storage.Where{{Field: "credentialID", Value: "credential-race"}},
	})
	if findErr != nil {
		t.Fatal(findErr)
	}
	if successes != 1 || harness.registrationCalls.Load() != 1 || len(rows) != 1 {
		t.Fatalf("successes=%d verifier=%d rows=%d", successes, harness.registrationCalls.Load(), len(rows))
	}
}
