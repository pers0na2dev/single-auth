package passkey

import (
	"errors"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/protocol/webauthn"
)

func authenticationResponse(id string) webauthn.AuthenticationResponseJSON {
	return webauthn.AuthenticationResponseJSON{
		ID: id, RawID: id, Type: webauthn.PublicKeyCredentialType,
		Response: webauthn.AssertionResponseJSON{
			ClientDataJSON: "client-data", AuthenticatorData: "authenticator-data", Signature: "signature",
		},
		ClientExtensionResults: map[string]any{},
	}
}

func TestAuthenticationLifecycleMatchesUpstream(t *testing.T) {
	var hookCalled bool
	harness := newHarness(t, func(options *Options, _ *testHarness) {
		options.Authentication.AfterVerification = func(args AfterAuthenticationVerificationArgs) error {
			hookCalled = true
			if args.ClientData.ID != "credential-a" || !args.Verification.Verified {
				t.Fatalf("authentication hook args = %#v", args)
			}
			return nil
		}
	})
	harness.seedUser(t, "user-a", "a@example.com")
	passkey := harness.seedPasskey(t, "user-a", "credential-a", "Laptop")
	harness.authenticationVerifier = func(options webauthn.VerifyAuthenticationOptions) (webauthn.VerifiedAuthenticationResponse, error) {
		if options.ExpectedChallenge == "" || len(options.ExpectedOrigins) != 1 || options.ExpectedOrigins[0] != "http://localhost:3000" {
			t.Fatalf("verification options = %#v", options)
		}
		if options.Credential.ID != "credential-a" || options.Credential.Counter != 0 ||
			len(options.Credential.PublicKey) != 3 || options.RequireUserVerification == nil || *options.RequireUserVerification {
			t.Fatalf("credential verification options = %#v", options)
		}
		return webauthn.VerifiedAuthenticationResponse{
			Verified: true, AuthenticationInfo: webauthn.AuthenticationInfo{NewCounter: 42},
		}, nil
	}
	headers := contract.NewHeaders(contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"})
	generated, err := harness.call(t, "GET", "/passkey/generate-authenticate-options", nil, contract.Headers{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	applyResponseCookies(&headers, generated)
	response, err := harness.call(t, "POST", "/passkey/verify-authentication", nil, headers, map[string]any{
		"response": authenticationResponse("credential-a"),
	})
	if err != nil {
		t.Fatal(err)
	}
	result := decodeResponse[map[string]storage.Record](t, response)
	if result["user"]["id"] != "user-a" || result["session"]["userId"] != "user-a" || !hookCalled {
		t.Fatalf("authentication result = %#v hook=%v", result, hookCalled)
	}
	if len(response.Headers().Values("Set-Cookie")) != 1 {
		t.Fatalf("session Set-Cookie = %#v", response.Headers().Values("Set-Cookie"))
	}
	stored, findErr := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "passkey", Where: []storage.Where{{Field: "id", Value: passkey["id"]}},
	})
	if findErr != nil {
		t.Fatal(findErr)
	}
	if counter, ok := recordUint32(stored, "counter"); !ok || counter != 42 {
		t.Fatalf("updated passkey = %#v", stored)
	}
	if harness.authenticationCalls.Load() != 1 || harness.issuedSessions.Load() != 1 {
		t.Fatalf("verifier=%d sessions=%d", harness.authenticationCalls.Load(), harness.issuedSessions.Load())
	}
}

func TestAuthenticationFailuresPreserveUpstreamStatus(t *testing.T) {
	tests := []struct {
		name       string
		credential string
		verify     AuthenticationVerifier
		wantStatus int
		wantCode   string
	}{
		{
			name: "credential not found", credential: "missing",
			wantStatus: contract.StatusUnauthorized, wantCode: ErrorPasskeyNotFound,
		},
		{
			name: "verified false", credential: "credential-a",
			verify: func(webauthn.VerifyAuthenticationOptions) (webauthn.VerifiedAuthenticationResponse, error) {
				return webauthn.VerifiedAuthenticationResponse{Verified: false}, nil
			},
			wantStatus: contract.StatusUnauthorized, wantCode: ErrorAuthenticationFailed,
		},
		{
			name: "protocol error", credential: "credential-a",
			verify: func(webauthn.VerifyAuthenticationOptions) (webauthn.VerifiedAuthenticationResponse, error) {
				return webauthn.VerifiedAuthenticationResponse{}, errors.New("bad assertion")
			},
			wantStatus: contract.StatusBadRequest, wantCode: ErrorAuthenticationFailed,
		},
		{
			name: "typed hook error", credential: "credential-a",
			verify: func(webauthn.VerifyAuthenticationOptions) (webauthn.VerifiedAuthenticationResponse, error) {
				return webauthn.VerifiedAuthenticationResponse{}, contract.NewAPIError(contract.StatusForbidden, "HOOK_DENIED", "denied")
			},
			wantStatus: contract.StatusForbidden, wantCode: "HOOK_DENIED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newHarness(t, nil)
			harness.seedUser(t, "user-a", "a@example.com")
			harness.seedPasskey(t, "user-a", "credential-a", "Laptop")
			if test.verify != nil {
				harness.authenticationVerifier = test.verify
			}
			headers := contract.NewHeaders(contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"})
			generated, err := harness.call(t, "GET", "/passkey/generate-authenticate-options", nil, contract.Headers{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			applyResponseCookies(&headers, generated)
			_, err = harness.call(t, "POST", "/passkey/verify-authentication", nil, headers, map[string]any{
				"response": authenticationResponse(test.credential),
			})
			assertAPIError(t, err, test.wantStatus, test.wantCode)
		})
	}
}

func TestMissingAuthenticationOriginDoesNotConsumeChallenge(t *testing.T) {
	harness := newHarness(t, nil)
	harness.seedUser(t, "user-a", "a@example.com")
	harness.seedPasskey(t, "user-a", "credential-a", "Laptop")
	harness.authenticationVerifier = func(webauthn.VerifyAuthenticationOptions) (webauthn.VerifiedAuthenticationResponse, error) {
		return webauthn.VerifiedAuthenticationResponse{Verified: false}, nil
	}
	headers := contract.Headers{}
	generated, err := harness.call(t, "GET", "/passkey/generate-authenticate-options", nil, headers, nil)
	if err != nil {
		t.Fatal(err)
	}
	applyResponseCookies(&headers, generated)
	_, err = harness.call(t, "POST", "/passkey/verify-authentication", nil, headers, map[string]any{
		"response": authenticationResponse("credential-a"),
	})
	assertAPIError(t, err, contract.StatusBadRequest, "BAD_REQUEST")
	if harness.authenticationCalls.Load() != 0 {
		t.Fatalf("verifier called without origin")
	}
	headers.Set("Origin", "http://localhost:3000")
	_, err = harness.call(t, "POST", "/passkey/verify-authentication", nil, headers, map[string]any{
		"response": authenticationResponse("credential-a"),
	})
	assertAPIError(t, err, contract.StatusUnauthorized, ErrorAuthenticationFailed)
	if harness.authenticationCalls.Load() != 1 {
		t.Fatalf("challenge was consumed by origin failure")
	}
}

func TestConcurrentAuthenticationConsumesChallengeOnce(t *testing.T) {
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

	const requests = 16
	errorsByRequest := make([]error, requests)
	var group sync.WaitGroup
	group.Add(requests)
	for index := range requests {
		go func() {
			defer group.Done()
			_, errorsByRequest[index] = harness.call(t, "POST", "/passkey/verify-authentication", nil, headers.Clone(), map[string]any{
				"response": authenticationResponse("credential-a"),
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
	if successes != 1 || harness.authenticationCalls.Load() != 1 || harness.issuedSessions.Load() != 1 {
		t.Fatalf("successes=%d verifier=%d sessions=%d", successes, harness.authenticationCalls.Load(), harness.issuedSessions.Load())
	}
}
