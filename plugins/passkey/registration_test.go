package passkey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/protocol/webauthn"
)

func successfulRegistration(id string) webauthn.VerifiedRegistrationResponse {
	return webauthn.VerifiedRegistrationResponse{
		Verified: true,
		RegistrationInfo: &webauthn.RegistrationInfo{
			AAGUID:               "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",
			CredentialDeviceType: webauthn.SingleDevice,
			CredentialBackedUp:   false,
			Credential: webauthn.Credential{
				ID: id, PublicKey: []byte{1, 2, 3}, Counter: 7,
			},
		},
	}
}

func registrationResponse(id string) webauthn.RegistrationResponseJSON {
	return webauthn.RegistrationResponseJSON{
		ID: id, RawID: id, Type: webauthn.PublicKeyCredentialType,
		Response: webauthn.AttestationResponseJSON{Transports: []string{"internal", "hybrid"}},
	}
}

func TestRegistrationLifecycleMatchesUpstream(t *testing.T) {
	var hookContext *string
	var hookUser RegistrationUser
	harness := newHarness(t, func(options *Options, _ *testHarness) {
		options.Registration.AfterVerification = func(args AfterRegistrationVerificationArgs) (AfterRegistrationVerificationResult, error) {
			hookContext = args.FlowContext
			hookUser = args.User
			return AfterRegistrationVerificationResult{Name: "Provider label"}, nil
		}
	})
	harness.seedUser(t, "user-a", "a@example.com")
	harness.registrationVerifier = func(options webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error) {
		if options.ExpectedChallenge == "" || len(options.ExpectedOrigins) != 1 || options.ExpectedOrigins[0] != "http://localhost:3000" {
			t.Fatalf("verification options = %#v", options)
		}
		if len(options.ExpectedRPIDs) != 1 || options.ExpectedRPIDs[0] != "localhost" ||
			options.RequireUserVerification == nil || *options.RequireUserVerification {
			t.Fatalf("verification options = %#v", options)
		}
		return successfulRegistration("credential-a"), nil
	}
	headers := contract.NewHeaders(
		contract.HeaderField{Name: "X-Test-User", Value: "user-a"},
		contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"},
	)
	generated, err := harness.call(t, "GET", "/passkey/generate-register-options", url.Values{
		"context": {"link-token"},
	}, headers, nil)
	if err != nil {
		t.Fatal(err)
	}
	applyResponseCookies(&headers, generated)

	response, err := harness.call(t, "POST", "/passkey/verify-registration", nil, headers, map[string]any{
		"response": registrationResponse("credential-a"), "name": "   ",
	})
	if err != nil {
		t.Fatal(err)
	}
	record := decodeResponse[storage.Record](t, response)
	if record["userId"] != "user-a" || record["credentialID"] != "credential-a" || record["name"] != "Provider label" {
		t.Fatalf("created passkey = %#v", record)
	}
	if record["publicKey"] != base64.StdEncoding.EncodeToString([]byte{1, 2, 3}) ||
		record["transports"] != "internal,hybrid" || record["aaguid"] == "" {
		t.Fatalf("created passkey protocol fields = %#v", record)
	}
	if hookContext == nil || *hookContext != "link-token" || hookUser.ID != "user-a" || hookUser.Name != "a@example.com" {
		t.Fatalf("hook context=%#v user=%#v", hookContext, hookUser)
	}

	_, err = harness.call(t, "POST", "/passkey/verify-registration", nil, headers, map[string]any{
		"response": registrationResponse("credential-a"),
	})
	assertAPIError(t, err, contract.StatusBadRequest, ErrorChallengeNotFound)
	if harness.registrationCalls.Load() != 1 {
		t.Fatalf("registration verifier calls = %d", harness.registrationCalls.Load())
	}
}

func TestRegistrationNamePrecedenceAndNoAAGUIDInference(t *testing.T) {
	tests := []struct {
		name       string
		clientName *string
		hookName   string
		wantName   string
	}{
		{name: "client trimmed", clientName: stringPointer("  Work key  "), hookName: "Provider", wantName: "Work key"},
		{name: "hook fallback", hookName: "  Provider  ", wantName: "Provider"},
		{name: "whitespace falls back", clientName: stringPointer("   "), hookName: "Provider", wantName: "Provider"},
		{name: "unlabelled remains unlabelled", clientName: stringPointer("   ")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newHarness(t, func(options *Options, _ *testHarness) {
				if test.hookName != "" {
					options.Registration.AfterVerification = func(AfterRegistrationVerificationArgs) (AfterRegistrationVerificationResult, error) {
						return AfterRegistrationVerificationResult{Name: test.hookName}, nil
					}
				}
			})
			harness.seedUser(t, "user-a", "a@example.com")
			harness.registrationVerifier = func(webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error) {
				return successfulRegistration("credential-name"), nil
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
			body := map[string]any{"response": registrationResponse("credential-name")}
			if test.clientName != nil {
				body["name"] = *test.clientName
			}
			response, err := harness.call(t, "POST", "/passkey/verify-registration", nil, headers, body)
			if err != nil {
				t.Fatal(err)
			}
			record := decodeResponse[storage.Record](t, response)
			name, exists := record["name"]
			if test.wantName == "" {
				if exists && name != nil {
					t.Fatalf("unexpected AAGUID-derived label: %#v", record)
				}
			} else if name != test.wantName {
				t.Fatalf("name = %#v, want %q", name, test.wantName)
			}
		})
	}
}

func TestPasskeyFirstRegistrationCanResolveAndReassignUser(t *testing.T) {
	var resolvedContext *string
	harness := newHarness(t, func(options *Options, _ *testHarness) {
		options.Registration.RequireSession = Bool(false)
		options.Registration.ResolveUser = func(args ResolveRegistrationUserArgs) (RegistrationUser, error) {
			resolvedContext = args.Context
			return RegistrationUser{ID: "provisional", Name: "preauth@example.com", DisplayName: "Preauth"}, nil
		}
		options.Registration.AfterVerification = func(args AfterRegistrationVerificationArgs) (AfterRegistrationVerificationResult, error) {
			return AfterRegistrationVerificationResult{UserID: "linked-user"}, nil
		}
	})
	harness.seedUser(t, "linked-user", "linked@example.com")
	harness.registrationVerifier = func(webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error) {
		return successfulRegistration("credential-linked"), nil
	}
	headers := contract.NewHeaders(contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"})
	generated, err := harness.call(t, "GET", "/passkey/generate-register-options", url.Values{
		"context": {"signup-state"},
	}, headers, nil)
	if err != nil {
		t.Fatal(err)
	}
	applyResponseCookies(&headers, generated)
	response, err := harness.call(t, "POST", "/passkey/verify-registration", nil, headers, map[string]any{
		"response": registrationResponse("credential-linked"),
	})
	if err != nil {
		t.Fatal(err)
	}
	record := decodeResponse[storage.Record](t, response)
	if record["userId"] != "linked-user" || resolvedContext == nil || *resolvedContext != "signup-state" {
		t.Fatalf("record=%#v context=%#v", record, resolvedContext)
	}
}

func TestRegistrationSessionAndIdentityGates(t *testing.T) {
	t.Run("session required", func(t *testing.T) {
		harness := newHarness(t, nil)
		_, err := harness.call(t, "GET", "/passkey/generate-register-options", nil, contract.Headers{}, nil)
		assertAPIError(t, err, contract.StatusUnauthorized, ErrorSessionRequired)
	})

	t.Run("fresh session", func(t *testing.T) {
		harness := newHarness(t, nil)
		harness.seedUser(t, "user-a", "a@example.com")
		headers := contract.NewHeaders(
			contract.HeaderField{Name: "X-Test-User", Value: "user-a"},
			contract.HeaderField{Name: "X-Test-Stale", Value: "true"},
		)
		_, err := harness.call(t, "GET", "/passkey/generate-register-options", nil, headers, nil)
		assertAPIError(t, err, contract.StatusForbidden, "SESSION_NOT_FRESH")
	})

	t.Run("resolve user required", func(t *testing.T) {
		harness := newHarness(t, func(options *Options, _ *testHarness) {
			options.Registration.RequireSession = Bool(false)
		})
		_, err := harness.call(t, "GET", "/passkey/generate-register-options", nil, contract.Headers{}, nil)
		assertAPIError(t, err, contract.StatusBadRequest, ErrorResolveUserRequired)
	})

	t.Run("invalid resolved user", func(t *testing.T) {
		harness := newHarness(t, func(options *Options, _ *testHarness) {
			options.Registration.RequireSession = Bool(false)
			options.Registration.ResolveUser = func(ResolveRegistrationUserArgs) (RegistrationUser, error) {
				return RegistrationUser{ID: "user-a"}, nil
			}
		})
		_, err := harness.call(t, "GET", "/passkey/generate-register-options", nil, contract.Headers{}, nil)
		assertAPIError(t, err, contract.StatusBadRequest, ErrorResolvedUserInvalid)
	})
}

func TestRegistrationRejectsSessionIdentityOverride(t *testing.T) {
	harness := newHarness(t, func(options *Options, _ *testHarness) {
		options.Registration.AfterVerification = func(AfterRegistrationVerificationArgs) (AfterRegistrationVerificationResult, error) {
			return AfterRegistrationVerificationResult{UserID: "other-user"}, nil
		}
	})
	harness.seedUser(t, "user-a", "a@example.com")
	harness.seedUser(t, "other-user", "other@example.com")
	harness.registrationVerifier = func(webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error) {
		return successfulRegistration("credential-reassigned"), nil
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
	_, err = harness.call(t, "POST", "/passkey/verify-registration", nil, headers, map[string]any{
		"response": registrationResponse("credential-reassigned"),
	})
	assertAPIError(t, err, contract.StatusUnauthorized, ErrorRegistrationNotAllowed)
	rows, findErr := harness.adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "passkey", Where: []storage.Where{{Field: "credentialID", Value: "credential-reassigned"}},
	})
	if findErr != nil || len(rows) != 0 {
		t.Fatalf("persisted rows = %#v, err=%v", rows, findErr)
	}
}

func TestRegistrationFailuresPreserveUpstreamStatus(t *testing.T) {
	tests := []struct {
		name       string
		verify     RegistrationVerifier
		wantStatus int
		wantCode   string
	}{
		{
			name: "verified false",
			verify: func(webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error) {
				return webauthn.VerifiedRegistrationResponse{Verified: false}, nil
			},
			wantStatus: contract.StatusBadRequest, wantCode: ErrorFailedToVerifyRegistration,
		},
		{
			name: "protocol error",
			verify: func(webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error) {
				return webauthn.VerifiedRegistrationResponse{}, errors.New("bad attestation")
			},
			wantStatus: contract.StatusInternalServerError, wantCode: ErrorFailedToVerifyRegistration,
		},
		{
			name: "typed error",
			verify: func(webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error) {
				return webauthn.VerifiedRegistrationResponse{}, contract.NewAPIError(contract.StatusForbidden, "ATTESTATION_DENIED", "denied")
			},
			wantStatus: contract.StatusForbidden, wantCode: "ATTESTATION_DENIED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newHarness(t, nil)
			harness.seedUser(t, "user-a", "a@example.com")
			harness.registrationVerifier = test.verify
			headers := contract.NewHeaders(
				contract.HeaderField{Name: "X-Test-User", Value: "user-a"},
				contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"},
			)
			generated, err := harness.call(t, "GET", "/passkey/generate-register-options", nil, headers, nil)
			if err != nil {
				t.Fatal(err)
			}
			applyResponseCookies(&headers, generated)
			_, err = harness.call(t, "POST", "/passkey/verify-registration", nil, headers, map[string]any{
				"response": registrationResponse("credential-failure"),
			})
			assertAPIError(t, err, test.wantStatus, test.wantCode)
		})
	}
}

func TestMissingRegistrationOriginDoesNotConsumeChallenge(t *testing.T) {
	harness := newHarness(t, nil)
	harness.seedUser(t, "user-a", "a@example.com")
	harness.registrationVerifier = func(webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error) {
		return webauthn.VerifiedRegistrationResponse{Verified: false}, nil
	}
	headers := contract.NewHeaders(contract.HeaderField{Name: "X-Test-User", Value: "user-a"})
	generated, err := harness.call(t, "GET", "/passkey/generate-register-options", nil, headers, nil)
	if err != nil {
		t.Fatal(err)
	}
	applyResponseCookies(&headers, generated)
	_, err = harness.call(t, "POST", "/passkey/verify-registration", nil, headers, map[string]any{
		"response": registrationResponse("credential-a"),
	})
	assertAPIError(t, err, contract.StatusBadRequest, ErrorFailedToVerifyRegistration)
	if harness.registrationCalls.Load() != 0 {
		t.Fatalf("registration verifier called without origin")
	}
	headers.Set("Origin", "http://localhost:3000")
	_, err = harness.call(t, "POST", "/passkey/verify-registration", nil, headers, map[string]any{
		"response": registrationResponse("credential-a"),
	})
	assertAPIError(t, err, contract.StatusBadRequest, ErrorFailedToVerifyRegistration)
	if harness.registrationCalls.Load() != 1 {
		t.Fatalf("challenge was consumed by origin failure")
	}
}

func TestRegistrationRejectsEmptyStoredTargetUser(t *testing.T) {
	harness := newHarness(t, func(options *Options, _ *testHarness) {
		options.Registration.RequireSession = Bool(false)
		options.Registration.ResolveUser = func(ResolveRegistrationUserArgs) (RegistrationUser, error) {
			return RegistrationUser{ID: "provisional", Name: "preauth@example.com"}, nil
		}
	})
	harness.registrationVerifier = func(webauthn.VerifyRegistrationOptions) (webauthn.VerifiedRegistrationResponse, error) {
		return successfulRegistration("credential-empty-user"), nil
	}
	headers := contract.NewHeaders(contract.HeaderField{Name: "Origin", Value: "http://localhost:3000"})
	generated, err := harness.call(t, "GET", "/passkey/generate-register-options", nil, headers, nil)
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
	challenge.UserData.ID = ""
	encoded, err := json.Marshal(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.adapter.Update(t.Context(), storage.UpdateParams{
		Model: "verification", Where: []storage.Where{{Field: "id", Value: rows[0]["id"]}},
		Update: storage.Record{"value": string(encoded)},
	}); err != nil {
		t.Fatal(err)
	}
	_, err = harness.call(t, "POST", "/passkey/verify-registration", nil, headers, map[string]any{
		"response": registrationResponse("credential-empty-user"),
	})
	assertAPIError(t, err, contract.StatusBadRequest, ErrorResolvedUserInvalid)
	created, findErr := harness.adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "passkey", Where: []storage.Where{{Field: "credentialID", Value: "credential-empty-user"}},
	})
	if findErr != nil || len(created) != 0 {
		t.Fatalf("passkeys = %#v, err=%v", created, findErr)
	}
}

func stringPointer(value string) *string { return &value }
