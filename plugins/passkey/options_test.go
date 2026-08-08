package passkey

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/protocol/webauthn"
)

func TestGeneratedOptionsMatchExpectedValues(t *testing.T) {
	requireResidentKey := false
	expectedRegistration := webauthn.CreationOptionsJSON{
		Challenge: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
		RP:        webauthn.RelyingPartyEntity{ID: "localhost", Name: "Single Auth Test App"},
		User: webauthn.UserEntity{
			ID:          "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU",
			Name:        "Work",
			DisplayName: "passkey@example.com",
		},
		PubKeyCredParams: []webauthn.CredentialParameter{
			{Alg: -8, Type: webauthn.PublicKeyCredentialType},
			{Alg: -7, Type: webauthn.PublicKeyCredentialType},
			{Alg: -257, Type: webauthn.PublicKeyCredentialType},
		},
		Timeout:            60_000,
		Attestation:        "none",
		ExcludeCredentials: []webauthn.CredentialDescriptor{},
		AuthenticatorSelection: webauthn.AuthenticatorSelectionCriteria{
			AuthenticatorAttachment: "platform",
			ResidentKey:             "preferred",
			RequireResidentKey:      &requireResidentKey,
			UserVerification:        "preferred",
		},
		Extensions: map[string]any{"credProps": true, "uvm": true},
		Hints:      []string{},
	}
	expectedAuthentication := webauthn.RequestOptionsJSON{
		RPID:             "localhost",
		Challenge:        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
		Timeout:          60_000,
		UserVerification: "preferred",
		Extensions:       map[string]any{"txAuthSimple": "Authorize"},
	}

	t.Run("registration", func(t *testing.T) {
		harness := newHarness(t, func(options *Options, _ *testHarness) {
			options.Registration.Extensions = map[string]any{"uvm": true}
		})
		harness.seedUser(t, "passkey-user", "passkey@example.com")
		headers := contract.NewHeaders(contract.HeaderField{Name: "X-Test-User", Value: "passkey-user"})
		response, err := harness.call(t, "GET", "/passkey/generate-register-options", url.Values{
			"authenticatorAttachment": {"platform"}, "name": {"Work"}, "context": {"registration-flow"},
		}, headers, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := decodeResponse[webauthn.CreationOptionsJSON](t, response)
		if !reflect.DeepEqual(got, expectedRegistration) {
			gotJSON, _ := json.MarshalIndent(got, "", "  ")
			wantJSON, _ := json.MarshalIndent(expectedRegistration, "", "  ")
			t.Fatalf("registration options mismatch\n got: %s\nwant: %s", gotJSON, wantJSON)
		}
		setCookies := response.Headers().Values("Set-Cookie")
		if len(setCookies) != 1 || !strings.HasPrefix(setCookies[0], "single-auth.single-auth-passkey=") ||
			!strings.Contains(setCookies[0], "Max-Age=300") || !strings.Contains(setCookies[0], "HttpOnly") {
			t.Fatalf("Set-Cookie = %#v", setCookies)
		}
		rows, err := harness.adapter.FindMany(t.Context(), storage.FindManyParams{Model: "verification"})
		if err != nil || len(rows) != 1 {
			t.Fatalf("verification rows = %#v, err = %v", rows, err)
		}
		stored, _ := recordString(rows[0], "value")
		var challenge storedChallenge
		if err := json.Unmarshal([]byte(stored), &challenge); err != nil {
			t.Fatal(err)
		}
		flowContext, err := challenge.flowContext()
		if err != nil || flowContext == nil || *flowContext != "registration-flow" || challenge.Type != registrationCeremony {
			t.Fatalf("stored challenge = %#v, context = %#v, err = %v", challenge, flowContext, err)
		}
	})

	t.Run("authentication conditional UI", func(t *testing.T) {
		harness := newHarness(t, func(options *Options, _ *testHarness) {
			options.Authentication.Extensions = map[string]any{"txAuthSimple": "Authorize"}
		})
		response, err := harness.call(t, "GET", "/passkey/generate-authenticate-options", nil, contract.Headers{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := decodeResponse[webauthn.RequestOptionsJSON](t, response)
		if !reflect.DeepEqual(got, expectedAuthentication) {
			gotJSON, _ := json.MarshalIndent(got, "", "  ")
			wantJSON, _ := json.MarshalIndent(expectedAuthentication, "", "  ")
			t.Fatalf("authentication options mismatch\n got: %s\nwant: %s", gotJSON, wantJSON)
		}
		if got.AllowCredentials != nil {
			t.Fatalf("discoverable credential options must omit allowCredentials: %#v", got)
		}
	})
}

func TestRegistrationOptionsUseSessionCredentialsAndOverrides(t *testing.T) {
	harness := newHarness(t, func(options *Options, _ *testHarness) {
		options.RPID = "login.example.com"
		options.RPName = "Example"
		options.AuthenticatorSelection = &webauthn.AuthenticatorSelectionCriteria{
			AuthenticatorAttachment: "cross-platform", ResidentKey: "required", UserVerification: "required",
		}
		options.Registration.ResolveExtensions = func(*engine.Context) (map[string]any, error) {
			return map[string]any{"largeBlob": map[string]any{"support": "required"}}, nil
		}
	})
	harness.seedUser(t, "user-a", "a@example.com")
	harness.seedPasskey(t, "user-a", "Y3JlZC1h", "A")
	headers := contract.NewHeaders(contract.HeaderField{Name: "X-Test-User", Value: "user-a"})
	response, err := harness.call(t, "GET", "/passkey/generate-register-options", url.Values{
		"authenticatorAttachment": {"platform"},
	}, headers, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := decodeResponse[webauthn.CreationOptionsJSON](t, response)
	if options.RP.ID != "login.example.com" || options.RP.Name != "Example" {
		t.Fatalf("rp = %#v", options.RP)
	}
	if options.AuthenticatorSelection.AuthenticatorAttachment != "platform" ||
		options.AuthenticatorSelection.ResidentKey != "required" ||
		options.AuthenticatorSelection.UserVerification != "required" {
		t.Fatalf("selection = %#v", options.AuthenticatorSelection)
	}
	if len(options.ExcludeCredentials) != 1 || options.ExcludeCredentials[0].ID != "Y3JlZC1h" ||
		!reflect.DeepEqual(options.ExcludeCredentials[0].Transports, []string{"internal", "hybrid"}) {
		t.Fatalf("excludeCredentials = %#v", options.ExcludeCredentials)
	}
	if options.Extensions["credProps"] != true || options.Extensions["largeBlob"] == nil {
		t.Fatalf("extensions = %#v", options.Extensions)
	}
}

func TestAuthenticationOptionsRestrictCredentialsOnlyWithSession(t *testing.T) {
	harness := newHarness(t, nil)
	harness.seedUser(t, "user-a", "a@example.com")
	harness.seedPasskey(t, "user-a", "Y3JlZC1h", "A")

	headers := contract.NewHeaders(contract.HeaderField{Name: "X-Test-User", Value: "user-a"})
	response, err := harness.call(t, "GET", "/passkey/generate-authenticate-options", nil, headers, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := decodeResponse[webauthn.RequestOptionsJSON](t, response)
	if len(options.AllowCredentials) != 1 || options.AllowCredentials[0].ID != "Y3JlZC1h" {
		t.Fatalf("allowCredentials = %#v", options.AllowCredentials)
	}

	response, err = harness.call(t, "GET", "/passkey/generate-authenticate-options", nil, contract.Headers{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(response.Body(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, exists := raw["allowCredentials"]; exists {
		t.Fatalf("conditional UI response includes allowCredentials: %#v", raw)
	}
}

func TestChallengeExpiryIsComputedPerRequest(t *testing.T) {
	harness := newHarness(t, nil)
	harness.seedUser(t, "user-a", "a@example.com")
	headers := contract.NewHeaders(contract.HeaderField{Name: "X-Test-User", Value: "user-a"})

	if _, err := harness.call(t, "GET", "/passkey/generate-register-options", nil, headers, nil); err != nil {
		t.Fatal(err)
	}
	harness.clock.Set(harness.clock.Now().Add(6 * time.Minute))
	if _, err := harness.call(t, "GET", "/passkey/generate-authenticate-options", nil, contract.Headers{}, nil); err != nil {
		t.Fatal(err)
	}
	rows, err := harness.adapter.FindMany(t.Context(), storage.FindManyParams{Model: "verification"})
	if err != nil || len(rows) != 2 {
		t.Fatalf("verification rows = %d, err = %v", len(rows), err)
	}
	for _, row := range rows {
		createdAt, createdOK := recordTime(row, "createdAt")
		expiresAt, expiresOK := recordTime(row, "expiresAt")
		if !createdOK || !expiresOK || expiresAt.Sub(createdAt) != defaultChallengeAge {
			t.Fatalf("challenge timestamps = created %v expires %v", createdAt, expiresAt)
		}
	}
	firstCreated, _ := recordTime(rows[0], "createdAt")
	secondCreated, _ := recordTime(rows[1], "createdAt")
	if secondCreated.Sub(firstCreated) != 6*time.Minute {
		t.Fatalf("createdAt delta = %s", secondCreated.Sub(firstCreated))
	}
}
