package siwe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestNonceRoutesAndBasicValidationMatchUpstream(t *testing.T) {
	t.Run("should generate a valid nonce for a valid public key", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		before := time.Now()
		response, body := callSIWE(t, auth, "/siwe/nonce", map[string]any{
			"walletAddress": testWalletAddress, "chainId": 1,
		})
		if response.Code != http.StatusOK || body["nonce"] != testNonce ||
			len(body["nonce"].(string)) != 17 {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
		rows := records(t, auth, "verification", []storage.Where{{
			Field: "identifier", Value: "siwe:" + testWalletAddress + ":1",
		}})
		if len(rows) != 1 || rows[0]["value"] != testNonce {
			t.Fatalf("verification rows = %#v", rows)
		}
		expiresAt, ok := rows[0]["expiresAt"].(time.Time)
		if !ok || expiresAt.Before(before.Add(14*time.Minute+59*time.Second)) ||
			expiresAt.After(time.Now().Add(15*time.Minute+time.Second)) {
			t.Fatalf("nonce expiration = %#v", rows[0]["expiresAt"])
		}
	})

	t.Run("should generate a valid nonce with default chainId", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		response, body := callSIWE(t, auth, "/siwe/nonce", map[string]any{
			"walletAddress": strings.ToLower(testWalletAddress),
		})
		if response.Code != http.StatusOK || body["nonce"] != testNonce {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
		rows := records(t, auth, "verification", []storage.Where{{
			Field: "identifier", Value: "siwe:" + testWalletAddress + ":1",
		}})
		if len(rows) != 1 {
			t.Fatalf("default chain verification rows = %#v", rows)
		}
	})

	t.Run("should support getNonce alias with address input", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		response, body := callSIWE(t, auth, "/siwe/get-nonce", map[string]any{
			"address": testWalletAddress, "chainId": 1,
		})
		if response.Code != http.StatusOK || body["nonce"] != testNonce {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
	})

	t.Run("should reject verification if nonce is missing", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		response, body := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", nil,
		)
		if response.Code != http.StatusUnauthorized ||
			responseCode(body) != "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE" ||
			!strings.Contains(strings.ToLower(responseMessage(body)), "nonce") {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
	})

	t.Run("should reject invalid public key", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		response, body := callSIWE(t, auth, "/siwe/nonce", map[string]any{"walletAddress": "invalid"})
		want := "[body.walletAddress] Invalid string: must match pattern /^0[xX][a-fA-F0-9]{40}$/i; [body.walletAddress] Too small: expected string to have >=42 characters"
		if response.Code != http.StatusBadRequest || responseMessage(body) != want {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
	})

	t.Run("should reject verification with invalid signature", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		requestNonce(t, auth, testWalletAddress, 1)
		response, body := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"invalid_signature", nil,
		)
		if response.Code != http.StatusUnauthorized || responseMessage(body) != "Unauthorized: Invalid SIWE signature" {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
	})

	t.Run("should reject invalid walletAddress format", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		response, _ := callSIWE(t, auth, "/siwe/nonce", map[string]any{"walletAddress": "not_a_valid_key"})
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("should reject invalid message", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		requestNonce(t, auth, testWalletAddress, 1)
		response, body := verifyWallet(
			t, auth, testWalletAddress, 1, "invalid_message", "valid_signature", nil,
		)
		if response.Code != http.StatusUnauthorized || responseCode(body) != "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH" {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
	})
}

func TestAnonymousAndEmailCollisionPolicyMatchesUpstream(t *testing.T) {
	t.Run("should reject verification without email when anonymous is false", func(t *testing.T) {
		options := defaultTestOptions()
		options.Anonymous = boolPointer(false)
		auth := newTestAuth(t, options)
		response, body := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", nil,
		)
		want := "[body.email] Email is required when the anonymous plugin option is disabled."
		if response.Code != http.StatusBadRequest || responseMessage(body) != want {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
	})

	t.Run("should accept verification with email when anonymous is false", func(t *testing.T) {
		options := defaultTestOptions()
		options.Anonymous = boolPointer(false)
		auth := newTestAuth(t, options)
		requestNonce(t, auth, testWalletAddress, 1)
		email := "user@example.com"
		response, body := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", &email,
		)
		assertSuccessfulVerification(t, response, body)
		users := records(t, auth, "user", []storage.Where{{Field: "email", Value: email}})
		if len(users) != 1 {
			t.Fatalf("users with supplied email = %#v", users)
		}
		accounts := records(t, auth, "account", []storage.Where{{Field: "providerId", Value: "siwe"}})
		if len(accounts) != 1 || accounts[0]["userId"] != users[0]["id"] ||
			accounts[0]["accountId"] != testWalletAddress+":1" {
			t.Fatalf("SIWE account = %#v", accounts)
		}
		sessions := records(t, auth, "session", []storage.Where{{Field: "userId", Value: users[0]["id"]}})
		if len(sessions) != 1 || sessions[0]["token"] != body["token"] {
			t.Fatalf("SIWE session = %#v response=%#v", sessions, body)
		}
	})

	t.Run("should not bind a caller-supplied email that already belongs to another account", func(t *testing.T) {
		options := defaultTestOptions()
		options.Anonymous = boolPointer(false)
		auth := newTestAuth(t, options)
		seedUser(t, auth, "existing-user", "claimed@example.com")
		requestNonce(t, auth, testWalletAddress, 1)
		email := "claimed@example.com"
		response, body := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", &email,
		)
		assertSuccessfulVerification(t, response, body)
		walletUsers := walletUsers(t, auth, testWalletAddress)
		if len(walletUsers) != 1 || walletUsers[0]["email"] == email ||
			len(records(t, auth, "user", []storage.Where{{Field: "email", Value: email}})) != 1 {
			t.Fatalf("email collision leaked or rebound: %#v", walletUsers)
		}
	})

	t.Run("should treat a case-variant of an existing email as the same email", func(t *testing.T) {
		options := defaultTestOptions()
		options.Anonymous = boolPointer(false)
		auth := newTestAuth(t, options)
		requestNonce(t, auth, testWalletAddress, 1)
		mixed := "Mixed@Case.com"
		first, firstBody := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", &mixed,
		)
		assertSuccessfulVerification(t, first, firstBody)
		firstUsers := walletUsers(t, auth, testWalletAddress)
		if len(firstUsers) != 1 || firstUsers[0]["email"] != "mixed@case.com" {
			t.Fatalf("first email was not normalized: %#v", firstUsers)
		}

		secondAddress := ChecksumAddress(testSecondWallet)
		requestNonce(t, auth, secondAddress, 1)
		lower := "mixed@case.com"
		second, secondBody := verifyWallet(
			t, auth, secondAddress, 1,
			testMessage(testMessageOptions{Address: secondAddress}),
			"valid_signature", &lower,
		)
		assertSuccessfulVerification(t, second, secondBody)
		secondUsers := walletUsers(t, auth, secondAddress)
		if len(secondUsers) != 1 || secondUsers[0]["email"] == lower {
			t.Fatalf("second wallet adopted claimed case-variant: %#v", secondUsers)
		}
	})

	t.Run("should reject invalid email format when anonymous is false", func(t *testing.T) {
		options := defaultTestOptions()
		options.Anonymous = boolPointer(false)
		auth := newTestAuth(t, options)
		invalid := "not-an-email"
		response, body := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", &invalid,
		)
		if response.Code != http.StatusBadRequest || responseMessage(body) != "[body.email] Invalid email address" {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
	})

	t.Run("should allow verification without email when anonymous is true", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		requestNonce(t, auth, testWalletAddress, 1)
		response, body := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", nil,
		)
		assertSuccessfulVerification(t, response, body)
	})

	t.Run("should reject empty string email when anonymous is false", func(t *testing.T) {
		options := defaultTestOptions()
		options.Anonymous = boolPointer(false)
		auth := newTestAuth(t, options)
		empty := ""
		response, body := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", &empty,
		)
		want := "[body.email] Invalid email address; [body.email] Email is required when the anonymous plugin option is disabled."
		if response.Code != http.StatusBadRequest || responseMessage(body) != want {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
	})
}

func TestNonceAtomicityExpiryAndReplayMatchUpstream(t *testing.T) {
	t.Run("should mint exactly one session when the same nonce is verified concurrently", func(t *testing.T) {
		options := defaultTestOptions()
		options.VerifyMessage = func(_ context.Context, input VerifyMessageArgs) (bool, error) {
			time.Sleep(50 * time.Millisecond)
			return input.Signature == "valid_signature", nil
		}
		auth := newTestAuth(t, options)
		requestNonce(t, auth, testWalletAddress, 1)

		encoded, err := json.Marshal(map[string]any{
			"message": testMessage(testMessageOptions{}), "signature": "valid_signature",
			"walletAddress": testWalletAddress, "chainId": 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		type result struct {
			status int
			body   []byte
		}
		results := make(chan result, 2)
		var group sync.WaitGroup
		for range 2 {
			group.Add(1)
			go func() {
				defer group.Done()
				request := httptest.NewRequest(
					http.MethodPost, "http://localhost:3000/api/auth/siwe/verify",
					bytes.NewReader(encoded),
				)
				request.Header.Set("Content-Type", "application/json")
				recorder := httptest.NewRecorder()
				auth.ServeHTTP(recorder, request)
				results <- result{status: recorder.Code, body: recorder.Body.Bytes()}
			}()
		}
		group.Wait()
		close(results)
		successes, failures := 0, 0
		for result := range results {
			switch result.status {
			case http.StatusOK:
				successes++
			case http.StatusUnauthorized:
				failures++
			default:
				t.Fatalf("unexpected status=%d body=%s", result.status, result.body)
			}
		}
		if successes != 1 || failures != 1 {
			t.Fatalf("successes=%d failures=%d", successes, failures)
		}
		if got := len(records(t, auth, "session", nil)); got != 1 {
			t.Fatalf("session count=%d", got)
		}
		if got := len(records(t, auth, "walletAddress", nil)); got != 1 {
			t.Fatalf("wallet count=%d", got)
		}
	})

	t.Run("should reject an expired nonce and consume the row", func(t *testing.T) {
		now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
		options := defaultTestOptions()
		auth := newTestAuthWithRoot(t, options, rootWithClock(now))
		identifier := verificationIdentifier(testWalletAddress, 1)
		_, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
			Model: "verification",
			Data: storage.Record{
				"identifier": identifier, "value": testNonce,
				"expiresAt": now.Add(-time.Second), "createdAt": now, "updatedAt": now,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		response, body := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", nil,
		)
		if response.Code != http.StatusUnauthorized || responseCode(body) != "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE" {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
		if remaining := records(t, auth, "verification", []storage.Where{{Field: "identifier", Value: identifier}}); len(remaining) != 0 {
			t.Fatalf("expired nonce remained: %#v", remaining)
		}
	})

	t.Run("should not allow nonce reuse", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		requestNonce(t, auth, testWalletAddress, 1)
		first, firstBody := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", nil,
		)
		assertSuccessfulVerification(t, first, firstBody)
		second, secondBody := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", nil,
		)
		if second.Code != http.StatusUnauthorized || responseCode(secondBody) != "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE" {
			t.Fatalf("status=%d body=%#v", second.Code, secondBody)
		}
	})
}

func TestWalletPersistenceSchemaAndChainsMatchUpstream(t *testing.T) {
	t.Run("should store and return the wallet address in checksum format", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		lowercase := strings.ToLower(testWalletAddress)
		requestNonce(t, auth, lowercase, 1)
		first, firstBody := verifyWallet(
			t, auth, lowercase, 1, testMessage(testMessageOptions{}),
			"valid_signature", nil,
		)
		assertSuccessfulVerification(t, first, firstBody)
		user := firstBody["user"].(map[string]any)
		if user["walletAddress"] != testWalletAddress {
			t.Fatalf("response address=%#v", user["walletAddress"])
		}
		wallets := records(t, auth, "walletAddress", []storage.Where{{Field: "address", Value: testWalletAddress}})
		if len(wallets) != 1 || wallets[0]["address"] != testWalletAddress {
			t.Fatalf("wallets=%#v", wallets)
		}

		uppercase := strings.ToUpper(testWalletAddress)
		requestNonce(t, auth, uppercase, 1)
		second, secondBody := verifyWallet(
			t, auth, uppercase, 1, testMessage(testMessageOptions{}),
			"valid_signature", nil,
		)
		assertSuccessfulVerification(t, second, secondBody)
		if len(records(t, auth, "walletAddress", nil)) != 1 {
			t.Fatal("address case variant created a duplicate wallet")
		}
	})

	t.Run("should reject duplicate wallet address entries", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		requestNonce(t, auth, testWalletAddress, 1)
		first, firstBody := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", nil,
		)
		assertSuccessfulVerification(t, first, firstBody)
		requestNonce(t, auth, testWalletAddress, 1)
		second, secondBody := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", nil,
		)
		assertSuccessfulVerification(t, second, secondBody)
		if responseUserID(firstBody) != responseUserID(secondBody) ||
			len(records(t, auth, "walletAddress", nil)) != 1 ||
			len(records(t, auth, "user", nil)) != 1 ||
			len(records(t, auth, "account", []storage.Where{{Field: "providerId", Value: "siwe"}})) != 1 {
			t.Fatalf("duplicate persistence: first=%#v second=%#v", firstBody, secondBody)
		}
	})

	t.Run("should support custom schema with mergeSchema", func(t *testing.T) {
		options := defaultTestOptions()
		options.Schema = storage.Schema{Models: map[string]storage.ModelSchema{
			"walletAddress": {
				ModelName: "wallet_address",
				Fields: map[string]storage.FieldAttribute{
					"userId":    {Type: storage.FieldString, FieldName: "user_id", Index: true, References: &storage.Reference{Model: "user", Field: "id"}},
					"address":   {Type: storage.FieldString, FieldName: "wallet_address"},
					"chainId":   {Type: storage.FieldNumber, FieldName: "chain_id"},
					"isPrimary": {Type: storage.FieldBoolean, FieldName: "is_primary", DefaultValue: storage.StaticValue(false)},
					"createdAt": {Type: storage.FieldDate, FieldName: "created_at"},
				},
			},
		}}
		factorySchema, err := NewFactory(options).Schema()
		if err != nil {
			t.Fatal(err)
		}
		model := factorySchema.Models["walletAddress"]
		if model.ModelName != "wallet_address" || model.Fields["address"].FieldName != "wallet_address" {
			t.Fatalf("custom schema not merged: %#v", model)
		}
		auth := newTestAuth(t, options)
		requestNonce(t, auth, testWalletAddress, 1)
		response, body := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", nil,
		)
		assertSuccessfulVerification(t, response, body)
		wallets := records(t, auth, "walletAddress", nil)
		if len(wallets) != 1 || wallets[0]["userId"] == nil || wallets[0]["createdAt"] == nil ||
			wallets[0]["address"] != testWalletAddress || wallets[0]["isPrimary"] != true {
			t.Fatalf("custom schema wallet=%#v", wallets)
		}
	})

	t.Run("should allow same address on different chains for same user", func(t *testing.T) {
		auth := newTestAuth(t, defaultTestOptions())
		requestNonce(t, auth, testWalletAddress, 1)
		first, firstBody := verifyWallet(
			t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
			"valid_signature", nil,
		)
		assertSuccessfulVerification(t, first, firstBody)
		requestNonce(t, auth, testWalletAddress, 137)
		second, secondBody := verifyWallet(
			t, auth, testWalletAddress, 137, testMessage(testMessageOptions{ChainID: 137}),
			"valid_signature", nil,
		)
		assertSuccessfulVerification(t, second, secondBody)
		if responseUserID(firstBody) != responseUserID(secondBody) {
			t.Fatalf("same address mapped to different users: %#v %#v", firstBody, secondBody)
		}
		wallets := records(t, auth, "walletAddress", []storage.Where{{Field: "address", Value: testWalletAddress}})
		if len(wallets) != 2 || wallets[0]["userId"] != wallets[1]["userId"] {
			t.Fatalf("wallet chains=%#v", wallets)
		}
		primary := 0
		for _, wallet := range wallets {
			if wallet["isPrimary"] == true {
				primary++
			}
		}
		if primary != 1 || len(records(t, auth, "account", []storage.Where{{Field: "providerId", Value: "siwe"}})) != 2 {
			t.Fatalf("primary=%d wallets=%#v", primary, wallets)
		}
	})
}

func TestStrictSIWEMessageBindingMatchesUpstream(t *testing.T) {
	tests := []struct {
		name        string
		message     func() string
		code        string
		createFirst bool
	}{
		{
			name:    "rejects a valid signature over a message with a non-matching nonce",
			message: func() string { return testMessage(testMessageOptions{Nonce: "some-other-nonce"}) },
			code:    "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH",
		},
		{
			name:    "rejects a message bound to a different domain",
			message: func() string { return testMessage(testMessageOptions{Domain: "other.example.com"}) },
			code:    "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH",
		},
		{
			name:    "rejects a message whose chain id does not match",
			message: func() string { return testMessage(testMessageOptions{ChainID: 137}) },
			code:    "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH",
		},
		{
			name:    "rejects an arbitrary (non-SIWE) message even with a valid signature",
			message: func() string { return "gm, please sign this to continue" },
			code:    "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH",
		},
		{
			name:    "rejects an expired SIWE message",
			message: func() string { return testMessage(testMessageOptions{ExpirationTime: "2020-01-01T00:00:00.000Z"}) },
			code:    "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED",
		},
		{
			name:    "does not mint a session for an existing wallet user when an unrelated signature is reused",
			message: func() string { return "Approve transfer of 1 ETH" },
			code:    "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH", createFirst: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := newTestAuth(t, defaultTestOptions())
			if test.createFirst {
				requestNonce(t, auth, testWalletAddress, 1)
				response, body := verifyWallet(
					t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
					"valid_signature", nil,
				)
				assertSuccessfulVerification(t, response, body)
			}
			sessionsBefore := len(records(t, auth, "session", nil))
			requestNonce(t, auth, testWalletAddress, 1)
			response, body := verifyWallet(
				t, auth, testWalletAddress, 1, test.message(), "valid_signature", nil,
			)
			if response.Code != http.StatusUnauthorized || responseCode(body) != test.code {
				t.Fatalf("status=%d body=%#v", response.Code, body)
			}
			if len(records(t, auth, "session", nil)) != sessionsBefore {
				t.Fatal("rejected signed message minted a session")
			}
		})
	}
}

func TestNotBeforeENSAndVerifierContract(t *testing.T) {
	t.Run("rejects a SIWE message that is not yet valid", func(t *testing.T) {
		now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
		auth := newTestAuthWithRoot(t, defaultTestOptions(), rootWithClock(now))
		requestNonce(t, auth, testWalletAddress, 1)
		response, body := verifyWallet(
			t, auth, testWalletAddress, 1,
			testMessage(testMessageOptions{NotBefore: now.Add(time.Hour).Format(time.RFC3339Nano)}),
			"valid_signature", nil,
		)
		if response.Code != http.StatusUnauthorized || responseCode(body) != "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID" {
			t.Fatalf("status=%d body=%#v", response.Code, body)
		}
	})

	t.Run("uses ENS profile data and passes the exact CAIP payload", func(t *testing.T) {
		options := defaultTestOptions()
		var seen VerifyMessageArgs
		options.VerifyMessage = func(_ context.Context, input VerifyMessageArgs) (bool, error) {
			seen = input
			return true, nil
		}
		options.ENSLookup = func(_ context.Context, input ENSLookupArgs) (ENSLookupResult, error) {
			if input.WalletAddress != testWalletAddress {
				return ENSLookupResult{}, errors.New("unexpected ENS address")
			}
			return ENSLookupResult{Name: "alice.eth", Avatar: "https://example.com/alice.png"}, nil
		}
		auth := newTestAuth(t, options)
		requestNonce(t, auth, testWalletAddress, 1)
		message := testMessage(testMessageOptions{})
		response, body := verifyWallet(t, auth, testWalletAddress, 1, message, "valid_signature", nil)
		assertSuccessfulVerification(t, response, body)
		if seen.Message != message || seen.Signature != "valid_signature" ||
			seen.Address != testWalletAddress || seen.ChainID != 1 ||
			seen.Cacao.Header.Type != "caip122" || seen.Cacao.Payload.Domain != testDomain ||
			seen.Cacao.Payload.Audience != testDomain || seen.Cacao.Payload.Nonce != testNonce ||
			seen.Cacao.Payload.Issuer != testDomain || seen.Cacao.Payload.Version != "1" ||
			seen.Cacao.Signature.Type != "eip191" || seen.Cacao.Signature.Value != "valid_signature" {
			t.Fatalf("verifier args=%#v", seen)
		}
		users := walletUsers(t, auth, testWalletAddress)
		if len(users) != 1 || users[0]["name"] != "alice.eth" || users[0]["image"] != "https://example.com/alice.png" {
			t.Fatalf("ENS user=%#v", users)
		}
	})
}

func assertSuccessfulVerification(
	t *testing.T, response *httptest.ResponseRecorder, body map[string]any,
) {
	t.Helper()
	if response.Code != http.StatusOK || body["success"] != true ||
		body["token"] == "" || responseUserID(body) == "" {
		t.Fatalf("status=%d body=%#v", response.Code, body)
	}
	token, _ := body["token"].(string)
	var sessionCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "single-auth.session_token" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil || !strings.HasPrefix(sessionCookie.Value, token+".") ||
		!sessionCookie.HttpOnly || sessionCookie.Path != "/" ||
		sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %#v", sessionCookie)
	}
}

func walletUsers(t *testing.T, auth interface {
	Adapter() storage.Adapter
}, address string) []storage.Record {
	t.Helper()
	wallets, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
		Model: "walletAddress", Where: []storage.Where{{Field: "address", Value: address}},
	})
	if err != nil {
		t.Fatal(err)
	}
	users := make([]storage.Record, 0, len(wallets))
	for _, wallet := range wallets {
		userID, _ := wallet["userId"].(string)
		user, findErr := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		})
		if findErr != nil {
			t.Fatal(findErr)
		}
		if user != nil {
			users = append(users, user)
		}
	}
	return users
}
