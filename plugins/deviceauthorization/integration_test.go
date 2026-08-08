package deviceauthorization

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestClientValidation(t *testing.T) {
	validClients := map[string]bool{"valid-client-1": true, "valid-client-2": true}
	harness := newDeviceHarness(t, func(options *Options) {
		options.ValidateClient = func(_ context.Context, clientID string) (bool, error) {
			return validClients[clientID], nil
		}
	})

	t.Run("should reject invalid client in device code request", func(t *testing.T) {
		result, err := harness.call(t, "deviceCode", http.MethodPost, contract.Headers{}, map[string]any{
			"client_id": "invalid-client",
		}, nil)
		assertOAuthError(t, result, err, http.StatusBadRequest, "invalid_client", "Invalid client ID")
	})

	t.Run("should accept valid client in device code request", func(t *testing.T) {
		response := harness.requestCode(t, map[string]any{"client_id": "valid-client-1"})
		if response.DeviceCode == "" {
			t.Fatal("device code is empty")
		}
	})

	t.Run("should reject invalid client in token request", func(t *testing.T) {
		code := harness.requestCode(t, map[string]any{"client_id": "valid-client-1"})
		result, err := harness.poll(t, code.DeviceCode, "invalid-client")
		assertOAuthError(t, result, err, http.StatusBadRequest, "invalid_grant", "Invalid client ID")
	})

	t.Run("should reject mismatched client_id in token request", func(t *testing.T) {
		code := harness.requestCode(t, map[string]any{"client_id": "valid-client-1"})
		result, err := harness.poll(t, code.DeviceCode, "valid-client-2")
		assertOAuthError(t, result, err, http.StatusBadRequest, "invalid_grant", "Client ID mismatch")
	})
}

func TestDeviceCodeRequest(t *testing.T) {
	var requestedClient string
	var requestedScope *string
	harness := newDeviceHarness(t, func(options *Options) {
		options.OnDeviceAuthRequest = func(_ context.Context, clientID string, scope *string) error {
			requestedClient = clientID
			requestedScope = scope
			return nil
		}
	})

	t.Run("should generate device and user codes", func(t *testing.T) {
		response := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		if len(response.DeviceCode) != 40 || !regexp.MustCompile(`^[a-zA-Z0-9]{40}$`).MatchString(response.DeviceCode) {
			t.Fatalf("device_code = %q", response.DeviceCode)
		}
		if !regexp.MustCompile(`^[A-Z0-9]{8}$`).MatchString(response.UserCode) {
			t.Fatalf("user_code = %q", response.UserCode)
		}
		if response.VerificationURI != "http://localhost:3000/device" ||
			response.VerificationURIComplete != "http://localhost:3000/device?user_code="+response.UserCode ||
			response.ExpiresIn != 300 || response.Interval != 2 {
			t.Fatalf("response = %#v", response)
		}
	})

	t.Run("should support custom client ID and scope", func(t *testing.T) {
		response := harness.requestCode(t, map[string]any{
			"client_id": "test-client", "scope": "read write",
		})
		if response.DeviceCode == "" || requestedClient != "test-client" || requestedScope == nil || *requestedScope != "read write" {
			t.Fatalf("response=%#v callback=%q %#v", response, requestedClient, requestedScope)
		}
		record := harness.deviceRecord(t, "deviceCode", response.DeviceCode)
		if record["clientId"] != "test-client" || record["scope"] != "read write" || record["status"] != "pending" {
			t.Fatalf("record = %#v", record)
		}
	})
}

func TestDeviceTokenPolling(t *testing.T) {
	t.Run("should return authorization_pending when not approved", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		result, err := harness.poll(t, code.DeviceCode, "test-client")
		assertOAuthError(t, result, err, http.StatusBadRequest, "authorization_pending", MessageAuthorizationPending)
		record := harness.deviceRecord(t, "deviceCode", code.DeviceCode)
		if _, ok := recordTime(record, "lastPolledAt"); !ok {
			t.Fatalf("lastPolledAt not persisted: %#v", record)
		}
	})

	t.Run("should return expired_token for expired device codes", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		harness.clock.Advance(301 * time.Second)
		result, err := harness.poll(t, code.DeviceCode, "test-client")
		assertOAuthError(t, result, err, http.StatusBadRequest, "expired_token", MessageExpiredDeviceCode)
		if record := harness.deviceRecord(t, "deviceCode", code.DeviceCode); record != nil {
			t.Fatalf("expired device code survived: %#v", record)
		}
	})

	t.Run("should return error for invalid device code", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		result, err := harness.poll(t, "invalid-code", "test-client")
		assertOAuthError(t, result, err, http.StatusBadRequest, "invalid_grant", MessageInvalidDeviceCode)
	})

	t.Run("should enforce rate limiting with slow_down error", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		first, firstErr := harness.poll(t, code.DeviceCode, "test-client")
		assertOAuthError(t, first, firstErr, http.StatusBadRequest, "authorization_pending", MessageAuthorizationPending)
		second, secondErr := harness.poll(t, code.DeviceCode, "test-client")
		assertOAuthError(t, second, secondErr, http.StatusBadRequest, "slow_down", MessagePollingTooFrequently)
		harness.clock.Advance(2 * time.Second)
		third, thirdErr := harness.poll(t, code.DeviceCode, "test-client")
		assertOAuthError(t, third, thirdErr, http.StatusBadRequest, "authorization_pending", MessageAuthorizationPending)
	})
}

func TestDeviceVerification(t *testing.T) {
	harness := newDeviceHarness(t, nil)
	t.Run("should verify valid user code", func(t *testing.T) {
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		result, err := harness.verify(t, code.UserCode, contract.Headers{})
		if err != nil {
			t.Fatal(err)
		}
		object := decodeObjectResponse(t, result)
		if object["user_code"] != code.UserCode || object["status"] != "pending" {
			t.Fatalf("verify = %#v", object)
		}
	})

	t.Run("should handle invalid user code", func(t *testing.T) {
		result, err := harness.verify(t, "INVALID", contract.Headers{})
		assertOAuthError(t, result, err, http.StatusBadRequest, "invalid_request", MessageInvalidUserCode)
	})
}

func TestDeviceApprovalAndDenial(t *testing.T) {
	t.Run("should approve device and create session", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		user := harness.signUp(t, 1)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		if _, err := harness.verify(t, code.UserCode, user.Headers); err != nil {
			t.Fatal(err)
		}
		approved, err := harness.decision(t, "deviceApprove", code.UserCode, user.Headers)
		if err != nil || decodeObjectResponse(t, approved)["success"] != true {
			t.Fatalf("approve = %#v, %v", approved.Value, err)
		}
		tokenResult, err := harness.poll(t, code.DeviceCode, "test-client")
		if err != nil {
			t.Fatalf("token = %s, %v", tokenResult.Response.Body(), err)
		}
		token := decodeObjectResponse(t, tokenResult)
		if token["access_token"] == "" || token["token_type"] != "Bearer" || token["scope"] != "" {
			t.Fatalf("token = %#v", token)
		}
		if values := tokenResult.Response.Headers().Values("Set-Cookie"); len(values) != 0 {
			t.Fatalf("device token wrote browser cookies: %#v", values)
		}
		if cache, _ := tokenResult.Response.Headers().Get("Cache-Control"); cache != "no-store" {
			t.Fatalf("Cache-Control = %q", cache)
		}
		if pragma, _ := tokenResult.Response.Headers().Get("Pragma"); pragma != "no-cache" {
			t.Fatalf("Pragma = %q", pragma)
		}
	})

	t.Run("should deny device authorization", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		user := harness.signUp(t, 2)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		if _, err := harness.verify(t, code.UserCode, user.Headers); err != nil {
			t.Fatal(err)
		}
		denied, err := harness.decision(t, "deviceDeny", code.UserCode, user.Headers)
		if err != nil || decodeObjectResponse(t, denied)["success"] != true {
			t.Fatalf("deny = %#v, %v", denied.Value, err)
		}
		result, pollErr := harness.poll(t, code.DeviceCode, "test-client")
		assertOAuthError(t, result, pollErr, http.StatusBadRequest, "access_denied", MessageAccessDenied)
		if record := harness.deviceRecord(t, "deviceCode", code.DeviceCode); record != nil {
			t.Fatalf("denied code survived token poll: %#v", record)
		}
	})

	t.Run("should require authentication for approval", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		result, err := harness.decision(t, "deviceApprove", code.UserCode, contract.Headers{})
		assertOAuthError(t, result, err, http.StatusUnauthorized, "unauthorized", MessageAuthenticationRequired)
	})

	t.Run("should require authentication for deny", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		result, err := harness.decision(t, "deviceDeny", code.UserCode, contract.Headers{})
		assertOAuthError(t, result, err, http.StatusUnauthorized, "unauthorized", MessageAuthenticationRequired)
	})
}

func TestDeviceAuthorizationEdgeCase(t *testing.T) {
	t.Run("should not allow approving already processed device code", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		user := harness.signUp(t, 10)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		_, _ = harness.verify(t, code.UserCode, user.Headers)
		if _, err := harness.decision(t, "deviceApprove", code.UserCode, user.Headers); err != nil {
			t.Fatal(err)
		}
		result, err := harness.decision(t, "deviceApprove", code.UserCode, user.Headers)
		assertOAuthError(t, result, err, http.StatusBadRequest, "invalid_request", MessageAlreadyProcessed)
	})

	t.Run("should handle user code without dashes", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		result, err := harness.verify(t, strings.ReplaceAll(code.UserCode, "-", ""), contract.Headers{})
		if err != nil || decodeObjectResponse(t, result)["status"] != "pending" {
			t.Fatalf("verify = %#v, %v", result.Value, err)
		}
	})

	t.Run("should store and use scope from device code request", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		user := harness.signUp(t, 11)
		code := harness.requestCode(t, map[string]any{
			"client_id": "test-client", "scope": "read write profile",
		})
		_, _ = harness.verify(t, code.UserCode, user.Headers)
		if _, err := harness.decision(t, "deviceApprove", code.UserCode, user.Headers); err != nil {
			t.Fatal(err)
		}
		result, err := harness.poll(t, code.DeviceCode, "test-client")
		if err != nil || decodeObjectResponse(t, result)["scope"] != "read write profile" {
			t.Fatalf("token = %#v, %v", result.Value, err)
		}
	})

	t.Run("should allow first user to approve but prevent re-approval", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		user := harness.signUp(t, 12)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		_, _ = harness.verify(t, code.UserCode, user.Headers)
		approved, err := harness.decision(t, "deviceApprove", code.UserCode, user.Headers)
		if err != nil || decodeObjectResponse(t, approved)["success"] != true {
			t.Fatalf("approve = %#v, %v", approved.Value, err)
		}
		record := harness.deviceRecord(t, "userCode", code.UserCode)
		if record["status"] != "approved" || record["userId"] != user.ID {
			t.Fatalf("record = %#v", record)
		}
		second, secondErr := harness.decision(t, "deviceApprove", code.UserCode, user.Headers)
		assertOAuthError(t, second, secondErr, http.StatusBadRequest, "invalid_request", MessageAlreadyProcessed)
	})
}

func TestDeviceAuthorizationOwnershipGate(t *testing.T) {
	t.Run("rejects approve from a session that did not claim the pending code", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		attacker := harness.signUp(t, 20)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		result, err := harness.decision(t, "deviceApprove", code.UserCode, attacker.Headers)
		assertOAuthError(t, result, err, http.StatusBadRequest, "invalid_request", MessageDeviceCodeNotClaimed)
		record := harness.deviceRecord(t, "userCode", code.UserCode)
		if record["userId"] == attacker.ID || record["status"] != "pending" {
			t.Fatalf("record = %#v", record)
		}
	})

	t.Run("rejects deny from a session that did not claim the pending code", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		attacker := harness.signUp(t, 21)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		result, err := harness.decision(t, "deviceDeny", code.UserCode, attacker.Headers)
		assertOAuthError(t, result, err, http.StatusBadRequest, "invalid_request", MessageDeviceCodeNotClaimed)
	})

	t.Run("allows approve when the same session called verify first", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		user := harness.signUp(t, 22)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		if _, err := harness.verify(t, code.UserCode, user.Headers); err != nil {
			t.Fatal(err)
		}
		result, err := harness.decision(t, "deviceApprove", code.UserCode, user.Headers)
		if err != nil || decodeObjectResponse(t, result)["success"] != true {
			t.Fatalf("approve = %#v, %v", result.Value, err)
		}
	})

	t.Run("rejects approve from a different user after another claimed the code", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		claimer := harness.signUp(t, 23)
		attacker := harness.signUp(t, 24)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		_, _ = harness.verify(t, code.UserCode, claimer.Headers)
		approve, approveErr := harness.decision(t, "deviceApprove", code.UserCode, attacker.Headers)
		assertOAuthError(t, approve, approveErr, http.StatusForbidden, "access_denied", "You are not authorized to approve this device authorization")
		deny, denyErr := harness.decision(t, "deviceDeny", code.UserCode, attacker.Headers)
		assertOAuthError(t, deny, denyErr, http.StatusForbidden, "access_denied", "You are not authorized to deny this device authorization")
	})

	t.Run("rejects approve from a different user if the code was generated for a different user_id", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		owner := harness.signUp(t, 25)
		attacker := harness.signUp(t, 26)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client", "user_id": owner.ID})
		approve, approveErr := harness.decision(t, "deviceApprove", code.UserCode, attacker.Headers)
		assertOAuthError(t, approve, approveErr, http.StatusForbidden, "access_denied", "You are not authorized to approve this device authorization")
		deny, denyErr := harness.decision(t, "deviceDeny", code.UserCode, attacker.Headers)
		assertOAuthError(t, deny, denyErr, http.StatusForbidden, "access_denied", "You are not authorized to deny this device authorization")
	})

	t.Run("allows approve when the pre-bound user matches the current user", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		owner := harness.signUp(t, 27)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client", "user_id": owner.ID})
		result, err := harness.decision(t, "deviceApprove", code.UserCode, owner.Headers)
		if err != nil || decodeObjectResponse(t, result)["success"] != true {
			t.Fatalf("approve = %#v, %v", result.Value, err)
		}
	})

	t.Run("allows deny when the pre-bound user matches the current user", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		owner := harness.signUp(t, 28)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client", "user_id": owner.ID})
		result, err := harness.decision(t, "deviceDeny", code.UserCode, owner.Headers)
		if err != nil || decodeObjectResponse(t, result)["success"] != true {
			t.Fatalf("deny = %#v, %v", result.Value, err)
		}
	})

	t.Run("treats an empty user_id as omitted and leaves the code unbound", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		user := harness.signUp(t, 29)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client", "user_id": ""})
		record := harness.deviceRecord(t, "userCode", code.UserCode)
		if record["userId"] != nil {
			t.Fatalf("empty user_id stored as bound: %#v", record)
		}
		_, _ = harness.verify(t, code.UserCode, user.Headers)
		result, err := harness.decision(t, "deviceApprove", code.UserCode, user.Headers)
		if err != nil || decodeObjectResponse(t, result)["success"] != true {
			t.Fatalf("approve = %#v, %v", result.Value, err)
		}
	})
}

func TestDeviceAuthorizationCustomOptions(t *testing.T) {
	t.Run("should correctly store interval as milliseconds in database", func(t *testing.T) {
		harness := newDeviceHarness(t, func(options *Options) { options.Interval = 5 * time.Second })
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		if code.Interval != 5 {
			t.Fatalf("interval = %d", code.Interval)
		}
		record := harness.deviceRecord(t, "deviceCode", code.DeviceCode)
		milliseconds, ok := recordMilliseconds(record, "pollingInterval")
		if !ok || milliseconds != 5000 {
			t.Fatalf("pollingInterval = %#v", record["pollingInterval"])
		}
	})

	t.Run("should use custom code generators", func(t *testing.T) {
		harness := newDeviceHarness(t, func(options *Options) {
			options.GenerateDeviceCode = func(context.Context) (string, error) { return "custom-device-code-12345", nil }
			options.GenerateUserCode = func(context.Context) (string, error) { return "CUSTOM12", nil }
		})
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		if code.DeviceCode != "custom-device-code-12345" || code.UserCode != "CUSTOM12" {
			t.Fatalf("custom codes = %#v", code)
		}
	})

	t.Run("should respect custom expiration time", func(t *testing.T) {
		harness := newDeviceHarness(t, func(options *Options) { options.ExpiresIn = time.Minute })
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		if code.ExpiresIn != 60 {
			t.Fatalf("expires_in = %d", code.ExpiresIn)
		}
	})
}

func TestVerificationURI(t *testing.T) {
	t.Run("should return default /device verification URIs when not configured", func(t *testing.T) {
		harness := newDeviceHarness(t, nil)
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		if code.VerificationURI != "http://localhost:3000/device" || code.VerificationURIComplete != code.VerificationURI+"?user_code="+code.UserCode {
			t.Fatalf("URIs = %#v", code)
		}
	})

	t.Run("should use custom relative path for verificationUri", func(t *testing.T) {
		harness := newDeviceHarness(t, func(options *Options) { options.VerificationURI = "/auth/device-verify" })
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		if code.VerificationURI != "http://localhost:3000/auth/device-verify" || code.VerificationURIComplete != code.VerificationURI+"?user_code="+code.UserCode {
			t.Fatalf("URIs = %#v", code)
		}
	})

	t.Run("should use absolute URL for verificationUri", func(t *testing.T) {
		harness := newDeviceHarness(t, func(options *Options) { options.VerificationURI = "https://myapp.com/device" })
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		if code.VerificationURI != "https://myapp.com/device" || code.VerificationURIComplete != "https://myapp.com/device?user_code="+code.UserCode {
			t.Fatalf("URIs = %#v", code)
		}
	})

	t.Run("should properly encode user_code in verification_uri_complete", func(t *testing.T) {
		harness := newDeviceHarness(t, func(options *Options) {
			options.VerificationURI = "/device"
			options.GenerateUserCode = func(context.Context) (string, error) { return "ABC-123", nil }
		})
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		if code.VerificationURIComplete != "http://localhost:3000/device?user_code=ABC-123" {
			t.Fatalf("URI = %q", code.VerificationURIComplete)
		}
	})

	t.Run("should support verificationUri with existing query parameters", func(t *testing.T) {
		harness := newDeviceHarness(t, func(options *Options) { options.VerificationURI = "/device?lang=en" })
		code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
		if code.VerificationURI != "http://localhost:3000/device?lang=en" ||
			code.VerificationURIComplete != "http://localhost:3000/device?lang=en&user_code="+code.UserCode {
			t.Fatalf("URIs = %#v", code)
		}
	})
}

func TestExpiredApprovedCodeIsBurned(t *testing.T) {
	harness := newDeviceHarness(t, nil)
	user := harness.signUp(t, 40)
	code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
	_, _ = harness.verify(t, code.UserCode, user.Headers)
	if _, err := harness.decision(t, "deviceApprove", code.UserCode, user.Headers); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "deviceCode", Where: []storage.Where{{Field: "deviceCode", Value: code.DeviceCode}},
		Update: storage.Record{"expiresAt": harness.clock.Now().Add(-time.Second)},
	}); err != nil {
		t.Fatal(err)
	}
	result, err := harness.poll(t, code.DeviceCode, "test-client")
	assertOAuthError(t, result, err, http.StatusBadRequest, "expired_token", MessageExpiredDeviceCode)
	if record := harness.deviceRecord(t, "deviceCode", code.DeviceCode); record != nil {
		t.Fatalf("expired approved code survived: %#v", record)
	}
}
