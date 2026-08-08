package apikey

import (
	"context"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
)

func TestAPIKeyExpirationConversionIsArchitectureIndependent(t *testing.T) {
	duration, exceedsDuration := durationFromFloat64(315_360_000_000, time.Second)
	if !exceedsDuration || duration != time.Duration(math.MaxInt64) {
		t.Fatalf("positive overflow duration=%v exceeds=%t", duration, exceedsDuration)
	}

	duration, exceedsDuration = durationFromFloat64(-315_360_000_000, time.Second)
	if exceedsDuration || duration != time.Duration(math.MinInt64) {
		t.Fatalf("negative overflow duration=%v exceeds=%t", duration, exceedsDuration)
	}

	duration, exceedsDuration = durationFromFloat64(1.5, time.Second)
	if exceedsDuration || duration != 1500*time.Millisecond {
		t.Fatalf("fractional duration=%v exceeds=%t", duration, exceedsDuration)
	}
}

func TestAPIKeyHTTPCreateRequiresSessionAndRejectsTrustedFields(t *testing.T) {
	harness := newOrgAPIKeyHarness(t, true, nil, bothAPIKeyConfigurations())
	owner := harness.signUp(t, "endpoint-owner")

	status, _, body := harness.exchange(t, http.MethodPost, "/api-key/create", "", map[string]any{
		"configId": "user-keys",
	}, nil)
	assertAPIKeyHTTPError(t, status, body, http.StatusUnauthorized, ErrorUnauthorizedSession)

	status, _, body = harness.exchange(t, http.MethodPost, "/api-key/create", owner.Cookie, map[string]any{
		"configId": "user-keys", "userId": owner.ID,
	}, nil)
	assertAPIKeyHTTPError(t, status, body, http.StatusUnauthorized, ErrorUnauthorizedSession)

	serverOnlyValues := map[string]any{
		"refillAmount":        int64(1),
		"refillInterval":      int64(1000),
		"rateLimitMax":        int64(100),
		"rateLimitTimeWindow": int64(1000),
		"rateLimitEnabled":    false,
		"permissions":         map[string][]string{"documents": {"read"}},
		"remaining":           int64(1),
	}
	for field, value := range serverOnlyValues {
		field, value := field, value
		t.Run(field, func(t *testing.T) {
			status, _, body := harness.exchange(t, http.MethodPost, "/api-key/create", owner.Cookie, map[string]any{
				"configId": "user-keys", field: value,
			}, nil)
			assertAPIKeyHTTPError(t, status, body, http.StatusBadRequest, ErrorServerOnlyProperty)
		})
	}

	status, _, body = harness.exchange(t, http.MethodPost, "/api-key/create", owner.Cookie, map[string]any{
		"configId": "user-keys", "remaining": nil,
	}, nil)
	if status != http.StatusOK || body["referenceId"] != owner.ID {
		t.Fatalf("remaining:null HTTP create status=%d body=%#v", status, body)
	}
}

func TestAPIKeyDirectCreateAcceptsUserIDAndVerifyRemainsServerOnly(t *testing.T) {
	harness := newOrgAPIKeyHarness(t, true, nil, bothAPIKeyConfigurations())
	owner := harness.signUp(t, "direct-owner")
	created := harness.mustInvokeObject(t, "createApiKey", http.MethodPost, "", map[string]any{
		"configId": "user-keys", "userId": owner.ID,
	})
	if created["referenceId"] != owner.ID {
		t.Fatalf("direct create referenceId=%#v, want %q", created["referenceId"], owner.ID)
	}

	status, _, body := harness.exchange(t, http.MethodPost, "/api-key/verify", "", map[string]any{
		"configId": "user-keys", "key": created["key"],
	}, nil)
	if status != http.StatusNotFound {
		t.Fatalf("server-only verify HTTP status=%d body=%#v, want 404", status, body)
	}

	verified := harness.mustInvokeObject(t, "verifyApiKey", http.MethodPost, "", map[string]any{
		"configId": "user-keys", "key": created["key"],
	})
	key, _ := verified["key"].(map[string]any)
	if verified["valid"] != true || key["referenceId"] != owner.ID {
		t.Fatalf("direct verify result=%#v", verified)
	}
}

func TestAPIKeyCreateValidatesReferenceSchemaConstraints(t *testing.T) {
	harness := newOrgAPIKeyHarness(t, true, nil, bothAPIKeyConfigurations())
	owner := harness.signUp(t, "create-validation-owner")
	service, err := NewService(Options{
		Configurations: []Configuration{{
			References: ReferenceUser, EnableMetadata: true,
		}},
		Runtime: Runtime{
			Adapter: harness.adapter,
			Clock:   func() time.Time { return harness.clock },
			KeyGenerator: func(_ context.Context, length int, prefix string) (string, error) {
				return prefix + strings.Repeat("K", length), nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tooShortExpiry := 500 * time.Millisecond
	negativeRemaining := int64(-1)
	zeroRefill := int64(0)
	refillInterval := time.Second
	for _, test := range []struct {
		name  string
		input CreateInput
	}{
		{name: "prefix_format", input: CreateInput{UserID: owner.ID, Prefix: "invalid.prefix"}},
		{name: "expires_in_minimum", input: CreateInput{UserID: owner.ID, ExpiresIn: &tooShortExpiry}},
		{name: "remaining_minimum", input: CreateInput{UserID: owner.ID, Remaining: &negativeRemaining}},
		{name: "refill_amount_minimum", input: CreateInput{UserID: owner.ID, RefillAmount: &zeroRefill, RefillInterval: &refillInterval}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, createErr := service.Create(t.Context(), test.input)
			statusError, ok := contract.AsAPIError(createErr)
			if !ok || statusError.Status != http.StatusBadRequest || statusError.Code != "VALIDATION_ERROR" || statusError.Message != "Invalid request body" {
				t.Fatalf("Create error=%#v, want single-auth validation error", createErr)
			}
		})
	}

	created, err := service.Create(t.Context(), CreateInput{
		UserID: owner.ID,
		Metadata: map[string]string{
			"scope": "read",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata, ok := created.Metadata.(map[string]any)
	if !ok || metadata["scope"] != "read" {
		t.Fatalf("typed Go metadata was not normalized as a JSON object: %#v", created.Metadata)
	}
}

func assertAPIKeyHTTPError(t *testing.T, status int, body map[string]any, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus || body["code"] != wantCode || body["message"] != errorMessages[wantCode] {
		t.Fatalf("status=%d body=%#v, want status=%d code=%s message=%q", status, body, wantStatus, wantCode, errorMessages[wantCode])
	}
}
