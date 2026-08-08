package phonenumber

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

func TestConcurrentVerificationReadsThenAtomicallyAllowsExactlyOneSuccess(t *testing.T) {
	schema, err := storage.CoreSchema().Merge(mustPhoneSchema(t))
	if err != nil {
		t.Fatal(err)
	}
	var ids atomic.Int64
	adapter, err := memory.New(
		memory.WithSchema(schema),
		memory.WithIDGenerator(func(model string) (any, error) {
			return fmt.Sprintf("%s-%d", model, ids.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	phone := "+251900000099"
	var code string
	var entered atomic.Int64
	release := make(chan struct{})
	var releaseOnce sync.Once
	peek := func(ctx context.Context, identifier string) (storage.Record, error) {
		row, findErr := findLatestVerification(ctx, adapter, identifier)
		if identifier == phone {
			if entered.Add(1) >= 2 {
				releaseOnce.Do(func() { close(release) })
			}
			<-release
		}
		return row, findErr
	}
	descriptor, err := New(Options{
		SendOTP: func(_ context.Context, message OTPMessage, _ *engine.Context) error {
			code = message.Code
			return nil
		},
		SignUpOnVerification: &SignUpOnVerificationOptions{
			GetTempEmail: func(phone string) string { return "temp-" + phone },
		},
		Runtime: Runtime{
			Adapter:          adapter,
			PeekVerification: peek,
			IssueSession: func(_ *engine.Context, userID string, _ bool) (*SessionState, error) {
				return &SessionState{
					Session: storage.Record{"id": "session-" + userID, "token": "token-" + userID},
					User:    storage.Record{"id": userID},
				}, nil
			},
			ResolveSession:        func(*engine.Context) (*SessionState, error) { return nil, nil },
			RegisterDatabaseHooks: func(singleauth.DatabaseHooks) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := engine.NewRegistry(nil, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	dispatch := func(path string, body map[string]any) (contract.Response, error) {
		encoded, _ := json.Marshal(body)
		return dispatcher.Dispatch(contract.NewRequest(http.MethodPost, "/api/auth"+path, contract.RequestOptions{
			Headers: contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"}),
			Body:    encoded,
		}))
	}
	if sent, sendErr := dispatch("/phone-number/send-otp", map[string]any{"phoneNumber": phone}); sendErr != nil || sent.Status() != http.StatusOK {
		t.Fatalf("send status=%d err=%v body=%s", sent.Status(), sendErr, sent.Body())
	}

	type result struct {
		response contract.Response
		err      error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			response, callErr := dispatch("/phone-number/verify", map[string]any{
				"phoneNumber": phone, "code": code,
			})
			results <- result{response: response, err: callErr}
		}()
	}
	successes, invalid := 0, 0
	for range 2 {
		result := <-results
		if result.response.Status() == http.StatusOK {
			successes++
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(result.response.Body(), &body); err != nil {
			t.Fatal(err)
		}
		if result.response.Status() == http.StatusBadRequest && body["code"] == CodeInvalidOTP {
			invalid++
			continue
		}
		t.Fatalf("race response status=%d body=%s err=%v", result.response.Status(), result.response.Body(), result.err)
	}
	if successes != 1 || invalid != 1 {
		t.Fatalf("successes=%d invalid=%d", successes, invalid)
	}
	if row, findErr := findLatestVerification(t.Context(), adapter, phone); findErr != nil || row != nil {
		t.Fatalf("verification row=%#v err=%v", row, findErr)
	}
	users, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "user"})
	if err != nil || len(users) != 1 {
		t.Fatalf("users=%#v err=%v", users, err)
	}
}

func mustPhoneSchema(t *testing.T) storage.Schema {
	t.Helper()
	schema, err := Schema(Options{})
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func TestConcurrentUniquePhoneClaimsCreateOnlyOneOwner(t *testing.T) {
	store := newCaptureStore()
	auth, _ := newRootHarness(t, standardOptions(store), nil)
	phone := "+15559990000"
	cookies := make([]string, 2)
	for index, email := range []string{"claim-a@example.com", "claim-b@example.com"} {
		created := exchange(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
			"email": email, "name": email, "password": "password123",
		})
		if created.status != http.StatusOK {
			t.Fatalf("sign-up %d status=%d body=%#v", index, created.status, created.body)
		}
		cookies[index] = created.cookie
	}
	// Each send rotates the code. Both callers intentionally use the latest
	// code, so OTP consumption is also a single winner before the unique field
	// can be written.
	exchange(t, auth, http.MethodPost, "/phone-number/send-otp", cookies[0], map[string]any{"phoneNumber": phone})
	code := store.code(phone)
	results := make(chan httpResult, 2)
	for index := range 2 {
		index := index
		go func() {
			results <- exchange(t, auth, http.MethodPost, "/phone-number/verify", cookies[index], map[string]any{
				"phoneNumber": phone, "code": code, "updatePhoneNumber": true,
			})
		}()
	}
	successes := 0
	for range 2 {
		result := <-results
		if result.status == http.StatusOK {
			successes++
		} else if result.status != http.StatusBadRequest {
			t.Fatalf("claim status=%d body=%#v", result.status, result.body)
		}
	}
	if successes != 1 {
		t.Fatalf("successful claims = %d", successes)
	}
	owners, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
		Model: "user", Where: []storage.Where{{Field: "phoneNumber", Value: phone}},
	})
	if err != nil || len(owners) != 1 {
		t.Fatalf("owners=%#v err=%v", owners, err)
	}
}
