package deviceauthorization

import (
	"net/http"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestApprovedDeviceCodeRedeemsAtMostOnceUnderConcurrentPolling(t *testing.T) {
	harness := newDeviceHarness(t, nil)
	user := harness.signUp(t, 50)
	code := harness.requestCode(t, map[string]any{"client_id": "test-client"})
	if _, err := harness.verify(t, code.UserCode, user.Headers); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.decision(t, "deviceApprove", code.UserCode, user.Headers); err != nil {
		t.Fatal(err)
	}

	type result struct {
		body map[string]any
		err  error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			call, err := harness.poll(t, code.DeviceCode, "test-client")
			var body map[string]any
			if call.Value != nil {
				body, _ = call.Value.(map[string]any)
			}
			results <- result{body: body, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	successes := 0
	failures := 0
	for outcome := range results {
		if outcome.err == nil && outcome.body["access_token"] != nil {
			successes++
			continue
		}
		failures++
		if apiError, ok := contract.AsAPIError(outcome.err); !ok ||
			(apiError.Code != "INVALID_GRANT" && apiError.Code != "SLOW_DOWN") {
			t.Fatalf("losing poll error = %T %#v body=%#v", outcome.err, outcome.err, outcome.body)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("concurrent results: successes=%d failures=%d", successes, failures)
	}
	if record := harness.deviceRecord(t, "deviceCode", code.DeviceCode); record != nil {
		t.Fatalf("redeemed row survived: %#v", record)
	}
	sessions, err := harness.auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
		Model: "session", Where: []storage.Where{{Field: "userId", Value: user.ID}},
	})
	if err != nil || len(sessions) != 2 {
		t.Fatalf("user sessions = %#v, %v", sessions, err)
	}
	replay, replayErr := harness.poll(t, code.DeviceCode, "test-client")
	assertOAuthError(t, replay, replayErr, http.StatusBadRequest, "invalid_grant", MessageInvalidDeviceCode)
}

func TestConcurrentVerificationNeverOverwritesTheFirstClaim(t *testing.T) {
	harness := newDeviceHarness(t, nil)
	first := harness.signUp(t, 51)
	second := harness.signUp(t, 52)
	code := harness.requestCode(t, map[string]any{"client_id": "test-client"})

	const workers = 64
	start := make(chan struct{})
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		headers := first.Headers
		if index%2 == 1 {
			headers = second.Headers
		}
		go func(headers contract.Headers) {
			defer wait.Done()
			<-start
			_, err := harness.verify(t, code.UserCode, headers)
			errors <- err
		}(headers)
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("verify error = %v", err)
		}
	}
	record := harness.deviceRecord(t, "userCode", code.UserCode)
	owner, _ := recordString(record, "userId")
	if owner != first.ID && owner != second.ID {
		t.Fatalf("claim owner = %q record=%#v", owner, record)
	}
	ownerUser, otherUser := first, second
	if owner == second.ID {
		ownerUser, otherUser = second, first
	}
	denied, deniedErr := harness.decision(t, "deviceApprove", code.UserCode, otherUser.Headers)
	assertOAuthError(t, denied, deniedErr, http.StatusForbidden, "access_denied", "You are not authorized to approve this device authorization")
	approved, approvedErr := harness.decision(t, "deviceApprove", code.UserCode, ownerUser.Headers)
	if approvedErr != nil || decodeObjectResponse(t, approved)["success"] != true {
		t.Fatalf("owner approve = %#v, %v", approved.Value, approvedErr)
	}
}
