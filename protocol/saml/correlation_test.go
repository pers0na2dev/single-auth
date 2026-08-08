package saml

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Oracle cases ported from the reference implementation 1.6.26 InResponseTo and replay tests.
func TestValidateInResponseToOracle(t *testing.T) {
	response, err := ParseResponse(validResponseFixture())
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore(func() time.Time { return fixtureNow })
	record, err := RecordAuthnRequest(
		context.Background(),
		store,
		AuthnRequest{ID: fixtureRequestID},
		"provider",
		0,
		func() time.Time { return fixtureNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.ExpiresAt != fixtureNow.Add(DefaultAuthnRequestTTL) {
		t.Fatalf("record expiry = %s", record.ExpiresAt)
	}
	consumed, err := ValidateInResponseTo(context.Background(), response, InResponseToValidationOptions{
		ProviderID: "provider",
		Store:      store,
		Now:        func() time.Time { return fixtureNow },
	})
	if err != nil || consumed == nil || consumed.RequestID != fixtureRequestID {
		t.Fatalf("consumed = %+v, error = %v", consumed, err)
	}
	if _, err := ValidateInResponseTo(context.Background(), response, InResponseToValidationOptions{
		ProviderID: "provider",
		Store:      store,
		Now:        func() time.Time { return fixtureNow },
	}); !IsErrorCode(err, "SAML_IN_RESPONSE_TO_UNKNOWN") {
		t.Fatalf("second consume error = %v", err)
	}
}

func TestInResponseToDefaultsAndFailures(t *testing.T) {
	response, err := ParseResponse(validResponseFixture())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("IdP initiated allowed by default", func(t *testing.T) {
		unsolicited := response
		unsolicited.Assertion.SubjectConfirmations = append(
			[]SubjectConfirmationData(nil),
			response.Assertion.SubjectConfirmations...,
		)
		unsolicited.InResponseTo = ""
		for index := range unsolicited.Assertion.SubjectConfirmations {
			unsolicited.Assertion.SubjectConfirmations[index].InResponseTo = ""
		}
		if record, err := ValidateInResponseTo(
			context.Background(),
			unsolicited,
			InResponseToValidationOptions{},
		); err != nil || record != nil {
			t.Fatalf("record = %+v, error = %v", record, err)
		}
		if _, err := ValidateInResponseTo(
			context.Background(),
			unsolicited,
			InResponseToValidationOptions{AllowIDPInitiated: boolPointer(false)},
		); !IsErrorCode(err, "SAML_UNSOLICITED_RESPONSE") {
			t.Fatalf("strict unsolicited error = %v", err)
		}
	})

	t.Run("explicitly disabled", func(t *testing.T) {
		if _, err := ValidateInResponseTo(
			context.Background(),
			response,
			InResponseToValidationOptions{EnableValidation: boolPointer(false)},
		); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("provider mismatch consumes record", func(t *testing.T) {
		store := NewMemoryStore(func() time.Time { return fixtureNow })
		_, err := RecordAuthnRequest(
			context.Background(),
			store,
			AuthnRequest{ID: fixtureRequestID},
			"other-provider",
			0,
			func() time.Time { return fixtureNow },
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateInResponseTo(context.Background(), response, InResponseToValidationOptions{
			ProviderID: "provider",
			Store:      store,
			Now:        func() time.Time { return fixtureNow },
		}); !IsErrorCode(err, "SAML_IN_RESPONSE_TO_PROVIDER_MISMATCH") {
			t.Fatalf("provider mismatch error = %v", err)
		}
		if _, found, err := store.ConsumeAuthnRequest(context.Background(), fixtureRequestID); err != nil || found {
			t.Fatalf("mismatched record was not consumed: found = %t, error = %v", found, err)
		}
	})

	t.Run("response and assertion mismatch", func(t *testing.T) {
		mismatched := response
		mismatched.Assertion.SubjectConfirmations = append(
			[]SubjectConfirmationData(nil),
			response.Assertion.SubjectConfirmations...,
		)
		mismatched.Assertion.SubjectConfirmations[0].InResponseTo = "_other"
		if _, err := ValidateInResponseTo(
			context.Background(),
			mismatched,
			InResponseToValidationOptions{},
		); !IsErrorCode(err, "SAML_IN_RESPONSE_TO_MISMATCH") {
			t.Fatalf("mismatch error = %v", err)
		}
	})

	t.Run("correlation uses the confirmation for this recipient", func(t *testing.T) {
		mixed := response
		mixed.Assertion.SubjectConfirmations = append(
			[]SubjectConfirmationData{{
				Method:       BearerConfirmation,
				Recipient:    "https://other.example.com/acs",
				InResponseTo: "_other",
			}},
			response.Assertion.SubjectConfirmations...,
		)
		store := NewMemoryStore(func() time.Time { return fixtureNow })
		if err := store.PutAuthnRequest(context.Background(), AuthnRequestRecord{
			RequestID:  fixtureRequestID,
			ProviderID: "provider",
			CreatedAt:  fixtureNow,
			ExpiresAt:  fixtureNow.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateInResponseTo(context.Background(), mixed, InResponseToValidationOptions{
			ProviderID:         "provider",
			ExpectedRecipients: []string{fixtureRecipient},
			Store:              store,
			Now:                func() time.Time { return fixtureNow },
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("expired request", func(t *testing.T) {
		store := NewMemoryStore(func() time.Time { return fixtureNow })
		if err := store.PutAuthnRequest(context.Background(), AuthnRequestRecord{
			RequestID:  fixtureRequestID,
			ProviderID: "provider",
			CreatedAt:  fixtureNow.Add(-time.Hour),
			ExpiresAt:  fixtureNow.Add(-time.Second),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateInResponseTo(context.Background(), response, InResponseToValidationOptions{
			ProviderID: "provider",
			Store:      store,
			Now:        func() time.Time { return fixtureNow },
		}); !IsErrorCode(err, "SAML_IN_RESPONSE_TO_UNKNOWN") {
			t.Fatalf("expired error = %v", err)
		}
	})
}

func TestMemoryStoreConcurrentConsume(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore(func() time.Time { return fixtureNow })
	if err := store.PutAuthnRequest(context.Background(), AuthnRequestRecord{
		RequestID:  fixtureRequestID,
		ProviderID: "provider",
		CreatedAt:  fixtureNow,
		ExpiresAt:  fixtureNow.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var waitGroup sync.WaitGroup
	for range 32 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, found, err := store.ConsumeAuthnRequest(context.Background(), fixtureRequestID)
			if err != nil {
				t.Errorf("ConsumeAuthnRequest() error = %v", err)
				return
			}
			if found {
				successes.Add(1)
			}
		}()
	}
	waitGroup.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful consumes = %d, want 1", successes.Load())
	}
}

func TestReserveAssertionReplayOracle(t *testing.T) {
	response, err := ParseResponse(validResponseFixture())
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore(func() time.Time { return fixtureNow })
	options := AssertionReplayOptions{
		ProviderID: "provider",
		Store:      store,
		Now:        func() time.Time { return fixtureNow },
	}
	record, err := ReserveAssertionReplay(context.Background(), response, options)
	if err != nil {
		t.Fatal(err)
	}
	wantExpiry := fixtureNow.Add(10 * time.Minute)
	if record.AssertionID != "_assertion" || record.Issuer != fixtureIssuer ||
		!record.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("replay record = %+v, want expiry %s", record, wantExpiry)
	}
	if _, err := ReserveAssertionReplay(context.Background(), response, options); !IsErrorCode(err, "SAML_ASSERTION_REPLAYED") {
		t.Fatalf("replay error = %v", err)
	}

	missingID := response
	missingID.Assertion.ID = ""
	warned := false
	if record, err := ReserveAssertionReplay(context.Background(), missingID, AssertionReplayOptions{
		Warn: func(message string, fields map[string]any) { warned = message != "" },
	}); err != nil || record.AssertionID != "" || !warned {
		t.Fatalf("missing-ID record = %+v, error = %v, warned = %t", record, err, warned)
	}
}

func TestMemoryStoreConcurrentReplayReservation(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore(func() time.Time { return fixtureNow })
	record := AssertionReplayRecord{
		AssertionID: "_concurrent",
		Issuer:      fixtureIssuer,
		ProviderID:  "provider",
		UsedAt:      fixtureNow,
		ExpiresAt:   fixtureNow.Add(time.Minute),
	}
	var successes atomic.Int32
	var waitGroup sync.WaitGroup
	for range 32 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			reserved, err := store.ReserveAssertion(context.Background(), record)
			if err != nil {
				t.Errorf("ReserveAssertion() error = %v", err)
				return
			}
			if reserved {
				successes.Add(1)
			}
		}()
	}
	waitGroup.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful reservations = %d, want 1", successes.Load())
	}
}
