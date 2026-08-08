package saml

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AuthnRequestRecord is the one-time correlation state created before an
// SP-initiated redirect or POST.
type AuthnRequestRecord struct {
	RequestID  string
	ProviderID string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// AssertionReplayRecord is the atomic replay tombstone for an assertion ID.
type AssertionReplayRecord struct {
	AssertionID string
	Issuer      string
	ProviderID  string
	UsedAt      time.Time
	ExpiresAt   time.Time
}

// AuthnRequestStore must atomically consume request IDs. A read followed by a
// delete is not a valid implementation because concurrent callbacks could both
// succeed.
type AuthnRequestStore interface {
	PutAuthnRequest(context.Context, AuthnRequestRecord) error
	ConsumeAuthnRequest(context.Context, string) (AuthnRequestRecord, bool, error)
}

// AssertionReplayStore must atomically reserve assertion IDs. It returns false
// when an unexpired tombstone already exists.
type AssertionReplayStore interface {
	ReserveAssertion(context.Context, AssertionReplayRecord) (bool, error)
}

// InResponseToValidationOptions configures one-time AuthnRequest correlation.
// Both validation and IdP-initiated SSO are enabled by default, as in Better
// Auth. Use pointers when an explicit false value is needed.
type InResponseToValidationOptions struct {
	EnableValidation   *bool
	AllowIDPInitiated  *bool
	ProviderID         string
	ExpectedRecipients []string
	Store              AuthnRequestStore
	Now                func() time.Time
}

// AssertionReplayOptions configures the assertion replay reservation.
type AssertionReplayOptions struct {
	ProviderID string
	Issuer     string
	ClockSkew  *time.Duration
	Store      AssertionReplayStore
	Now        func() time.Time
	Warn       func(message string, fields map[string]any)
}

// RecordAuthnRequest writes a correlation record using the reference implementation's five
// minute default TTL.
func RecordAuthnRequest(
	ctx context.Context,
	store AuthnRequestStore,
	request AuthnRequest,
	providerID string,
	ttl time.Duration,
	now func() time.Time,
) (AuthnRequestRecord, error) {
	if err := contextError(ctx); err != nil {
		return AuthnRequestRecord{}, err
	}
	if store == nil {
		return AuthnRequestRecord{}, newError(
			"SAML_AUTHN_REQUEST_STORE_MISSING",
			"SAML AuthnRequest store is not configured",
		)
	}
	if request.ID == "" || providerID == "" {
		return AuthnRequestRecord{}, newError(
			"SAML_AUTHN_REQUEST_RECORD_INVALID",
			"SAML AuthnRequest record requires request and provider IDs",
		)
	}
	if ttl == 0 {
		ttl = DefaultAuthnRequestTTL
	}
	if ttl < 0 {
		return AuthnRequestRecord{}, newError(
			"SAML_AUTHN_REQUEST_TTL_INVALID",
			"SAML AuthnRequest TTL must be positive",
		)
	}
	createdAt := currentTime(now)
	record := AuthnRequestRecord{
		RequestID:  request.ID,
		ProviderID: providerID,
		CreatedAt:  createdAt,
		ExpiresAt:  createdAt.Add(ttl),
	}
	if err := store.PutAuthnRequest(ctx, record); err != nil {
		return AuthnRequestRecord{}, newError(
			"SAML_AUTHN_REQUEST_STORE_FAILED",
			"Failed to store SAML AuthnRequest correlation state",
			err,
		)
	}
	return record, nil
}

// ValidateInResponseTo resolves the authenticated response correlation value
// and consumes it atomically. The record is consumed even when its provider is
// wrong, matching the reference implementation and preventing repeated probing.
func ValidateInResponseTo(
	ctx context.Context,
	response Response,
	options InResponseToValidationOptions,
) (*AuthnRequestRecord, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if options.EnableValidation != nil && !*options.EnableValidation {
		return nil, nil
	}
	inResponseTo, err := responseCorrelationID(response, options.ExpectedRecipients)
	if err != nil {
		return nil, err
	}
	allowIDPInitiated := options.AllowIDPInitiated == nil || *options.AllowIDPInitiated
	if inResponseTo == "" {
		if allowIDPInitiated {
			return nil, nil
		}
		return nil, newError(
			"SAML_UNSOLICITED_RESPONSE",
			"IdP-initiated SSO is not allowed",
		)
	}
	if options.Store == nil {
		return nil, newError(
			"SAML_AUTHN_REQUEST_STORE_MISSING",
			"SAML AuthnRequest store is not configured",
		)
	}
	record, found, err := options.Store.ConsumeAuthnRequest(ctx, inResponseTo)
	if err != nil {
		return nil, newError(
			"SAML_AUTHN_REQUEST_CONSUME_FAILED",
			"Failed to consume SAML AuthnRequest correlation state",
			err,
		)
	}
	if !found {
		return nil, newError(
			"SAML_IN_RESPONSE_TO_UNKNOWN",
			"Unknown or expired SAML AuthnRequest ID",
		)
	}
	if !record.ExpiresAt.IsZero() && currentTime(options.Now).After(record.ExpiresAt) {
		return nil, newError(
			"SAML_IN_RESPONSE_TO_UNKNOWN",
			"Unknown or expired SAML AuthnRequest ID",
		)
	}
	if record.ProviderID != options.ProviderID {
		return nil, newError(
			"SAML_IN_RESPONSE_TO_PROVIDER_MISMATCH",
			"SAML AuthnRequest provider does not match the response provider",
		)
	}
	return &record, nil
}

func responseCorrelationID(response Response, expectedRecipients []string) (string, error) {
	var assertionValue string
	recipients := stringSet(expectedRecipients)
	for _, confirmation := range response.Assertion.SubjectConfirmations {
		if confirmation.Method != BearerConfirmation || confirmation.InResponseTo == "" {
			continue
		}
		if len(recipients) > 0 {
			if _, expected := recipients[confirmation.Recipient]; !expected {
				continue
			}
		}
		if assertionValue != "" && assertionValue != confirmation.InResponseTo {
			return "", newError(
				"SAML_IN_RESPONSE_TO_MISMATCH",
				"SAML bearer confirmations contain conflicting InResponseTo values",
			)
		}
		assertionValue = confirmation.InResponseTo
	}
	if response.InResponseTo != "" && assertionValue != "" &&
		response.InResponseTo != assertionValue {
		return "", newError(
			"SAML_IN_RESPONSE_TO_MISMATCH",
			"SAML Response and Assertion InResponseTo values do not match",
		)
	}
	if assertionValue != "" {
		return assertionValue, nil
	}
	return response.InResponseTo, nil
}

// ReserveAssertionReplay atomically reserves the assertion ID. A missing ID is
// skipped with a warning for the reference implementation compatibility.
func ReserveAssertionReplay(
	ctx context.Context,
	response Response,
	options AssertionReplayOptions,
) (AssertionReplayRecord, error) {
	if err := contextError(ctx); err != nil {
		return AssertionReplayRecord{}, err
	}
	assertionID := response.Assertion.ID
	if assertionID == "" {
		if options.Warn != nil {
			options.Warn(
				"Could not extract assertion ID for replay protection",
				map[string]any{"providerId": options.ProviderID},
			)
		}
		return AssertionReplayRecord{}, nil
	}
	if options.Store == nil {
		return AssertionReplayRecord{}, newError(
			"SAML_ASSERTION_REPLAY_STORE_MISSING",
			"SAML assertion replay store is not configured",
		)
	}
	clockSkew := DefaultClockSkew
	if options.ClockSkew != nil {
		clockSkew = *options.ClockSkew
		if clockSkew < 0 {
			return AssertionReplayRecord{}, newError(
				"SAML_CLOCK_SKEW_INVALID",
				"SAML clock skew must not be negative",
			)
		}
	}
	now := currentTime(options.Now)
	expiresAt := now.Add(DefaultAssertionTTL)
	if rawExpiry := response.Assertion.Conditions.NotOnOrAfter; rawExpiry != "" {
		parsedExpiry, err := time.Parse(time.RFC3339Nano, rawExpiry)
		if err != nil {
			return AssertionReplayRecord{}, newError(
				"SAML_NOT_ON_OR_AFTER_INVALID",
				"SAML assertion has invalid NotOnOrAfter timestamp",
				err,
			)
		}
		expiresAt = parsedExpiry.Add(clockSkew)
	}
	issuer := options.Issuer
	if issuer == "" {
		issuer = response.Assertion.Issuer
	}
	if issuer == "" {
		issuer = response.Issuer
	}
	record := AssertionReplayRecord{
		AssertionID: assertionID,
		Issuer:      issuer,
		ProviderID:  options.ProviderID,
		UsedAt:      now,
		ExpiresAt:   expiresAt,
	}
	reserved, err := options.Store.ReserveAssertion(ctx, record)
	if err != nil {
		return AssertionReplayRecord{}, newError(
			"SAML_ASSERTION_REPLAY_STORE_FAILED",
			"Failed to reserve SAML assertion replay state",
			err,
		)
	}
	if !reserved {
		return AssertionReplayRecord{}, newError(
			"SAML_ASSERTION_REPLAYED",
			"SAML assertion has already been used",
		)
	}
	return record, nil
}

// MemoryStore is a process-local, concurrency-safe reference implementation of
// both correlation stores. Distributed deployments should provide a shared
// implementation with equivalent atomic consume/reserve operations.
type MemoryStore struct {
	mu            sync.Mutex
	now           func() time.Time
	authnRequests map[string]AuthnRequestRecord
	assertions    map[string]AssertionReplayRecord
}

// NewMemoryStore creates an empty reference store. now may be nil.
func NewMemoryStore(now func() time.Time) *MemoryStore {
	return &MemoryStore{
		now:           now,
		authnRequests: make(map[string]AuthnRequestRecord),
		assertions:    make(map[string]AssertionReplayRecord),
	}
}

// PutAuthnRequest implements AuthnRequestStore.
func (store *MemoryStore) PutAuthnRequest(
	ctx context.Context,
	record AuthnRequestRecord,
) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if record.RequestID == "" || record.ExpiresAt.IsZero() {
		return newError(
			"SAML_AUTHN_REQUEST_RECORD_INVALID",
			"SAML AuthnRequest record is invalid",
		)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ensureMaps()
	if existing, ok := store.authnRequests[record.RequestID]; ok &&
		!currentTime(store.now).After(existing.ExpiresAt) {
		return newError(
			"SAML_AUTHN_REQUEST_EXISTS",
			fmt.Sprintf("SAML AuthnRequest already exists: %s", record.RequestID),
		)
	}
	store.authnRequests[record.RequestID] = record
	return nil
}

// ConsumeAuthnRequest implements AuthnRequestStore as one mutex-protected
// take operation.
func (store *MemoryStore) ConsumeAuthnRequest(
	ctx context.Context,
	requestID string,
) (AuthnRequestRecord, bool, error) {
	if err := contextError(ctx); err != nil {
		return AuthnRequestRecord{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ensureMaps()
	record, found := store.authnRequests[requestID]
	if !found {
		return AuthnRequestRecord{}, false, nil
	}
	delete(store.authnRequests, requestID)
	if currentTime(store.now).After(record.ExpiresAt) {
		return AuthnRequestRecord{}, false, nil
	}
	return record, true, nil
}

// ReserveAssertion implements AssertionReplayStore as one mutex-protected
// compare-and-insert operation.
func (store *MemoryStore) ReserveAssertion(
	ctx context.Context,
	record AssertionReplayRecord,
) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	if record.AssertionID == "" || record.ExpiresAt.IsZero() {
		return false, newError(
			"SAML_ASSERTION_REPLAY_RECORD_INVALID",
			"SAML assertion replay record is invalid",
		)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ensureMaps()
	now := currentTime(store.now)
	if existing, ok := store.assertions[record.AssertionID]; ok {
		if !now.After(existing.ExpiresAt) {
			return false, nil
		}
		delete(store.assertions, record.AssertionID)
	}
	store.assertions[record.AssertionID] = record
	return true, nil
}

func (store *MemoryStore) ensureMaps() {
	if store.authnRequests == nil {
		store.authnRequests = make(map[string]AuthnRequestRecord)
	}
	if store.assertions == nil {
		store.assertions = make(map[string]AssertionReplayRecord)
	}
}

func currentTime(now func() time.Time) time.Time {
	if now != nil {
		return now()
	}
	return time.Now()
}
