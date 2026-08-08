package core

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

// InternalAdapter is the Go counterpart of upstream implementation's internalAdapter.
// It keeps lifecycle hooks, secondary-storage behavior, identifier hashing,
// and transaction scoping above the raw storage.Adapter contract.
type InternalAdapter struct {
	auth *Auth
}

// InternalOAuthUser is the user/account pair created by CreateOAuthUser.
type InternalOAuthUser struct {
	User    storage.Record
	Account storage.Record
}

// InternalSession is the joined session/user value returned by FindSession
// and FindSessions.
type InternalSession struct {
	Session storage.Record
	User    storage.Record
}

// InternalSessionCreateOptions represents upstream implementation's optional
// dontRememberMe, override, and overrideAll createSession arguments.
type InternalSessionCreateOptions struct {
	DontRemember bool
	Override     storage.Record
	OverrideAll  bool
	IPAddress    string
	UserAgent    string
}

// VerificationValue is the create/reserve input for a single-use value.
type VerificationValue struct {
	Identifier string
	Value      string
	ExpiresAt  time.Time
}

// InternalAdapter returns a lightweight immutable facade backed by this Auth.
func (a *Auth) InternalAdapter() InternalAdapter { return InternalAdapter{auth: a} }

func (internal InternalAdapter) valid() bool {
	return internal.auth != nil && internal.auth.adapter != nil
}

// CreateOAuthUser atomically creates the user and provider account, including
// configured ID generation and every database create hook.
func (internal InternalAdapter) CreateOAuthUser(
	ctx context.Context,
	user storage.Record,
	account storage.Record,
) (InternalOAuthUser, error) {
	if !internal.valid() {
		return InternalOAuthUser{}, errors.New("single-auth: auth is not initialized")
	}
	var result InternalOAuthUser
	err := internal.auth.runWithTransactionAdapter(ctx, func(txContext context.Context, tx storage.TransactionAdapter) error {
		createdUser, err := internal.auth.createInternalUser(txContext, tx, user)
		if err != nil {
			return err
		}
		accountData := cloneStorageRecord(account)
		accountData["userId"] = createdUser["id"]
		for _, field := range []string{
			"accessToken", "refreshToken", "idToken", "accessTokenExpiresAt",
			"refreshTokenExpiresAt", "scope", "password",
		} {
			if _, exists := accountData[field]; !exists {
				accountData[field] = nil
			}
		}
		now := internal.auth.options.Clock().UTC()
		accountData["createdAt"] = now
		accountData["updatedAt"] = now
		createdAccount, err := internal.auth.createInternalRecord(txContext, tx, "account", accountData)
		if err != nil {
			return err
		}
		result = InternalOAuthUser{
			User: cloneStorageRecord(createdUser), Account: cloneStorageRecord(createdAccount),
		}
		return nil
	})
	return result, err
}

// CreateUser creates one canonical user through the internal hook pipeline.
func (internal InternalAdapter) CreateUser(ctx context.Context, user storage.Record) (storage.Record, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	return internal.auth.createInternalUser(
		ctx, currentTransactionAdapter(ctx, internal.auth.adapter), user,
	)
}

func (a *Auth) createInternalUser(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	user storage.Record,
) (storage.Record, error) {
	now := a.options.Clock().UTC()
	data := storage.Record{"createdAt": now, "updatedAt": now}
	for key, value := range user {
		data[key] = value
	}
	if _, exists := data["image"]; !exists {
		data["image"] = nil
	}
	if email, ok := recordString(data, "email"); ok {
		data["email"] = strings.ToLower(email)
	}
	return a.createInternalRecord(ctx, adapter, "user", data)
}

func (a *Auth) createInternalRecord(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	model string,
	data storage.Record,
) (storage.Record, error) {
	id, generated, err := generateIdentifier(a.options, model, 32)
	if err != nil {
		return nil, err
	}
	data = cloneStorageRecord(data)
	if generated {
		data["id"] = id
	}
	return adapter.Create(ctx, storage.CreateParams{
		Model: model, Data: data, ForceAllowID: generated,
	})
}

// UpdateUser updates a user and refreshes every valid cached session payload.
func (internal InternalAdapter) UpdateUser(
	ctx context.Context,
	userID string,
	update storage.Record,
) (storage.Record, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	update = cloneStorageRecord(update)
	if email, ok := recordString(update, "email"); ok {
		update["email"] = strings.ToLower(email)
	}
	adapter := currentTransactionAdapter(ctx, internal.auth.adapter)
	user, err := adapter.Update(ctx, storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}}, Update: update,
	})
	if err != nil || user == nil {
		return user, err
	}
	if err := internal.auth.refreshSecondaryUser(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// DeleteUser removes every session from secondary storage and the database,
// then deletes the user's accounts and user row through the hook-aware
// adapter. It mirrors upstream implementation's internalAdapter.deleteUser operation.
func (internal InternalAdapter) DeleteUser(ctx context.Context, userID string) error {
	if !internal.valid() {
		return errors.New("single-auth: auth is not initialized")
	}
	if userID == "" {
		return errors.New("single-auth: user ID is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := internal.auth.deleteStoredUserSessions(ctx, userID, true); err != nil {
		return err
	}
	adapter := currentTransactionAdapter(ctx, internal.auth.adapter)
	if _, err := adapter.DeleteMany(ctx, storage.DeleteManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	}); err != nil {
		return err
	}
	return adapter.Delete(ctx, storage.DeleteParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
}

// CreateAccount creates one provider or credential account through hooks.
func (internal InternalAdapter) CreateAccount(ctx context.Context, account storage.Record) (storage.Record, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	now := internal.auth.options.Clock().UTC()
	data := storage.Record{"createdAt": now, "updatedAt": now}
	for key, value := range account {
		data[key] = value
	}
	return internal.auth.createInternalRecord(
		ctx, currentTransactionAdapter(ctx, internal.auth.adapter), "account", data,
	)
}

func (internal InternalAdapter) FindAccounts(ctx context.Context, userID string) ([]storage.Record, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	return currentTransactionAdapter(ctx, internal.auth.adapter).FindMany(ctx, storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
}

func (internal InternalAdapter) FindAccountByProviderID(
	ctx context.Context,
	accountID string,
	providerID string,
) (storage.Record, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	return currentTransactionAdapter(ctx, internal.auth.adapter).FindOne(ctx, storage.FindOneParams{
		Model: "account", Where: []storage.Where{
			{Field: "accountId", Value: accountID}, {Field: "providerId", Value: providerID},
		},
	})
}

// DeleteAccount deletes by the account row's primary id, not accountId.
func (internal InternalAdapter) DeleteAccount(ctx context.Context, id string) error {
	if !internal.valid() {
		return errors.New("single-auth: auth is not initialized")
	}
	return currentTransactionAdapter(ctx, internal.auth.adapter).Delete(ctx, storage.DeleteParams{
		Model: "account", Where: []storage.Where{{Field: "id", Value: id}},
	})
}

func (internal InternalAdapter) DeleteAccounts(ctx context.Context, userID string) error {
	if !internal.valid() {
		return errors.New("single-auth: auth is not initialized")
	}
	_, err := currentTransactionAdapter(ctx, internal.auth.adapter).DeleteMany(ctx, storage.DeleteManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	return err
}

// CreateSession creates a session without issuing browser cookies.
func (internal InternalAdapter) CreateSession(
	ctx context.Context,
	userID string,
	options InternalSessionCreateOptions,
) (storage.Record, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return internal.auth.createSessionRecord(
		ctx,
		currentTransactionAdapter(ctx, internal.auth.adapter),
		userID,
		options.DontRemember,
		options.Override,
		options.OverrideAll,
		options.IPAddress,
		options.UserAgent,
	)
}

func (internal InternalAdapter) FindSession(ctx context.Context, token string) (*InternalSession, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	value, err := internal.auth.findStoredSession(
		ctx, currentTransactionAdapter(ctx, internal.auth.adapter), token,
	)
	if err != nil || value == nil {
		return nil, err
	}
	return &InternalSession{
		Session: cloneStorageRecord(value.Session), User: cloneStorageRecord(value.User),
	}, nil
}

func (internal InternalAdapter) FindSessions(
	ctx context.Context,
	tokens []string,
	onlyActive bool,
) ([]InternalSession, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	values, err := internal.auth.findStoredSessions(ctx, append([]string(nil), tokens...), onlyActive)
	if err != nil {
		return nil, err
	}
	result := make([]InternalSession, 0, len(values))
	for _, value := range values {
		result = append(result, InternalSession{
			Session: cloneStorageRecord(value.Session), User: cloneStorageRecord(value.User),
		})
	}
	return result, nil
}

func (internal InternalAdapter) ListSessions(
	ctx context.Context,
	userID string,
	onlyActive bool,
) ([]storage.Record, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	if internal.auth.secondary != nil {
		return internal.auth.listSecondarySessions(ctx, userID, onlyActive)
	}
	where := []storage.Where{{Field: "userId", Value: userID}}
	if onlyActive {
		where = append(where, storage.Where{
			Field: "expiresAt", Value: internal.auth.options.Clock(), Operator: storage.OpGt,
		})
	}
	return currentTransactionAdapter(ctx, internal.auth.adapter).FindMany(ctx, storage.FindManyParams{
		Model: "session", Where: where,
	})
}

func (internal InternalAdapter) UpdateSession(
	ctx context.Context,
	token string,
	update storage.Record,
) (storage.Record, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	return internal.auth.updateStoredSession(ctx, token, update)
}

func (internal InternalAdapter) DeleteSession(ctx context.Context, token string) error {
	if !internal.valid() {
		return errors.New("single-auth: auth is not initialized")
	}
	return internal.auth.deleteStoredSession(ctx, token)
}

func (internal InternalAdapter) CreateVerificationValue(
	ctx context.Context,
	value VerificationValue,
) (storage.Record, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	return internal.auth.createStoredVerification(
		ctx, value.Identifier, value.Value, value.ExpiresAt,
	)
}

func (internal InternalAdapter) FindVerificationValue(ctx context.Context, identifier string) (storage.Record, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	return internal.auth.findStoredVerification(ctx, identifier)
}

func (internal InternalAdapter) DeleteVerificationByIdentifier(ctx context.Context, identifier string) error {
	if !internal.valid() {
		return errors.New("single-auth: auth is not initialized")
	}
	return internal.auth.deleteStoredVerification(ctx, identifier)
}

func (internal InternalAdapter) ConsumeVerificationValue(ctx context.Context, identifier string) (storage.Record, error) {
	if !internal.valid() {
		return nil, errors.New("single-auth: auth is not initialized")
	}
	return internal.auth.consumeStoredVerification(ctx, identifier)
}

// ReserveVerificationValue is the first-writer-wins dual of consume. The
// database path uses a deterministic primary key and therefore stays atomic
// across processes on every conforming adapter.
func (internal InternalAdapter) ReserveVerificationValue(
	ctx context.Context,
	value VerificationValue,
) (bool, error) {
	if !internal.valid() {
		return false, errors.New("single-auth: auth is not initialized")
	}
	return internal.auth.reserveStoredVerification(ctx, value)
}

func (a *Auth) reserveStoredVerification(ctx context.Context, value VerificationValue) (bool, error) {
	storedIdentifier, _, err := a.processVerificationIdentifier(value.Identifier)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256([]byte("reserve:" + value.Identifier))
	reservationID := base64.RawURLEncoding.EncodeToString(digest[:])
	ttl := secondaryTTL(value.ExpiresAt, a.options.Clock().UTC())

	if a.secondary != nil && !a.options.Verification.StoreInDatabase {
		key := verificationPrefix + storedIdentifier
		lock := a.verificationLock("reserve:" + storedIdentifier)
		lock.Lock()
		defer lock.Unlock()
		existing, getErr := a.secondary.Get(ctx, key)
		if getErr != nil {
			return false, getErr
		}
		if !secondaryValueMissing(existing) {
			return false, nil
		}
		record := storage.Record{
			"id": reservationID, "identifier": storedIdentifier,
			"value": value.Value, "expiresAt": value.ExpiresAt.UTC(),
		}
		encoded, encodeErr := encodeSecondary(normalizeSecondaryRecord(record))
		if encodeErr != nil {
			return false, encodeErr
		}
		if err := a.secondary.Set(ctx, key, encoded, ttl); err != nil {
			return false, err
		}
		return true, nil
	}

	now := a.options.Clock().UTC()
	record := storage.Record{
		"id": reservationID, "identifier": storedIdentifier,
		"value": value.Value, "expiresAt": value.ExpiresAt.UTC(),
		"createdAt": now, "updatedAt": now,
	}
	adapter := a.adapter
	if hooked, ok := adapter.(*hookedAdapter); ok {
		adapter = hooked.base
	}
	if _, err := adapter.Create(ctx, storage.CreateParams{
		Model: "verification", Data: record, ForceAllowID: true,
	}); err != nil {
		existing, findErr := adapter.FindOne(ctx, storage.FindOneParams{
			Model: "verification", Where: []storage.Where{{Field: "id", Value: reservationID}},
		})
		if findErr != nil {
			return false, findErr
		}
		if existing != nil {
			return false, nil
		}
		return false, err
	}

	if a.secondary != nil && ttl > 0 {
		cached := storage.Record{
			"id": reservationID, "identifier": storedIdentifier,
			"value": value.Value, "expiresAt": value.ExpiresAt.UTC(),
		}
		encoded, err := encodeSecondary(normalizeSecondaryRecord(cached))
		if err != nil {
			return false, err
		}
		if err := a.secondary.Set(ctx, verificationPrefix+storedIdentifier, encoded, ttl); err != nil {
			return false, err
		}
	}
	return true, nil
}
