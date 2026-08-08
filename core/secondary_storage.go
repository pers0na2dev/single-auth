package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"

	"github.com/pers0na2dev/single-auth/internal/domain"
	"github.com/pers0na2dev/single-auth/storage"
)

const activeSessionsPrefix = "active-sessions-"
const verificationPrefix = "verification:"

type activeSessionEntry = domain.ActiveSessionEntry
type secondarySessionPayload = domain.SessionPair

func (a *Auth) databaseStoresSessions() bool {
	return a.secondary == nil || a.options.Session.StoreSessionInDatabase
}

func (a *Auth) preservesDatabaseSessions() bool {
	return a.secondary != nil && a.options.Session.PreserveSessionInDatabase
}

func secondaryTTL(expiresAt, now time.Time) int64 {
	milliseconds := expiresAt.Sub(now).Milliseconds()
	if milliseconds <= 0 {
		return 0
	}
	return milliseconds / 1000
}

func normalizeSecondaryRecord(record storage.Record) storage.Record {
	if record == nil {
		return nil
	}
	result := make(storage.Record, len(record))
	for key, value := range record {
		if instant, ok := value.(time.Time); ok {
			result[key] = instant.UTC().Format("2006-01-02T15:04:05.000Z")
			continue
		}
		result[key] = value
	}
	return result
}

func (a *Auth) prepareSecondaryCreate(modelName string, data storage.Record) (storage.Record, error) {
	modelSchema, exists := a.options.Schema.Models[modelName]
	if !exists {
		return cloneStorageRecord(data), nil
	}
	// upstream implementation's secondary-only create callback receives the complete value
	// produced by database hooks before an adapter has had a chance to discard
	// unknown fields. Preserve those hook-owned fields while still applying the
	// configured schema defaults and transforms to known fields.
	result := cloneStorageRecord(data)
	valueContext := storage.ValueContext{Now: a.options.Clock}
	for fieldName, attribute := range modelSchema.Fields {
		value, supplied := data[fieldName]
		if (!supplied || (value == nil && attribute.IsRequired())) && attribute.DefaultValue != nil {
			var err error
			value, err = attribute.DefaultValue(valueContext)
			if err != nil {
				return nil, err
			}
			supplied = true
		}
		if !supplied {
			continue
		}
		if attribute.Transform.Input != nil {
			transformed, err := attribute.Transform.Input(value)
			if err != nil {
				return nil, err
			}
			value = transformed
		}
		if attribute.Transform.Output != nil {
			transformed, err := attribute.Transform.Output(value)
			if err != nil {
				return nil, err
			}
			value = transformed
		}
		result[fieldName] = value
	}
	return result, nil
}

func encodeSecondary(value any) (string, error) {
	encoded, err := marshalJSON(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

var secondaryISO8601 = regexp.MustCompile(
	`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$`,
)

func secondaryValueMissing(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return typed == ""
	case []byte:
		return len(typed) == 0
	case json.RawMessage:
		return len(typed) == 0
	default:
		return false
	}
}

func decodeSecondaryValue(raw any) (any, bool) {
	if secondaryValueMissing(raw) {
		return nil, false
	}

	var encoded []byte
	switch typed := raw.(type) {
	case string:
		encoded = []byte(typed)
	case []byte:
		encoded = append([]byte(nil), typed...)
	case json.RawMessage:
		encoded = append([]byte(nil), typed...)
	default:
		var err error
		encoded, err = marshalJSON(typed)
		if err != nil {
			return nil, false
		}
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return reviveSecondaryDates(value), true
}

func reviveSecondaryDates(value any) any {
	switch typed := value.(type) {
	case string:
		if !secondaryISO8601.MatchString(typed) {
			return typed
		}
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		if err != nil {
			return typed
		}
		return parsed
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = reviveSecondaryDates(item)
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = reviveSecondaryDates(item)
		}
		return result
	default:
		return typed
	}
}

func secondaryRecord(value any) (storage.Record, bool) {
	object, ok := value.(map[string]any)
	if !ok || object == nil {
		return nil, false
	}
	return storage.Record(object), true
}

func decodeSecondaryRecord(raw any) (storage.Record, bool) {
	value, ok := decodeSecondaryValue(raw)
	if !ok {
		return nil, false
	}
	return secondaryRecord(value)
}

func decodeSecondarySession(raw any) (*authenticatedSession, bool) {
	value, ok := decodeSecondaryValue(raw)
	if !ok {
		return nil, false
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	session, sessionOK := secondaryRecord(object["session"])
	user, userOK := secondaryRecord(object["user"])
	if !sessionOK || !userOK {
		return nil, false
	}
	return &authenticatedSession{Session: session, User: user}, true
}

func (a *Auth) storeSecondarySession(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	session storage.Record,
	userID string,
) error {
	if a.secondary == nil {
		return nil
	}
	user, err := adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
	if err != nil {
		return err
	}
	return a.storeSecondarySessionWithUser(ctx, session, user)
}

func (a *Auth) storeSecondarySessionWithUser(
	ctx context.Context,
	session, user storage.Record,
) error {
	if a.secondary == nil {
		return nil
	}
	token, tokenOK := recordString(session, "token")
	userID, userOK := recordString(session, "userId")
	expiresAt, expiryOK := recordTime(session, "expiresAt")
	if !tokenOK || !userOK || !expiryOK {
		return nil
	}
	return a.storeSecondarySessionPayload(ctx, session, user, token, userID, expiresAt)
}

func (a *Auth) storeSecondarySessionPayload(
	ctx context.Context,
	session, user storage.Record,
	indexToken, indexUserID string,
	indexExpiresAt time.Time,
) error {
	if a.secondary == nil || indexToken == "" || indexUserID == "" {
		return nil
	}
	now := a.options.Clock().UTC()
	ttl := secondaryTTL(indexExpiresAt, now)
	if ttl <= 0 {
		return nil
	}
	listKey := activeSessionsPrefix + indexUserID
	lock := a.secondary.LockFor(listKey)
	lock.Lock()
	defer lock.Unlock()

	list, err := a.secondarySessionList(ctx, listKey)
	if err != nil {
		return err
	}
	filtered := make([]activeSessionEntry, 0, len(list)+1)
	for _, entry := range list {
		if entry.ExpiresAt > now.UnixMilli() && entry.Token != indexToken {
			filtered = append(filtered, entry)
		}
	}
	filtered = append(filtered, activeSessionEntry{Token: indexToken, ExpiresAt: indexExpiresAt.UnixMilli()})
	sort.SliceStable(filtered, func(left, right int) bool {
		return filtered[left].ExpiresAt < filtered[right].ExpiresAt
	})
	listTTL := (filtered[len(filtered)-1].ExpiresAt - now.UnixMilli()) / 1000
	if listTTL > 0 {
		encoded, encodeErr := encodeSecondary(filtered)
		if encodeErr != nil {
			return encodeErr
		}
		if err := a.secondary.Set(ctx, listKey, encoded, listTTL); err != nil {
			return err
		}
	}
	payload := secondarySessionPayload{
		Session: normalizeSecondaryRecord(session), User: normalizeSecondaryRecord(user),
	}
	encoded, err := encodeSecondary(payload)
	if err != nil {
		return err
	}
	return a.secondary.Set(ctx, indexToken, encoded, ttl)
}

func (a *Auth) secondarySessionList(ctx context.Context, key string) ([]activeSessionEntry, error) {
	raw, err := a.secondary.Get(ctx, key)
	if err != nil || secondaryValueMissing(raw) {
		return nil, err
	}
	value, valid := decodeSecondaryValue(raw)
	if !valid {
		return nil, nil
	}
	encoded, err := marshalJSON(value)
	if err != nil {
		return nil, nil
	}
	var list []activeSessionEntry
	if json.Unmarshal(encoded, &list) != nil {
		return nil, nil
	}
	return list, nil
}

func (a *Auth) loadSecondarySession(ctx context.Context, token string) (*authenticatedSession, error) {
	if a.secondary == nil {
		return nil, nil
	}
	raw, err := a.secondary.Get(ctx, token)
	if err != nil || secondaryValueMissing(raw) {
		return nil, err
	}
	payload, valid := decodeSecondarySession(raw)
	if !valid {
		return nil, nil
	}
	return payload, nil
}

func (a *Auth) findStoredSession(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	token string,
) (*authenticatedSession, error) {
	if a.secondary != nil {
		cached, err := a.loadSecondarySession(ctx, token)
		if err != nil || cached != nil {
			return cached, err
		}
		if !a.options.Session.StoreSessionInDatabase || a.options.Session.PreserveSessionInDatabase {
			return nil, nil
		}
	}
	session, err := adapter.FindOne(ctx, storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: token}},
	})
	if err != nil || session == nil {
		return nil, err
	}
	userID, _ := recordString(session, "userId")
	user, err := adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
	if err != nil || user == nil {
		return nil, err
	}
	return &authenticatedSession{Session: session, User: user}, nil
}

func (a *Auth) findStoredSessions(
	ctx context.Context,
	tokens []string,
	onlyActive bool,
) ([]authenticatedSession, error) {
	if len(tokens) == 0 {
		return []authenticatedSession{}, nil
	}
	if a.secondary != nil {
		result := make([]authenticatedSession, 0, len(tokens))
		now := a.options.Clock().UTC()
		for _, token := range tokens {
			stored, err := a.loadSecondarySession(ctx, token)
			if err != nil {
				return nil, err
			}
			if stored == nil {
				continue
			}
			if onlyActive {
				expiresAt, ok := recordTime(stored.Session, "expiresAt")
				if !ok || !expiresAt.After(now) {
					continue
				}
			}
			result = append(result, authenticatedSession{
				Session: cloneStorageRecord(stored.Session),
				User:    cloneStorageRecord(stored.User),
			})
		}
		return result, nil
	}

	where := []storage.Where{{Field: "token", Value: append([]string(nil), tokens...), Operator: storage.OpIn}}
	if onlyActive {
		where = append(where, storage.Where{
			Field: "expiresAt", Value: a.options.Clock().UTC(), Operator: storage.OpGt,
		})
	}
	sessions, err := a.adapter.FindMany(ctx, storage.FindManyParams{Model: "session", Where: where})
	if err != nil || len(sessions) == 0 {
		return []authenticatedSession{}, err
	}
	result := make([]authenticatedSession, 0, len(sessions))
	for _, session := range sessions {
		userID, _ := recordString(session, "userId")
		user, findErr := a.adapter.FindOne(ctx, storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		})
		if findErr != nil {
			return nil, findErr
		}
		// upstream implementation's joined database path returns an empty result if any row
		// has a missing user relation.
		if user == nil {
			return []authenticatedSession{}, nil
		}
		result = append(result, authenticatedSession{
			Session: cloneStorageRecord(session), User: cloneStorageRecord(user),
		})
	}
	return result, nil
}

func (a *Auth) listSecondarySessions(ctx context.Context, userID string, onlyActive bool) ([]storage.Record, error) {
	if a.secondary == nil {
		return nil, nil
	}
	list, err := a.secondarySessionList(ctx, activeSessionsPrefix+userID)
	if err != nil {
		return nil, err
	}
	now := a.options.Clock().UnixMilli()
	seen := make(map[string]struct{}, len(list))
	result := make([]storage.Record, 0, len(list))
	for _, entry := range list {
		if entry.ExpiresAt <= now {
			continue
		}
		if _, duplicate := seen[entry.Token]; duplicate {
			continue
		}
		seen[entry.Token] = struct{}{}
		stored, loadErr := a.loadSecondarySession(ctx, entry.Token)
		if loadErr != nil {
			return nil, loadErr
		}
		if stored == nil {
			continue
		}
		if onlyActive {
			expiresAt, ok := recordTime(stored.Session, "expiresAt")
			if !ok || !expiresAt.After(a.options.Clock()) {
				continue
			}
		}
		result = append(result, stored.Session)
	}
	return result, nil
}

func (a *Auth) updateStoredSession(
	ctx context.Context,
	token string,
	update storage.Record,
) (storage.Record, error) {
	hooked, ok := a.adapter.(*hookedAdapter)
	if !ok {
		return nil, fmt.Errorf("single-auth: hooked adapter is not initialized")
	}
	return hooked.customUpdate(ctx, "session", update, func(
		base storage.TransactionAdapter,
		actual storage.Record,
	) (storage.Record, error) {
		var secondaryUpdated storage.Record
		if a.secondary != nil {
			cached, err := a.loadSecondarySession(ctx, token)
			if err != nil {
				return nil, err
			}
			if cached != nil {
				secondaryUpdated = cloneStorageRecord(cached.Session)
				for key, value := range actual {
					secondaryUpdated[key] = value
				}
				userID, userOK := recordString(secondaryUpdated, "userId")
				expiresAt, expiryOK := recordTime(secondaryUpdated, "expiresAt")
				if userOK && expiryOK {
					if err := a.storeSecondarySessionPayload(
						ctx, secondaryUpdated, cached.User, token, userID, expiresAt,
					); err != nil {
						return nil, err
					}
				}
			}
		}
		if a.databaseStoresSessions() {
			return base.Update(ctx, storage.UpdateParams{
				Model: "session", Where: []storage.Where{{Field: "token", Value: token}}, Update: actual,
			})
		}
		return secondaryUpdated, nil
	})
}

func (a *Auth) deleteStoredSession(ctx context.Context, token string) error {
	if a.secondary != nil {
		cached, err := a.loadSecondarySession(ctx, token)
		if err != nil {
			return err
		}
		if cached != nil {
			userID, _ := recordString(cached.Session, "userId")
			listKey := activeSessionsPrefix + userID
			lock := a.secondary.LockFor(listKey)
			lock.Lock()
			list, listErr := a.secondarySessionList(ctx, listKey)
			if listErr == nil {
				now := a.options.Clock().UnixMilli()
				filtered := make([]activeSessionEntry, 0, len(list))
				for _, entry := range list {
					if entry.ExpiresAt > now && entry.Token != token {
						filtered = append(filtered, entry)
					}
				}
				if len(filtered) == 0 {
					listErr = a.secondary.Delete(ctx, listKey)
				} else {
					sort.SliceStable(filtered, func(left, right int) bool {
						return filtered[left].ExpiresAt < filtered[right].ExpiresAt
					})
					encoded, encodeErr := encodeSecondary(filtered)
					if encodeErr != nil {
						listErr = encodeErr
					} else {
						ttl := (filtered[len(filtered)-1].ExpiresAt - now) / 1000
						listErr = a.secondary.Set(ctx, listKey, encoded, ttl)
					}
				}
			}
			lock.Unlock()
			if listErr != nil {
				return listErr
			}
		}
		if err := a.secondary.Delete(ctx, token); err != nil {
			return err
		}
	}
	if a.databaseStoresSessions() && !a.preservesDatabaseSessions() {
		return a.adapter.Delete(ctx, storage.DeleteParams{
			Model: "session", Where: []storage.Where{{Field: "token", Value: token}},
		})
	}
	return nil
}

func (a *Auth) deleteStoredSessions(ctx context.Context, tokens []string) error {
	if len(tokens) == 0 {
		return nil
	}
	if a.secondary != nil {
		for _, token := range tokens {
			raw, err := a.secondary.Get(ctx, token)
			if err != nil {
				return err
			}
			if secondaryValueMissing(raw) {
				continue
			}
			if err := a.secondary.Delete(ctx, token); err != nil {
				return err
			}
		}
	}
	if a.databaseStoresSessions() && !a.preservesDatabaseSessions() {
		_, err := a.adapter.DeleteMany(ctx, storage.DeleteManyParams{
			Model: "session",
			Where: []storage.Where{{
				Field: "token", Value: append([]string(nil), tokens...), Operator: storage.OpIn,
			}},
		})
		return err
	}
	return nil
}

func (a *Auth) deleteSecondaryUserSessions(ctx context.Context, userID string) error {
	if a.secondary == nil {
		return nil
	}
	key := activeSessionsPrefix + userID
	lock := a.secondary.LockFor(key)
	lock.Lock()
	defer lock.Unlock()
	list, err := a.secondarySessionList(ctx, key)
	if err != nil {
		return err
	}
	for _, entry := range list {
		if err := a.secondary.Delete(ctx, entry.Token); err != nil {
			return err
		}
	}
	return a.secondary.Delete(ctx, key)
}

func (a *Auth) deleteStoredUserSessions(ctx context.Context, userID string, forceDatabase bool) error {
	if err := a.deleteSecondaryUserSessions(ctx, userID); err != nil {
		return err
	}
	if a.databaseStoresSessions() && (forceDatabase || !a.preservesDatabaseSessions()) {
		_, err := a.adapter.DeleteMany(ctx, storage.DeleteManyParams{
			Model: "session", Where: []storage.Where{{Field: "userId", Value: userID}},
		})
		return err
	}
	return nil
}

func (a *Auth) refreshSecondaryUser(ctx context.Context, user storage.Record) error {
	if a.secondary == nil {
		return nil
	}
	userID, ok := recordString(user, "id")
	if !ok {
		return nil
	}
	list, err := a.secondarySessionList(ctx, activeSessionsPrefix+userID)
	if err != nil {
		return err
	}
	now := a.options.Clock()
	for _, entry := range list {
		if entry.ExpiresAt <= now.UnixMilli() {
			continue
		}
		cached, loadErr := a.loadSecondarySession(ctx, entry.Token)
		if loadErr != nil {
			return loadErr
		}
		if cached == nil {
			continue
		}
		expiresAt, ok := recordTime(cached.Session, "expiresAt")
		if !ok {
			continue
		}
		ttl := secondaryTTL(expiresAt, now)
		payload := secondarySessionPayload{
			Session: normalizeSecondaryRecord(cached.Session), User: normalizeSecondaryRecord(user),
		}
		encoded, encodeErr := encodeSecondary(payload)
		if encodeErr != nil {
			return encodeErr
		}
		if err := a.secondary.Set(ctx, entry.Token, encoded, ttl); err != nil {
			return err
		}
	}
	return nil
}

func (a *Auth) storeSecondaryVerification(ctx context.Context, record storage.Record) error {
	if a.secondary == nil {
		return nil
	}
	identifier, identifierOK := recordString(record, "identifier")
	if !identifierOK {
		return nil
	}
	return a.storeSecondaryVerificationAt(ctx, identifier, record)
}

func (a *Auth) storeSecondaryVerificationAt(
	ctx context.Context,
	identifier string,
	record storage.Record,
) error {
	if a.secondary == nil || identifier == "" {
		return nil
	}
	expiresAt, expiryOK := recordTime(record, "expiresAt")
	if !expiryOK {
		return nil
	}
	ttl := secondaryTTL(expiresAt, a.options.Clock().UTC())
	if ttl <= 0 {
		return nil
	}
	encoded, err := encodeSecondary(normalizeSecondaryRecord(record))
	if err != nil {
		return err
	}
	return a.secondary.Set(ctx, verificationPrefix+identifier, encoded, ttl)
}

func (a *Auth) loadSecondaryVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if a.secondary == nil {
		return nil, nil
	}
	raw, err := a.secondary.Get(ctx, verificationPrefix+identifier)
	if err != nil || secondaryValueMissing(raw) {
		return nil, err
	}
	record, valid := decodeSecondaryRecord(raw)
	if !valid {
		return nil, nil
	}
	return record, nil
}

func (a *Auth) consumeSecondaryVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if a.secondary == nil {
		return nil, nil
	}
	key := verificationPrefix + identifier
	consume := func() (any, error) {
		if value, atomic, err := a.secondary.AtomicGetAndDelete(ctx, key); atomic {
			return value, err
		}
		a.secondary.WarnNonAtomicVerification()
		lock := a.secondary.LockFor(key)
		lock.Lock()
		defer lock.Unlock()
		raw, err := a.secondary.Get(ctx, key)
		if err != nil || secondaryValueMissing(raw) {
			return raw, err
		}
		if err := a.secondary.Delete(ctx, key); err != nil {
			return nil, err
		}
		return raw, nil
	}
	raw, err := consume()
	if err != nil || secondaryValueMissing(raw) {
		return nil, err
	}
	record, valid := decodeSecondaryRecord(raw)
	if !valid {
		return nil, nil
	}
	expiresAt, valid := recordTime(record, "expiresAt")
	if !valid || expiresAt.Before(a.options.Clock()) {
		return nil, nil
	}
	return record, nil
}

func (a *Auth) deleteStoredVerification(ctx context.Context, identifier string) error {
	storedIdentifier, _, err := a.processVerificationIdentifier(identifier)
	if err != nil {
		return err
	}
	if a.secondary != nil {
		if err := a.secondary.Delete(ctx, verificationPrefix+storedIdentifier); err != nil {
			return err
		}
	}
	if a.secondary == nil || a.options.Verification.StoreInDatabase {
		return a.adapter.Delete(ctx, storage.DeleteParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: storedIdentifier}},
		})
	}
	return nil
}

func (a *Auth) updateStoredVerification(
	ctx context.Context,
	identifier string,
	update storage.Record,
) error {
	storedIdentifier, _, err := a.processVerificationIdentifier(identifier)
	if err != nil {
		return err
	}
	if a.secondary != nil {
		cached, err := a.loadSecondaryVerification(ctx, storedIdentifier)
		if err != nil {
			return err
		}
		if cached != nil {
			for field, value := range update {
				cached[field] = value
			}
			if err := a.storeSecondaryVerificationAt(ctx, storedIdentifier, cached); err != nil {
				return err
			}
			if !a.options.Verification.StoreInDatabase {
				return nil
			}
		}
	}
	if a.secondary == nil || a.options.Verification.StoreInDatabase {
		_, err = a.adapter.Update(ctx, storage.UpdateParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: storedIdentifier}},
			Update: update,
		})
		return err
	}
	return nil
}

func (a *Auth) cleanupExpiredVerifications(ctx context.Context) error {
	if a.options.Verification.DisableCleanup {
		return nil
	}
	if a.secondary != nil && !a.options.Verification.StoreInDatabase {
		return nil
	}
	_, err := a.adapter.DeleteMany(ctx, storage.DeleteManyParams{
		Model: "verification",
		Where: []storage.Where{{Field: "expiresAt", Value: a.options.Clock(), Operator: storage.OpLt}},
	})
	if errors.Is(err, storage.ErrModelNotFound) {
		return nil
	}
	return err
}
