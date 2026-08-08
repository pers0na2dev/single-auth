package jwt

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type jwksAdapter struct {
	options Options
}

func (adapter jwksAdapter) executor(ctx *engine.Context) storage.TransactionAdapter {
	goContext := context.Background()
	if ctx != nil {
		goContext = ctx.GoContext()
	}
	if adapter.options.Runtime.AdapterForContext != nil {
		if current := adapter.options.Runtime.AdapterForContext(goContext); current != nil {
			return current
		}
	}
	return adapter.options.Runtime.Adapter
}

func (adapter jwksAdapter) getAll(ctx *engine.Context) ([]JWK, error) {
	if adapter.options.Adapter.GetJWKs != nil {
		keys, err := adapter.options.Adapter.GetJWKs(ctx)
		return cloneKeys(keys), err
	}
	executor := adapter.executor(ctx)
	if executor == nil {
		return nil, fmt.Errorf("jwt: Runtime.Adapter is required")
	}
	goContext := context.Background()
	if ctx != nil {
		goContext = ctx.GoContext()
	}
	rows, err := executor.FindMany(goContext, storage.FindManyParams{Model: "jwks"})
	if err != nil {
		return nil, err
	}
	keys := make([]JWK, 0, len(rows))
	for _, row := range rows {
		key, err := recordToJWK(row)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (adapter jwksAdapter) getLatest(ctx *engine.Context) (*JWK, error) {
	keys, err := adapter.getAll(ctx)
	if err != nil || len(keys) == 0 {
		return nil, err
	}
	sort.SliceStable(keys, func(left, right int) bool {
		return keys[left].CreatedAt.After(keys[right].CreatedAt)
	})
	key := keys[0]
	return &key, nil
}

func (adapter jwksAdapter) create(ctx *engine.Context, input JWK) (JWK, error) {
	input = cloneKey(input)
	if adapter.options.Adapter.CreateJWK != nil {
		return adapter.options.Adapter.CreateJWK(ctx, input)
	}
	executor := adapter.executor(ctx)
	if executor == nil {
		return JWK{}, fmt.Errorf("jwt: Runtime.Adapter is required")
	}
	// single-auth's jwks table persists only the encoded keys and timestamps.
	// Algorithm and curve stay available to custom Adapter callbacks, but must
	// not be sent to schema-aware database adapters.
	data := storage.Record{
		"publicKey": input.PublicKey, "privateKey": input.PrivateKey,
		"createdAt": adapter.options.Runtime.Clock().UTC(),
	}
	if input.ExpiresAt != nil {
		data["expiresAt"] = input.ExpiresAt.UTC()
	}
	goContext := context.Background()
	if ctx != nil {
		goContext = ctx.GoContext()
	}
	row, err := executor.Create(goContext, storage.CreateParams{Model: "jwks", Data: data})
	if err != nil {
		return JWK{}, err
	}
	return recordToJWK(row)
}

func recordToJWK(record storage.Record) (JWK, error) {
	if record == nil {
		return JWK{}, fmt.Errorf("jwt: adapter returned an empty JWK")
	}
	id, ok := recordString(record, "id")
	if !ok || id == "" {
		return JWK{}, fmt.Errorf("jwt: JWK id is invalid")
	}
	publicKey, ok := recordString(record, "publicKey")
	if !ok || publicKey == "" {
		return JWK{}, fmt.Errorf("jwt: JWK public key is invalid")
	}
	privateKey, ok := recordString(record, "privateKey")
	if !ok || privateKey == "" {
		return JWK{}, fmt.Errorf("jwt: JWK private key is invalid")
	}
	createdAt, ok := recordTime(record, "createdAt")
	if !ok {
		return JWK{}, fmt.Errorf("jwt: JWK createdAt is invalid")
	}
	var expiresAt *timeValue
	if value, exists := record["expiresAt"]; exists && value != nil {
		parsed, valid := recordTime(record, "expiresAt")
		if !valid {
			return JWK{}, fmt.Errorf("jwt: JWK expiresAt is invalid")
		}
		expiresAt = (*timeValue)(&parsed)
	}
	algorithm, _ := recordString(record, "alg")
	curve, _ := recordString(record, "crv")
	key := JWK{
		ID: id, PublicKey: publicKey, PrivateKey: privateKey,
		CreatedAt: createdAt, Algorithm: Algorithm(algorithm), Curve: curve,
	}
	if expiresAt != nil {
		value := expiresAt.time()
		key.ExpiresAt = &value
	}
	return key, nil
}

// timeValue avoids retaining pointers into adapter-owned records.
type timeValue time.Time

func (value timeValue) time() time.Time { return time.Time(value) }

func cloneKeys(keys []JWK) []JWK {
	if keys == nil {
		return nil
	}
	result := make([]JWK, len(keys))
	for index, key := range keys {
		result[index] = cloneKey(key)
	}
	return result
}

func cloneKey(key JWK) JWK {
	if key.ExpiresAt != nil {
		expiresAt := *key.ExpiresAt
		key.ExpiresAt = &expiresAt
	}
	return key
}
