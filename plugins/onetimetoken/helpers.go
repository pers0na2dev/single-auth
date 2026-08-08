package onetimetoken

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	tokenAlphabet       = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
	maxRequestBodyBytes = 4 << 20
)

type lockedReader struct {
	mu     sync.Mutex
	reader io.Reader
}

func (reader *lockedReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.reader.Read(target)
}

func randomToken(reader io.Reader, size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("onetimetoken: random token length must be positive")
	}
	result := make([]byte, size)
	buffer := make([]byte, size*2)
	ceiling := 256 - 256%len(tokenAlphabet)
	written := 0
	for written < size {
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return "", fmt.Errorf("onetimetoken: generate token: %w", err)
		}
		for _, value := range buffer {
			if int(value) >= ceiling {
				continue
			}
			result[written] = tokenAlphabet[int(value)%len(tokenAlphabet)]
			written++
			if written == size {
				break
			}
		}
	}
	return string(result), nil
}

func defaultTokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (p *plugin) storedToken(ctx context.Context, token string) (string, error) {
	switch p.options.Storage.Mode {
	case StoreHashed:
		return defaultTokenHash(token), nil
	case StoreCustom:
		return p.options.Storage.CustomHash(ctx, token)
	default:
		return token, nil
	}
}

func (p *plugin) makeToken(ctx *engine.Context, state SessionState) (string, error) {
	if p.options.GenerateToken != nil {
		return p.options.GenerateToken(ctx, cloneSessionState(state))
	}
	return randomToken(p.random, 32)
}

func (p *plugin) createVerification(
	ctx context.Context,
	identifier, value string,
	expiresAt time.Time,
) error {
	if create := p.options.Runtime.CreateVerification; create != nil {
		_, err := create(ctx, identifier, value, expiresAt)
		return err
	}
	now := p.clock().UTC()
	_, err := p.options.Runtime.Adapter.Create(ctx, storage.CreateParams{
		Model: "verification",
		Data: storage.Record{
			"identifier": identifier,
			"value":      value,
			"expiresAt":  expiresAt.UTC(),
			"createdAt":  now,
			"updatedAt":  now,
		},
	})
	return err
}

func (p *plugin) consumeVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if consume := p.options.Runtime.ConsumeVerification; consume != nil {
		return consume(ctx, identifier)
	}
	var consumed storage.Record
	err := p.options.Runtime.Adapter.Transaction(ctx, func(transaction storage.TransactionAdapter) error {
		rows, err := transaction.FindMany(ctx, storage.FindManyParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
			SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Descending}, Limit: storage.Int(1),
		})
		if err != nil || len(rows) == 0 {
			return err
		}
		id, ok := recordString(rows[0], "id")
		if !ok {
			return fmt.Errorf("onetimetoken: verification row has no id")
		}
		consumed, err = transaction.ConsumeOne(ctx, storage.ConsumeOneParams{
			Model: "verification", Where: []storage.Where{{Field: "id", Value: id}},
		})
		if err != nil || consumed == nil {
			return err
		}
		_, err = transaction.DeleteMany(ctx, storage.DeleteManyParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
		})
		return err
	})
	if errors.Is(err, storage.ErrTransactionsUnsupported) {
		consumed, err = p.options.Runtime.Adapter.ConsumeOne(ctx, storage.ConsumeOneParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
		})
	}
	if err != nil || consumed == nil {
		return consumed, err
	}
	expiresAt, ok := recordTime(consumed, "expiresAt")
	if !ok || expiresAt.Before(p.clock()) {
		return nil, nil
	}
	return consumed, nil
}

func decodeTokenBody(ctx *engine.Context) (string, error) {
	body := ctx.Request().Body()
	if len(body) > maxRequestBodyBytes {
		return "", validationError("Request body is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return "", validationError("Invalid request body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return "", validationError("Invalid request body")
	}
	value, exists := object["token"]
	if !exists {
		return "", validationError("token is required")
	}
	token, ok := value.(string)
	if !ok {
		return "", validationError("token must be a string")
	}
	return token, nil
}

func jsonResponse(value any) (contract.Response, error) {
	return contract.JSONResponse(contract.StatusOK, value)
}

func recordString(record storage.Record, key string) (string, bool) {
	if record == nil {
		return "", false
	}
	value, exists := record[key]
	if !exists || value == nil {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func recordTime(record storage.Record, key string) (time.Time, bool) {
	if record == nil {
		return time.Time{}, false
	}
	switch value := record[key].(type) {
	case time.Time:
		return value, !value.IsZero()
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed, true
			}
		}
	}
	return time.Time{}, false
}

func cloneRecord(source storage.Record) storage.Record {
	if source == nil {
		return nil
	}
	result := make(storage.Record, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneSessionState(source SessionState) SessionState {
	return SessionState{Session: cloneRecord(source.Session), User: cloneRecord(source.User)}
}

func mergeExposedHeaders(value string) string {
	ordered := make([]string, 0, 4)
	seen := make(map[string]struct{})
	for _, header := range strings.Split(value, ",") {
		header = strings.TrimSpace(header)
		if header == "" {
			continue
		}
		if _, exists := seen[header]; exists {
			continue
		}
		seen[header] = struct{}{}
		ordered = append(ordered, header)
	}
	if _, exists := seen["set-ott"]; !exists {
		ordered = append(ordered, "set-ott")
	}
	return strings.Join(ordered, ", ")
}
