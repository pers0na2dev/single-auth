package magiclink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/fnv"
	"io"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

const tokenAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func (p *plugin) generateToken(ctx context.Context, email string) (string, error) {
	if generator := p.options.GenerateToken; generator != nil {
		return generator(ctx, email)
	}
	return randomToken(p.random, 32)
}

func randomToken(random io.Reader, length int) (string, error) {
	result := make([]byte, length)
	buffer := make([]byte, 1)
	limit := byte(256 - (256 % len(tokenAlphabet)))
	for index := range result {
		for {
			if _, err := io.ReadFull(random, buffer); err != nil {
				return "", err
			}
			if buffer[0] < limit {
				result[index] = tokenAlphabet[int(buffer[0])%len(tokenAlphabet)]
				break
			}
		}
	}
	return string(result), nil
}

func defaultTokenHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (p *plugin) storeToken(ctx context.Context, token string) (string, error) {
	if custom := p.options.Storage.CustomHash; custom != nil {
		return custom(ctx, token)
	}
	if p.options.Storage.Mode == StoreHashed {
		return defaultTokenHash(token), nil
	}
	return token, nil
}

func encodeVerificationValue(email string, name *string) (string, error) {
	payload := struct {
		Email string  `json:"email"`
		Name  *string `json:"name,omitempty"`
	}{Email: email, Name: name}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buffer.String(), "\n"), nil
}

func (p *plugin) createVerification(ctx context.Context, identifier, value string) (storage.Record, error) {
	now := p.clock().UTC()
	if create := p.options.Runtime.CreateVerification; create != nil {
		return create(ctx, identifier, value, now.Add(p.options.ExpiresIn))
	}
	return p.options.Runtime.Adapter.Create(ctx, storage.CreateParams{
		Model: "verification",
		Data: storage.Record{
			"identifier": identifier,
			"value":      value,
			"expiresAt":  now.Add(p.options.ExpiresIn),
			"createdAt":  now,
			"updatedAt":  now,
		},
	})
}

func findVerificationWith(ctx context.Context, adapter storage.TransactionAdapter, identifier string) (storage.Record, error) {
	rows, err := adapter.FindMany(ctx, storage.FindManyParams{
		Model:  "verification",
		Where:  []storage.Where{{Field: "identifier", Value: identifier}},
		SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Descending},
		Limit:  storage.Int(1),
	})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

func (p *plugin) withTokenLock(identifier string, work func() error) error {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(identifier))
	lock := &p.locks[hash.Sum64()%uint64(len(p.locks))]
	lock.Lock()
	defer lock.Unlock()
	return work()
}

func (p *plugin) consumeVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if consume := p.options.Runtime.ConsumeVerification; consume != nil {
		return consume(ctx, identifier)
	}
	var consumed storage.Record
	err := p.withTokenLock(identifier, func() error {
		consume := func(adapter storage.TransactionAdapter) error {
			latest, err := findVerificationWith(ctx, adapter, identifier)
			if err != nil || latest == nil {
				return err
			}
			id, ok := recordString(latest, "id")
			if !ok || id == "" {
				return errors.New("magiclink: verification row has no id")
			}
			consumed, err = adapter.ConsumeOne(ctx, storage.ConsumeOneParams{
				Model: "verification", Where: []storage.Where{{Field: "id", Value: id}},
			})
			if err != nil || consumed == nil {
				return err
			}
			_, err = adapter.DeleteMany(ctx, storage.DeleteManyParams{
				Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
			})
			return err
		}
		err := p.options.Runtime.Adapter.Transaction(ctx, consume)
		if errors.Is(err, storage.ErrTransactionsUnsupported) {
			consumed = nil
			err = consume(p.options.Runtime.Adapter)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if consumed == nil {
		return nil, nil
	}
	expiresAt, ok := recordTime(consumed, "expiresAt")
	if !ok || expiresAt.Before(p.clock()) {
		return nil, nil
	}
	return consumed, nil
}
