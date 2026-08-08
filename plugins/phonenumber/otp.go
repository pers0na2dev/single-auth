package phonenumber

import (
	"context"
	"errors"
	"hash/fnv"
	"io"
	"strconv"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func randomDigits(random io.Reader, length int) (string, error) {
	result := make([]byte, length)
	buffer := make([]byte, 1)
	for index := range result {
		for {
			if _, err := io.ReadFull(random, buffer); err != nil {
				return "", err
			}
			if buffer[0] < 250 {
				result[index] = '0' + buffer[0]%10
				break
			}
		}
	}
	return string(result), nil
}

func splitStoredOTP(value string) (string, int) {
	parts := strings.Split(value, ":")
	otp := ""
	if len(parts) > 0 {
		otp = parts[0]
	}
	attempts := 0
	if len(parts) > 1 {
		attempts = parseAttempts(parts[1])
	}
	return otp, attempts
}

func (p *plugin) withIdentifierLock(identifier string, work func() error) error {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(identifier))
	lock := &p.locks[hash.Sum64()%uint64(len(p.locks))]
	lock.Lock()
	defer lock.Unlock()
	return work()
}

func (p *plugin) createVerification(
	ctx context.Context,
	identifier, value string,
) (storage.Record, error) {
	expiresAt := p.clock().Add(p.options.ExpiresIn)
	if create := p.options.Runtime.CreateVerification; create != nil {
		return create(ctx, identifier, value, expiresAt)
	}
	now := p.clock().UTC()
	return p.options.Runtime.Adapter.Create(ctx, storage.CreateParams{
		Model: "verification",
		Data: storage.Record{
			"identifier": identifier, "value": value, "expiresAt": expiresAt.UTC(),
			"createdAt": now, "updatedAt": now,
		},
	})
}

func findLatestVerification(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	identifier string,
) (storage.Record, error) {
	rows, err := adapter.FindMany(ctx, storage.FindManyParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
		SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Descending}, Limit: storage.Int(1),
	})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

func (p *plugin) peekVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if peek := p.options.Runtime.PeekVerification; peek != nil {
		return peek(ctx, identifier)
	}
	if find := p.options.Runtime.FindVerification; find != nil {
		return find(ctx, identifier)
	}
	return findLatestVerification(ctx, p.options.Runtime.Adapter, identifier)
}

func (p *plugin) consumeVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if consume := p.options.Runtime.ConsumeVerification; consume != nil {
		return consume(ctx, identifier)
	}
	var consumed storage.Record
	consume := func(adapter storage.TransactionAdapter) error {
		latest, err := findLatestVerification(ctx, adapter, identifier)
		if err != nil || latest == nil {
			return err
		}
		id, ok := recordString(latest, "id")
		if !ok || id == "" {
			return errors.New("phonenumber: verification row has no id")
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
	return consumed, err
}

func (p *plugin) deleteVerification(ctx context.Context, identifier string) error {
	if remove := p.options.Runtime.DeleteVerification; remove != nil {
		return remove(ctx, identifier)
	}
	_, err := p.options.Runtime.Adapter.DeleteMany(ctx, storage.DeleteManyParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
	})
	return err
}

func (p *plugin) verifyInternalOTP(ctx *engine.Context, identifier, provided string) error {
	existing, err := p.peekVerification(ctx.GoContext(), identifier)
	if err != nil {
		return internalError(err)
	}
	if existing == nil {
		return phoneError(contract.StatusBadRequest, CodeOTPNotFound)
	}
	expiresAt, valid := recordTime(existing, "expiresAt")
	if !valid {
		return internalError(errors.New("phonenumber: verification expiry is invalid"))
	}
	if expiresAt.Before(p.clock()) {
		if err := p.deleteVerification(ctx.GoContext(), identifier); err != nil {
			return internalError(err)
		}
		return phoneError(contract.StatusBadRequest, CodeOTPExpired)
	}
	peekValue, ok := recordString(existing, "value")
	if !ok {
		return internalError(errors.New("phonenumber: verification value is invalid"))
	}
	_, peekAttempts := splitStoredOTP(peekValue)
	if peekAttempts >= p.options.AllowedAttempts {
		if err := p.deleteVerification(ctx.GoContext(), identifier); err != nil {
			return internalError(err)
		}
		return phoneError(contract.StatusForbidden, CodeTooManyAttempts)
	}

	// Keep the read before this local race gate, like upstream: concurrent
	// callers may both observe the live row, but only one may consume it. The
	// loser is then INVALID_OTP rather than passing state changes downstream.
	return p.withIdentifierLock(identifier, func() error {
		consumed, err := p.consumeVerification(ctx.GoContext(), identifier)
		if err != nil {
			return internalError(err)
		}
		if consumed == nil {
			return phoneError(contract.StatusBadRequest, CodeInvalidOTP)
		}
		value, ok := recordString(consumed, "value")
		if !ok {
			return internalError(errors.New("phonenumber: verification value is invalid"))
		}
		storedOTP, attempts := splitStoredOTP(value)
		if attempts >= p.options.AllowedAttempts {
			return phoneError(contract.StatusForbidden, CodeTooManyAttempts)
		}
		if storedOTP == provided {
			return nil
		}
		consumedExpiry, valid := recordTime(consumed, "expiresAt")
		if !valid {
			return internalError(errors.New("phonenumber: verification expiry is invalid"))
		}
		if create := p.options.Runtime.CreateVerification; create != nil {
			if _, err := create(
				ctx.GoContext(), identifier, storedOTP+":"+strconv.Itoa(attempts+1), consumedExpiry,
			); err != nil {
				return internalError(err)
			}
		} else {
			now := p.clock().UTC()
			if _, err := p.options.Runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{
				Model: "verification", Data: storage.Record{
					"identifier": identifier, "value": storedOTP + ":" + strconv.Itoa(attempts+1),
					"expiresAt": consumedExpiry.UTC(), "createdAt": now, "updatedAt": now,
				},
			}); err != nil {
				return internalError(err)
			}
		}
		return phoneError(contract.StatusBadRequest, CodeInvalidOTP)
	})
}
