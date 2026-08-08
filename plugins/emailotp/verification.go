package emailotp

import (
	"context"
	"errors"
	"hash/fnv"
	"strconv"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) withIdentifierLock(identifier string, fn func() error) error {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(identifier))
	lock := &p.locks[hash.Sum64()%uint64(len(p.locks))]
	lock.Lock()
	defer lock.Unlock()
	return fn()
}

func (p *plugin) createVerification(ctx context.Context, identifier, value string, expiresAt time.Time) (storage.Record, error) {
	if create := p.options.Runtime.CreateVerification; create != nil {
		return create(ctx, identifier, value, expiresAt)
	}
	now := p.clock().UTC()
	return p.options.Runtime.Adapter.Create(ctx, storage.CreateParams{
		Model: "verification",
		Data: storage.Record{
			"identifier": identifier,
			"value":      value,
			"expiresAt":  expiresAt.UTC(),
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

func (p *plugin) findVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if find := p.options.Runtime.FindVerification; find != nil {
		return find(ctx, identifier)
	}
	row, err := findVerificationWith(ctx, p.options.Runtime.Adapter, identifier)
	if err != nil {
		return nil, err
	}
	_, cleanupErr := p.options.Runtime.Adapter.DeleteMany(ctx, storage.DeleteManyParams{
		Model: "verification",
		Where: []storage.Where{{Field: "expiresAt", Operator: storage.OpLt, Value: p.clock().UTC()}},
	})
	if cleanupErr != nil {
		return nil, cleanupErr
	}
	return row, nil
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

func (p *plugin) updateVerification(ctx context.Context, identifier string, update storage.Record) error {
	if apply := p.options.Runtime.UpdateVerification; apply != nil {
		return apply(ctx, identifier, update)
	}
	_, err := p.options.Runtime.Adapter.UpdateMany(ctx, storage.UpdateManyParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}}, Update: update,
	})
	return err
}

func (p *plugin) consumeVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if consume := p.options.Runtime.ConsumeVerification; consume != nil {
		return consume(ctx, identifier)
	}
	var consumed storage.Record
	consume := func(adapter storage.TransactionAdapter) error {
		latest, err := findVerificationWith(ctx, adapter, identifier)
		if err != nil || latest == nil {
			return err
		}
		id, ok := recordString(latest, "id")
		if !ok || id == "" {
			return errors.New("emailotp: verification row has no id")
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
	if err != nil {
		return nil, err
	}
	if consumed != nil {
		expiresAt, valid := recordTime(consumed, "expiresAt")
		if !valid || expiresAt.Before(p.clock()) {
			return nil, nil
		}
	}
	return consumed, nil
}

func (p *plugin) atomicVerifyOTP(ctx *engine.Context, identifier, provided string) error {
	return p.withIdentifierLock(identifier, func() error {
		existing, err := p.findVerification(ctx.GoContext(), identifier)
		if err != nil {
			return internalError(err)
		}
		if existing != nil {
			expiresAt, valid := recordTime(existing, "expiresAt")
			if !valid || expiresAt.Before(p.clock()) {
				if err := p.deleteVerification(ctx.GoContext(), identifier); err != nil {
					return internalError(err)
				}
				return otpError(contract.StatusBadRequest, ErrorOTPExpired)
			}
		}
		consumed, err := p.consumeVerification(ctx.GoContext(), identifier)
		if err != nil {
			return internalError(err)
		}
		if consumed == nil {
			return otpError(contract.StatusBadRequest, ErrorInvalidOTP)
		}
		value, ok := recordString(consumed, "value")
		if !ok {
			return internalError(errors.New("emailotp: verification value is invalid"))
		}
		stored, attemptText := SplitStoredValue(value)
		attempts := parseAttempts(attemptText)
		if attempts >= p.options.AllowedAttempts {
			return otpError(contract.StatusForbidden, ErrorTooManyAttempts)
		}
		verified, err := p.verifyStoredOTP(ctx.GoContext(), stored, provided)
		if err != nil {
			return internalError(err)
		}
		if verified {
			return nil
		}
		expiresAt, valid := recordTime(consumed, "expiresAt")
		if !valid {
			return internalError(errors.New("emailotp: verification expiry is invalid"))
		}
		if _, err := p.createVerification(ctx.GoContext(), identifier, stored+":"+strconv.Itoa(attempts+1), expiresAt); err != nil {
			return internalError(err)
		}
		return otpError(contract.StatusBadRequest, ErrorInvalidOTP)
	})
}
