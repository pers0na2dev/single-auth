package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) createVerification(
	ctx context.Context,
	identifier, value string,
	expiresAt time.Time,
) (storage.Record, error) {
	if callback := p.options.Runtime.CreateVerification; callback != nil {
		return callback(ctx, identifier, value, expiresAt)
	}
	now := p.clock().UTC()
	return p.adapter(ctx).Create(ctx, storage.CreateParams{
		Model: "verification",
		Data: storage.Record{
			"identifier": identifier, "value": value, "expiresAt": expiresAt.UTC(),
			"createdAt": now, "updatedAt": now,
		},
	})
}

func (p *plugin) peekVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if callback := p.options.Runtime.PeekVerification; callback != nil {
		return callback(ctx, identifier)
	}
	rows, err := p.adapter(ctx).FindMany(ctx, storage.FindManyParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
		SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Descending}, Limit: storage.Int(1),
	})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

func (p *plugin) findVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if callback := p.options.Runtime.FindVerification; callback != nil {
		return callback(ctx, identifier)
	}
	record, err := p.peekVerification(ctx, identifier)
	if err != nil || record == nil {
		return record, err
	}
	expiresAt, ok := recordTime(record, "expiresAt")
	if !ok || expiresAt.Before(p.clock()) {
		if err := p.deleteVerification(ctx, identifier); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return record, nil
}

func (p *plugin) consumeVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if callback := p.options.Runtime.ConsumeVerification; callback != nil {
		return callback(ctx, identifier)
	}
	adapter := p.options.Runtime.Adapter
	if adapter == nil {
		return nil, fmt.Errorf("mcp: Runtime.Adapter is required")
	}
	var consumed storage.Record
	err := adapter.Transaction(ctx, func(transaction storage.TransactionAdapter) error {
		rows, err := transaction.FindMany(ctx, storage.FindManyParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
			SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Descending}, Limit: storage.Int(1),
		})
		if err != nil || len(rows) == 0 {
			return err
		}
		id := recordID(rows[0])
		if id == nil {
			return nil
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
	if err != nil || consumed == nil {
		return consumed, err
	}
	expiresAt, ok := recordTime(consumed, "expiresAt")
	if !ok || expiresAt.Before(p.clock()) {
		return nil, nil
	}
	return consumed, nil
}

func (p *plugin) updateVerification(ctx context.Context, identifier string, update storage.Record) error {
	if callback := p.options.Runtime.UpdateVerification; callback != nil {
		return callback(ctx, identifier, update)
	}
	_, err := p.adapter(ctx).Update(ctx, storage.UpdateParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}}, Update: update,
	})
	return err
}

func (p *plugin) deleteVerification(ctx context.Context, identifier string) error {
	if callback := p.options.Runtime.DeleteVerification; callback != nil {
		return callback(ctx, identifier)
	}
	_, err := p.adapter(ctx).DeleteMany(ctx, storage.DeleteManyParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
	})
	return err
}
