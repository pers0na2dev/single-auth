package core

import (
	"context"
	"fmt"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (a *Auth) createPluginSessionWithData(
	ctx *engine.Context,
	userID string,
	dontRemember bool,
	data storage.Record,
) (*PluginSessionState, error) {
	if ctx == nil || userID == "" {
		return nil, fmt.Errorf("single-auth: plugin session requires a user ID")
	}
	session, err := a.createSessionWithData(ctx, a.adapter, userID, dontRemember, cloneStorageRecord(data))
	if err != nil || session == nil {
		return nil, err
	}
	user, err := a.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
	if err != nil || user == nil {
		return nil, err
	}
	return &PluginSessionState{Session: session, User: user}, nil
}

func (a *Auth) updatePluginUser(
	ctx *engine.Context,
	userID string,
	update storage.Record,
) (storage.Record, error) {
	if ctx == nil || userID == "" {
		return nil, fmt.Errorf("single-auth: plugin user update requires a user ID")
	}
	updated, err := a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}}, Update: cloneStorageRecord(update),
	})
	if err != nil || updated == nil {
		return updated, err
	}
	if err := a.refreshSecondaryUser(ctx.GoContext(), updated); err != nil {
		return nil, err
	}
	return updated, nil
}

func (a *Auth) deletePluginUser(ctx *engine.Context, userID string) error {
	if ctx == nil || userID == "" {
		return fmt.Errorf("single-auth: plugin user deletion requires a user ID")
	}
	if err := a.deleteStoredUserSessions(ctx.GoContext(), userID, true); err != nil {
		return err
	}
	if _, err := a.adapter.DeleteMany(ctx.GoContext(), storage.DeleteManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	}); err != nil {
		return err
	}
	return a.adapter.Delete(ctx.GoContext(), storage.DeleteParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
}

func (a *Auth) listPluginUserSessions(
	ctx context.Context,
	userID string,
	onlyActive bool,
) ([]storage.Record, error) {
	if a.secondary != nil {
		return a.listSecondarySessions(ctx, userID, onlyActive)
	}
	where := []storage.Where{{Field: "userId", Value: userID}}
	if onlyActive {
		where = append(where, storage.Where{
			Field: "expiresAt", Value: a.options.Clock().UTC(), Operator: storage.OpGt,
		})
	}
	return a.adapter.FindMany(ctx, storage.FindManyParams{Model: "session", Where: where})
}

func (a *Auth) setPluginCredentialPassword(
	ctx *engine.Context,
	userID string,
	hash string,
) error {
	if ctx == nil || userID == "" {
		return fmt.Errorf("single-auth: plugin credential password requires a user ID")
	}
	accounts, err := a.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return err
	}
	for _, account := range accounts {
		providerID, _ := recordString(account, "providerId")
		if providerID != "credential" {
			continue
		}
		id, _ := recordString(account, "id")
		_, err = a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "account", Where: []storage.Where{{Field: "id", Value: id}},
			Update: storage.Record{"password": hash},
		})
		return err
	}
	id, generated, err := generateIdentifier(a.options, "account", 32)
	if err != nil {
		return err
	}
	now := a.options.Clock().UTC()
	account := storage.Record{
		"providerId": "credential", "accountId": userID, "userId": userID,
		"password": hash, "createdAt": now, "updatedAt": now,
	}
	if generated {
		account["id"] = id
	}
	_, err = a.adapter.Create(ctx.GoContext(), storage.CreateParams{
		Model: "account", Data: account, ForceAllowID: generated,
	})
	return err
}
