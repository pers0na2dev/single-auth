package phonenumber

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"

	singleauth "github.com/pers0na2dev/single-auth"
)

func (p *plugin) matchesForbiddenPhoneUpdate(ctx *engine.Context) (bool, error) {
	if ctx == nil || ctx.Path() != "/update-user" {
		return false, nil
	}
	body, err := decodeObject(ctx)
	if err != nil {
		// Preserve the core endpoint's validation result for malformed bodies.
		return false, nil
	}
	value, exists := body["phoneNumber"]
	return exists && value != nil, nil
}

func (p *plugin) blockForbiddenPhoneUpdate(*engine.Context) (*contract.Response, error) {
	return nil, phoneError(contract.StatusBadRequest, CodePhoneNumberCannotBeUpdated)
}

func (p *plugin) databaseHooks() singleauth.DatabaseHooks {
	return singleauth.DatabaseHooks{"user": {
		Update: singleauth.DatabaseOperationHooks{Before: p.beforeUserUpdate},
	}}
}

func (p *plugin) beforeUserUpdate(
	data storage.Record,
	_ singleauth.DatabaseHookContext,
) (singleauth.DatabaseHookResult, error) {
	value, exists := data["phoneNumber"]
	if exists && value == nil {
		return singleauth.DatabaseHookResult{Data: storage.Record{
			"phoneNumberVerified": false,
		}}, nil
	}
	return singleauth.DatabaseHookResult{}, nil
}
