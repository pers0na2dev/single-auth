package emailotp

import (
	"errors"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) findUserByEmail(ctx *engine.Context, email string) (storage.Record, error) {
	return p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: email}},
	})
}

func (p *plugin) findUserByID(ctx *engine.Context, id string) (storage.Record, error) {
	return p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: id}},
	})
}

func (p *plugin) createUser(ctx *engine.Context, input CreateUserInput) (storage.Record, error) {
	if create := p.options.Runtime.CreateUser; create != nil {
		return create(ctx, input)
	}
	record := cloneRecord(input.Additional)
	if record == nil {
		record = storage.Record{}
	}
	record["email"] = input.Email
	record["emailVerified"] = true
	record["name"] = input.Name
	if input.Image != nil {
		record["image"] = *input.Image
	}
	return p.options.Runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{Model: "user", Data: record})
}

func (p *plugin) updateUser(ctx *engine.Context, id string, update storage.Record) (storage.Record, error) {
	return p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: id}}, Update: update,
	})
}

func (p *plugin) revokeUnprovenAccess(ctx *engine.Context, userID string) error {
	if revoke := p.options.Runtime.RevokeUnproven; revoke != nil {
		return revoke(ctx, userID)
	}
	current, err := p.findUserByID(ctx, userID)
	if err != nil || current == nil {
		return err
	}
	verified, _ := recordBool(current, "emailVerified")
	if verified {
		return nil
	}
	accounts, err := p.options.Runtime.Adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return err
	}
	for _, account := range accounts {
		provider, _ := recordString(account, "providerId")
		id, _ := recordString(account, "id")
		if provider == "credential" && id != "" {
			if err := p.options.Runtime.Adapter.Delete(ctx.GoContext(), storage.DeleteParams{
				Model: "account", Where: []storage.Where{{Field: "id", Value: id}},
			}); err != nil {
				return err
			}
		}
	}
	return p.revokeSessions(ctx, userID)
}

func (p *plugin) revokeSessions(ctx *engine.Context, userID string) error {
	if revoke := p.options.Runtime.RevokeSessions; revoke != nil {
		return revoke(ctx, userID)
	}
	_, err := p.options.Runtime.Adapter.DeleteMany(ctx.GoContext(), storage.DeleteManyParams{
		Model: "session", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	return err
}

func (p *plugin) issueSession(ctx *engine.Context, user storage.Record) (*SessionState, error) {
	state, err := p.options.Runtime.IssueSession(ctx, cloneRecord(user))
	if err != nil {
		return nil, err
	}
	if state == nil || state.Session == nil {
		return nil, errors.New("emailotp: session creation failed")
	}
	if state.User == nil {
		state.User = cloneRecord(user)
	}
	return state, nil
}

func (p *plugin) additionalUserFields(ctx *engine.Context, body map[string]any) (storage.Record, error) {
	for _, name := range []string{"email", "otp", "name", "image"} {
		delete(body, name)
	}
	if parser := p.options.Runtime.ParseUserInput; parser != nil {
		return parser(ctx, body)
	}
	// single-auth filters additional fields through its root schema. Without an
	// explicit parser, fail closed and do not persist arbitrary input.
	return storage.Record{}, nil
}

func (p *plugin) updatePassword(ctx *engine.Context, user storage.Record, password string) error {
	userID, ok := recordString(user, "id")
	if !ok || userID == "" {
		return errors.New("emailotp: user id is invalid")
	}
	var hash string
	var err error
	if p.options.Password.HashWithContext != nil {
		hash, err = p.options.Password.HashWithContext(ctx, password)
	} else {
		hash, err = p.options.Password.Hash(password)
	}
	if err != nil {
		return err
	}
	accounts, err := p.options.Runtime.Adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return err
	}
	for _, account := range accounts {
		provider, _ := recordString(account, "providerId")
		if provider != "credential" {
			continue
		}
		id, _ := recordString(account, "id")
		if id == "" {
			return errors.New("emailotp: credential account id is invalid")
		}
		_, err = p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "account", Where: []storage.Where{{Field: "id", Value: id}}, Update: storage.Record{"password": hash},
		})
		return err
	}
	_, err = p.options.Runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{
		Model: "account", Data: storage.Record{
			"userId": userID, "providerId": "credential", "accountId": userID, "password": hash,
		},
	})
	return err
}
