package magiclink

import (
	"strings"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) findUserByEmail(ctx *engine.Context, email string) (storage.Record, error) {
	return p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: strings.ToLower(email)}},
	})
}

func (p *plugin) findUserByID(ctx *engine.Context, id string) (storage.Record, error) {
	return p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: id}},
	})
}

func (p *plugin) createUser(ctx *engine.Context, email, name string) (storage.Record, error) {
	if create := p.options.Runtime.CreateUser; create != nil {
		return create(ctx, CreateUserInput{Email: email, Name: name})
	}
	return p.options.Runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{
		Model: "user", Data: storage.Record{
			"email": strings.ToLower(email), "emailVerified": true, "name": name,
		},
	})
}

func (p *plugin) updateUser(ctx *engine.Context, id string, update storage.Record) (storage.Record, error) {
	return p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: id}}, Update: update,
	})
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
