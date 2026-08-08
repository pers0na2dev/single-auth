package multisession

import (
	"context"

	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) installAdapterFallbacks() {
	adapter := p.options.Runtime.Adapter
	if p.options.Runtime.FindSession == nil {
		p.options.Runtime.FindSession = func(ctx context.Context, token string) (*SessionState, error) {
			session, err := adapter.FindOne(ctx, storage.FindOneParams{
				Model: "session", Where: []storage.Where{{Field: "token", Value: token}},
			})
			if err != nil || session == nil {
				return nil, err
			}
			userID, _ := recordString(session, "userId")
			user, err := adapter.FindOne(ctx, storage.FindOneParams{
				Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
			})
			if err != nil || user == nil {
				return nil, err
			}
			return &SessionState{Session: session, User: user}, nil
		}
	}
	if p.options.Runtime.FindSessions == nil {
		p.options.Runtime.FindSessions = func(ctx context.Context, tokens []string, onlyActive bool) ([]SessionState, error) {
			where := []storage.Where{{Field: "token", Operator: storage.OpIn, Value: tokens}}
			if onlyActive {
				where = append(where, storage.Where{Field: "expiresAt", Operator: storage.OpGt, Value: p.clock()})
			}
			sessions, err := adapter.FindMany(ctx, storage.FindManyParams{Model: "session", Where: where})
			if err != nil || len(sessions) == 0 {
				return nil, err
			}
			result := make([]SessionState, 0, len(sessions))
			for _, session := range sessions {
				userID, _ := recordString(session, "userId")
				user, findErr := adapter.FindOne(ctx, storage.FindOneParams{
					Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
				})
				if findErr != nil {
					return nil, findErr
				}
				if user == nil {
					return []SessionState{}, nil
				}
				result = append(result, SessionState{Session: session, User: user})
			}
			return result, nil
		}
	}
	if p.options.Runtime.DeleteSession == nil {
		p.options.Runtime.DeleteSession = func(ctx context.Context, token string) error {
			return adapter.Delete(ctx, storage.DeleteParams{
				Model: "session", Where: []storage.Where{{Field: "token", Value: token}},
			})
		}
	}
	if p.options.Runtime.DeleteSessions == nil {
		p.options.Runtime.DeleteSessions = func(ctx context.Context, tokens []string) error {
			_, err := adapter.DeleteMany(ctx, storage.DeleteManyParams{
				Model: "session", Where: []storage.Where{{Field: "token", Operator: storage.OpIn, Value: tokens}},
			})
			return err
		}
	}
}
