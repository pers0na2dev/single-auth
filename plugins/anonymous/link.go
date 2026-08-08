package anonymous

import (
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) linkAccount(
	ctx *engine.Context,
	response contract.Response,
) (*contract.Response, error) {
	if !p.responseHasSessionCookie(ctx, response) {
		return nil, nil
	}

	previous, err := p.options.Runtime.ResolveSession(ctx, SessionOptional)
	if err != nil {
		return nil, err
	}
	if previous == nil || !jsTruthy(previous.User["isAnonymous"]) {
		return nil, nil
	}

	newSession := p.options.Runtime.NewSession(ctx)
	if ctx.Path() == "/sign-in/anonymous" && newSession == nil {
		return nil, anonymousError(
			contract.StatusBadRequest,
			ErrorAnonymousUsersCannotSignInAgainAnonymously,
		)
	}
	if newSession == nil {
		return nil, nil
	}

	if callback := p.options.OnLinkAccount; callback != nil {
		if err := callback(LinkAccountData{
			AnonymousUser: SessionState{
				Session: cloneRecord(previous.Session), User: cloneRecord(previous.User),
			},
			NewUser: SessionState{
				Session: cloneRecord(newSession.Session), User: cloneRecord(newSession.User),
			},
			Context: ctx,
		}); err != nil {
			return nil, err
		}
	}

	previousID, _ := recordString(previous.User, "id")
	newID, _ := recordString(newSession.User, "id")
	if p.options.DisableDeleteAnonymousUser || previousID == newID || jsTruthy(newSession.User["isAnonymous"]) {
		return nil, nil
	}
	if err := p.options.Runtime.Adapter.Delete(ctx.GoContext(), storage.DeleteParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: previousID}},
	}); err != nil {
		p.logError(
			"Failed to clean up anonymous user during post-link cleanup",
			map[string]any{"anonymousUserId": previousID, "error": err},
		)
	}
	return nil, nil
}

func (p *plugin) responseHasSessionCookie(
	ctx *engine.Context,
	response contract.Response,
) bool {
	resolved := p.options.Runtime.ResolveSessionCookies(ctx.Request())
	name := resolved.SessionToken.Name
	if name == "" {
		return false
	}
	parsed := cookies.ParseSetCookieHeader(strings.Join(response.Headers().Values("Set-Cookie"), ", "))
	for _, candidate := range parsed {
		if candidate.Name != name {
			continue
		}
		value := candidate.Attributes.Value
		first, _, _ := strings.Cut(value, ".")
		if first == "" {
			return false
		}
		return true
	}
	return false
}
