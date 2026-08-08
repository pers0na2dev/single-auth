package multisession

import (
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func (p *plugin) listDeviceSessions(ctx *engine.Context) (contract.Response, error) {
	pairs := requestCookies(ctx.Request()).Pairs()
	if len(pairs) == 0 {
		return contract.JSONResponse(contract.StatusOK, []any{})
	}
	tokens := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		if !isMultiSessionCookie(pair.Name) {
			continue
		}
		if token, valid := signedCookie(ctx.Request(), pair.Name, p.options.Runtime.Secret); valid {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) == 0 {
		return contract.JSONResponse(contract.StatusOK, []any{})
	}
	states, err := p.options.Runtime.FindSessions(ctx.GoContext(), tokens, true)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	now := p.clock()
	seenUsers := make(map[string]struct{}, len(states))
	result := make([]map[string]any, 0, len(states))
	for _, state := range states {
		expiresAt, validExpiry := recordTime(state.Session, "expiresAt")
		if !validExpiry || !expiresAt.After(now) {
			continue
		}
		userID, _ := recordString(state.User, "id")
		if _, duplicate := seenUsers[userID]; duplicate {
			continue
		}
		seenUsers[userID] = struct{}{}
		result = append(result, map[string]any{
			"session": p.options.Runtime.SerializeSession(cloneRecord(state.Session)),
			"user":    p.options.Runtime.SerializeUser(cloneRecord(state.User)),
		})
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

func (p *plugin) setActiveSession(ctx *engine.Context) (contract.Response, error) {
	token, err := decodeSessionTokenBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	resolved := p.options.Runtime.ResolveSessionCookies(ctx.Request())
	cookieName := multiCookieName(resolved.SessionToken.Name, token)
	authoritativeToken, valid := signedCookie(ctx.Request(), cookieName, p.options.Runtime.Secret)
	if !valid {
		return contract.Response{}, invalidSessionToken()
	}
	state, err := p.options.Runtime.FindSession(ctx.GoContext(), authoritativeToken)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	expiresAt, validExpiry := timeFromState(state)
	if state == nil || !validExpiry || expiresAt.Before(p.clock()) {
		expireCookieName(ctx, cookieName, resolved.SessionToken.Attributes)
		return contract.Response{}, invalidSessionToken()
	}
	if err := p.refreshSession(ctx, *state, resolved); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"session": p.options.Runtime.SerializeSession(cloneRecord(state.Session)),
		"user":    p.options.Runtime.SerializeUser(cloneRecord(state.User)),
	})
}

func (p *plugin) revokeDeviceSession(ctx *engine.Context) (contract.Response, error) {
	bodyToken, err := decodeSessionTokenBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	active, err := p.options.Runtime.ResolveSession(ctx)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if active == nil || active.Session == nil {
		return contract.Response{}, unauthorized()
	}
	resolved := p.options.Runtime.ResolveSessionCookies(ctx.Request())
	cookieName := multiCookieName(resolved.SessionToken.Name, bodyToken)
	authoritativeToken, valid := signedCookie(ctx.Request(), cookieName, p.options.Runtime.Secret)
	if !valid {
		return contract.Response{}, invalidSessionToken()
	}
	if err := p.options.Runtime.DeleteSession(ctx.GoContext(), authoritativeToken); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	expireCookieName(ctx, cookieName, resolved.SessionToken.Attributes)
	activeToken, _ := recordString(active.Session, "token")
	if activeToken != authoritativeToken {
		return contract.JSONResponse(contract.StatusOK, map[string]any{"status": true})
	}

	verified := p.verifiedMultiTokens(ctx)
	if len(verified) > 0 {
		states, findErr := p.options.Runtime.FindSessions(ctx.GoContext(), verified, false)
		if findErr != nil {
			return contract.Response{}, preserveRuntimeError(findErr)
		}
		now := p.clock()
		for _, state := range states {
			expiresAt, ok := recordTime(state.Session, "expiresAt")
			if !ok || !expiresAt.After(now) {
				continue
			}
			if refreshErr := p.refreshSession(ctx, state, resolved); refreshErr != nil {
				return contract.Response{}, preserveRuntimeError(refreshErr)
			}
			return contract.JSONResponse(contract.StatusOK, map[string]any{"status": true})
		}
	}
	p.deleteSessionCookies(ctx, resolved)
	return contract.JSONResponse(contract.StatusOK, map[string]any{"status": true})
}

func timeFromState(state *SessionState) (expiresAt time.Time, ok bool) {
	if state == nil {
		return time.Time{}, false
	}
	return recordTime(state.Session, "expiresAt")
}
