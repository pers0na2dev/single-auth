package core

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/internal/domain"
	"github.com/pers0na2dev/single-auth/storage"
)

type authenticatedSession = domain.SessionPair

func (a *Auth) listSessions(ctx *engine.Context) (contract.Response, error) {
	current, err := a.sessionForEndpoint(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if err := a.requireFreshSession(current.Session); err != nil {
		return contract.Response{}, err
	}
	userID, _ := recordString(current.User, "id")
	now := a.options.Clock().UTC()
	var sessions []storage.Record
	if a.secondary != nil {
		sessions, err = a.listSecondarySessions(ctx.GoContext(), userID, true)
	} else {
		sessions, err = a.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
			Model: "session",
			Where: []storage.Where{
				{Field: "userId", Value: userID},
				{Field: "expiresAt", Value: now, Operator: storage.OpGt},
			},
		})
	}
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	result := make([]map[string]any, 0, len(sessions))
	for _, session := range sessions {
		expiresAt, ok := recordTime(session, "expiresAt")
		if ok && expiresAt.After(now) {
			result = append(result, a.publicSession(session))
		}
	}
	return jsonResponse(contract.StatusOK, result)
}

func (a *Auth) revokeSession(ctx *engine.Context) (contract.Response, error) {
	current, err := a.sessionForEndpoint(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	token, ok := requiredString(body, "token")
	if !ok {
		return contract.Response{}, missingField("token")
	}
	target, err := a.findStoredSession(ctx.GoContext(), a.adapter, token)
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	currentUserID, _ := recordString(current.User, "id")
	var targetUserID string
	if target != nil {
		targetUserID, _ = recordString(target.Session, "userId")
	}
	if target != nil && targetUserID == currentUserID {
		if err := a.deleteStoredSession(ctx.GoContext(), token); err != nil {
			return contract.Response{}, internalServerError(err)
		}
	}
	return jsonResponse(contract.StatusOK, map[string]any{"status": true})
}

func (a *Auth) revokeSessions(ctx *engine.Context) (contract.Response, error) {
	current, err := a.sessionForEndpoint(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	userID, _ := recordString(current.User, "id")
	if err := a.deleteStoredUserSessions(ctx.GoContext(), userID, false); err != nil {
		return contract.Response{}, internalServerError(err)
	}
	return jsonResponse(contract.StatusOK, map[string]any{"status": true})
}

func (a *Auth) revokeOtherSessions(ctx *engine.Context) (contract.Response, error) {
	current, err := a.sessionForEndpoint(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	userID, _ := recordString(current.User, "id")
	currentToken, _ := recordString(current.Session, "token")
	now := a.options.Clock().UTC()
	var sessions []storage.Record
	if a.secondary != nil {
		sessions, err = a.listSecondarySessions(ctx.GoContext(), userID, true)
	} else {
		sessions, err = a.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
			Model: "session",
			Where: []storage.Where{
				{Field: "userId", Value: userID},
				{Field: "expiresAt", Value: now, Operator: storage.OpGt},
			},
		})
	}
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	for _, session := range sessions {
		token, _ := recordString(session, "token")
		if token == "" || token == currentToken {
			continue
		}
		if err := a.deleteStoredSession(ctx.GoContext(), token); err != nil {
			return contract.Response{}, internalServerError(err)
		}
	}
	return jsonResponse(contract.StatusOK, map[string]any{"status": true})
}

// sessionForEndpoint mirrors upstream implementation's regular and sensitive session
// middleware. Sensitive endpoints always bypass session_data so a revoked
// database session cannot remain authoritative through the cookie cache.
func (a *Auth) sessionForEndpoint(ctx *engine.Context, authoritative bool) (*authenticatedSession, error) {
	if injected, ok := SessionFromEndpointContext(ctx); ok {
		return &authenticatedSession{Session: injected.Session, User: injected.User}, nil
	}
	request := ctx.Request()
	token, ok := a.signedSessionToken(request)
	if !ok {
		return nil, unauthorized()
	}
	if !authoritative || !a.options.stateful {
		if cached, valid := a.cachedSession(request); valid {
			session, sessionOK := cached.payload["session"].(map[string]any)
			user, userOK := cached.payload["user"].(map[string]any)
			if sessionOK && userOK {
				return &authenticatedSession{
					Session: storage.Record(session),
					User:    storage.Record(user),
				}, nil
			}
		}
	}
	stored, err := a.findStoredSession(ctx.GoContext(), a.adapter, token)
	if err != nil {
		return nil, internalServerError(err)
	}
	if stored == nil {
		return nil, unauthorized()
	}
	session, user := stored.Session, stored.User
	expiresAt, ok := recordTime(session, "expiresAt")
	if !ok || expiresAt.Before(a.options.Clock()) {
		a.expireSessionCookies(ctx)
		return nil, unauthorized()
	}
	if user == nil {
		return nil, unauthorized()
	}
	return &authenticatedSession{Session: session, User: user}, nil
}

func (a *Auth) requireFreshSession(session storage.Record) error {
	freshAge := defaultSessionFreshAge
	if a.options.Session.FreshAge != nil {
		freshAge = *a.options.Session.FreshAge
	}
	if freshAge == 0 {
		return nil
	}
	createdAt, ok := recordTime(session, "createdAt")
	if !ok || a.options.Clock().Sub(createdAt) >= freshAge {
		return baseError(contract.StatusForbidden, ErrorSessionNotFresh)
	}
	return nil
}

func unauthorized() *contract.APIError {
	return contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
}

func internalServerError(err error) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Internal Server Error",
	).WithCause(err)
}
