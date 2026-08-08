package onetimetoken

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func (p *plugin) generateForSession(ctx *engine.Context, state SessionState) (string, error) {
	token, err := p.makeToken(ctx, state)
	if err != nil {
		return "", err
	}
	stored, err := p.storedToken(ctx.GoContext(), token)
	if err != nil {
		return "", err
	}
	sessionToken, ok := recordString(state.Session, "token")
	if !ok {
		return "", internalError(nil)
	}
	if err := p.createVerification(
		ctx.GoContext(),
		"one-time-token:"+stored,
		sessionToken,
		p.clock().UTC().Add(p.expires),
	); err != nil {
		return "", err
	}
	return token, nil
}

func (p *plugin) generate(ctx *engine.Context) (contract.Response, error) {
	if p.options.DisableClientRequest && !ctx.IsDirect() {
		return contract.Response{}, badRequest("Client requests are disabled")
	}
	state, err := p.options.Runtime.ResolveSession(ctx)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if state == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized",
		)
	}
	token, err := p.generateForSession(ctx, *state)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	return jsonResponse(map[string]any{"token": token})
}

func (p *plugin) verify(ctx *engine.Context) (contract.Response, error) {
	token, err := decodeTokenBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	stored, err := p.storedToken(ctx.GoContext(), token)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	verification, err := p.consumeVerification(ctx.GoContext(), "one-time-token:"+stored)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if verification == nil {
		return contract.Response{}, badRequest("Invalid token")
	}
	sessionToken, ok := recordString(verification, "value")
	if !ok {
		return contract.Response{}, badRequest("Session not found")
	}
	state, err := p.options.Runtime.FindSession(ctx.GoContext(), sessionToken)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if state == nil {
		return contract.Response{}, badRequest("Session not found")
	}
	if !p.options.DisableSetSessionCookie {
		if err := p.options.Runtime.RefreshSession(ctx, cloneSessionState(*state)); err != nil {
			return contract.Response{}, preserveRuntimeError(err)
		}
	}
	expiresAt, ok := recordTime(state.Session, "expiresAt")
	if !ok || expiresAt.Before(p.clock()) {
		return contract.Response{}, badRequest("Session expired")
	}
	return jsonResponse(map[string]any{
		"session": p.options.Runtime.SerializeSession(state.Session),
		"user":    p.options.Runtime.SerializeUser(state.User),
	})
}

func (p *plugin) afterNewSession(
	ctx *engine.Context,
	response contract.Response,
) (*contract.Response, error) {
	if !p.options.SetOTTHeaderOnNewSession {
		return nil, nil
	}
	state := p.options.Runtime.NewSession(ctx)
	if state == nil {
		return nil, nil
	}
	token, err := p.generateForSession(ctx, *state)
	if err != nil {
		return nil, preserveRuntimeError(err)
	}
	ctx.SetResponseHeader("set-ott", token)
	exposedHeaders, _ := response.Headers().Get("Access-Control-Expose-Headers")
	ctx.SetResponseHeader(
		"Access-Control-Expose-Headers",
		mergeExposedHeaders(exposedHeaders),
	)
	return nil, nil
}
