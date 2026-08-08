package multisession

import (
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func (p *plugin) afterNewSession(
	ctx *engine.Context,
	response contract.Response,
) (*contract.Response, error) {
	cookieString := responseCookieString(response)
	if cookieString == "" {
		return nil, nil
	}
	newSession := p.options.Runtime.NewSession(ctx)
	if newSession == nil || newSession.Session == nil || newSession.User == nil {
		return nil, nil
	}
	resolved := p.options.Runtime.ResolveSessionCookies(ctx.Request())
	token, tokenOK := recordString(newSession.Session, "token")
	if !tokenOK {
		return nil, nil
	}
	cookieName := multiCookieName(resolved.SessionToken.Name, token)
	request := requestCookies(ctx.Request())
	if responseHasCookie(response, cookieName) {
		return nil, nil
	}
	if _, exists := request.Get(cookieName); exists {
		return nil, nil
	}

	multiKeys := make([]string, 0)
	for _, pair := range request.Pairs() {
		if isMultiSessionCookie(pair.Name) {
			multiKeys = append(multiKeys, pair.Name)
		}
	}
	newUserID, _ := recordString(newSession.User, "id")
	tokensToDelete := make([]string, 0)
	for _, key := range multiKeys {
		oldToken, valid := signedCookie(ctx.Request(), key, p.options.Runtime.Secret)
		if !valid {
			continue
		}
		oldSession, err := p.options.Runtime.FindSession(ctx.GoContext(), oldToken)
		if err != nil {
			return nil, preserveRuntimeError(err)
		}
		if oldSession == nil {
			continue
		}
		oldUserID, _ := recordString(oldSession.User, "id")
		if oldUserID != newUserID {
			continue
		}
		tokensToDelete = append(tokensToDelete, oldToken)
		expireCookieName(ctx, key, resolved.SessionToken.Attributes)
	}
	if len(tokensToDelete) > 0 {
		if err := p.options.Runtime.DeleteSessions(ctx.GoContext(), tokensToDelete); err != nil {
			return nil, preserveRuntimeError(err)
		}
	}
	currentCount := multiCookieCount(
		len(multiKeys),
		len(tokensToDelete),
		strings.Contains(cookieString, resolved.SessionToken.Name),
	)
	if currentCount > p.maximumSessions {
		return nil, nil
	}
	ctx.AddSetCookie(cookies.Serialize(
		cookieName,
		signedCookieValue(token, p.options.Runtime.Secret),
		resolved.SessionToken.Attributes,
	))
	return nil, nil
}

func (p *plugin) afterSignOut(
	ctx *engine.Context,
	_ contract.Response,
) (*contract.Response, error) {
	pairs := requestCookies(ctx.Request()).Pairs()
	if len(pairs) == 0 {
		return nil, nil
	}
	resolved := p.options.Runtime.ResolveSessionCookies(ctx.Request())
	verified := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		if !isMultiSessionCookie(pair.Name) {
			continue
		}
		token, valid := signedCookie(ctx.Request(), pair.Name, p.options.Runtime.Secret)
		if !valid {
			continue
		}
		expireCookieName(ctx, secureCookieDeleteName(pair.Name), resolved.SessionToken.Attributes)
		verified = append(verified, token)
	}
	if len(verified) > 0 {
		if err := p.options.Runtime.DeleteSessions(ctx.GoContext(), verified); err != nil {
			return nil, preserveRuntimeError(err)
		}
	}
	return nil, nil
}

func (p *plugin) verifiedMultiTokens(ctx *engine.Context) []string {
	pairs := requestCookies(ctx.Request()).Pairs()
	result := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		if !isMultiSessionCookie(pair.Name) {
			continue
		}
		if token, valid := signedCookie(ctx.Request(), pair.Name, p.options.Runtime.Secret); valid {
			result = append(result, token)
		}
	}
	return result
}

func (p *plugin) refreshSession(
	ctx *engine.Context,
	state SessionState,
	resolved SessionCookies,
) error {
	dontRemember := false
	if value, valid := signedCookie(
		ctx.Request(), resolved.DontRemember.Name, p.options.Runtime.Secret,
	); valid && value != "" {
		dontRemember = true
	}
	return p.options.Runtime.RefreshSession(ctx, cloneState(state), dontRemember)
}

func (p *plugin) deleteSessionCookies(ctx *engine.Context, resolved SessionCookies) {
	expireCookie(ctx, resolved.SessionToken)
	expireCookie(ctx, resolved.SessionData)
	if resolved.AccountData != nil {
		expireCookie(ctx, *resolved.AccountData)
		p.expireChunks(ctx, *resolved.AccountData)
	}
	if resolved.OAuthState != nil {
		expireCookie(ctx, *resolved.OAuthState)
	}
	p.expireChunks(ctx, resolved.SessionData)
	expireCookie(ctx, resolved.DontRemember)
}

func (p *plugin) expireChunks(ctx *engine.Context, cookie Cookie) {
	if cookie.Name == "" {
		return
	}
	for _, pair := range requestCookies(ctx.Request()).Pairs() {
		if strings.HasPrefix(pair.Name, cookie.Name+".") {
			expireCookieName(ctx, pair.Name, cookie.Attributes)
		}
	}
}
