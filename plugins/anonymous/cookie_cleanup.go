package anonymous

import (
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func (p *plugin) expireSessionCookies(ctx *engine.Context) {
	request := ctx.Request()
	resolved := p.options.Runtime.ResolveSessionCookies(request)
	p.expireCookie(ctx, resolved.SessionToken)
	p.expireCookie(ctx, resolved.SessionData)

	if resolved.AccountData != nil {
		p.expireCookie(ctx, *resolved.AccountData)
		p.expireChunks(ctx, request, *resolved.AccountData)
	}
	if resolved.OAuthState != nil {
		p.expireCookie(ctx, *resolved.OAuthState)
	}
	p.expireChunks(ctx, request, resolved.SessionData)
	p.expireCookie(ctx, resolved.DontRemember)
}

func (p *plugin) expireCookie(ctx *engine.Context, cookie Cookie) {
	if cookie.Name == "" {
		return
	}
	attributes := cookie.Attributes
	zero := 0
	attributes.MaxAge = &zero
	ctx.AddSetCookie(cookies.Serialize(cookie.Name, "", attributes))
}

func (p *plugin) expireChunks(
	ctx *engine.Context,
	request contract.Request,
	cookie Cookie,
) {
	if cookie.Name == "" {
		return
	}
	header := strings.Join(request.Headers().Values("Cookie"), "; ")
	parsed := cookies.Parse(header)
	for _, pair := range parsed.Pairs() {
		if !strings.HasPrefix(pair.Name, cookie.Name+".") {
			continue
		}
		chunk := cookie
		chunk.Name = pair.Name
		p.expireCookie(ctx, chunk)
	}
}
