package core

import (
	"strings"

	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (a *Auth) syncAccountCookieForSession(ctx *engine.Context, user storage.Record) {
	if a == nil || ctx == nil || !accountCookieEnabled(a.options.Account) {
		return
	}
	config := a.cookiesForRequest(ctx.Request())
	if responseHasCookie(ctx, config.accountDataName) {
		return
	}
	account := a.getAccountCookie(ctx.Request())
	if account == nil {
		return
	}
	if a.options.Database != nil {
		accountUserID, accountHasUser := recordString(account, "userId")
		userID, userHasID := recordString(user, "id")
		if accountHasUser && userHasID && accountUserID != userID {
			a.expireAccountCookie(ctx, config.accountDataName, config.accountData)
			return
		}
	}
	a.setAccountCookie(ctx, account)
}

func responseHasCookie(ctx *engine.Context, cookieName string) bool {
	for _, value := range ctx.ResponseHeaderValues("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(value) {
			if parsed.Name == cookieName || strings.HasPrefix(parsed.Name, cookieName+".") {
				return true
			}
		}
	}
	return false
}

func scrubResponseCookie(ctx *engine.Context, cookieName string) {
	values := ctx.ResponseHeaderValues("Set-Cookie")
	if len(values) == 0 {
		return
	}
	survivors := cookies.ScrubSetCookieValues(values, cookieName)
	ctx.RemoveResponseHeaderValues("Set-Cookie", values...)
	for _, survivor := range survivors {
		ctx.AddSetCookie(survivor)
	}
}

// ExpireCookie removes pending writes for a cookie and its chunk variants,
// then appends an expiring cookie while preserving all configured attributes.
func ExpireCookie(ctx *engine.Context, cookieName string, options cookies.Options) {
	if ctx == nil || cookieName == "" {
		return
	}
	scrubResponseCookie(ctx, cookieName)
	zero := 0
	expired := options
	expired.MaxAge = &zero
	ctx.AddSetCookie(cookies.Serialize(cookieName, "", expired))
}

func (a *Auth) expireAccountCookie(
	ctx *engine.Context,
	cookieName string,
	options cookies.Options,
) {
	ExpireCookie(ctx, cookieName, options)

	incoming := strings.Join(ctx.Request().Headers().Values("Cookie"), "; ")
	store := cookies.NewStore("account_data", cookieName, options, incoming, a.warn)
	for _, chunk := range store.Clean() {
		ctx.AddSetCookie(cookies.Serialize(chunk.Name, chunk.Value, chunk.Options))
	}
}
