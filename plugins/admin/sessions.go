package admin

import (
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) listUserSessions(ctx *engine.Context) (contract.Response, error) {
	if _, err := p.authorized(ctx, "session", "list"); err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	userID, err := requiredCoercedString(body, "userId")
	if err != nil {
		return contract.Response{}, err
	}
	if p.options.Runtime.ListUserSessions == nil {
		return contract.Response{}, internalError(nil)
	}
	sessions, err := p.options.Runtime.ListUserSessions(ctx.GoContext(), userID, false)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	serialized := make([]any, len(sessions))
	for index, session := range sessions {
		serialized[index] = p.options.Runtime.SerializeSession(session)
	}
	return jsonSuccess(map[string]any{"sessions": serialized})
}

func (p *plugin) revokeUserSession(ctx *engine.Context) (contract.Response, error) {
	if _, err := p.authorized(ctx, "session", "revoke"); err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	token, err := requiredString(body, "sessionToken")
	if err != nil {
		return contract.Response{}, err
	}
	if p.options.Runtime.DeleteSession == nil {
		return contract.Response{}, internalError(nil)
	}
	if err := p.options.Runtime.DeleteSession(ctx.GoContext(), token); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	return jsonSuccess(map[string]any{"success": true})
}

func (p *plugin) revokeUserSessions(ctx *engine.Context) (contract.Response, error) {
	if _, err := p.authorized(ctx, "session", "revoke"); err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	userID, err := requiredCoercedString(body, "userId")
	if err != nil {
		return contract.Response{}, err
	}
	if p.options.Runtime.RevokeSessions == nil {
		return contract.Response{}, internalError(nil)
	}
	if err := p.options.Runtime.RevokeSessions(ctx, userID); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	return jsonSuccess(map[string]any{"success": true})
}

func (p *plugin) impersonateUser(ctx *engine.Context) (contract.Response, error) {
	state, err := p.authorized(ctx, "user", "impersonate")
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	userID, err := requiredCoercedString(body, "userId")
	if err != nil {
		return contract.Response{}, err
	}
	target, err := p.findUser(ctx.GoContext(), userID)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if target == nil {
		return contract.Response{}, userNotFound()
	}
	if p.isAdminUser(target) {
		actorID, _ := recordString(state.User, "id")
		actorRole, _ := recordString(state.User, "role")
		allowed := p.options.AllowImpersonatingAdmins || hasPermission(
			actorID, actorRole, p.options, permission("user", "impersonate-admins"),
		)
		if !allowed {
			return contract.Response{}, adminError(contract.StatusForbidden, ErrorYouCannotImpersonateAdmins)
		}
	}
	if p.options.Runtime.CreateSession == nil || p.options.Runtime.RefreshSession == nil {
		return contract.Response{}, internalError(nil)
	}
	actorID, _ := recordString(state.User, "id")
	expiresAt := p.clock().Add(p.options.ImpersonationSessionDuration).UTC()
	created, err := p.options.Runtime.CreateSession(ctx, userID, true, storage.Record{
		"impersonatedBy": actorID,
		"expiresAt":      expiresAt,
	})
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if created == nil || created.Session == nil {
		return contract.Response{}, adminError(contract.StatusInternalServerError, ErrorFailedToCreateUser)
	}

	adminToken, _ := recordString(state.Session, "token")
	dontRemember := ""
	if p.options.Runtime.Cookie != nil {
		name, _ := p.options.Runtime.Cookie(ctx.Request(), "dont_remember", "dont_remember")
		dontRemember, _ = readSignedCookie(ctx.Request(), name, p.options.Runtime.Secret)
	}
	if p.options.Runtime.Cookie != nil && p.options.Runtime.SessionCookie != nil {
		name, _ := p.options.Runtime.Cookie(ctx.Request(), "admin_session", "admin_session")
		_, attributes := p.options.Runtime.SessionCookie(ctx.Request())
		setSignedCookie(ctx, name, adminToken+":"+dontRemember, p.options.Runtime.Secret, attributes)
	}
	if err := p.options.Runtime.RefreshSession(ctx, *created, true); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	return jsonSuccess(map[string]any{
		"session": p.options.Runtime.SerializeSession(created.Session),
		"user":    p.options.Runtime.SerializeUser(created.User),
	})
}

func (p *plugin) stopImpersonating(ctx *engine.Context) (contract.Response, error) {
	if p.options.Runtime.ResolveSession == nil {
		return contract.Response{}, internalError(nil)
	}
	current, err := p.options.Runtime.ResolveSession(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if current == nil || current.Session == nil {
		return contract.Response{}, baseError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	adminUserID, ok := recordString(current.Session, "impersonatedBy")
	if !ok || adminUserID == "" {
		return contract.Response{}, baseError(contract.StatusBadRequest, "BAD_REQUEST", "You are not impersonating anyone")
	}
	adminUser, err := p.findUser(ctx.GoContext(), adminUserID)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if adminUser == nil {
		return contract.Response{}, baseError(contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Failed to find user")
	}
	if p.options.Runtime.Cookie == nil || p.options.Runtime.FindSession == nil {
		return contract.Response{}, internalError(nil)
	}
	adminCookieName, adminCookieOptions := p.options.Runtime.Cookie(ctx.Request(), "admin_session", "admin_session")
	value, valid := readSignedCookie(ctx.Request(), adminCookieName, p.options.Runtime.Secret)
	if !valid {
		return contract.Response{}, baseError(contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Failed to find admin session")
	}
	parts := strings.Split(value, ":")
	originalToken := ""
	dontRemember := ""
	if len(parts) > 0 {
		originalToken = parts[0]
	}
	if len(parts) > 1 {
		dontRemember = parts[1]
	}
	original, err := p.options.Runtime.FindSession(ctx.GoContext(), originalToken)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	originalUserID := ""
	if original != nil {
		originalUserID, _ = recordString(original.Session, "userId")
	}
	if original == nil || originalUserID != adminUserID {
		return contract.Response{}, baseError(contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Failed to find admin session")
	}
	currentToken, _ := recordString(current.Session, "token")
	if p.options.Runtime.DeleteSession == nil || p.options.Runtime.RefreshSession == nil {
		return contract.Response{}, internalError(nil)
	}
	if err := p.options.Runtime.DeleteSession(ctx.GoContext(), currentToken); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if err := p.options.Runtime.RefreshSession(ctx, *original, dontRemember != ""); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	expireCookie(ctx, adminCookieName, adminCookieOptions)
	return jsonSuccess(map[string]any{
		"session": p.options.Runtime.SerializeSession(original.Session),
		"user":    p.options.Runtime.SerializeUser(original.User),
	})
}

func (p *plugin) isAdminUser(user storage.Record) bool {
	id, _ := recordString(user, "id")
	if containsString(p.options.AdminUserIDs, id) {
		return true
	}
	role, _ := recordString(user, "role")
	adminRoles := make(map[string]struct{}, len(p.options.AdminRoles))
	for _, item := range p.options.AdminRoles {
		adminRoles[strings.TrimSpace(item)] = struct{}{}
	}
	for _, item := range splitComma(role) {
		if _, exists := adminRoles[item]; exists {
			return true
		}
	}
	return false
}

func readSignedCookie(request contract.Request, name, secret string) (string, bool) {
	if name == "" {
		return "", false
	}
	header := strings.Join(request.Headers().Values("Cookie"), "; ")
	value, exists := cookies.Parse(header).Get(name)
	if !exists {
		return "", false
	}
	index := strings.LastIndexByte(value, '.')
	if index < 1 || !baCrypto.VerifySignature(value[:index], value[index+1:], secret) {
		return "", false
	}
	return value[:index], true
}

func setSignedCookie(ctx *engine.Context, name, value, secret string, options cookies.Options) {
	signed := value + "." + baCrypto.MakeSignature(value, secret)
	ctx.AddSetCookie(cookies.Serialize(name, signed, options))
}

func expireCookie(ctx *engine.Context, name string, options cookies.Options) {
	zero := 0
	options.MaxAge = &zero
	ctx.AddSetCookie(cookies.Serialize(name, "", options))
}
