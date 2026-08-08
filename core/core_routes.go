package core

import (
	"context"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/internal/httpio"
	"github.com/pers0na2dev/single-auth/internal/recordutil"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/storage"
)

func (a *Auth) coreEndpoints() []engine.Endpoint {
	return []engine.Endpoint{
		{
			Name: "ok", Path: "/ok", Methods: []string{"GET"}, OperationID: "ok",
			Handler: func(*engine.Context) (contract.Response, error) {
				return jsonResponse(contract.StatusOK, map[string]any{"ok": true})
			},
		},
		{
			Name: "error", Path: "/error", Methods: []string{"GET"}, OperationID: "error",
			Handler: a.errorPage,
		},
		{
			Name: "signUpEmail", Path: "/sign-up/email", Methods: []string{"POST"},
			OperationID: "signUpWithEmailAndPassword", Handler: a.signUpEmail,
		},
		{
			Name: "signInEmail", Path: "/sign-in/email", Methods: []string{"POST"},
			OperationID: "signInEmail", Handler: a.signInEmail,
		},
		{
			Name: "signInSocial", Path: "/sign-in/social", Methods: []string{"POST"},
			OperationID: "socialSignIn", Handler: a.signInSocial,
		},
		{
			Name: "callbackOAuth", Path: "/callback/:id", Methods: []string{"GET", "POST"},
			OperationID: "handleOAuthCallback", Handler: a.callbackOAuth,
		},
		{
			Name: "getSession", Path: "/get-session", Methods: []string{"GET", "POST"},
			OperationID: "getSession", Handler: a.getSession,
		},
		{
			Name: "listSessions", Path: "/list-sessions", Methods: []string{"GET"},
			OperationID: "listUserSessions", Handler: a.listSessions,
		},
		{
			Name: "revokeSession", Path: "/revoke-session", Methods: []string{"POST"},
			OperationID: "revokeSession", Handler: a.revokeSession,
		},
		{
			Name: "revokeSessions", Path: "/revoke-sessions", Methods: []string{"POST"},
			OperationID: "revokeSessions", Handler: a.revokeSessions,
		},
		{
			Name: "revokeOtherSessions", Path: "/revoke-other-sessions", Methods: []string{"POST"},
			OperationID: "revokeOtherSessions", Handler: a.revokeOtherSessions,
		},
		{
			Name: "updateSession", Path: "/update-session", Methods: []string{"POST"},
			OperationID: "updateSession", Handler: a.updateSession,
		},
		{
			Name: "updateUser", Path: "/update-user", Methods: []string{"POST"},
			OperationID: "updateUser", Handler: a.updateUser,
		},
		{
			Name: "changePassword", Path: "/change-password", Methods: []string{"POST"},
			OperationID: "changePassword", Handler: a.changePassword,
		},
		{
			Name: "setPassword", Methods: []string{"POST"}, ServerOnly: true,
			OperationID: "setPassword", Handler: a.setPassword,
		},
		{
			Name: "requestPasswordReset", Path: "/request-password-reset", Methods: []string{"POST"},
			OperationID: "requestPasswordReset", Handler: a.requestPasswordReset,
		},
		{
			Name: "requestPasswordResetCallback", Path: "/reset-password/:token", Methods: []string{"GET"},
			OperationID: "resetPasswordCallback", Handler: a.requestPasswordResetCallback,
		},
		{
			Name: "resetPassword", Path: "/reset-password", Methods: []string{"POST"},
			OperationID: "resetPassword", Handler: a.resetPassword,
		},
		{
			Name: "verifyPassword", Path: "/verify-password", Methods: []string{"POST"},
			OperationID: "verifyPassword", Handler: a.verifyPassword,
		},
		{
			Name: "sendVerificationEmail", Path: "/send-verification-email", Methods: []string{"POST"},
			OperationID: "sendVerificationEmail", Handler: a.sendVerificationEmail,
		},
		{
			Name: "verifyEmail", Path: "/verify-email", Methods: []string{"GET"},
			OperationID: "verifyEmail", Handler: a.verifyEmail,
		},
		{
			Name: "listUserAccounts", Path: "/list-accounts", Methods: []string{"GET"},
			OperationID: "listUserAccounts", Handler: a.listUserAccounts,
		},
		{
			Name: "linkSocialAccount", Path: "/link-social", Methods: []string{"POST"},
			OperationID: "linkSocialAccount", Handler: a.linkSocialAccount,
		},
		{
			Name: "getAccessToken", Path: "/get-access-token", Methods: []string{"POST"},
			OperationID: "getAccessToken", Handler: a.getAccessToken,
		},
		{
			Name: "refreshToken", Path: "/refresh-token", Methods: []string{"POST"},
			OperationID: "refreshToken", Handler: a.refreshToken,
		},
		{
			Name: "accountInfo", Path: "/account-info", Methods: []string{"GET"},
			OperationID: "accountInfo", Handler: a.accountInfo,
		},
		{
			Name: "unlinkAccount", Path: "/unlink-account", Methods: []string{"POST"},
			OperationID: "unlinkAccount", Handler: a.unlinkAccount,
		},
		{
			Name: "deleteUser", Path: "/delete-user", Methods: []string{"POST"},
			OperationID: "deleteUser", Handler: a.deleteUser,
		},
		{
			Name: "deleteUserCallback", Path: "/delete-user/callback", Methods: []string{"GET"},
			OperationID: "deleteUserCallback", Handler: a.deleteUserCallback,
		},
		{
			Name: "changeEmail", Path: "/change-email", Methods: []string{"POST"},
			OperationID: "changeEmail", Handler: a.changeEmail,
		},
		{
			Name: "signOut", Path: "/sign-out", Methods: []string{"POST"},
			OperationID: "signOut", Handler: a.signOut,
		},
	}
}

func (a *Auth) signUpEmail(ctx *engine.Context) (contract.Response, error) {
	settings := a.options.EmailAndPassword
	if !settings.Enabled || settings.DisableSignUp {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest,
			"EMAIL_PASSWORD_SIGN_UP_DISABLED",
			"Email and password sign up is not enabled",
		)
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	name, ok := requiredString(body, "name")
	if !ok {
		return contract.Response{}, missingField("name")
	}
	email, ok := requiredString(body, "email")
	if !ok || !validEmail(email) {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorInvalidEmail)
	}
	password, ok := requiredString(body, "password")
	if !ok || password == "" {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorInvalidPassword)
	}
	passwordLength := len(utf16.Encode([]rune(password)))
	if passwordLength < settings.MinPasswordLength {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorPasswordTooShort)
	}
	if passwordLength > settings.MaxPasswordLength {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorPasswordTooLong)
	}
	rememberMe, _ := optionalBool(body, "rememberMe")
	dontRemember := rememberMe != nil && !*rememberMe
	additionalUserFields, err := a.parseAdditionalInput("user", body)
	if err != nil {
		return contract.Response{}, err
	}
	normalizedEmail := strings.ToLower(email)

	existing, findErr := a.findUserByEmail(ctx.GoContext(), a.adapter, normalizedEmail)
	if findErr != nil {
		return contract.Response{}, findErr
	}
	if existing != nil {
		// Equalize the expensive path before returning a duplicate result.
		if _, hashErr := a.hashPassword(ctx, password); hashErr != nil {
			return contract.Response{}, passwordHashError(hashErr, nil)
		}
		generic := settings.RequireEmailVerification || autoSignInDisabled(settings)
		if generic {
			user := userFromRecord(existing)
			if settings.OnExistingUserSignUp != nil {
				if callbackErr := a.runBackground(ctx.GoContext(), func(callbackContext context.Context) error {
					return settings.OnExistingUserSignUp(callbackContext, user)
				}); callbackErr != nil {
					return contract.Response{}, callbackErr
				}
			}
			return jsonResponse(contract.StatusOK, map[string]any{
				"token": nil,
				"user":  a.publicUser(existing),
			})
		}
		return contract.Response{}, baseError(422, ErrorUserAlreadyExistsAnotherEmail)
	}

	hash, err := a.hashPassword(ctx, password)
	if err != nil {
		return contract.Response{}, passwordHashError(err, contract.NewAPIError(
			contract.StatusInternalServerError,
			string(ErrorFailedToCreateUser),
			ErrorMessage(ErrorFailedToCreateUser),
		))
	}

	now := a.options.Clock().UTC()
	userID, generated, err := generateIdentifier(a.options, "user", 32)
	if err != nil {
		return contract.Response{}, err
	}
	userData := storage.Record{
		"name":          name,
		"email":         normalizedEmail,
		"emailVerified": false,
		"createdAt":     now,
		"updatedAt":     now,
	}
	if generated {
		userData["id"] = userID
	}
	if image, exists := optionalString(body, "image"); exists {
		if image == nil {
			userData["image"] = nil
		} else {
			userData["image"] = *image
		}
	}
	for key, value := range additionalUserFields {
		userData[key] = value
	}

	var createdUser storage.Record
	var session storage.Record
	err = a.runTransaction(ctx.GoContext(), func(tx storage.TransactionAdapter) error {
		var createErr error
		createdUser, createErr = tx.Create(ctx.GoContext(), storage.CreateParams{
			Model:        "user",
			Data:         userData,
			ForceAllowID: generated,
		})
		if createErr != nil {
			return createErr
		}
		createdID, ok := recordString(createdUser, "id")
		if !ok || createdID == "" {
			return baseError(contract.StatusBadRequest, ErrorFailedToCreateUser)
		}
		accountID, accountGenerated, generateErr := generateIdentifier(a.options, "account", 32)
		if generateErr != nil {
			return generateErr
		}
		account := storage.Record{
			"providerId": "credential",
			"accountId":  createdID,
			"userId":     createdID,
			"password":   hash,
			"createdAt":  now,
			"updatedAt":  now,
		}
		if accountGenerated {
			account["id"] = accountID
		}
		if _, createErr = tx.Create(ctx.GoContext(), storage.CreateParams{
			Model: "account", Data: account, ForceAllowID: accountGenerated,
		}); createErr != nil {
			return createErr
		}
		if settings.RequireEmailVerification || autoSignInDisabled(settings) {
			return nil
		}
		session, createErr = a.createSession(ctx, tx, createdID, dontRemember)
		return createErr
	})
	if err != nil {
		if apiError, ok := contract.AsAPIError(err); ok {
			return contract.Response{}, apiError
		}
		return contract.Response{}, contract.NewAPIError(
			422,
			string(ErrorFailedToCreateUser),
			ErrorMessage(ErrorFailedToCreateUser),
		).WithCause(err)
	}

	if err := a.maybeSendVerification(ctx.GoContext(), ctx.Request(), createdUser, body, true); err != nil {
		return contract.Response{}, err
	}
	if settings.RequireEmailVerification || autoSignInDisabled(settings) {
		return jsonResponse(contract.StatusOK, map[string]any{
			"token": nil,
			"user":  a.publicUser(createdUser),
		})
	}
	a.setSessionCookies(ctx, session, createdUser, dontRemember)
	token, _ := recordString(session, "token")
	return jsonResponse(contract.StatusOK, map[string]any{
		"token": token,
		"user":  a.publicUser(createdUser),
	})
}

func (a *Auth) signInEmail(ctx *engine.Context) (contract.Response, error) {
	settings := a.options.EmailAndPassword
	if !settings.Enabled {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest,
			"EMAIL_PASSWORD_DISABLED",
			"Email and password is not enabled",
		)
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	email, ok := requiredString(body, "email")
	if !ok || !validEmail(email) {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorInvalidEmail)
	}
	password, ok := requiredString(body, "password")
	if !ok {
		return contract.Response{}, missingField("password")
	}
	user, err := a.findUserByEmail(ctx.GoContext(), a.adapter, strings.ToLower(email))
	if err != nil {
		return contract.Response{}, err
	}
	if user == nil {
		if _, hashErr := a.hashPassword(ctx, password); hashErr != nil {
			return contract.Response{}, passwordHashError(hashErr, nil)
		}
		return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorInvalidEmailOrPassword)
	}
	userID, _ := recordString(user, "id")
	account, err := a.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "account",
		Where: []storage.Where{
			{Field: "userId", Value: userID},
			{Field: "providerId", Value: "credential"},
		},
	})
	if err != nil {
		return contract.Response{}, err
	}
	storedHash, hasPassword := recordString(account, "password")
	if account == nil || !hasPassword || storedHash == "" {
		if _, hashErr := a.hashPassword(ctx, password); hashErr != nil {
			return contract.Response{}, passwordHashError(hashErr, nil)
		}
		return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorInvalidEmailOrPassword)
	}
	if !settings.Password.Verify(storedHash, password) {
		return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorInvalidEmailOrPassword)
	}
	if settings.RequireEmailVerification {
		verified, _ := recordBool(user, "emailVerified")
		if !verified {
			if a.options.EmailVerification.SendOnSignIn {
				if sendErr := a.maybeSendVerification(ctx.GoContext(), ctx.Request(), user, body, false); sendErr != nil {
					return contract.Response{}, sendErr
				}
			}
			return contract.Response{}, baseError(contract.StatusForbidden, ErrorEmailNotVerified)
		}
	}
	rememberMe, _ := optionalBool(body, "rememberMe")
	dontRemember := rememberMe != nil && !*rememberMe
	var session storage.Record
	err = a.runTransaction(ctx.GoContext(), func(tx storage.TransactionAdapter) error {
		var createErr error
		session, createErr = a.createSession(ctx, tx, userID, dontRemember)
		return createErr
	})
	if err != nil {
		if _, ok := contract.AsAPIError(err); ok {
			return contract.Response{}, err
		}
		return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorFailedToCreateSession).WithCause(err)
	}
	if session == nil {
		return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorFailedToCreateSession)
	}
	a.setSessionCookies(ctx, session, user, dontRemember)
	token, _ := recordString(session, "token")
	callbackURL, _ := optionalString(body, "callbackURL")
	redirect := callbackURL != nil && *callbackURL != ""
	response := map[string]any{
		"redirect": redirect,
		"token":    token,
		"user":     a.publicUser(user),
	}
	if callbackURL != nil {
		response["url"] = *callbackURL
		if redirect {
			ctx.SetResponseHeader("Location", *callbackURL)
		}
	}
	return jsonResponse(contract.StatusOK, response)
}

func (a *Auth) getSession(ctx *engine.Context) (contract.Response, error) {
	ctx.SetResponseHeader("Cache-Control", "no-store")
	ctx.SetResponseHeader("Pragma", "no-cache")
	request := ctx.Request()
	if request.Method() == "POST" && !a.options.Session.DeferSessionRefresh {
		return contract.Response{}, baseError(
			contract.StatusMethodNotAllowed,
			ErrorMethodNeedsDeferredSession,
		)
	}

	// The signed session token is the authority for the cache cookie. Reading
	// session_data before this check would allow an orphaned cache to survive
	// sign-out or token tampering.
	token, ok := a.signedSessionToken(request)
	if !ok {
		return jsonResponse(contract.StatusOK, nil)
	}
	query, err := request.Query()
	if err != nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Validation Error",
		).WithCause(err)
	}
	disableCookieCache := queryBoolean(query, "disableCookieCache")
	disableRefresh := queryBoolean(query, "disableRefresh")
	if !disableCookieCache {
		if cached, valid := a.cachedSession(request); valid {
			if refreshAge, enabled := a.cookieCacheRefreshAge(); enabled &&
				cached.expiresAt.Sub(a.options.Clock()) < refreshAge &&
				!engine.ShouldSkipSessionRefresh(ctx) {
				session, sessionOK := cached.payload["session"].(map[string]any)
				user, userOK := cached.payload["user"].(map[string]any)
				if sessionOK && userOK {
					dontRemember := a.hasSignedCookie(
						request,
						a.cookiesForRequest(request).dontRememberName,
					)
					a.refreshCachedSessionCookies(
						ctx,
						storage.Record(session),
						storage.Record(user),
						dontRemember,
					)
				}
			}
			return jsonResponse(contract.StatusOK, map[string]any{
				"session": cached.payload["session"],
				"user":    cached.payload["user"],
			})
		} else if a.hasSessionDataCookie(request) {
			a.expireSessionDataCookies(ctx)
		}
	}

	stored, err := a.findStoredSession(ctx.GoContext(), a.adapter, token)
	if err != nil {
		return contract.Response{}, failedToGetSession(err)
	}
	if stored == nil {
		a.expireSessionCookies(ctx)
		return jsonResponse(contract.StatusOK, nil)
	}
	session, user := stored.Session, stored.User
	now := a.options.Clock().UTC()
	expiresAt, ok := recordTime(session, "expiresAt")
	if !ok || expiresAt.Before(now) {
		if !a.options.Session.DeferSessionRefresh || request.Method() == "POST" {
			if deleteErr := a.deleteStoredSession(ctx.GoContext(), token); deleteErr != nil {
				return contract.Response{}, failedToGetSession(deleteErr)
			}
		}
		a.expireSessionCookies(ctx)
		return jsonResponse(contract.StatusOK, nil)
	}

	dontRemember := a.hasSignedCookie(request, a.cookiesForRequest(request).dontRememberName)
	if dontRemember || disableRefresh {
		return jsonResponse(contract.StatusOK, map[string]any{
			"session": a.publicSession(session),
			"user":    a.publicUser(user),
		})
	}
	updateAge := defaultSessionUpdateAge
	if a.options.Session.UpdateAge != nil {
		updateAge = *a.options.Session.UpdateAge
	}
	dueAt := expiresAt.Add(-a.options.Session.ExpiresIn).Add(updateAge)
	needsRefresh := !now.Before(dueAt) && !a.options.Session.DisableSessionRefresh &&
		!engine.ShouldSkipSessionRefresh(ctx)
	if a.options.Session.DeferSessionRefresh && request.Method() != "POST" {
		if a.options.Session.CookieCache.Enabled {
			a.setCompactSessionCookie(ctx, session, user, false)
		}
		return jsonResponse(contract.StatusOK, map[string]any{
			"session":      a.publicSession(session),
			"user":         a.publicUser(user),
			"needsRefresh": needsRefresh,
		})
	}
	if needsRefresh {
		updated, updateErr := a.updateStoredSession(ctx.GoContext(), token, storage.Record{
			"updatedAt": now,
			"expiresAt": now.Add(a.options.Session.ExpiresIn),
		})
		if updateErr != nil {
			return contract.Response{}, failedToGetSession(updateErr)
		}
		if updated == nil {
			a.expireSessionCookies(ctx)
			return contract.Response{}, baseError(contract.StatusUnauthorized, ErrorFailedToGetSession)
		}
		session = updated
		a.setSessionCookies(ctx, session, user, false)
	} else if a.options.Session.CookieCache.Enabled {
		a.setCompactSessionCookie(ctx, session, user, false)
	}
	return jsonResponse(contract.StatusOK, map[string]any{
		"session": a.publicSession(session),
		"user":    a.publicUser(user),
	})
}

func (a *Auth) signOut(ctx *engine.Context) (contract.Response, error) {
	if token, ok := a.signedSessionToken(ctx.Request()); ok {
		if err := a.deleteStoredSession(ctx.GoContext(), token); err != nil {
			return contract.Response{}, err
		}
	}
	a.expireSessionCookies(ctx)
	return jsonResponse(contract.StatusOK, map[string]any{"success": true})
}

func (a *Auth) createSession(
	ctx *engine.Context,
	adapter storage.TransactionAdapter,
	userID string,
	dontRemember bool,
) (storage.Record, error) {
	return a.createSessionWithData(ctx, adapter, userID, dontRemember, nil)
}

func (a *Auth) createSessionWithData(
	ctx *engine.Context,
	adapter storage.TransactionAdapter,
	userID string,
	dontRemember bool,
	extensions storage.Record,
) (storage.Record, error) {
	return a.createSessionRecord(
		ctx.GoContext(), adapter, userID, dontRemember, extensions, true,
		a.resolveIPAddress(ctx.Request()), requestHeader(ctx.Request(), "User-Agent"),
	)
}

func (a *Auth) createSessionRecord(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	userID string,
	dontRemember bool,
	override storage.Record,
	overrideAll bool,
	ipAddress string,
	userAgent string,
) (storage.Record, error) {
	now := a.options.Clock().UTC()
	id, generated, err := generateIdentifier(a.options, "session", 32)
	if err != nil {
		return nil, err
	}
	token, err := randomString(a.options.Random, 32)
	if err != nil {
		return nil, err
	}
	expiresIn := a.options.Session.ExpiresIn
	if dontRemember {
		expiresIn = 24 * time.Hour
	}
	rest := cloneStorageRecord(override)
	delete(rest, "id")
	data := storage.Record{"ipAddress": ipAddress, "userAgent": userAgent}
	for key, value := range rest {
		data[key] = value
	}
	data["userId"] = userID
	data["expiresAt"] = now.Add(expiresIn)
	data["token"] = token
	data["createdAt"] = now
	data["updatedAt"] = now
	if overrideAll {
		for key, value := range rest {
			data[key] = value
		}
	}
	if generated {
		data["id"] = id
	}
	if !generated && !a.databaseStoresSessions() {
		id, err = randomString(a.options.Random, 32)
		if err != nil {
			return nil, err
		}
		data["id"] = id
	}
	custom, ok := adapter.(databaseCustomExecutor)
	if !ok {
		return nil, fmt.Errorf("single-auth: hooked transaction adapter is not initialized")
	}
	secondaryToken, _ := recordString(data, "token")
	secondaryExpiresAt, _ := recordTime(data, "expiresAt")
	return custom.customCreate(ctx, "session", data, func(
		base storage.TransactionAdapter,
		actual storage.Record,
	) (storage.Record, error) {
		var session storage.Record
		if a.databaseStoresSessions() {
			session, err = base.Create(ctx, storage.CreateParams{
				Model: "session", Data: actual, ForceAllowID: true,
			})
		} else {
			session, err = a.prepareSecondaryCreate("session", actual)
		}
		if err != nil {
			return nil, err
		}
		if a.secondary != nil {
			user, findErr := base.FindOne(ctx, storage.FindOneParams{
				Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
			})
			if findErr != nil {
				return nil, findErr
			}
			if err := a.storeSecondarySessionPayload(
				ctx, session, user, secondaryToken, userID, secondaryExpiresAt,
			); err != nil {
				return nil, err
			}
		}
		return session, nil
	})
}

func (a *Auth) setSessionCookies(ctx *engine.Context, session, user storage.Record, dontRemember bool) {
	token, ok := recordString(session, "token")
	if !ok {
		return
	}
	setPluginNewSession(ctx, &PluginSessionState{Session: session, User: user})
	config := a.cookiesForRequest(ctx.Request())
	options := config.sessionToken
	if dontRemember {
		options.MaxAge = nil
	}
	signed := token + "." + baCrypto.MakeSignature(token, a.options.Secret)
	ctx.AddSetCookie(cookies.Serialize(config.sessionName, signed, options))
	if dontRemember {
		value := "true"
		signedRemember := value + "." + baCrypto.MakeSignature(value, a.options.Secret)
		ctx.AddSetCookie(cookies.Serialize(
			config.dontRememberName,
			signedRemember,
			config.dontRemember,
		))
	}
	if a.options.Session.CookieCache.Enabled {
		a.setCompactSessionCookie(ctx, session, user, dontRemember)
	}
}

func (a *Auth) expireSessionCookies(ctx *engine.Context) {
	config := a.cookiesForRequest(ctx.Request())
	zero := 0
	session := config.sessionToken
	session.MaxAge = &zero
	ctx.AddSetCookie(cookies.Serialize(config.sessionName, "", session))
	data := config.sessionData
	data.MaxAge = &zero
	ctx.AddSetCookie(cookies.Serialize(config.sessionDataName, "", data))
	a.expireSessionDataCookies(ctx)
	dontRemember := config.dontRemember
	dontRemember.MaxAge = &zero
	ctx.AddSetCookie(cookies.Serialize(config.dontRememberName, "", dontRemember))
}

func (a *Auth) signedSessionToken(request contract.Request) (string, bool) {
	return a.signedCookieValue(request, a.cookiesForRequest(request).sessionName)
}

func (a *Auth) hasSignedCookie(request contract.Request, name string) bool {
	_, ok := a.signedCookieValue(request, name)
	return ok
}

func (a *Auth) signedCookieValue(request contract.Request, name string) (string, bool) {
	header := strings.Join(request.Headers().Values("Cookie"), "; ")
	value, ok := cookies.Parse(header).Get(name)
	if !ok {
		return "", false
	}
	index := strings.LastIndexByte(value, '.')
	if index < 1 {
		return "", false
	}
	token, signature := value[:index], value[index+1:]
	if !baCrypto.VerifySignature(token, signature, a.options.Secret) {
		return "", false
	}
	return token, true
}

func queryBoolean(values url.Values, name string) bool {
	entries, ok := values[name]
	if !ok || len(entries) == 0 {
		return false
	}
	// z.coerce.boolean follows JavaScript Boolean(): every non-empty string,
	// including "false" and "0", becomes true.
	return entries[0] != ""
}

func failedToGetSession(err error) *contract.APIError {
	return baseError(contract.StatusInternalServerError, ErrorFailedToGetSession).WithCause(err)
}

func (a *Auth) runTransaction(ctx context.Context, callback func(storage.TransactionAdapter) error) error {
	return a.runWithTransactionAdapter(ctx, func(
		_ context.Context,
		adapter storage.TransactionAdapter,
	) error {
		return callback(adapter)
	})
}

func (a *Auth) runBackground(ctx context.Context, callback func(context.Context) error) error {
	if a.options.RunBackground == nil {
		return callback(ctx)
	}
	return a.options.RunBackground(ctx, callback)
}

func (a *Auth) findUserByEmail(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	email string,
) (storage.Record, error) {
	return adapter.FindOne(ctx, storage.FindOneParams{
		Model: "user",
		Where: []storage.Where{{
			Field: "email", Value: email, Mode: storage.Insensitive,
		}},
	})
}

func (a *Auth) additionalUserFields(body map[string]any) storage.Record {
	result := storage.Record{}
	table, ok := a.options.Schema.Models["user"]
	if !ok {
		return result
	}
	for field, attribute := range table.Fields {
		if isCoreUserField(field) || !attribute.IsInput() {
			continue
		}
		if value, exists := body[field]; exists {
			result[field] = value
		}
	}
	return result
}

func autoSignInDisabled(options EmailAndPasswordOptions) bool {
	return options.AutoSignIn != nil && !*options.AutoSignIn
}

func decodeObjectBody(request contract.Request) (map[string]any, error) {
	return httpio.DecodeObjectBody(
		request,
		string(ErrorBodyMustBeObject),
		ErrorMessage(ErrorBodyMustBeObject),
	)
}

func requiredString(body map[string]any, name string) (string, bool) {
	return httpio.RequiredString(body, name)
}

func optionalString(body map[string]any, name string) (*string, bool) {
	return httpio.OptionalString(body, name)
}

func optionalBool(body map[string]any, name string) (*bool, bool) {
	return httpio.OptionalBool(body, name)
}

func validEmail(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n") {
		return false
	}
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value && strings.Contains(value, "@")
}

func missingField(field string) *contract.APIError {
	return contract.NewAPIError(
		contract.StatusBadRequest,
		string(ErrorMissingField),
		fmt.Sprintf("%s: %s", field, ErrorMessage(ErrorMissingField)),
	)
}

func baseError(status int, code ErrorCode) *contract.APIError {
	return contract.NewAPIError(status, string(code), ErrorMessage(code))
}

func jsonResponse(status int, value any) (contract.Response, error) {
	return contract.JSONResponse(status, value)
}

func recordString(record storage.Record, key string) (string, bool) {
	return recordutil.String(record, key)
}

func recordBool(record storage.Record, key string) (bool, bool) {
	return recordutil.Bool(record, key)
}

func recordTime(record storage.Record, key string) (time.Time, bool) {
	return recordutil.Time(record, key)
}

func (a *Auth) publicUser(record storage.Record) map[string]any {
	return a.publicRecord("user", record)
}

func (a *Auth) publicSession(record storage.Record) map[string]any {
	return a.publicRecord("session", record)
}

func (a *Auth) publicRecord(modelName string, record storage.Record) map[string]any {
	result := make(map[string]any, len(record))
	table := a.options.Schema.Models[modelName]
	for key, value := range record {
		if attribute, exists := table.Fields[key]; exists && !attribute.IsReturned() {
			continue
		}
		if date, ok := value.(time.Time); ok {
			result[key] = date.UTC().Format("2006-01-02T15:04:05.000Z")
			continue
		}
		result[key] = value
	}
	// SQL-backed upstream implementation records materialize explicitly optional extension
	// columns as null. Keep that response shape even when single-auth is using
	// an adapter (such as the in-memory adapter) that omits missing columns.
	for _, plugin := range a.options.Plugins {
		if plugin.ID != "additional-fields" && plugin.ID != "username" {
			continue
		}
		for key, attribute := range plugin.Schema.Models[modelName].Fields {
			if _, exists := result[key]; exists || !attribute.IsReturned() {
				continue
			}
			if attribute.Required != nil && !*attribute.Required {
				result[key] = nil
			}
		}
	}
	return result
}

func userFromRecord(record storage.Record) model.User {
	id, _ := recordString(record, "id")
	name, _ := recordString(record, "name")
	email, _ := recordString(record, "email")
	verified, _ := recordBool(record, "emailVerified")
	createdAt, _ := recordTime(record, "createdAt")
	updatedAt, _ := recordTime(record, "updatedAt")
	user := model.User{
		Core: model.Core{ID: id, CreatedAt: createdAt, UpdatedAt: updatedAt},
		Name: name, Email: email, EmailVerified: verified,
		AdditionalFields: model.FieldsFromRecord(record,
			"id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt"),
	}
	if image, exists := record["image"]; exists {
		if image == nil {
			user.Image = model.Null[string]()
		} else if text, ok := image.(string); ok {
			user.Image = model.Present(text)
		}
	}
	return user
}

func isCoreUserField(name string) bool {
	switch name {
	case "id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt":
		return true
	default:
		return false
	}
}

func requestHeader(request contract.Request, name string) string {
	value, _ := request.Headers().Get(name)
	return value
}
