package core

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const genericPasswordResetMessage = "If this email exists in our system, check your email for the reset link"

func (a *Auth) requestPasswordReset(ctx *engine.Context) (contract.Response, error) {
	if !a.shouldSkipOrigin(ctx) {
		if err := a.validateRedirectFields(ctx.Request()); err != nil {
			return contract.Response{}, err
		}
	}
	settings := a.options.EmailAndPassword
	if settings.SendResetPassword == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "RESET_PASSWORD_DISABLED", "Reset password isn't enabled",
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
	redirectTo, _ := optionalString(body, "redirectTo")
	user, err := a.findUserByEmail(ctx.GoContext(), a.adapter, strings.ToLower(email))
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	if user == nil {
		// Preserve the same storage/random work shape as a real request without
		// revealing whether the address exists.
		_, _ = randomString(a.options.Random, 24)
		_, _ = a.findVerification(ctx, "dummy-verification-token")
		return jsonResponse(contract.StatusOK, map[string]any{
			"status": true, "message": genericPasswordResetMessage,
		})
	}
	token, err := randomString(a.options.Random, 24)
	if err != nil {
		return contract.Response{}, err
	}
	userID, _ := recordString(user, "id")
	if _, err := a.createVerification(
		ctx,
		"reset-password:"+token,
		userID,
		a.options.Clock().Add(settings.ResetPasswordTokenExpiresIn),
	); err != nil {
		return contract.Response{}, internalServerError(err)
	}
	callback := ""
	if redirectTo != nil {
		callback = percentEncodeURIComponent(*redirectTo)
	}
	resetURL := a.baseURLForRequest(ctx.Request()) + "/reset-password/" + token + "?callbackURL=" + callback
	message := PasswordResetMessage{User: userFromRecord(user), URL: resetURL, Token: token}
	if err := a.runBackground(ctx.GoContext(), func(callbackContext context.Context) error {
		return settings.SendResetPassword(callbackContext, message)
	}); err != nil {
		return contract.Response{}, err
	}
	return jsonResponse(contract.StatusOK, map[string]any{
		"status": true, "message": genericPasswordResetMessage,
	})
}

func (a *Auth) requestPasswordResetCallback(ctx *engine.Context) (contract.Response, error) {
	if !a.shouldSkipOrigin(ctx) {
		if err := a.validateRedirectFields(ctx.Request()); err != nil {
			return contract.Response{}, err
		}
	}
	token, _ := ctx.Param("token")
	query, _ := ctx.Request().Query()
	callbackURL := query.Get("callbackURL")
	if token == "" || callbackURL == "" {
		return redirectResponse(a.redirectURL(ctx.Request(), callbackURL, map[string]string{"error": "INVALID_TOKEN"})), nil
	}
	verification, err := a.findVerification(ctx, "reset-password:"+token)
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	expiresAt, validExpiry := recordTime(verification, "expiresAt")
	if verification == nil || !validExpiry || expiresAt.Before(a.options.Clock()) {
		return redirectResponse(a.redirectURL(ctx.Request(), callbackURL, map[string]string{"error": "INVALID_TOKEN"})), nil
	}
	return redirectResponse(a.redirectURL(ctx.Request(), callbackURL, map[string]string{"token": token})), nil
}

func (a *Auth) resetPassword(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	newPassword, ok := requiredString(body, "newPassword")
	if !ok {
		return contract.Response{}, missingField("newPassword")
	}
	if err := a.validatePasswordLength(newPassword); err != nil {
		return contract.Response{}, err
	}
	token, _ := optionalString(body, "token")
	if token == nil || *token == "" {
		query, _ := ctx.Request().Query()
		if value := query.Get("token"); value != "" {
			token = &value
		}
	}
	if token == nil || *token == "" {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorInvalidToken)
	}
	verification, err := a.consumeVerification(ctx, "reset-password:"+*token)
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	if verification == nil {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorInvalidToken)
	}
	userID, _ := recordString(verification, "value")
	passwordHash, err := a.hashPassword(ctx, newPassword)
	if err != nil {
		return contract.Response{}, passwordHashError(err, nil)
	}
	accounts, err := a.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	var credential storage.Record
	for _, account := range accounts {
		providerID, _ := recordString(account, "providerId")
		if providerID == "credential" {
			credential = account
			break
		}
	}
	if credential == nil {
		if err := a.createCredentialAccount(ctx, userID, passwordHash); err != nil {
			return contract.Response{}, err
		}
	} else {
		accountID, _ := recordString(credential, "id")
		if _, err := a.adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model:  "account",
			Where:  []storage.Where{{Field: "id", Value: accountID}},
			Update: storage.Record{"password": passwordHash},
		}); err != nil {
			return contract.Response{}, internalServerError(err)
		}
	}
	if a.options.EmailAndPassword.OnPasswordReset != nil {
		user, findErr := a.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		})
		if findErr != nil {
			return contract.Response{}, internalServerError(findErr)
		}
		if user != nil {
			if callbackErr := a.options.EmailAndPassword.OnPasswordReset(ctx.GoContext(), userFromRecord(user)); callbackErr != nil {
				return contract.Response{}, callbackErr
			}
		}
	}
	if a.options.EmailAndPassword.RevokeSessionsOnReset {
		if err := a.deleteStoredUserSessions(ctx.GoContext(), userID, false); err != nil {
			return contract.Response{}, internalServerError(err)
		}
	}
	return jsonResponse(contract.StatusOK, map[string]any{"status": true})
}

func (a *Auth) verifyPassword(ctx *engine.Context) (contract.Response, error) {
	current, err := a.sessionForEndpoint(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	password, ok := requiredString(body, "password")
	if !ok {
		return contract.Response{}, missingField("password")
	}
	userID, _ := recordString(current.User, "id")
	accounts, err := a.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	valid := false
	for _, account := range accounts {
		providerID, _ := recordString(account, "providerId")
		hash, hasPassword := recordString(account, "password")
		if providerID == "credential" && hasPassword && hash != "" {
			valid = a.options.EmailAndPassword.Password.Verify(hash, password)
			break
		}
	}
	if !valid {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorInvalidPassword)
	}
	return jsonResponse(contract.StatusOK, map[string]any{"status": true})
}

func (a *Auth) createCredentialAccount(ctx *engine.Context, userID, passwordHash string) error {
	id, generated, err := generateIdentifier(a.options, "account", 32)
	if err != nil {
		return err
	}
	now := a.options.Clock().UTC()
	account := storage.Record{
		"providerId": "credential", "accountId": userID, "userId": userID,
		"password": passwordHash, "createdAt": now, "updatedAt": now,
	}
	if generated {
		account["id"] = id
	}
	if _, err := a.adapter.Create(ctx.GoContext(), storage.CreateParams{
		Model: "account", Data: account, ForceAllowID: generated,
	}); err != nil {
		return internalServerError(err)
	}
	return nil
}

func (a *Auth) createVerification(
	ctx *engine.Context,
	identifier, value string,
	expiresAt time.Time,
) (storage.Record, error) {
	return a.createStoredVerification(ctx.GoContext(), identifier, value, expiresAt)
}

func (a *Auth) createStoredVerification(
	ctx context.Context,
	identifier, value string,
	expiresAt time.Time,
) (storage.Record, error) {
	storedIdentifier, _, err := a.processVerificationIdentifier(identifier)
	if err != nil {
		return nil, err
	}
	id, generated, err := generateIdentifier(a.options, "verification", 32)
	if err != nil {
		return nil, err
	}
	now := a.options.Clock().UTC()
	record := storage.Record{
		"identifier": storedIdentifier, "value": value, "expiresAt": expiresAt.UTC(),
		"createdAt": now, "updatedAt": now,
	}
	if generated {
		record["id"] = id
	}
	if !generated && a.secondary != nil && !a.options.Verification.StoreInDatabase {
		id, err = randomString(a.options.Random, 32)
		if err != nil {
			return nil, err
		}
		record["id"] = id
	}
	hooked, ok := a.adapter.(*hookedAdapter)
	if !ok {
		return nil, fmt.Errorf("single-auth: hooked adapter is not initialized")
	}
	return hooked.customCreate(ctx, "verification", record, func(
		base storage.TransactionAdapter,
		data storage.Record,
	) (storage.Record, error) {
		var created storage.Record
		if a.secondary == nil || a.options.Verification.StoreInDatabase {
			created, err = base.Create(ctx, storage.CreateParams{
				Model: "verification", Data: data, ForceAllowID: true,
			})
		} else {
			created, err = a.prepareSecondaryCreate("verification", data)
		}
		if err != nil {
			return nil, err
		}
		if err := a.storeSecondaryVerificationAt(ctx, storedIdentifier, created); err != nil {
			return nil, err
		}
		return created, nil
	})
}

func (a *Auth) findVerification(ctx *engine.Context, identifier string) (storage.Record, error) {
	return a.findStoredVerification(ctx.GoContext(), identifier)
}

func (a *Auth) findStoredVerification(ctx context.Context, identifier string) (storage.Record, error) {
	identifiers, err := a.verificationIdentifiersToTry(identifier)
	if err != nil {
		return nil, err
	}
	if a.secondary != nil {
		for _, storedIdentifier := range identifiers {
			cached, loadErr := a.loadSecondaryVerification(ctx, storedIdentifier)
			if loadErr != nil || cached != nil {
				return cached, loadErr
			}
		}
		if !a.options.Verification.StoreInDatabase {
			return nil, nil
		}
	}
	verification, err := a.peekDatabaseVerificationCandidates(ctx, identifiers)
	if err != nil {
		return nil, err
	}
	// upstream implementation returns the row selected by this read even when the same call
	// subsequently removes it as expired. A second read observes the cleanup.
	if err := a.cleanupExpiredVerifications(ctx); err != nil {
		return nil, err
	}
	return verification, nil
}

func (a *Auth) peekStoredVerification(ctx context.Context, identifier string) (storage.Record, error) {
	identifiers, err := a.verificationIdentifiersToTry(identifier)
	if err != nil {
		return nil, err
	}
	if a.secondary != nil {
		for _, storedIdentifier := range identifiers {
			cached, loadErr := a.loadSecondaryVerification(ctx, storedIdentifier)
			if loadErr != nil || cached != nil {
				return cached, loadErr
			}
		}
		if !a.options.Verification.StoreInDatabase {
			return nil, nil
		}
	}
	return a.peekDatabaseVerificationCandidates(ctx, identifiers)
}

func (a *Auth) peekDatabaseVerificationCandidates(
	ctx context.Context,
	identifiers []string,
) (storage.Record, error) {
	for _, identifier := range identifiers {
		verification, err := a.peekDatabaseVerification(ctx, identifier)
		if err != nil || verification != nil {
			return verification, err
		}
	}
	return nil, nil
}

func (a *Auth) peekDatabaseVerification(ctx context.Context, identifier string) (storage.Record, error) {
	rows, err := a.adapter.FindMany(ctx, storage.FindManyParams{
		Model:  "verification",
		Where:  []storage.Where{{Field: "identifier", Value: identifier}},
		SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Descending},
		Limit:  storage.Int(1),
	})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

func (a *Auth) consumeVerification(ctx *engine.Context, identifier string) (storage.Record, error) {
	return a.consumeStoredVerification(ctx.GoContext(), identifier)
}

func (a *Auth) consumeStoredVerification(ctx context.Context, identifier string) (storage.Record, error) {
	identifiers, err := a.verificationIdentifiersToTry(identifier)
	if err != nil {
		return nil, err
	}
	if a.secondary != nil && !a.options.Verification.StoreInDatabase {
		return a.consumeSecondaryVerifications(ctx, identifiers)
	}
	lock := a.verificationLock(identifiers[0])
	lock.Lock()
	defer lock.Unlock()
	var consumed storage.Record
	err = a.adapter.Transaction(ctx, func(transaction storage.TransactionAdapter) error {
		for _, storedIdentifier := range identifiers {
			rows, findErr := transaction.FindMany(ctx, storage.FindManyParams{
				Model: "verification", Where: []storage.Where{{Field: "identifier", Value: storedIdentifier}},
				SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Descending}, Limit: storage.Int(1),
			})
			if findErr != nil {
				return findErr
			}
			if len(rows) == 0 {
				continue
			}
			latest := rows[0]
			id, _ := recordString(latest, "id")
			hooked, ok := transaction.(*hookedExecutor)
			if !ok {
				return fmt.Errorf("single-auth: hooked transaction adapter is not initialized")
			}
			var consumeErr error
			consumed, consumeErr = hooked.customConsume(ctx, "verification", latest, func(
				base storage.TransactionAdapter,
			) (storage.Record, error) {
				winner, consumeOneErr := base.ConsumeOne(ctx, storage.ConsumeOneParams{
					Model: "verification", Where: []storage.Where{{Field: "id", Value: id}},
				})
				if consumeOneErr != nil || winner == nil {
					return winner, consumeOneErr
				}
				if _, deleteErr := base.DeleteMany(ctx, storage.DeleteManyParams{
					Model: "verification", Where: []storage.Where{{Field: "identifier", Value: storedIdentifier}},
				}); deleteErr != nil {
					return nil, deleteErr
				}
				return winner, nil
			})
			if consumeErr != nil || consumed != nil {
				return consumeErr
			}
		}
		return nil
	})
	if err != nil || consumed == nil {
		return consumed, err
	}
	if a.secondary != nil {
		for _, storedIdentifier := range identifiers {
			if err := a.secondary.Delete(ctx, verificationPrefix+storedIdentifier); err != nil {
				return nil, err
			}
		}
	}
	expiresAt, ok := recordTime(consumed, "expiresAt")
	if !ok || expiresAt.Before(a.options.Clock()) {
		return nil, nil
	}
	return consumed, nil
}

func (a *Auth) verificationLock(identifier string) *sync.Mutex {
	var hash uint32 = 2166136261
	for index := 0; index < len(identifier); index++ {
		hash ^= uint32(identifier[index])
		hash *= 16777619
	}
	return &a.verificationLocks[int(hash%uint32(len(a.verificationLocks)))]
}

func (a *Auth) redirectURL(request contract.Request, callback string, query map[string]string) string {
	base := a.baseURLForRequest(request)
	target := callback
	if target == "" {
		target = base + "/error"
	}
	baseURL, _ := url.Parse(base)
	targetURL, err := url.Parse(target)
	if err != nil {
		targetURL, _ = url.Parse(base + "/error")
	} else if baseURL != nil {
		targetURL = baseURL.ResolveReference(targetURL)
	}
	values := targetURL.Query()
	for key, value := range query {
		values.Set(key, value)
	}
	targetURL.RawQuery = values.Encode()
	return targetURL.String()
}

func redirectResponse(location string) contract.Response {
	return contract.NewResponse(
		contract.StatusFound,
		contract.NewHeaders(contract.HeaderField{Name: "Location", Value: location}),
		nil,
	)
}

func percentEncodeURIComponent(value string) string {
	var builder strings.Builder
	for _, b := range []byte(value) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
			b == '-' || b == '_' || b == '.' || b == '!' || b == '~' || b == '*' || b == '\'' || b == '(' || b == ')' {
			builder.WriteByte(b)
			continue
		}
		builder.WriteString(fmt.Sprintf("%%%02X", b))
	}
	return builder.String()
}
