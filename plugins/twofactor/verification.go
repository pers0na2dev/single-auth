package twofactor

import (
	"errors"
	"strconv"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type attempt struct {
	recordFailure func() error
	restore       func() error
}

type verificationContext struct {
	plugin       *plugin
	ctx          *engine.Context
	session      *SessionState
	key          string
	challengeKey string
	challenge    storage.Record
	dontRemember bool
	twoCookie    Cookie
	isSignIn     bool
}

func (p *plugin) verifyTwoFactor(ctx *engine.Context) (*verificationContext, error) {
	session, err := p.options.Runtime.ResolveSession(ctx, singleauth.PluginSessionOptional)
	if err != nil {
		return nil, err
	}
	if session != nil && session.User != nil && session.Session != nil {
		userID, userErr := userID(session.User)
		if userErr != nil {
			return nil, internalError(userErr)
		}
		sessionID, _ := recordString(session.Session, "id")
		return &verificationContext{
			plugin: p, ctx: ctx, session: session, key: userID + "!" + sessionID,
		}, nil
	}

	twoCookie := p.cookie(ctx, "two_factor", "two_factor", p.options.TwoFactorCookieMaxAge)
	challengeKey, ok := signedCookie(ctx.Request(), twoCookie.Name, p.options.Runtime.Secret)
	if !ok || challengeKey == "" {
		return nil, twoFactorError(contract.StatusUnauthorized, CodeInvalidTwoFactorCookie)
	}
	challenge, err := p.options.Runtime.FindVerification(ctx.GoContext(), challengeKey)
	if err != nil {
		return nil, internalError(err)
	}
	if challenge == nil {
		return nil, twoFactorError(contract.StatusUnauthorized, CodeInvalidTwoFactorCookie)
	}
	userIDValue, _ := recordString(challenge, "value")
	if userIDValue == "" {
		return nil, twoFactorError(contract.StatusUnauthorized, CodeInvalidTwoFactorCookie)
	}
	user, err := p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userIDValue}},
	})
	if err != nil {
		return nil, internalError(err)
	}
	if user == nil {
		return nil, twoFactorError(contract.StatusUnauthorized, CodeInvalidTwoFactorCookie)
	}
	dontRememberCookie := p.options.Runtime.Cookie(ctx.Request(), "dont_remember", "dont_remember")
	_, dontRemember := signedCookie(ctx.Request(), dontRememberCookie.Name, p.options.Runtime.Secret)
	return &verificationContext{
		plugin: p, ctx: ctx, session: &SessionState{User: user}, key: challengeKey,
		challengeKey: challengeKey, challenge: challenge, dontRemember: dontRemember,
		twoCookie: twoCookie, isSignIn: true,
	}, nil
}

func (verification *verificationContext) invalid(code string) error {
	return twoFactorError(contract.StatusUnauthorized, code)
}

func (verification *verificationContext) beginAttempt(allowed int) (*attempt, error) {
	if !verification.isSignIn {
		return &attempt{recordFailure: func() error { return nil }, restore: func() error { return nil }}, nil
	}
	identifier := "2fa-attempts-" + verification.challengeKey
	consumed, err := verification.plugin.options.Runtime.ConsumeVerification(
		verification.ctx.GoContext(), identifier,
	)
	if err != nil || consumed == nil {
		return nil, twoFactorError(contract.StatusUnauthorized, CodeInvalidTwoFactorCookie).WithCause(err)
	}
	raw, _ := recordString(consumed, "value")
	attempts, parseErr := strconv.Atoi(raw)
	if parseErr != nil || attempts < 0 {
		attempts = allowed
	}
	if attempts >= allowed {
		_, _ = verification.plugin.options.Runtime.ConsumeVerification(
			verification.ctx.GoContext(), verification.challengeKey,
		)
		expireCookie(verification.ctx, verification.twoCookie)
		return nil, twoFactorError(contract.StatusBadRequest, CodeTooManyAttempts)
	}
	expiresAt, ok := recordTime(verification.challenge, "expiresAt")
	if !ok {
		return nil, twoFactorError(contract.StatusUnauthorized, CodeInvalidTwoFactorCookie)
	}
	rearm := func(value int) error {
		_, createErr := verification.plugin.options.Runtime.CreateVerification(
			verification.ctx.GoContext(), identifier, strconv.Itoa(value), expiresAt,
		)
		return createErr
	}
	return &attempt{
		recordFailure: func() error { return rearm(attempts + 1) },
		restore:       func() error { return rearm(attempts) },
	}, nil
}

func (verification *verificationContext) valid(trustDevice bool) (contract.Response, error) {
	if !verification.isSignIn {
		token, _ := recordString(verification.session.Session, "token")
		return successResponse(map[string]any{
			"token": token,
			"user":  verification.plugin.options.Runtime.SerializeUser(verification.session.User),
		})
	}
	consumed, err := verification.plugin.options.Runtime.ConsumeVerification(
		verification.ctx.GoContext(), verification.challengeKey,
	)
	if err != nil || consumed == nil {
		expireCookie(verification.ctx, verification.twoCookie)
		return contract.Response{}, twoFactorError(
			contract.StatusUnauthorized, CodeInvalidTwoFactorCookie,
		).WithCause(err)
	}
	consumedUserID, _ := recordString(consumed, "value")
	userIDValue, _ := userID(verification.session.User)
	if consumedUserID == "" || consumedUserID != userIDValue {
		expireCookie(verification.ctx, verification.twoCookie)
		return contract.Response{}, twoFactorError(contract.StatusUnauthorized, CodeInvalidTwoFactorCookie)
	}
	state, err := verification.plugin.options.Runtime.IssueSession(
		verification.ctx, consumedUserID, verification.dontRemember,
	)
	if err != nil || state == nil || state.Session == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusInternalServerError,
			"FAILED_TO_CREATE_SESSION",
			"failed to create session",
		).WithCause(err)
	}
	verification.session = state
	expireCookie(verification.ctx, verification.twoCookie)
	if trustDevice {
		if err := verification.setTrustedDevice(consumedUserID); err != nil {
			return contract.Response{}, err
		}
	}
	token, _ := recordString(state.Session, "token")
	return successResponse(map[string]any{
		"token": token,
		"user":  verification.plugin.options.Runtime.SerializeUser(state.User),
	})
}

func (verification *verificationContext) setTrustedDevice(userID string) error {
	identifier, err := randomFromAlphabet(
		verification.plugin.random, 32, defaultRandomAlphabet,
	)
	if err != nil {
		return internalError(err)
	}
	identifier = "trust-device-" + identifier
	token := baCrypto.MakeURLSignature(userID+"!"+identifier, verification.plugin.options.Runtime.Secret)
	if _, err := verification.plugin.options.Runtime.CreateVerification(
		verification.ctx.GoContext(), identifier, userID,
		verification.plugin.clock().Add(verification.plugin.options.TrustDeviceMaxAge),
	); err != nil {
		return internalError(err)
	}
	cookie := verification.plugin.cookie(
		verification.ctx, "trust_device", "trust_device", verification.plugin.options.TrustDeviceMaxAge,
	)
	setSignedCookie(
		verification.ctx, cookie, token+"!"+identifier,
		verification.plugin.options.Runtime.Secret,
	)
	dontRemember := verification.plugin.options.Runtime.Cookie(
		verification.ctx.Request(), "dont_remember", "dont_remember",
	)
	expireCookie(verification.ctx, dontRemember)
	return nil
}

func (p *plugin) assertNotLocked(ctx *engine.Context, twoFactor storage.Record) error {
	if !p.accountLockoutEnabled() {
		return nil
	}
	lockedUntil, exists := recordTime(twoFactor, "lockedUntil")
	if !exists {
		return nil
	}
	if lockedUntil.After(p.clock()) {
		return twoFactorError(contract.StatusTooManyRequests, CodeAccountTemporarilyLocked)
	}
	id, _ := recordString(twoFactor, "id")
	if id == "" {
		return internalError(errors.New("twofactor: record id is invalid"))
	}
	_, err := p.options.Runtime.Adapter.IncrementOne(ctx.GoContext(), storage.IncrementOneParams{
		Model: "twoFactor",
		Where: []storage.Where{
			{Field: "id", Value: id},
			{Field: "lockedUntil", Operator: storage.OpLTE, Value: p.clock()},
		},
		Set: storage.Record{"failedVerificationCount": 0, "lockedUntil": nil},
	})
	if err != nil {
		return internalError(err)
	}
	return nil
}

func (p *plugin) recordFailure(ctx *engine.Context, twoFactor storage.Record) error {
	if !p.accountLockoutEnabled() {
		return nil
	}
	id, _ := recordString(twoFactor, "id")
	if id == "" {
		return internalError(errors.New("twofactor: record id is invalid"))
	}
	updated, err := p.options.Runtime.Adapter.IncrementOne(ctx.GoContext(), storage.IncrementOneParams{
		Model: "twoFactor", Where: []storage.Where{{Field: "id", Value: id}},
		Increment: map[string]float64{"failedVerificationCount": 1},
	})
	if err != nil {
		return internalError(err)
	}
	if updated != nil && recordInt(updated, "failedVerificationCount") >= p.options.AccountLockout.MaxFailedAttempts {
		_, err = p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "twoFactor", Where: []storage.Where{{Field: "id", Value: id}},
			Update: storage.Record{"lockedUntil": p.clock().Add(p.options.AccountLockout.Duration)},
		})
		if err != nil {
			return internalError(err)
		}
	}
	return nil
}

func (p *plugin) resetFailures(ctx *engine.Context, twoFactor storage.Record) error {
	if !p.accountLockoutEnabled() {
		return nil
	}
	id, _ := recordString(twoFactor, "id")
	if id == "" {
		return internalError(errors.New("twofactor: record id is invalid"))
	}
	_, err := p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "twoFactor", Where: []storage.Where{{Field: "id", Value: id}},
		Update: storage.Record{"failedVerificationCount": 0, "lockedUntil": nil},
	})
	if err != nil {
		return internalError(err)
	}
	return nil
}

func (p *plugin) accountLockoutEnabled() bool {
	return p.options.AccountLockout.Enabled == nil || *p.options.AccountLockout.Enabled
}

func splitOTPValue(value string) (string, int) {
	code, counter, found := strings.Cut(value, ":")
	if !found {
		return code, 0
	}
	attempts, _ := strconv.Atoi(counter)
	return code, attempts
}
