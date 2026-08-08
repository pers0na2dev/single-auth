package twofactor

import (
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) afterCredentialSignIn(
	ctx *engine.Context,
	response contract.Response,
) (*contract.Response, error) {
	state := p.options.Runtime.NewSession(ctx)
	if state == nil || state.User == nil || state.Session == nil {
		return nil, nil
	}
	enabled, _ := recordBool(state.User, "twoFactorEnabled")
	if !enabled {
		return nil, nil
	}
	userID, err := userID(state.User)
	if err != nil {
		return nil, internalError(err)
	}

	trustCookie := p.cookie(ctx, "trust_device", "trust_device", p.options.TrustDeviceMaxAge)
	if trustValue, ok := signedCookie(ctx.Request(), trustCookie.Name, p.options.Runtime.Secret); ok {
		if p.rotateTrustedDevice(ctx, userID, trustValue, trustCookie) {
			return nil, nil
		}
		expireCookie(ctx, trustCookie)
	}

	sessionToken, ok := recordString(state.Session, "token")
	if !ok || sessionToken == "" {
		return nil, internalError(errors.New("twofactor: new session token is invalid"))
	}
	if err := p.options.Runtime.DeleteSession(ctx.GoContext(), sessionToken); err != nil {
		return nil, internalError(err)
	}
	p.options.Runtime.SetNewSession(ctx, nil)

	filtered := p.scrubCredentialSessionCookies(ctx, response)
	identifier, err := randomFromAlphabet(
		p.random,
		20,
		defaultRandomAlphabet,
	)
	if err != nil {
		return nil, internalError(err)
	}
	identifier = "2fa-" + identifier
	expiresAt := p.clock().Add(p.options.TwoFactorCookieMaxAge)
	if _, err := p.options.Runtime.CreateVerification(
		ctx.GoContext(), identifier, userID, expiresAt,
	); err != nil {
		return nil, internalError(err)
	}
	if _, err := p.options.Runtime.CreateVerification(
		ctx.GoContext(), "2fa-attempts-"+identifier, "0", expiresAt,
	); err != nil {
		return nil, internalError(err)
	}
	challengeCookie := p.cookie(ctx, "two_factor", "two_factor", p.options.TwoFactorCookieMaxAge)
	setSignedCookie(ctx, challengeCookie, identifier, p.options.Runtime.Secret)

	methods := make([]string, 0, 2)
	if !p.options.TOTP.Disable {
		twoFactor, findErr := p.findTwoFactor(ctx, userID)
		if findErr != nil {
			return nil, internalError(findErr)
		}
		if twoFactor != nil {
			verified, present := recordBool(twoFactor, "verified")
			if !present || verified {
				methods = append(methods, "totp")
			}
		}
	}
	if p.options.OTP.SendOTP != nil {
		methods = append(methods, "otp")
	}

	replacement, err := successResponse(map[string]any{
		"twoFactorRedirect": true,
		"twoFactorMethods":  methods,
	})
	if err != nil {
		return nil, err
	}
	replacement = replacement.WithHeaders(filtered.Headers())
	return &replacement, nil
}

func (p *plugin) rotateTrustedDevice(
	ctx *engine.Context,
	userID, value string,
	cookie Cookie,
) bool {
	token, identifier, ok := strings.Cut(value, "!")
	if !ok || token == "" || identifier == "" {
		return false
	}
	expected := baCrypto.MakeURLSignature(userID+"!"+identifier, p.options.Runtime.Secret)
	if len(token) != len(expected) || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
		return false
	}
	record, err := p.options.Runtime.FindVerification(ctx.GoContext(), identifier)
	if err != nil || record == nil {
		return false
	}
	valueUser, _ := recordString(record, "value")
	expiresAt, hasExpiry := recordTime(record, "expiresAt")
	if valueUser != userID || !hasExpiry || !expiresAt.After(p.clock()) {
		return false
	}
	if err := p.options.Runtime.DeleteVerification(ctx.GoContext(), identifier); err != nil {
		return false
	}
	newIdentifier, err := randomFromAlphabet(
		p.random, 32, defaultRandomAlphabet,
	)
	if err != nil {
		return false
	}
	newIdentifier = "trust-device-" + newIdentifier
	if _, err := p.options.Runtime.CreateVerification(
		ctx.GoContext(), newIdentifier, userID, p.clock().Add(p.options.TrustDeviceMaxAge),
	); err != nil {
		return false
	}
	newToken := baCrypto.MakeURLSignature(userID+"!"+newIdentifier, p.options.Runtime.Secret)
	setSignedCookie(ctx, cookie, newToken+"!"+newIdentifier, p.options.Runtime.Secret)
	return true
}

func (p *plugin) scrubCredentialSessionCookies(
	ctx *engine.Context,
	response contract.Response,
) contract.Response {
	sessionCookie := p.options.Runtime.SessionCookie(ctx.Request())
	sessionData := p.options.Runtime.Cookie(ctx.Request(), "session_data", "session_data")
	dontRemember := p.options.Runtime.Cookie(ctx.Request(), "dont_remember", "dont_remember")
	accountData := p.options.Runtime.Cookie(ctx.Request(), "account_data", "account_data")
	oauthState := p.options.Runtime.Cookie(ctx.Request(), "oauth_state", "oauth_state")

	filtered := scrubResponseCookies(
		ctx,
		response,
		sessionCookie.Name,
		sessionData.Name,
		accountData.Name,
		oauthState.Name,
	)
	expireCookie(ctx, sessionCookie)
	expireCookie(ctx, sessionData)
	if p.options.Runtime.AccountCookieEnabled {
		expireCookie(ctx, accountData)
	}
	if p.options.Runtime.OAuthStateCookieEnabled {
		expireCookie(ctx, oauthState)
	}
	for _, pair := range requestCookies(ctx.Request()).Pairs() {
		if strings.HasPrefix(pair.Name, sessionData.Name+".") {
			chunk := sessionData
			chunk.Name = pair.Name
			expireCookie(ctx, chunk)
		}
		if p.options.Runtime.AccountCookieEnabled && strings.HasPrefix(pair.Name, accountData.Name+".") {
			chunk := accountData
			chunk.Name = pair.Name
			expireCookie(ctx, chunk)
		}
	}
	_ = dontRemember // deliberately preserved during a pending challenge
	return filtered
}

func (p *plugin) cookie(
	ctx *engine.Context,
	key, suffix string,
	maxAge time.Duration,
) Cookie {
	result := p.options.Runtime.Cookie(ctx.Request(), key, suffix)
	seconds := int(maxAge / time.Second)
	result.Attributes.MaxAge = &seconds
	return result
}

func (p *plugin) findTwoFactor(ctx *engine.Context, userID string) (storage.Record, error) {
	return p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "twoFactor", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
}

func responseCookieNames(response contract.Response) []string {
	result := make([]string, 0)
	for _, line := range response.Headers().Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			result = append(result, parsed.Name)
		}
	}
	return result
}
