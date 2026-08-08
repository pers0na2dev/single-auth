package twofactor

import (
	"errors"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) enableTwoFactor(ctx *engine.Context) (contract.Response, error) {
	session, err := p.options.Runtime.ResolveSession(ctx, singleauth.PluginSessionRequired)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	password, err := optionalString(body, "password")
	if err != nil {
		return contract.Response{}, err
	}
	issuer, err := optionalString(body, "issuer")
	if err != nil {
		return contract.Response{}, err
	}
	userIDValue, err := userID(session.User)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if err := p.checkPassword(ctx, userIDValue, password, p.options.AllowPasswordless); err != nil {
		return contract.Response{}, err
	}
	secret, err := randomFromAlphabet(
		p.random, 32, defaultRandomAlphabet,
	)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	encryptedSecret, err := p.encryptSecret([]byte(secret))
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	backupCodes, encodedBackupCodes, err := p.generateBackupCodeSet()
	if err != nil {
		return contract.Response{}, internalError(err)
	}

	if p.options.SkipVerificationOnEnable {
		updated, updateErr := p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: userIDValue}},
			Update: storage.Record{"twoFactorEnabled": true},
		})
		if updateErr != nil || updated == nil {
			return contract.Response{}, internalError(updateErr)
		}
		if err := p.replaceSession(ctx, session, userIDValue); err != nil {
			return contract.Response{}, err
		}
	}
	existing, err := p.findTwoFactor(ctx, userIDValue)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if _, err := p.options.Runtime.Adapter.DeleteMany(ctx.GoContext(), storage.DeleteManyParams{
		Model: "twoFactor", Where: []storage.Where{{Field: "userId", Value: userIDValue}},
	}); err != nil {
		return contract.Response{}, internalError(err)
	}
	verified := p.options.SkipVerificationOnEnable
	if existing != nil {
		oldVerified, present := recordBool(existing, "verified")
		verified = verified || !present || oldVerified
	}
	if _, err := p.options.Runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{
		Model: "twoFactor",
		Data: storage.Record{
			"secret": encryptedSecret, "backupCodes": encodedBackupCodes,
			"userId": userIDValue, "verified": verified,
		},
	}); err != nil {
		return contract.Response{}, internalError(err)
	}
	issuerValue := p.options.Issuer
	if issuerValue == "" {
		issuerValue = p.options.Runtime.AppName
	}
	if issuer != nil {
		issuerValue = *issuer
	}
	email, _ := recordString(session.User, "email")
	return successResponse(map[string]any{
		"totpURI":     TOTPURI(secret, issuerValue, email, p.options.TOTP.Digits, p.options.TOTP.Period),
		"backupCodes": backupCodes,
	})
}

func (p *plugin) disableTwoFactor(ctx *engine.Context) (contract.Response, error) {
	session, err := p.options.Runtime.ResolveSession(ctx, singleauth.PluginSessionAuthoritative)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	password, err := optionalString(body, "password")
	if err != nil {
		return contract.Response{}, err
	}
	userIDValue, err := userID(session.User)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if err := p.checkPassword(ctx, userIDValue, password, p.options.AllowPasswordless); err != nil {
		return contract.Response{}, err
	}
	updated, err := p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userIDValue}},
		Update: storage.Record{"twoFactorEnabled": false},
	})
	if err != nil || updated == nil {
		return contract.Response{}, internalError(err)
	}
	if err := p.options.Runtime.Adapter.Delete(ctx.GoContext(), storage.DeleteParams{
		Model: "twoFactor", Where: []storage.Where{{Field: "userId", Value: userIDValue}},
	}); err != nil {
		return contract.Response{}, internalError(err)
	}
	if err := p.replaceSession(ctx, session, userIDValue); err != nil {
		return contract.Response{}, err
	}
	trustCookie := p.cookie(ctx, "trust_device", "trust_device", p.options.TrustDeviceMaxAge)
	if value, ok := signedCookie(ctx.Request(), trustCookie.Name, p.options.Runtime.Secret); ok {
		_, identifier, found := strings.Cut(value, "!")
		if found && identifier != "" {
			if err := p.options.Runtime.DeleteVerification(ctx.GoContext(), identifier); err != nil {
				return contract.Response{}, internalError(err)
			}
		}
		expireCookie(ctx, trustCookie)
	}
	return successResponse(map[string]any{"status": true})
}

func (p *plugin) getTOTPURI(ctx *engine.Context) (contract.Response, error) {
	if p.options.TOTP.Disable {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeTOTPNotConfigured)
	}
	session, err := p.options.Runtime.ResolveSession(ctx, singleauth.PluginSessionRequired)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	password, err := optionalString(body, "password")
	if err != nil {
		return contract.Response{}, err
	}
	userIDValue, err := userID(session.User)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	twoFactor, err := p.findTwoFactor(ctx, userIDValue)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if twoFactor == nil {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeTOTPNotEnabled)
	}
	allowPasswordless := p.options.AllowPasswordless
	if p.options.TOTP.AllowPasswordless != nil {
		allowPasswordless = *p.options.TOTP.AllowPasswordless
	}
	if err := p.checkPassword(ctx, userIDValue, password, allowPasswordless); err != nil {
		return contract.Response{}, err
	}
	encrypted, _ := recordString(twoFactor, "secret")
	secret, err := p.options.Runtime.DecryptSecret(encrypted)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	issuer := p.options.Issuer
	if issuer == "" {
		issuer = p.options.Runtime.AppName
	}
	email, _ := recordString(session.User, "email")
	return successResponse(map[string]any{
		"totpURI": TOTPURI(string(secret), issuer, email, p.options.TOTP.Digits, p.options.TOTP.Period),
	})
}

func (p *plugin) generateTOTP(ctx *engine.Context) (contract.Response, error) {
	if p.options.TOTP.Disable {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeTOTPNotConfigured)
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	secret, err := requiredString(body, "secret")
	if err != nil {
		return contract.Response{}, err
	}
	code, err := GenerateTOTP(secret, p.clock(), p.options.TOTP.Digits, p.options.TOTP.Period)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	return successResponse(map[string]any{"code": code})
}

func (p *plugin) generateBackupCodes(ctx *engine.Context) (contract.Response, error) {
	session, err := p.options.Runtime.ResolveSession(ctx, singleauth.PluginSessionRequired)
	if err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	password, err := optionalString(body, "password")
	if err != nil {
		return contract.Response{}, err
	}
	userIDValue, err := userID(session.User)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	enabled, _ := recordBool(session.User, "twoFactorEnabled")
	if !enabled {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeTwoFactorNotEnabled)
	}
	allowPasswordless := p.options.AllowPasswordless
	if p.options.BackupCodes.AllowPasswordless != nil {
		allowPasswordless = *p.options.BackupCodes.AllowPasswordless
	}
	if err := p.checkPassword(ctx, userIDValue, password, allowPasswordless); err != nil {
		return contract.Response{}, err
	}
	twoFactor, err := p.findTwoFactor(ctx, userIDValue)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if twoFactor == nil {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeTwoFactorNotEnabled)
	}
	codes, encoded, err := p.generateBackupCodeSet()
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	id, _ := recordString(twoFactor, "id")
	if _, err := p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "twoFactor", Where: []storage.Where{{Field: "id", Value: id}},
		Update: storage.Record{"backupCodes": encoded},
	}); err != nil {
		return contract.Response{}, internalError(err)
	}
	return successResponse(map[string]any{"status": true, "backupCodes": codes})
}

func (p *plugin) viewBackupCodes(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	userIDValue, err := requiredString(body, "userId")
	if err != nil {
		return contract.Response{}, err
	}
	twoFactor, err := p.findTwoFactor(ctx, userIDValue)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if twoFactor == nil {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeBackupCodesNotEnabled)
	}
	encoded, _ := recordString(twoFactor, "backupCodes")
	codes, err := p.decodeBackupCodes(encoded)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if codes == nil {
		return contract.Response{}, twoFactorError(contract.StatusBadRequest, CodeInvalidBackupCode)
	}
	return successResponse(map[string]any{"status": true, "backupCodes": codes})
}

func (p *plugin) checkPassword(
	ctx *engine.Context,
	userIDValue string,
	password *string,
	allowPasswordless bool,
) error {
	account, err := p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "account", Where: []storage.Where{
			{Field: "userId", Value: userIDValue},
			{Field: "providerId", Value: "credential"},
		},
	})
	if err != nil {
		return internalError(err)
	}
	if allowPasswordless && account == nil {
		return nil
	}
	invalid := func() error {
		return contract.NewAPIError(
			contract.StatusBadRequest,
			string(singleauth.ErrorInvalidPassword),
			singleauth.ErrorMessage(singleauth.ErrorInvalidPassword),
		)
	}
	if password == nil || account == nil {
		return invalid()
	}
	stored, ok := recordString(account, "password")
	if !ok || stored == "" || !p.options.Runtime.VerifyPassword(stored, *password) {
		return invalid()
	}
	return nil
}

func (p *plugin) replaceSession(ctx *engine.Context, current *SessionState, userIDValue string) error {
	newSession, err := p.options.Runtime.IssueSession(ctx, userIDValue, false)
	if err != nil || newSession == nil || newSession.Session == nil {
		return internalError(err)
	}
	oldToken, ok := recordString(current.Session, "token")
	if !ok || oldToken == "" {
		return internalError(errors.New("twofactor: current session token is invalid"))
	}
	if err := p.options.Runtime.DeleteSession(ctx.GoContext(), oldToken); err != nil {
		return internalError(err)
	}
	return nil
}
