package admin

import (
	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func (p *plugin) setUserPassword(ctx *engine.Context) (contract.Response, error) {
	if _, err := p.authorized(ctx, "user", "set-password"); err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	password, err := requiredString(body, "newPassword")
	if err != nil {
		return contract.Response{}, err
	}
	if password == "" {
		return contract.Response{}, validationError("newPassword cannot be empty")
	}
	userID, err := requiredCoercedString(body, "userId")
	if err != nil {
		return contract.Response{}, err
	}
	if userID == "" {
		return contract.Response{}, validationError("userId cannot be empty")
	}
	length := passwordLength(password)
	if minimum := p.options.Runtime.MinPasswordLength; minimum > 0 && length < minimum {
		return contract.Response{}, baseError(contract.StatusBadRequest, string(singleauth.ErrorPasswordTooShort), singleauth.ErrorMessage(singleauth.ErrorPasswordTooShort))
	}
	if maximum := p.options.Runtime.MaxPasswordLength; maximum > 0 && length > maximum {
		return contract.Response{}, baseError(contract.StatusBadRequest, string(singleauth.ErrorPasswordTooLong), singleauth.ErrorMessage(singleauth.ErrorPasswordTooLong))
	}
	user, err := p.findUser(ctx.GoContext(), userID)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if user == nil {
		return contract.Response{}, userNotFound()
	}
	if p.options.Runtime.HashPassword == nil || p.options.Runtime.SetCredentialPassword == nil {
		return contract.Response{}, internalError(nil)
	}
	hash, err := p.options.Runtime.HashPassword(ctx, password)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if err := p.options.Runtime.SetCredentialPassword(ctx, userID, hash); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	return jsonSuccess(map[string]any{"status": true})
}
