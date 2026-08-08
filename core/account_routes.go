package core

import (
	"strings"
	"sync"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (a *Auth) listUserAccounts(ctx *engine.Context) (contract.Response, error) {
	current, err := a.sessionForEndpoint(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	userID, _ := recordString(current.User, "id")
	accounts, err := a.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	result := make([]map[string]any, 0, len(accounts))
	for _, account := range accounts {
		parsed := a.publicAccount(account)
		scopes := []string{}
		if scope, ok := recordString(account, "scope"); ok && scope != "" {
			scopes = strings.Split(scope, ",")
		}
		delete(parsed, "scope")
		parsed["scopes"] = scopes
		result = append(result, parsed)
	}
	return jsonResponse(contract.StatusOK, result)
}

func (a *Auth) unlinkAccount(ctx *engine.Context) (contract.Response, error) {
	current, err := a.sessionForEndpoint(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if err := a.requireFreshSession(current.Session); err != nil {
		return contract.Response{}, err
	}
	body, err := decodeObjectBody(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	providerID, ok := requiredString(body, "providerId")
	if !ok {
		return contract.Response{}, missingField("providerId")
	}
	accountIDValue, err := accountTokenOptionalString(body, "accountId")
	if err != nil {
		return contract.Response{}, err
	}
	var accountID *string
	if accountIDValue != "" {
		accountID = &accountIDValue
	}
	userID, _ := recordString(current.User, "id")
	lock := a.accountOperationLock("unlink:" + userID)
	lock.Lock()
	defer lock.Unlock()
	accounts, err := a.adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return contract.Response{}, internalServerError(err)
	}
	if len(accounts) == 1 && !a.options.Account.AccountLinking.AllowUnlinkingAll {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorFailedToUnlinkLastAccount)
	}
	var target storage.Record
	for _, account := range accounts {
		candidateProvider, _ := recordString(account, "providerId")
		candidateAccount, _ := recordString(account, "accountId")
		if candidateProvider == providerID && (accountID == nil || candidateAccount == *accountID) {
			target = account
			break
		}
	}
	if target == nil {
		return contract.Response{}, baseError(contract.StatusBadRequest, ErrorAccountNotFound)
	}
	id, _ := recordString(target, "id")
	if err := a.adapter.Delete(ctx.GoContext(), storage.DeleteParams{
		Model: "account", Where: []storage.Where{{Field: "id", Value: id}},
	}); err != nil {
		return contract.Response{}, internalServerError(err)
	}
	return jsonResponse(contract.StatusOK, map[string]any{"status": true})
}

func (a *Auth) publicAccount(record storage.Record) map[string]any {
	return a.publicRecord("account", record)
}

// accountOperationLock serializes the small read-check-write windows used by
// account linking, unlinking, and token rotation. Durable adapters still own
// transaction isolation; this lock closes same-runtime races that could
// otherwise unlink every login method or create the same provider account
// twice after two concurrent lookups both observed it as absent.
func (a *Auth) accountOperationLock(key string) *sync.Mutex {
	var hash uint32 = 2166136261
	for index := 0; index < len(key); index++ {
		hash ^= uint32(key[index])
		hash *= 16777619
	}
	return &a.accountLocks[int(hash%uint32(len(a.accountLocks)))]
}
