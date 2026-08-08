package admin

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) authorized(ctx *engine.Context, resource string, actions ...string) (*SessionState, error) {
	if p.options.Runtime.ResolveSession == nil {
		return nil, internalError(nil)
	}
	state, err := p.options.Runtime.ResolveSession(ctx, true)
	if err != nil {
		return nil, err
	}
	if state == nil || state.User == nil {
		return nil, baseError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	userID, _ := recordString(state.User, "id")
	role, _ := recordString(state.User, "role")
	if hasPermission(userID, role, p.options, permission(resource, actions...)) {
		return state, nil
	}
	code := permissionError(resource, actions)
	return nil, adminError(contract.StatusForbidden, code)
}

func permissionError(resource string, actions []string) string {
	action := ""
	if len(actions) != 0 {
		action = actions[0]
	}
	switch resource + ":" + action {
	case "user:get":
		return ErrorNotAllowedToGetUser
	case "user:create":
		return ErrorNotAllowedToCreateUsers
	case "user:list":
		return ErrorNotAllowedToListUsers
	case "user:set-role":
		return ErrorNotAllowedToChangeUsersRole
	case "user:ban":
		return ErrorNotAllowedToBanUsers
	case "user:impersonate":
		return ErrorNotAllowedToImpersonateUsers
	case "user:delete":
		return ErrorNotAllowedToDeleteUsers
	case "user:set-password":
		return ErrorNotAllowedToSetUsersPassword
	case "user:set-email":
		return ErrorNotAllowedToSetUsersEmail
	case "user:update":
		return ErrorNotAllowedToUpdateUsers
	case "session:list":
		return ErrorNotAllowedToListUsersSessions
	case "session:revoke":
		return ErrorNotAllowedToRevokeUsersSessions
	default:
		return ErrorNotAllowedToUpdateUsers
	}
}

func (p *plugin) getUser(ctx *engine.Context) (contract.Response, error) {
	if _, err := p.authorized(ctx, "user", "get"); err != nil {
		return contract.Response{}, err
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, validationError("Invalid query").WithCause(err)
	}
	id, exists := stringQuery(query, "id")
	if !exists {
		return contract.Response{}, validationError("id is required")
	}
	user, err := p.findUser(ctx.GoContext(), id)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if user == nil {
		return contract.Response{}, userNotFound()
	}
	return jsonSuccess(p.options.Runtime.SerializeUser(user))
}

func (p *plugin) createUser(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	email, err := requiredString(body, "email")
	if err != nil {
		return contract.Response{}, err
	}
	name, err := requiredString(body, "name")
	if err != nil {
		return contract.Response{}, err
	}
	password, err := optionalString(body, "password")
	if err != nil {
		return contract.Response{}, err
	}
	rawData := map[string]any{}
	if value, exists := body["data"]; exists && value != nil {
		object, ok := value.(map[string]any)
		if !ok {
			return contract.Response{}, validationError("data must be an object")
		}
		for key, item := range object {
			rawData[key] = item
		}
	}

	var session *SessionState
	if !ctx.IsDirect() || requestHasCallerHeaders(ctx) {
		session, err = p.authorized(ctx, "user", "create")
		if err != nil {
			return contract.Response{}, err
		}
	}

	requested, roleRequested := body["role"]
	if !roleRequested {
		requested, roleRequested = rawData["role"]
	}
	delete(rawData, "role")
	roles := []string{p.options.DefaultRole}
	if roleRequested {
		if session != nil {
			userID, _ := recordString(session.User, "id")
			role, _ := recordString(session.User, "role")
			if !hasPermission(userID, role, p.options, permission("user", "set-role")) {
				return contract.Response{}, adminError(contract.StatusForbidden, ErrorNotAllowedToChangeUsersRole)
			}
		}
		roles, err = roleValue(requested)
		if err != nil {
			return contract.Response{}, err
		}
		if err := p.validateRoles(roles); err != nil {
			return contract.Response{}, err
		}
	}

	if session != nil && hasAnyKey(rawData, "banned", "banReason", "banExpires") {
		userID, _ := recordString(session.User, "id")
		role, _ := recordString(session.User, "role")
		if !hasPermission(userID, role, p.options, permission("user", "ban")) {
			return contract.Response{}, adminError(contract.StatusForbidden, ErrorNotAllowedToBanUsers)
		}
	}

	normalizedEmail := strings.ToLower(email)
	if !validEmail(normalizedEmail) {
		return contract.Response{}, baseError(contract.StatusBadRequest, string(singleauth.ErrorInvalidEmail), singleauth.ErrorMessage(singleauth.ErrorInvalidEmail))
	}
	existing, err := p.findUserByEmail(ctx.GoContext(), normalizedEmail)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if existing != nil {
		return contract.Response{}, adminError(contract.StatusBadRequest, ErrorUserAlreadyExistsUseAnotherEmail)
	}

	parseInput := make(map[string]any, len(rawData))
	for key, value := range rawData {
		parseInput[key] = value
	}
	// Admin owns these protected fields. They are intentionally marked as
	// non-input in the public schema, so feeding them through parseUserInput
	// would reject even an authorized administrator before the permission
	// checks above can take effect.
	for _, key := range []string{"banned", "banReason", "banExpires"} {
		delete(parseInput, key)
	}
	parsed := storage.Record{}
	if p.options.Runtime.ParseUserInput != nil {
		parsed, err = p.options.Runtime.ParseUserInput(ctx, parseInput)
		if err != nil {
			return contract.Response{}, err
		}
	}
	for _, key := range []string{"emailVerified", "image", "banned", "banReason", "banExpires"} {
		if value, exists := rawData[key]; exists {
			parsed[key] = value
		}
	}
	parsed["email"] = normalizedEmail
	parsed["name"] = name
	parsed["role"] = joinRoles(roles)
	if _, exists := parsed["emailVerified"]; !exists {
		parsed["emailVerified"] = false
	}
	if _, exists := parsed["createdAt"]; !exists {
		parsed["createdAt"] = p.clock().UTC()
	}
	if _, exists := parsed["updatedAt"]; !exists {
		parsed["updatedAt"] = p.clock().UTC()
	}
	if p.options.Runtime.CreateUser == nil {
		return contract.Response{}, internalError(nil)
	}
	user, err := p.options.Runtime.CreateUser(ctx, parsed)
	if err != nil {
		if errors.Is(err, storage.ErrUniqueConstraint) {
			return contract.Response{}, adminError(contract.StatusBadRequest, ErrorUserAlreadyExistsUseAnotherEmail)
		}
		return contract.Response{}, preserveRuntimeError(err)
	}
	if user == nil {
		return contract.Response{}, adminError(contract.StatusInternalServerError, ErrorFailedToCreateUser)
	}
	if password != nil && *password != "" {
		if p.options.Runtime.HashPassword == nil || p.options.Runtime.SetCredentialPassword == nil {
			return contract.Response{}, internalError(nil)
		}
		hash, hashErr := p.options.Runtime.HashPassword(ctx, *password)
		if hashErr != nil {
			return contract.Response{}, preserveRuntimeError(hashErr)
		}
		userID, _ := recordString(user, "id")
		if setErr := p.options.Runtime.SetCredentialPassword(ctx, userID, hash); setErr != nil {
			return contract.Response{}, preserveRuntimeError(setErr)
		}
	}
	return jsonSuccess(map[string]any{"user": p.options.Runtime.SerializeUser(user)})
}

func (p *plugin) updateUser(ctx *engine.Context) (contract.Response, error) {
	state, err := p.authorized(ctx, "user", "update")
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
	raw, exists := body["data"]
	if !exists {
		return contract.Response{}, validationError("data is required")
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return contract.Response{}, validationError("data must be an object")
	}
	update := cloneRecord(storage.Record(object))
	if len(update) == 0 {
		return contract.Response{}, adminError(contract.StatusBadRequest, ErrorNoDataToUpdate)
	}
	if _, exists := update["password"]; exists {
		return contract.Response{}, adminError(contract.StatusBadRequest, ErrorPasswordCannotBeUpdatedViaUpdateUser)
	}
	actorID, _ := recordString(state.User, "id")
	actorRole, _ := recordString(state.User, "role")
	if roleValueRaw, exists := update["role"]; exists {
		if !hasPermission(actorID, actorRole, p.options, permission("user", "set-role")) {
			return contract.Response{}, adminError(contract.StatusForbidden, ErrorNotAllowedToChangeUsersRole)
		}
		roles, roleErr := roleValue(roleValueRaw)
		if roleErr != nil {
			return contract.Response{}, roleErr
		}
		if roleErr = p.validateRoles(roles); roleErr != nil {
			return contract.Response{}, roleErr
		}
		update["role"] = joinRoles(roles)
	}
	if hasAnyKey(update, "banned", "banReason", "banExpires") {
		if !hasPermission(actorID, actorRole, p.options, permission("user", "ban")) {
			return contract.Response{}, adminError(contract.StatusForbidden, ErrorNotAllowedToBanUsers)
		}
		if banned, _ := update["banned"].(bool); banned && userID == actorID {
			return contract.Response{}, adminError(contract.StatusBadRequest, ErrorYouCannotBanYourself)
		}
	}
	if hasAnyKey(update, "email", "emailVerified") {
		if !hasPermission(actorID, actorRole, p.options, permission("user", "set-email")) {
			return contract.Response{}, adminError(contract.StatusForbidden, ErrorNotAllowedToSetUsersEmail)
		}
		if rawEmail, exists := update["email"]; exists {
			email, ok := rawEmail.(string)
			if !ok || !validEmail(strings.ToLower(email)) {
				return contract.Response{}, baseError(contract.StatusBadRequest, string(singleauth.ErrorInvalidEmail), singleauth.ErrorMessage(singleauth.ErrorInvalidEmail))
			}
			email = strings.ToLower(email)
			existing, findErr := p.findUserByEmail(ctx.GoContext(), email)
			if findErr != nil {
				return contract.Response{}, preserveRuntimeError(findErr)
			}
			if existing != nil {
				existingID, _ := recordString(existing, "id")
				if existingID != userID {
					return contract.Response{}, adminError(contract.StatusBadRequest, ErrorUserAlreadyExistsUseAnotherEmail)
				}
			}
			update["email"] = email
		}
	}
	existing, err := p.findUser(ctx.GoContext(), userID)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if existing == nil {
		return contract.Response{}, userNotFound()
	}
	if p.options.Runtime.UpdateUser == nil {
		return contract.Response{}, internalError(nil)
	}
	updated, err := p.options.Runtime.UpdateUser(ctx, userID, update)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if updated == nil {
		return contract.Response{}, userNotFound()
	}
	if banned, _ := update["banned"].(bool); banned && p.options.Runtime.RevokeSessions != nil {
		if err := p.options.Runtime.RevokeSessions(ctx, userID); err != nil {
			return contract.Response{}, preserveRuntimeError(err)
		}
	}
	return jsonSuccess(p.options.Runtime.SerializeUser(updated))
}

func (p *plugin) setRole(ctx *engine.Context) (contract.Response, error) {
	if _, err := p.authorized(ctx, "user", "set-role"); err != nil {
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
	raw, exists := body["role"]
	if !exists {
		return contract.Response{}, validationError("role is required")
	}
	roles, err := roleValue(raw)
	if err != nil {
		return contract.Response{}, err
	}
	if err := p.validateRoles(roles); err != nil {
		return contract.Response{}, err
	}
	if user, findErr := p.findUser(ctx.GoContext(), userID); findErr != nil {
		return contract.Response{}, preserveRuntimeError(findErr)
	} else if user == nil {
		return contract.Response{}, userNotFound()
	}
	updated, err := p.options.Runtime.UpdateUser(ctx, userID, storage.Record{"role": joinRoles(roles)})
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if updated == nil {
		return contract.Response{}, userNotFound()
	}
	return jsonSuccess(map[string]any{"user": p.options.Runtime.SerializeUser(updated)})
}

func (p *plugin) listUsers(ctx *engine.Context) (contract.Response, error) {
	if _, err := p.authorized(ctx, "user", "list"); err != nil {
		return contract.Response{}, err
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, validationError("Invalid query").WithCause(err)
	}
	where := make([]storage.Where, 0, 2)
	if search, ok := stringQuery(query, "searchValue"); ok && search != "" {
		field, _ := stringQuery(query, "searchField")
		if field == "" {
			field = "email"
		}
		op := storage.OpContains
		if raw, exists := stringQuery(query, "searchOperator"); exists {
			op = storage.Operator(raw)
		}
		where = append(where, storage.Where{Field: field, Value: search, Operator: op})
	}
	if raw, ok := stringQuery(query, "filterValue"); ok {
		field, _ := stringQuery(query, "filterField")
		if field == "" {
			field = "email"
		}
		op := storage.OpEq
		if value, exists := stringQuery(query, "filterOperator"); exists {
			op = storage.Operator(value)
		}
		var filter any = parseQueryScalar(raw)
		if all := query["filterValue"]; len(all) > 1 {
			items := make([]any, len(all))
			for index, value := range all {
				items[index] = parseQueryScalar(value)
			}
			filter = items
		}
		where = append(where, storage.Where{Field: field, Value: filter, Operator: op})
	}
	limit := queryInteger(query, "limit")
	offset := queryInteger(query, "offset")
	var sort *storage.Sort
	if field, ok := stringQuery(query, "sortBy"); ok && field != "" {
		direction := storage.Ascending
		if raw, exists := stringQuery(query, "sortDirection"); exists && raw == "desc" {
			direction = storage.Descending
		}
		sort = &storage.Sort{Field: field, Direction: direction}
	}
	users, findErr := p.options.Runtime.Adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "user", Where: where, Limit: limit, Offset: offset, SortBy: sort,
	})
	if findErr != nil {
		return jsonSuccess(map[string]any{"users": []any{}, "total": 0})
	}
	total, countErr := p.options.Runtime.Adapter.Count(ctx.GoContext(), storage.CountParams{Model: "user", Where: where})
	if countErr != nil {
		return jsonSuccess(map[string]any{"users": []any{}, "total": 0})
	}
	serialized := make([]any, len(users))
	for index, user := range users {
		serialized[index] = p.options.Runtime.SerializeUser(user)
	}
	result := map[string]any{"users": serialized, "total": total}
	if limit != nil {
		result["limit"] = *limit
	}
	if offset != nil {
		result["offset"] = *offset
	}
	return jsonSuccess(result)
}

func (p *plugin) banUser(ctx *engine.Context) (contract.Response, error) {
	state, err := p.authorized(ctx, "user", "ban")
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
	found, err := p.findUser(ctx.GoContext(), userID)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if found == nil {
		return contract.Response{}, userNotFound()
	}
	actorID, _ := recordString(state.User, "id")
	if userID == actorID {
		return contract.Response{}, adminError(contract.StatusBadRequest, ErrorYouCannotBanYourself)
	}
	reason := p.options.DefaultBanReason
	if raw, exists := body["banReason"].(string); exists && raw != "" {
		reason = raw
	}
	if reason == "" {
		reason = "No reason"
	}
	update := storage.Record{"banned": true, "banReason": reason, "updatedAt": p.clock().UTC()}
	seconds, err := optionalNumber(body, "banExpiresIn")
	if err != nil {
		return contract.Response{}, err
	}
	if seconds != nil && *seconds != 0 {
		update["banExpires"] = p.clock().Add(time.Duration(*seconds * float64(time.Second))).UTC()
	} else if p.options.DefaultBanExpiresIn != 0 {
		update["banExpires"] = p.clock().Add(p.options.DefaultBanExpiresIn).UTC()
	}
	updated, err := p.options.Runtime.UpdateUser(ctx, userID, update)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if err := p.options.Runtime.RevokeSessions(ctx, userID); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	return jsonSuccess(map[string]any{"user": p.options.Runtime.SerializeUser(updated)})
}

func (p *plugin) unbanUser(ctx *engine.Context) (contract.Response, error) {
	if _, err := p.authorized(ctx, "user", "ban"); err != nil {
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
	found, err := p.findUser(ctx.GoContext(), userID)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if found == nil {
		return contract.Response{}, userNotFound()
	}
	updated, err := p.options.Runtime.UpdateUser(ctx, userID, storage.Record{
		"banned": false, "banExpires": nil, "banReason": nil, "updatedAt": p.clock().UTC(),
	})
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	return jsonSuccess(map[string]any{"user": p.options.Runtime.SerializeUser(updated)})
}

func (p *plugin) removeUser(ctx *engine.Context) (contract.Response, error) {
	state, err := p.authorized(ctx, "user", "delete")
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
	actorID, _ := recordString(state.User, "id")
	if userID == actorID {
		return contract.Response{}, adminError(contract.StatusBadRequest, ErrorYouCannotRemoveYourself)
	}
	user, err := p.findUser(ctx.GoContext(), userID)
	if err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	if user == nil {
		return contract.Response{}, userNotFound()
	}
	if p.options.Runtime.DeleteUser == nil {
		return contract.Response{}, internalError(nil)
	}
	if err := p.options.Runtime.DeleteUser(ctx, userID); err != nil {
		return contract.Response{}, preserveRuntimeError(err)
	}
	return jsonSuccess(map[string]any{"success": true})
}

func (p *plugin) findUser(ctx context.Context, id string) (storage.Record, error) {
	if p.options.Runtime.Adapter == nil {
		return nil, nil
	}
	return p.options.Runtime.Adapter.FindOne(ctx, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: id}}})
}

func (p *plugin) findUserByEmail(ctx context.Context, email string) (storage.Record, error) {
	if p.options.Runtime.Adapter == nil {
		return nil, nil
	}
	return p.options.Runtime.Adapter.FindOne(ctx, storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "email", Value: email}}})
}

func (p *plugin) validateRoles(roles []string) error {
	if p.options.Roles == nil {
		return nil
	}
	for _, role := range roles {
		if _, exists := p.options.Roles[role]; !exists {
			return adminError(contract.StatusBadRequest, ErrorNotAllowedToSetNonExistentValue)
		}
	}
	return nil
}

func hasAnyKey(object map[string]any, names ...string) bool {
	for _, name := range names {
		if _, exists := object[name]; exists {
			return true
		}
	}
	return false
}

func queryInteger(query map[string][]string, name string) *int {
	raw, ok := stringQuery(query, name)
	if !ok {
		return nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed == 0 {
		return nil
	}
	return storage.Int(parsed)
}

func requestHasCookie(ctx *engine.Context) bool {
	return len(ctx.Request().Headers().Values("Cookie")) != 0
}

func requestHasCallerHeaders(ctx *engine.Context) bool {
	for _, field := range ctx.Request().Headers().Fields() {
		// DirectAPI.Call synthesizes this header while encoding Body. It does
		// not correspond to single-auth's explicit `headers` option.
		if !strings.EqualFold(field.Name, "Content-Type") {
			return true
		}
	}
	return false
}

func userNotFound() *contract.APIError {
	return baseError(contract.StatusNotFound, string(singleauth.ErrorUserNotFound), singleauth.ErrorMessage(singleauth.ErrorUserNotFound))
}
