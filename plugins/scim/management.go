package scim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const tokenAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var builtInAccountProviderIDs = map[string]struct{}{
	"credential":   {},
	"email-otp":    {},
	"magic-link":   {},
	"phone-number": {},
	"anonymous":    {},
	"siwe":         {},
}

type generateTokenBody struct {
	ProviderID     string `json:"providerId"`
	OrganizationID string `json:"organizationId"`
}

type deleteProviderBody struct {
	ProviderID string `json:"providerId"`
}

type providerView struct {
	ID             string  `json:"id"`
	ProviderID     string  `json:"providerId"`
	OrganizationID *string `json:"organizationId"`
}

func (p *plugin) generateToken(ctx *engine.Context) (contract.Response, error) {
	var body generateTokenBody
	if err := decodeManagementBody(ctx, &body); err != nil {
		return contract.Response{}, err
	}
	if strings.TrimSpace(body.ProviderID) == "" {
		return contract.Response{}, managementError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
	}
	if strings.Contains(body.ProviderID, ":") {
		return contract.Response{}, managementError(contract.StatusBadRequest, "BAD_REQUEST", "Provider id contains forbidden characters")
	}
	state, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok {
		return contract.Response{}, managementError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	userID := recordString(state.User, "id")
	if userID == "" {
		return contract.Response{}, managementError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	if p.providerIDReserved(body.ProviderID) {
		return contract.Response{}, providerCollisionError()
	}
	adapter := p.adapter(ctx)
	if adapter == nil {
		return contract.Response{}, fmt.Errorf("scim: runtime adapter is required")
	}
	if p.hasPlugin("sso") {
		existingSSO, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "ssoProvider", Where: []storage.Where{{Field: "providerId", Value: body.ProviderID}},
		})
		if err != nil {
			return contract.Response{}, err
		}
		if existingSSO != nil {
			return contract.Response{}, providerCollisionError()
		}
	}
	if body.OrganizationID != "" && !p.hasPlugin("organization") {
		return contract.Response{}, managementError(
			contract.StatusBadRequest,
			"BAD_REQUEST",
			"Restricting a token to an organization requires the organization plugin",
		)
	}

	var member storage.Record
	if body.OrganizationID != "" {
		var err error
		member, err = p.findOrganizationMember(ctx.GoContext(), adapter, userID, body.OrganizationID)
		if err != nil {
			return contract.Response{}, err
		}
		if member == nil {
			return contract.Response{}, managementError(contract.StatusForbidden, "FORBIDDEN", "You are not a member of the organization")
		}
		if !hasRequiredRole(recordString(member, "role"), p.requiredRoles()) {
			return contract.Response{}, managementError(contract.StatusForbidden, "FORBIDDEN", "Insufficient role for this operation")
		}
	}

	payload := TokenGenerationPayload{
		User: cloneSCIMRecord(state.User), Member: cloneSCIMRecord(member),
		ProviderID: body.ProviderID, OrganizationID: body.OrganizationID,
	}
	if p.options.CanGenerateToken != nil {
		allowed, err := p.options.CanGenerateToken(ctx.GoContext(), payload)
		if err != nil {
			return contract.Response{}, err
		}
		if !allowed {
			return contract.Response{}, managementError(contract.StatusForbidden, "FORBIDDEN", "You are not allowed to generate a SCIM token")
		}
	}

	existing, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "scimProvider", Where: []storage.Where{{Field: "providerId", Value: body.ProviderID}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if existing != nil {
		provider := providerFromRecord(existing)
		if err = p.assertProviderAccess(ctx.GoContext(), adapter, userID, provider); err != nil {
			return contract.Response{}, err
		}
		if err = adapter.Delete(ctx.GoContext(), storage.DeleteParams{
			Model: "scimProvider", Where: []storage.Where{{Field: "id", Value: provider.ID}},
		}); err != nil {
			return contract.Response{}, err
		}
	}

	secret, err := randomToken(p.options.Runtime.Random, 24)
	if err != nil {
		return contract.Response{}, fmt.Errorf("scim: generate token: %w", err)
	}
	encoded := EncodeBearerToken(secret, body.ProviderID, body.OrganizationID)
	payload.SCIMToken = encoded
	if p.options.BeforeSCIMTokenGenerated != nil {
		if err = p.options.BeforeSCIMTokenGenerated(ctx.GoContext(), payload); err != nil {
			return contract.Response{}, err
		}
	}
	stored, err := p.storeToken(ctx.GoContext(), secret)
	if err != nil {
		return contract.Response{}, err
	}
	data := storage.Record{"providerId": body.ProviderID, "scimToken": stored}
	if body.OrganizationID != "" {
		data["organizationId"] = body.OrganizationID
	}
	if p.options.ProviderOwnership.Enabled {
		data["userId"] = userID
	}
	created, err := adapter.Create(ctx.GoContext(), storage.CreateParams{Model: "scimProvider", Data: data})
	if err != nil {
		return contract.Response{}, err
	}
	provider := providerFromRecord(created)
	payload.SCIMProvider = &provider
	if p.options.AfterSCIMTokenGenerated != nil {
		if err = p.options.AfterSCIMTokenGenerated(ctx.GoContext(), payload); err != nil {
			return contract.Response{}, err
		}
	}
	return contract.JSONResponse(http.StatusCreated, map[string]string{"scimToken": encoded})
}

func (p *plugin) listProviderConnections(ctx *engine.Context) (contract.Response, error) {
	state, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok {
		return contract.Response{}, managementError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	userID := recordString(state.User, "id")
	adapter := p.adapter(ctx)
	if adapter == nil {
		return contract.Response{}, fmt.Errorf("scim: runtime adapter is required")
	}
	memberships := map[string][]string{}
	if p.hasPlugin("organization") {
		members, err := adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
			Model: "member", Where: []storage.Where{{Field: "userId", Value: userID}},
		})
		if err != nil {
			return contract.Response{}, err
		}
		for _, member := range members {
			memberships[recordString(member, "organizationId")] = parseMemberRoles(recordString(member, "role"))
		}
	}
	providers, err := adapter.FindMany(ctx.GoContext(), storage.FindManyParams{Model: "scimProvider"})
	if err != nil {
		return contract.Response{}, err
	}
	required := p.requiredRoles()
	views := make([]providerView, 0, len(providers))
	for _, record := range providers {
		provider := providerFromRecord(record)
		if provider.OrganizationID != "" {
			roles, member := memberships[provider.OrganizationID]
			if !member || !rolesContainRequired(roles, required) {
				continue
			}
		} else if provider.UserID != "" && provider.UserID != userID {
			continue
		}
		views = append(views, normalizeProvider(provider))
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{"providers": views})
}

func (p *plugin) getProviderConnection(ctx *engine.Context) (contract.Response, error) {
	state, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok {
		return contract.Response{}, managementError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	query, err := ctx.Request().Query()
	if err != nil || strings.TrimSpace(query.Get("providerId")) == "" {
		return contract.Response{}, managementError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters")
	}
	adapter := p.adapter(ctx)
	provider, err := p.checkProviderAccess(ctx.GoContext(), adapter, recordString(state.User, "id"), query.Get("providerId"))
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, normalizeProvider(provider))
}

func (p *plugin) deleteProviderConnection(ctx *engine.Context) (contract.Response, error) {
	state, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok {
		return contract.Response{}, managementError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	var body deleteProviderBody
	if err := decodeManagementBody(ctx, &body); err != nil || strings.TrimSpace(body.ProviderID) == "" {
		return contract.Response{}, managementError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
	}
	adapter := p.adapter(ctx)
	provider, err := p.checkProviderAccess(ctx.GoContext(), adapter, recordString(state.User, "id"), body.ProviderID)
	if err != nil {
		return contract.Response{}, err
	}
	if err = adapter.Delete(ctx.GoContext(), storage.DeleteParams{
		Model: "scimProvider", Where: []storage.Where{{Field: "id", Value: provider.ID}},
	}); err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, map[string]bool{"success": true})
}

type scimCreateName struct {
	Formatted  string `json:"formatted"`
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

type scimCreateEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

type scimCreateUserBody struct {
	UserName   string            `json:"userName"`
	ExternalID string            `json:"externalId"`
	Name       *scimCreateName   `json:"name"`
	Emails     []scimCreateEmail `json:"emails"`
	Active     *bool             `json:"active"`
}

func (p *plugin) createUser(ctx *engine.Context) (contract.Response, error) {
	provider, err := scimProviderFromContext(ctx)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	var body scimCreateUserBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil || strings.TrimSpace(body.UserName) == "" {
		err := validationError("Invalid request body")
		return contract.ResponseFromError(err), err
	}
	adapter := p.adapter(ctx)
	if adapter == nil {
		return contract.Response{}, fmt.Errorf("scim: runtime adapter is required")
	}
	accountID := body.ExternalID
	if accountID == "" {
		accountID = body.UserName
	}
	existingAccount, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "account", Where: []storage.Where{{Field: "accountId", Value: accountID}, {Field: "providerId", Value: provider.ProviderID}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if existingAccount != nil {
		err = scimError(contract.StatusConflict, "User already exists", "uniqueness")
		return contract.ResponseFromError(err), err
	}
	if body.Active != nil && !*body.Active {
		if _, err = resolveActivePatch(p.options.Runtime, storage.Record{"banned": true}); err != nil {
			return contract.ResponseFromError(err), err
		}
	}
	email := strings.ToLower(primarySCIMEmail(body))
	existingUser, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: email}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	name := scimFullName(email, body.Name)
	var user storage.Record
	if existingUser != nil {
		allowed, linkErr := p.canLinkExistingUser(ctx.GoContext(), adapter, provider, existingUser, email)
		if linkErr != nil {
			return contract.Response{}, linkErr
		}
		if !allowed {
			err = scimError(contract.StatusConflict, "User already exists", "uniqueness")
			return contract.ResponseFromError(err), err
		}
		user = existingUser
	} else {
		userData := storage.Record{"email": email, "name": name, "emailVerified": false}
		if p.options.Runtime.CreateUser != nil {
			user, err = p.options.Runtime.CreateUser(ctx, userData)
		} else {
			now := p.options.Runtime.Clock().UTC()
			userData["createdAt"] = now
			userData["updatedAt"] = now
			user, err = adapter.Create(ctx.GoContext(), storage.CreateParams{Model: "user", Data: userData})
		}
	}
	if err != nil {
		return contract.Response{}, err
	}
	userID := recordString(user, "id")
	now := p.options.Runtime.Clock().UTC()
	accountData := storage.Record{
		"userId": userID, "providerId": provider.ProviderID, "accountId": accountID,
		"accessToken": "", "refreshToken": "", "createdAt": now, "updatedAt": now,
	}
	var account storage.Record
	if p.options.Runtime.CreateAccount != nil {
		account, err = p.options.Runtime.CreateAccount(ctx.GoContext(), accountData)
	} else {
		account, err = adapter.Create(ctx.GoContext(), storage.CreateParams{Model: "account", Data: accountData})
	}
	if err != nil {
		return contract.Response{}, err
	}
	if provider.OrganizationID != "" {
		member, findErr := p.findOrganizationMember(ctx.GoContext(), adapter, userID, provider.OrganizationID)
		if findErr != nil {
			return contract.Response{}, findErr
		}
		if member == nil {
			if _, err = adapter.Create(ctx.GoContext(), storage.CreateParams{Model: "member", Data: storage.Record{
				"userId": userID, "organizationId": provider.OrganizationID, "role": "member", "createdAt": now,
			}}); err != nil {
				return contract.Response{}, err
			}
		}
	}
	if body.Active != nil && !*body.Active {
		deactivation := storage.Record{"banned": true}
		if _, err = resolveActivePatch(p.options.Runtime, deactivation); err != nil {
			return contract.ResponseFromError(err), err
		}
		if p.options.Runtime.UpdateUser != nil {
			user, err = p.options.Runtime.UpdateUser(ctx, userID, deactivation)
		} else {
			user, err = adapter.Update(ctx.GoContext(), storage.UpdateParams{
				Model: "user", Where: []storage.Where{{Field: "id", Value: userID}}, Update: deactivation,
			})
		}
		if err != nil {
			return contract.Response{}, err
		}
		if p.options.Runtime.RevokeSessions == nil {
			return contract.Response{}, fmt.Errorf("scim: Runtime.RevokeSessions is required for deactivation")
		}
		if err = p.options.Runtime.RevokeSessions(ctx, userID); err != nil {
			return contract.Response{}, err
		}
	}
	resource := scimUserResource(ctx, user, account)
	response, err := contract.JSONResponse(http.StatusCreated, resource)
	if err != nil {
		return contract.Response{}, err
	}
	return response.WithHeader("Location", resourceLocation(ctx, userID)), nil
}

func (p *plugin) checkProviderAccess(ctx context.Context, adapter storage.TransactionAdapter, userID, providerID string) (Provider, error) {
	if adapter == nil {
		return Provider{}, fmt.Errorf("scim: runtime adapter is required")
	}
	record, err := adapter.FindOne(ctx, storage.FindOneParams{
		Model: "scimProvider", Where: []storage.Where{{Field: "providerId", Value: providerID}},
	})
	if err != nil {
		return Provider{}, err
	}
	if record == nil {
		return Provider{}, managementError(contract.StatusNotFound, "NOT_FOUND", "SCIM provider not found")
	}
	provider := providerFromRecord(record)
	if err = p.assertProviderAccess(ctx, adapter, userID, provider); err != nil {
		return Provider{}, err
	}
	return provider, nil
}

func (p *plugin) assertProviderAccess(ctx context.Context, adapter storage.TransactionAdapter, userID string, provider Provider) error {
	if provider.OrganizationID != "" {
		if !p.hasPlugin("organization") {
			return managementError(contract.StatusForbidden, "FORBIDDEN", "Organization plugin is required to access this SCIM provider")
		}
		member, err := p.findOrganizationMember(ctx, adapter, userID, provider.OrganizationID)
		if err != nil {
			return err
		}
		if member == nil {
			return managementError(contract.StatusForbidden, "FORBIDDEN", "You must be a member of the organization to access this provider")
		}
		if !hasRequiredRole(recordString(member, "role"), p.requiredRoles()) {
			return managementError(contract.StatusForbidden, "FORBIDDEN", "Insufficient role for this operation")
		}
		return nil
	}
	if provider.UserID != "" && provider.UserID != userID {
		return managementError(contract.StatusForbidden, "FORBIDDEN", "You must be the owner to access this provider")
	}
	return nil
}

func (p *plugin) findOrganizationMember(ctx context.Context, adapter storage.TransactionAdapter, userID, organizationID string) (storage.Record, error) {
	return adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{{Field: "userId", Value: userID}, {Field: "organizationId", Value: organizationID}},
	})
}

func (p *plugin) requiredRoles() []string {
	if p.options.RequiredRoles != nil {
		return append([]string(nil), p.options.RequiredRoles...)
	}
	creatorRole := p.options.CreatorRole
	if creatorRole == "" {
		creatorRole = "owner"
	}
	if creatorRole == "admin" {
		return []string{"admin"}
	}
	return []string{"admin", creatorRole}
}

func parseMemberRoles(role string) []string {
	parts := strings.Split(role, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func hasRequiredRole(role string, required []string) bool {
	return rolesContainRequired(parseMemberRoles(role), required)
}

func rolesContainRequired(roles, required []string) bool {
	if len(required) == 0 {
		return true
	}
	allowed := make(map[string]struct{}, len(required))
	for _, role := range required {
		allowed[role] = struct{}{}
	}
	for _, role := range roles {
		if _, ok := allowed[role]; ok {
			return true
		}
	}
	return false
}

func (p *plugin) adapter(ctx *engine.Context) storage.TransactionAdapter {
	adapter := p.options.Runtime.Adapter
	if p.options.Runtime.AdapterForContext != nil {
		adapter = p.options.Runtime.AdapterForContext(ctx.GoContext())
	}
	return adapter
}

func (p *plugin) hasPlugin(id string) bool {
	return p.options.Runtime.HasPlugin != nil && p.options.Runtime.HasPlugin(id)
}

func (p *plugin) providerIDReserved(providerID string) bool {
	if _, reserved := builtInAccountProviderIDs[providerID]; reserved {
		return true
	}
	return p.options.Runtime.ReservedProviderID != nil && p.options.Runtime.ReservedProviderID(providerID)
}

func providerCollisionError() error {
	return managementError(
		contract.StatusBadRequest,
		"BAD_REQUEST",
		"Provider id collides with another account provider and cannot be used for SCIM",
	)
}

func managementError(status int, code, message string) *contract.APIError {
	return contract.NewAPIError(status, code, message)
}

func decodeManagementBody(ctx *engine.Context, target any) error {
	if ctx == nil || len(ctx.Request().Body()) == 0 {
		return managementError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
	}
	if err := json.Unmarshal(ctx.Request().Body(), target); err != nil {
		return managementError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body").WithCause(err)
	}
	return nil
}

func providerFromRecord(record storage.Record) Provider {
	return Provider{
		ID: recordString(record, "id"), ProviderID: recordString(record, "providerId"),
		SCIMToken: recordString(record, "scimToken"), OrganizationID: recordString(record, "organizationId"),
		UserID: recordString(record, "userId"),
	}
}

func normalizeProvider(provider Provider) providerView {
	var organizationID *string
	if provider.OrganizationID != "" {
		value := provider.OrganizationID
		organizationID = &value
	}
	return providerView{ID: provider.ID, ProviderID: provider.ProviderID, OrganizationID: organizationID}
}

func validateTokenStorage(configuration TokenStorage, runtime Runtime) error {
	if configuration.Hash != nil && (configuration.Encrypt != nil || configuration.Decrypt != nil) {
		return fmt.Errorf("scim: custom hash and encryption storage are mutually exclusive")
	}
	if (configuration.Encrypt == nil) != (configuration.Decrypt == nil) {
		return fmt.Errorf("scim: custom encryption requires both Encrypt and Decrypt")
	}
	if configuration.Hash != nil || configuration.Encrypt != nil {
		return nil
	}
	switch configuration.Mode {
	case "", TokenStoragePlain, TokenStorageHashed:
		return nil
	case TokenStorageEncrypted:
		if runtime.EncryptSecret == nil || runtime.DecryptSecret == nil {
			return fmt.Errorf("scim: encrypted token storage requires EncryptSecret and DecryptSecret")
		}
		return nil
	default:
		return fmt.Errorf("scim: unsupported token storage mode %q", configuration.Mode)
	}
}

func (p *plugin) storeToken(ctx context.Context, secret string) (string, error) {
	configuration := p.options.StoreSCIMToken
	switch {
	case configuration.Hash != nil:
		return configuration.Hash(ctx, secret)
	case configuration.Encrypt != nil:
		return configuration.Encrypt(ctx, secret)
	case configuration.Mode == TokenStorageHashed:
		return hashToken(secret), nil
	case configuration.Mode == TokenStorageEncrypted:
		return p.options.Runtime.EncryptSecret([]byte(secret))
	default:
		return secret, nil
	}
}

func (p *plugin) verifyStoredToken(ctx context.Context, stored, presented string) (bool, error) {
	if p.options.VerifyToken != nil {
		return p.options.VerifyToken(ctx, stored, presented)
	}
	configuration := p.options.StoreSCIMToken
	var candidate string
	var err error
	switch {
	case configuration.Hash != nil:
		candidate, err = configuration.Hash(ctx, presented)
	case configuration.Decrypt != nil:
		candidate, err = configuration.Decrypt(ctx, stored)
		stored = presented
	case configuration.Mode == TokenStorageHashed:
		candidate = hashToken(presented)
	case configuration.Mode == TokenStorageEncrypted:
		var decoded []byte
		decoded, err = p.options.Runtime.DecryptSecret(stored)
		candidate = string(decoded)
		stored = presented
	default:
		candidate = presented
	}
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(stored)) == 1, nil
}

func hashToken(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func randomToken(random io.Reader, size int) (string, error) {
	if random == nil || size < 1 {
		return "", fmt.Errorf("invalid random token configuration")
	}
	limit := 256 - 256%len(tokenAlphabet)
	result := make([]byte, size)
	buffer := []byte{0}
	for index := 0; index < size; {
		if _, err := io.ReadFull(random, buffer); err != nil {
			return "", err
		}
		if int(buffer[0]) >= limit {
			continue
		}
		result[index] = tokenAlphabet[int(buffer[0])%len(tokenAlphabet)]
		index++
	}
	return string(result), nil
}

func primarySCIMEmail(body scimCreateUserBody) string {
	for _, email := range body.Emails {
		if email.Primary && email.Value != "" {
			return email.Value
		}
	}
	for _, email := range body.Emails {
		if email.Value != "" {
			return email.Value
		}
	}
	return body.UserName
}

func scimFullName(email string, name *scimCreateName) string {
	if name == nil {
		return email
	}
	if formatted := strings.TrimSpace(name.Formatted); formatted != "" {
		return formatted
	}
	parts := make([]string, 0, 2)
	if name.GivenName != "" {
		parts = append(parts, name.GivenName)
	}
	if name.FamilyName != "" {
		parts = append(parts, name.FamilyName)
	}
	if len(parts) == 0 {
		return email
	}
	return strings.Join(parts, " ")
}

func resourceLocation(ctx *engine.Context, userID string) string {
	scheme := ctx.Request().Scheme()
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + ctx.Request().Host() + "/api/auth/scim/v2/Users/" + userID
}

func cloneSCIMRecord(source storage.Record) storage.Record {
	if source == nil {
		return nil
	}
	result := make(storage.Record, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
