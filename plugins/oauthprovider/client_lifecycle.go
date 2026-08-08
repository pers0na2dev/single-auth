package oauthprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (server *Server) clientEndpoints() []engine.Endpoint {
	return []engine.Endpoint{
		{Name: "createOAuthClient", Path: CreateClientPath, Methods: []string{http.MethodPost}, OperationID: "createOAuthClient", Handler: server.createClient},
		{Name: "getOAuthClient", Path: GetClientPath, Methods: []string{http.MethodGet}, OperationID: "getOAuthClient", Handler: server.getClient},
		{Name: "getOAuthClientPublic", Path: GetPublicClientPath, Methods: []string{http.MethodGet}, OperationID: "getOAuthClientPublic", Handler: server.getPublicClient},
		{Name: "getOAuthClients", Path: GetClientsPath, Methods: []string{http.MethodGet}, OperationID: "getOAuthClients", Handler: server.getClients},
		{Name: "updateOAuthClient", Path: UpdateClientPath, Methods: []string{http.MethodPost}, OperationID: "updateOAuthClient", Handler: server.updateClient},
		{Name: "rotateClientSecret", Path: RotateSecretPath, Methods: []string{http.MethodPost}, OperationID: "rotateClientSecret", Handler: server.rotateClientSecret},
		{Name: "deleteOAuthClient", Path: DeleteClientPath, Methods: []string{http.MethodPost}, OperationID: "deleteOAuthClient", Handler: server.deleteClient},
	}
}

func (server *Server) registerClient(ctx *engine.Context) (contract.Response, error) {
	if !server.options.AllowDynamicClientRegistration {
		return serverOAuthError(contract.StatusForbidden, "access_denied", "Client registration is disabled")
	}
	body, err := serverDecodeObject(ctx.Request())
	if err != nil || body == nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "Invalid request body")
	}
	if _, exists := body["skip_consent"]; exists {
		return serverOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "skip_consent cannot be set during dynamic client registration")
	}
	session, err := server.runtime.resolveSession(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if session == nil && !server.options.AllowUnauthenticatedClientRegistration {
		return serverOAuthError(contract.StatusUnauthorized, "invalid_token", "Authentication required for client registration")
	}
	client, err := decodeServerClient(body)
	if err != nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "Invalid request body")
	}
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []GrantType{GrantTypeAuthorizationCode}
	}
	if len(client.ResponseTypes) == 0 {
		client.ResponseTypes = []string{"code"}
	}
	if client.Scope == "" {
		defaults := server.options.ClientRegistrationDefaultScopes
		if defaults == nil {
			defaults = server.options.Scopes
		}
		client.Scope = strings.Join(defaults, " ")
	}
	if session == nil {
		if containsClientGrant(client.GrantTypes, GrantTypeClientCredentials) {
			return serverOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "client_credentials grant requires authenticated registration")
		}
		client.TokenEndpointAuthMethod = TokenEndpointAuthMethodNone
		client.Public = true
		if client.Type == "web" {
			client.Type = ""
		}
	} else if client.TokenEndpointAuthMethod == "" {
		client.TokenEndpointAuthMethod = AuthMethodClientSecretBasic
	}
	return server.persistClient(ctx, client, session, true)
}

func (server *Server) createClient(ctx *engine.Context) (contract.Response, error) {
	session, err := server.runtime.resolveSession(ctx, true)
	if err != nil || session == nil {
		if err != nil {
			return contract.Response{}, err
		}
		return serverOAuthError(contract.StatusUnauthorized, "unauthorized", "Authentication required")
	}
	if err := server.assertClientPrivilege(ctx.GoContext(), ClientPrivilegeCreate, session); err != nil {
		return contract.ResponseFromError(err), err
	}
	body, err := serverDecodeObject(ctx.Request())
	if err != nil || body == nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "Invalid request body")
	}
	client, err := decodeServerClient(body)
	if err != nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "Invalid request body")
	}
	if client.TokenEndpointAuthMethod == "" {
		client.TokenEndpointAuthMethod = AuthMethodClientSecretBasic
	}
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []GrantType{GrantTypeAuthorizationCode}
	}
	if len(client.ResponseTypes) == 0 {
		client.ResponseTypes = []string{"code"}
	}
	return server.persistClient(ctx, client, session, false)
}

func (server *Server) persistClient(ctx *engine.Context, client Client, session *Session, registration bool) (contract.Response, error) {
	if err := server.validateClient(client, registration); err != nil {
		return contract.ResponseFromError(err), err
	}
	clientID := ""
	if server.options.GenerateClientID != nil {
		clientID = strings.TrimSpace(server.options.GenerateClientID())
	}
	var err error
	if clientID == "" {
		clientID, err = serverRandomToken(server.runtime.random)
		if err != nil {
			return serverInternalError(err)
		}
	}
	client.ClientID = clientID
	client.Public = client.TokenEndpointAuthMethod == TokenEndpointAuthMethodNone
	plainSecret := ""
	if !client.Public {
		if server.options.GenerateClientSecret != nil {
			plainSecret = strings.TrimSpace(server.options.GenerateClientSecret())
		}
		if plainSecret == "" {
			plainSecret, err = serverRandomToken(server.runtime.random)
			if err != nil {
				return serverInternalError(err)
			}
		}
		client.ClientSecret, err = server.storeClientSecret(plainSecret)
		if err != nil {
			return serverInternalError(err)
		}
	}
	now := time.Unix(server.runtime.clock().Unix(), 0).UTC()
	client.ClientIDIssuedAt = now.Unix()
	if session != nil {
		reference, referenceErr := server.resolveClientReference(ctx.GoContext(), session)
		if referenceErr != nil {
			return serverInternalError(referenceErr)
		}
		if reference != "" {
			client.ReferenceID = reference
			client.UserID = ""
		} else {
			client.UserID = serverRecordString(session.User, "id")
			if client.UserID == "" {
				client.UserID = serverRecordString(session.Session, "userId")
			}
		}
	}
	record := server.clientToRecord(client)
	record["createdAt"], record["updatedAt"] = now, now
	created, err := server.adapter(ctx.GoContext()).Create(ctx.GoContext(), storage.CreateParams{Model: "oauthClient", Data: record})
	if err != nil {
		return serverInternalError(err)
	}
	result := server.clientFromRecord(created, false)
	if plainSecret != "" {
		result.ClientSecret = server.options.ClientSecretPrefix + plainSecret
		result.ClientSecretExpiresAt = 0
	}
	response, err := serverJSON(http.StatusCreated, result)
	if err != nil {
		return serverInternalError(err)
	}
	return response.WithHeader("Cache-Control", "no-store").WithHeader("Pragma", "no-cache"), nil
}

func (server *Server) getClient(ctx *engine.Context) (contract.Response, error) {
	session, err := server.requireClientSession(ctx, ClientPrivilegeRead)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid query")
	}
	record, err := server.findClient(ctx.GoContext(), query.Get("client_id"))
	if err != nil {
		return serverInternalError(err)
	}
	if record == nil {
		return serverOAuthError(contract.StatusNotFound, "not_found", "client not found")
	}
	if allowed, ownerErr := server.clientOwnedBy(ctx.GoContext(), record, session); ownerErr != nil {
		return serverInternalError(ownerErr)
	} else if !allowed {
		return serverOAuthError(contract.StatusUnauthorized, "unauthorized", "Unauthorized")
	}
	return serverJSON(contract.StatusOK, server.clientFromRecord(record, false))
}

func (server *Server) getPublicClient(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid query")
	}
	record, err := server.findClient(ctx.GoContext(), query.Get("client_id"))
	if err != nil {
		return serverInternalError(err)
	}
	if record == nil || serverRecordBool(record, "disabled") {
		return serverOAuthError(contract.StatusNotFound, "not_found", "client not found")
	}
	client := server.clientFromRecord(record, false)
	client.RedirectURIs = nil
	client.PostLogoutRedirectURIs = nil
	client.Scope = ""
	client.GrantTypes = nil
	client.ResponseTypes = nil
	client.UserID = ""
	client.ReferenceID = ""
	client.Metadata = nil
	return serverJSON(contract.StatusOK, client)
}

func (server *Server) getClients(ctx *engine.Context) (contract.Response, error) {
	session, err := server.requireClientSession(ctx, ClientPrivilegeList)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	reference, err := server.resolveClientReference(ctx.GoContext(), session)
	if err != nil {
		return serverInternalError(err)
	}
	where := []storage.Where(nil)
	if reference != "" {
		where = []storage.Where{{Field: "referenceId", Value: reference}}
	} else {
		userID := serverRecordString(session.User, "id")
		if userID == "" {
			return serverOAuthError(contract.StatusBadRequest, "invalid_request", "either user_id or reference_id must be provided")
		}
		where = []storage.Where{{Field: "userId", Value: userID}}
	}
	records, err := server.adapter(ctx.GoContext()).FindMany(ctx.GoContext(), storage.FindManyParams{Model: "oauthClient", Where: where})
	if err != nil {
		return serverInternalError(err)
	}
	result := make([]Client, len(records))
	for index, record := range records {
		result[index] = server.clientFromRecord(record, false)
	}
	return serverJSON(contract.StatusOK, result)
}

func (server *Server) updateClient(ctx *engine.Context) (contract.Response, error) {
	session, err := server.requireClientSession(ctx, ClientPrivilegeUpdate)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	body, err := serverDecodeObject(ctx.Request())
	if err != nil || body == nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid request body")
	}
	clientID := serverString(body, "client_id")
	record, err := server.mutableOwnedClient(ctx.GoContext(), clientID, session)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	updates, ok := body["update"].(map[string]any)
	if !ok {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "update is required")
	}
	if _, exists := updates["client_id"]; exists {
		return serverOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "client_id cannot be updated")
	}
	if _, exists := updates["client_secret"]; exists {
		return serverOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "client_secret cannot be updated")
	}
	if authMethod := serverString(updates, "token_endpoint_auth_method"); authMethod == string(TokenEndpointAuthMethodNone) && !serverRecordBool(record, "public") {
		return serverOAuthError(contract.StatusBadRequest, "invalid_client", "clients cannot become public")
	}
	current := server.clientFromRecord(record, false)
	patch, err := decodeServerClient(updates)
	if err != nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "Invalid client update")
	}
	mergeClientUpdate(&current, patch, updates)
	if err := server.validateClient(current, false); err != nil {
		return contract.ResponseFromError(err), err
	}
	updated, err := server.adapter(ctx.GoContext()).Update(ctx.GoContext(), storage.UpdateParams{
		Model: "oauthClient", Where: []storage.Where{{Field: "clientId", Value: clientID}},
		Update: server.clientUpdateRecord(current, updates),
	})
	if err != nil {
		return serverInternalError(err)
	}
	return serverJSON(contract.StatusOK, server.clientFromRecord(updated, false))
}

func (server *Server) rotateClientSecret(ctx *engine.Context) (contract.Response, error) {
	session, err := server.requireClientSession(ctx, ClientPrivilegeRotate)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	body, err := serverDecodeObject(ctx.Request())
	if err != nil || body == nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid request body")
	}
	clientID := serverString(body, "client_id")
	record, err := server.mutableOwnedClient(ctx.GoContext(), clientID, session)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	if serverRecordBool(record, "public") || serverRecordString(record, "clientSecret") == "" {
		return serverOAuthError(contract.StatusBadRequest, "invalid_client", "public clients cannot be updated")
	}
	plain := ""
	if server.options.GenerateClientSecret != nil {
		plain = server.options.GenerateClientSecret()
	}
	if plain == "" {
		plain, err = serverRandomToken(server.runtime.random)
		if err != nil {
			return serverInternalError(err)
		}
	}
	stored, err := server.storeClientSecret(plain)
	if err != nil {
		return serverInternalError(err)
	}
	updated, err := server.adapter(ctx.GoContext()).Update(ctx.GoContext(), storage.UpdateParams{
		Model: "oauthClient", Where: []storage.Where{{Field: "clientId", Value: clientID}},
		Update: storage.Record{"clientSecret": stored, "updatedAt": time.Unix(server.runtime.clock().Unix(), 0).UTC()},
	})
	if err != nil {
		return serverInternalError(err)
	}
	result := server.clientFromRecord(updated, false)
	result.ClientSecret = server.options.ClientSecretPrefix + plain
	result.ClientSecretExpiresAt = 0
	response, err := serverJSON(contract.StatusOK, result)
	if err != nil {
		return serverInternalError(err)
	}
	return response.WithHeader("Cache-Control", "no-store").WithHeader("Pragma", "no-cache"), nil
}

func (server *Server) deleteClient(ctx *engine.Context) (contract.Response, error) {
	session, err := server.requireClientSession(ctx, ClientPrivilegeDelete)
	if err != nil {
		return contract.ResponseFromError(err), err
	}
	body, err := serverDecodeObject(ctx.Request())
	if err != nil || body == nil {
		return serverOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid request body")
	}
	clientID := serverString(body, "client_id")
	if _, err := server.mutableOwnedClient(ctx.GoContext(), clientID, session); err != nil {
		return contract.ResponseFromError(err), err
	}
	if err := server.adapter(ctx.GoContext()).Delete(ctx.GoContext(), storage.DeleteParams{Model: "oauthClient", Where: []storage.Where{{Field: "clientId", Value: clientID}}}); err != nil {
		return serverInternalError(err)
	}
	return serverJSON(contract.StatusOK, nil)
}

func (server *Server) validateClient(client Client, registration bool) error {
	public := client.TokenEndpointAuthMethod == TokenEndpointAuthMethodNone
	if client.TokenEndpointAuthMethod == "" {
		client.TokenEndpointAuthMethod = AuthMethodClientSecretBasic
	}
	switch client.TokenEndpointAuthMethod {
	case TokenEndpointAuthMethodNone, AuthMethodClientSecretBasic, AuthMethodClientSecretPost:
	default:
		return contract.NewAPIError(contract.StatusBadRequest, "INVALID_CLIENT_METADATA", "invalid token_endpoint_auth_method")
	}
	if client.Type != "" {
		if public && client.Type != "native" && client.Type != "user-agent-based" {
			return contract.NewAPIError(contract.StatusBadRequest, "INVALID_CLIENT_METADATA", "Type must be 'native' or 'user-agent-based' for public applications")
		}
		if !public && client.Type != "web" {
			return contract.NewAPIError(contract.StatusBadRequest, "INVALID_CLIENT_METADATA", "Type must be 'web' for confidential applications")
		}
	}
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []GrantType{GrantTypeAuthorizationCode}
	}
	for _, grant := range client.GrantTypes {
		if !containsClientGrant(server.options.GrantTypes, grant) {
			return contract.NewAPIError(contract.StatusBadRequest, "INVALID_CLIENT_METADATA", "unsupported grant type")
		}
	}
	if containsClientGrant(client.GrantTypes, GrantTypeAuthorizationCode) && len(client.RedirectURIs) == 0 {
		return contract.NewAPIError(contract.StatusBadRequest, "INVALID_REDIRECT_URI", "Redirect URIs are required for authorization_code grant type")
	}
	if containsClientGrant(client.GrantTypes, GrantTypeAuthorizationCode) && !serverContains(client.ResponseTypes, "code") {
		return contract.NewAPIError(contract.StatusBadRequest, "INVALID_CLIENT_METADATA", "When 'authorization_code' grant type is used, 'code' response type must be included")
	}
	for _, redirectURI := range append(append([]string(nil), client.RedirectURIs...), client.PostLogoutRedirectURIs...) {
		if ValidateSafeURL(redirectURI) != nil {
			return contract.NewAPIError(contract.StatusBadRequest, "INVALID_REDIRECT_URI", "invalid redirect URI")
		}
	}
	if client.SubjectType != "" && client.SubjectType != "public" && client.SubjectType != "pairwise" {
		return contract.NewAPIError(contract.StatusBadRequest, "INVALID_CLIENT_METADATA", "subject_type must be public or pairwise")
	}
	if client.SubjectType == "pairwise" {
		if server.options.PairwiseSecret == "" {
			return contract.NewAPIError(contract.StatusBadRequest, "INVALID_CLIENT_METADATA", "pairwise subject_type requires server pairwiseSecret configuration")
		}
		host := ""
		for _, raw := range client.RedirectURIs {
			parsed, _ := url.Parse(raw)
			if host == "" {
				host = parsed.Host
			} else if parsed.Host != host {
				return contract.NewAPIError(contract.StatusBadRequest, "INVALID_CLIENT_METADATA", "pairwise clients must use one redirect host")
			}
		}
	}
	allowedScopes := server.options.Scopes
	if registration && server.options.ClientRegistrationAllowedScopes != nil {
		allowedScopes = server.options.ClientRegistrationAllowedScopes
	}
	if !serverSubset(strings.Fields(client.Scope), allowedScopes) {
		return contract.NewAPIError(contract.StatusBadRequest, "INVALID_SCOPE", "client requested an unsupported scope")
	}
	if registration && client.RequirePKCE != nil && !*client.RequirePKCE {
		return contract.NewAPIError(contract.StatusBadRequest, "INVALID_CLIENT_METADATA", "pkce is required for registered clients")
	}
	return nil
}

func decodeServerClient(body map[string]any) (Client, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return Client{}, err
	}
	var client Client
	if err := json.Unmarshal(encoded, &client); err != nil {
		return Client{}, err
	}
	return client, nil
}

func containsClientGrant(values []GrantType, expected GrantType) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (server *Server) findClient(ctx context.Context, clientID string) (storage.Record, error) {
	if clientID == "" {
		return nil, nil
	}
	return server.adapter(ctx).FindOne(ctx, storage.FindOneParams{Model: "oauthClient", Where: []storage.Where{{Field: "clientId", Value: clientID}}})
}

func (server *Server) clientToRecord(client Client) storage.Record {
	record := storage.Record{
		"clientId": client.ClientID, "clientSecret": nil, "disabled": client.Disabled,
		"skipConsent": client.SkipConsent, "enableEndSession": client.EnableEndSession,
		"subjectType": client.SubjectType,
		"userId":      nil, "name": client.ClientName, "uri": client.ClientURI,
		"icon": client.LogoURI, "contacts": append([]string(nil), client.Contacts...),
		"tos": client.TOSURI, "policy": client.PolicyURI,
		"softwareId": client.SoftwareID, "softwareVersion": client.SoftwareVersion,
		"softwareStatement":       client.SoftwareStatement,
		"redirectUris":            append([]string(nil), client.RedirectURIs...),
		"postLogoutRedirectUris":  append([]string(nil), client.PostLogoutRedirectURIs...),
		"tokenEndpointAuthMethod": string(client.TokenEndpointAuthMethod),
		"grantTypes":              grantTypeStrings(client.GrantTypes), "responseTypes": append([]string(nil), client.ResponseTypes...),
		"public": client.Public, "type": client.Type, "referenceId": nil,
		"metadata": cloneUserInfoMap(client.Metadata),
	}
	if client.ClientSecret != "" {
		record["clientSecret"] = client.ClientSecret
	}
	if client.Scope != "" {
		record["scopes"] = strings.Fields(client.Scope)
	}
	if client.UserID != "" {
		record["userId"] = client.UserID
	}
	if client.ReferenceID != "" {
		record["referenceId"] = client.ReferenceID
	}
	if client.RequirePKCE != nil {
		record["requirePKCE"] = *client.RequirePKCE
	}
	return record
}

func grantTypeStrings(values []GrantType) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func (server *Server) clientFromRecord(record storage.Record, includeSecret bool) Client {
	client := Client{
		ClientID: serverRecordString(record, "clientId"), Scope: strings.Join(serverStrings(record["scopes"]), " "),
		UserID: serverRecordString(record, "userId"), ClientName: serverRecordString(record, "name"),
		ClientURI: serverRecordString(record, "uri"), LogoURI: serverRecordString(record, "icon"),
		Contacts: serverStrings(record["contacts"]), TOSURI: serverRecordString(record, "tos"), PolicyURI: serverRecordString(record, "policy"),
		SoftwareID: serverRecordString(record, "softwareId"), SoftwareVersion: serverRecordString(record, "softwareVersion"), SoftwareStatement: serverRecordString(record, "softwareStatement"),
		RedirectURIs: serverStrings(record["redirectUris"]), PostLogoutRedirectURIs: serverStrings(record["postLogoutRedirectUris"]),
		TokenEndpointAuthMethod: AuthMethod(serverRecordString(record, "tokenEndpointAuthMethod")), ResponseTypes: serverStrings(record["responseTypes"]),
		Public: serverRecordBool(record, "public"), Type: serverRecordString(record, "type"), Disabled: serverRecordBool(record, "disabled"),
		SkipConsent: serverRecordBool(record, "skipConsent"), EnableEndSession: serverRecordBool(record, "enableEndSession"),
		SubjectType: serverRecordString(record, "subjectType"), ReferenceID: serverRecordString(record, "referenceId"),
	}
	for _, grant := range serverStrings(record["grantTypes"]) {
		client.GrantTypes = append(client.GrantTypes, GrantType(grant))
	}
	if includeSecret {
		client.ClientSecret = serverRecordString(record, "clientSecret")
	}
	if createdAt, ok := serverRecordTime(record, "createdAt"); ok {
		client.ClientIDIssuedAt = createdAt.Unix()
	}
	if value, exists := record["requirePKCE"].(bool); exists {
		client.RequirePKCE = &value
	}
	if metadata, ok := record["metadata"].(map[string]any); ok {
		client.Metadata = cloneUserInfoMap(metadata)
	}
	return client
}

func (server *Server) requireClientSession(ctx *engine.Context, action ClientPrivilegeAction) (*Session, error) {
	session, err := server.runtime.resolveSession(ctx, true)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
	}
	if err := server.assertClientPrivilege(ctx.GoContext(), action, session); err != nil {
		return nil, err
	}
	return session, nil
}

func (server *Server) assertClientPrivilege(ctx context.Context, action ClientPrivilegeAction, session *Session) error {
	if session == nil {
		return contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
	}
	if server.options.ClientPrivileges == nil {
		return nil
	}
	allowed, err := server.options.ClientPrivileges(ctx, action, session)
	if err != nil {
		return err
	}
	if !allowed {
		return contract.NewAPIError(contract.StatusForbidden, "FORBIDDEN", "Forbidden")
	}
	return nil
}

func (server *Server) resolveClientReference(ctx context.Context, session *Session) (string, error) {
	if server.options.ClientReference == nil {
		return "", nil
	}
	return server.options.ClientReference(ctx, session)
}

func (server *Server) clientOwnedBy(ctx context.Context, record storage.Record, session *Session) (bool, error) {
	if userID := serverRecordString(record, "userId"); userID != "" {
		return userID == serverRecordString(session.User, "id"), nil
	}
	if reference := serverRecordString(record, "referenceId"); reference != "" {
		resolved, err := server.resolveClientReference(ctx, session)
		return resolved == reference, err
	}
	return false, nil
}

func (server *Server) mutableOwnedClient(ctx context.Context, clientID string, session *Session) (storage.Record, error) {
	if _, trusted := server.options.CachedTrustedClients[clientID]; trusted {
		return nil, contract.NewAPIError(contract.StatusInternalServerError, "INVALID_CLIENT", "trusted clients must be updated manually")
	}
	record, err := server.findClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, contract.NewAPIError(contract.StatusNotFound, "NOT_FOUND", "client not found")
	}
	allowed, err := server.clientOwnedBy(ctx, record, session)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	return record, nil
}

func mergeClientUpdate(current *Client, patch Client, raw map[string]any) {
	if _, ok := raw["scope"]; ok {
		current.Scope = patch.Scope
	}
	if _, ok := raw["client_name"]; ok {
		current.ClientName = patch.ClientName
	}
	if _, ok := raw["client_uri"]; ok {
		current.ClientURI = patch.ClientURI
	}
	if _, ok := raw["logo_uri"]; ok {
		current.LogoURI = patch.LogoURI
	}
	if _, ok := raw["contacts"]; ok {
		current.Contacts = patch.Contacts
	}
	if _, ok := raw["tos_uri"]; ok {
		current.TOSURI = patch.TOSURI
	}
	if _, ok := raw["policy_uri"]; ok {
		current.PolicyURI = patch.PolicyURI
	}
	if _, ok := raw["redirect_uris"]; ok {
		current.RedirectURIs = patch.RedirectURIs
	}
	if _, ok := raw["post_logout_redirect_uris"]; ok {
		current.PostLogoutRedirectURIs = patch.PostLogoutRedirectURIs
	}
	if _, ok := raw["grant_types"]; ok {
		current.GrantTypes = patch.GrantTypes
	}
	if _, ok := raw["response_types"]; ok {
		current.ResponseTypes = patch.ResponseTypes
	}
	if _, ok := raw["token_endpoint_auth_method"]; ok {
		current.TokenEndpointAuthMethod = patch.TokenEndpointAuthMethod
	}
	if _, ok := raw["disabled"]; ok {
		current.Disabled = patch.Disabled
	}
	if _, ok := raw["skip_consent"]; ok {
		current.SkipConsent = patch.SkipConsent
	}
	if _, ok := raw["enable_end_session"]; ok {
		current.EnableEndSession = patch.EnableEndSession
	}
	if _, ok := raw["require_pkce"]; ok {
		current.RequirePKCE = patch.RequirePKCE
	}
	if _, ok := raw["subject_type"]; ok {
		current.SubjectType = patch.SubjectType
	}
	if _, ok := raw["metadata"]; ok {
		current.Metadata = patch.Metadata
	}
}

func (server *Server) clientUpdateRecord(client Client, raw map[string]any) storage.Record {
	all := server.clientToRecord(client)
	result := storage.Record{"updatedAt": time.Unix(server.runtime.clock().Unix(), 0).UTC()}
	fieldMap := map[string]string{
		"scope": "scopes", "client_name": "name", "client_uri": "uri", "logo_uri": "icon", "contacts": "contacts", "tos_uri": "tos", "policy_uri": "policy",
		"redirect_uris": "redirectUris", "post_logout_redirect_uris": "postLogoutRedirectUris", "grant_types": "grantTypes", "response_types": "responseTypes",
		"token_endpoint_auth_method": "tokenEndpointAuthMethod", "disabled": "disabled", "skip_consent": "skipConsent", "enable_end_session": "enableEndSession",
		"require_pkce": "requirePKCE", "subject_type": "subjectType", "metadata": "metadata",
	}
	for wire, stored := range fieldMap {
		if _, exists := raw[wire]; exists {
			result[stored] = all[stored]
		}
	}
	return result
}
