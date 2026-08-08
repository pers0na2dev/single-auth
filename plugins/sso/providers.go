package sso

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) listProviders(ctx *engine.Context) (contract.Response, error) {
	userID, err := sessionUserID(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	adapter := p.adapter(ctx)
	if adapter == nil {
		return contract.Response{}, fmt.Errorf("sso: runtime adapter is required")
	}
	providers, err := adapter.FindMany(ctx.GoContext(), storage.FindManyParams{Model: "ssoProvider"})
	if err != nil {
		return contract.Response{}, err
	}
	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	personal := make([]any, 0, len(providers))
	organization := make([]any, 0, len(providers))
	for _, provider := range providers {
		if ok, accessErr := p.hasProviderAccess(ctx.GoContext(), adapter, userID, provider); accessErr != nil {
			return contract.Response{}, accessErr
		} else if ok {
			sanitized := sanitizeSSOProvider(provider, strings.TrimRight(baseURL, "/"))
			if recordStringValue(provider, "organizationId") == "" {
				personal = append(personal, sanitized)
			} else {
				organization = append(organization, sanitized)
			}
		}
	}
	accessible := append(personal, organization...)
	return contract.JSONResponse(http.StatusOK, map[string]any{"providers": accessible})
}

func (p *plugin) getProvider(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil || len(query["providerId"]) != 1 || strings.TrimSpace(query.Get("providerId")) == "" {
		return contract.Response{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters")
	}
	provider, err := p.checkProviderAccess(ctx, query.Get("providerId"))
	if err != nil {
		return contract.Response{}, err
	}
	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(http.StatusOK, sanitizeSSOProvider(provider, strings.TrimRight(baseURL, "/")))
}

func (p *plugin) updateProvider(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	providerID, err := requiredProviderBodyString(body, "providerId")
	if err != nil {
		return contract.Response{}, err
	}
	_, hasIssuer := body["issuer"]
	_, hasDomain := body["domain"]
	_, hasSAML := body["samlConfig"]
	_, hasOIDC := body["oidcConfig"]
	if !hasIssuer && !hasDomain && !hasSAML && !hasOIDC {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "No fields provided for update")
	}
	existing, err := p.checkProviderAccess(ctx, providerID)
	if err != nil {
		return contract.Response{}, err
	}
	adapter := p.adapter(ctx)
	if adapter == nil {
		return contract.Response{}, fmt.Errorf("sso: runtime adapter is required")
	}
	update := storage.Record{}
	identityChanged := false
	issuer := recordStringValue(existing, "issuer")
	if hasIssuer {
		issuer, err = requiredProviderBodyString(body, "issuer")
		if err != nil {
			return contract.Response{}, err
		}
		if _, err := absoluteHTTPURL(issuer); err != nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid issuer")
		}
		identityChanged = issuer != recordStringValue(existing, "issuer")
		update["issuer"] = issuer
	}
	if hasDomain {
		domain, stringErr := requiredProviderBodyString(body, "domain")
		if stringErr != nil {
			return contract.Response{}, stringErr
		}
		update["domain"] = domain
		if p.domainVerificationEnabled && domain != recordStringValue(existing, "domain") {
			update["domainVerified"] = false
		}
	}
	if hasSAML {
		updates, ok := body["samlConfig"].(map[string]any)
		if !ok || updates == nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid samlConfig")
		}
		current := decodeStoredSAMLConfig(existing["samlConfig"])
		if current == nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Cannot update SAML config for a provider that doesn't have SAML configured")
		}
		merged, mergeErr := mergeTypedConfig(*current, updates)
		if mergeErr != nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid samlConfig")
		}
		var updated SAMLConfig
		if decodeErr := decodeJSONMap(merged, &updated); decodeErr != nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid samlConfig")
		}
		updated.Issuer = firstNonEmpty(issuer, current.Issuer, recordStringValue(existing, "issuer"))
		if err := validateSAMLMetadataSize(updated, p.options.SAML.MaxMetadataSize); err != nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", err.Error())
		}
		if err := samlprotocol.ValidateConfigAlgorithms(samlprotocol.ConfigAlgorithms{
			SignatureAlgorithm: updated.SignatureAlgorithm,
			DigestAlgorithm:    updated.DigestAlgorithm,
		}, p.options.SAML.Algorithms); err != nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", err.Error())
		}
		if _, err := validateResolvedSAMLConfig(&updated, p.options.SAML.MaxMetadataSize); err != nil {
			return contract.Response{}, err
		}
		if samlIdentityBoundaryChanged(*current, updated) {
			identityChanged = true
		}
		encoded, encodeErr := json.Marshal(updated)
		if encodeErr != nil {
			return contract.Response{}, encodeErr
		}
		update["samlConfig"] = string(encoded)
	}
	if hasOIDC {
		updates, ok := body["oidcConfig"].(map[string]any)
		if !ok || updates == nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid oidcConfig")
		}
		current := decodeStoredOIDCConfig(existing["oidcConfig"])
		if current == nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Cannot update OIDC config for a provider that doesn't have OIDC configured")
		}
		merged, mergeErr := mergeTypedConfig(*current, updates)
		if mergeErr != nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid oidcConfig")
		}
		updated, decodeErr := decodeRegisterOIDCConfig(merged, firstNonEmpty(issuer, current.Issuer, recordStringValue(existing, "issuer")))
		if decodeErr != nil {
			return contract.Response{}, decodeErr
		}
		if validationErr := p.validateOIDCEndpoints(ctx, updated, false); validationErr != nil {
			return contract.Response{}, discoveryAPIError(validationErr)
		}
		if oidcIdentityBoundaryChanged(*current, updated) {
			identityChanged = true
		}
		encoded, encodeErr := json.Marshal(updated)
		if encodeErr != nil {
			return contract.Response{}, encodeErr
		}
		update["oidcConfig"] = string(encoded)
	}
	if identityChanged {
		linked, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "account", Where: []storage.Where{{Field: "providerId", Value: providerID}},
		})
		if findErr != nil {
			return contract.Response{}, findErr
		}
		if linked != nil {
			return contract.Response{}, apiError(
				http.StatusConflict, "CONFLICT",
				"Cannot change SSO provider identity fields while linked accounts exist",
			)
		}
	}
	if len(update) == 0 {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "No fields provided for update")
	}
	if _, err := adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "ssoProvider", Where: []storage.Where{{Field: "providerId", Value: providerID}}, Update: update,
	}); err != nil {
		return contract.Response{}, err
	}
	updated, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "ssoProvider", Where: []storage.Where{{Field: "providerId", Value: providerID}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if updated == nil {
		return contract.Response{}, apiError(http.StatusNotFound, "NOT_FOUND", "Provider not found after update")
	}
	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(http.StatusOK, sanitizeSSOProvider(updated, strings.TrimRight(baseURL, "/")))
}

func (p *plugin) deleteProvider(ctx *engine.Context) (contract.Response, error) {
	providerID, err := providerIDFromBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	if _, err := p.checkProviderAccess(ctx, providerID); err != nil {
		return contract.Response{}, err
	}
	adapter := p.adapter(ctx)
	if adapter == nil {
		return contract.Response{}, fmt.Errorf("sso: runtime adapter is required")
	}
	deleteRows := func(transactionContext context.Context, transaction storage.TransactionAdapter) error {
		if _, err := transaction.DeleteMany(transactionContext, storage.DeleteManyParams{
			Model: "account", Where: []storage.Where{{Field: "providerId", Value: providerID}},
		}); err != nil {
			return err
		}
		return transaction.Delete(transactionContext, storage.DeleteParams{
			Model: "ssoProvider", Where: []storage.Where{{Field: "providerId", Value: providerID}},
		})
	}
	if transactional, ok := adapter.(storage.Adapter); ok {
		if err := storage.RunWithTransaction(ctx.GoContext(), transactional, deleteRows); err != nil {
			return contract.Response{}, err
		}
	} else if err := deleteRows(ctx.GoContext(), adapter); err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(http.StatusOK, map[string]any{"success": true})
}

func (p *plugin) checkProviderAccess(ctx *engine.Context, providerID string) (storage.Record, error) {
	userID, err := sessionUserID(ctx)
	if err != nil {
		return nil, err
	}
	adapter := p.adapter(ctx)
	if adapter == nil {
		return nil, fmt.Errorf("sso: runtime adapter is required")
	}
	provider, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "ssoProvider", Where: []storage.Where{{Field: "providerId", Value: providerID}},
	})
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, apiError(http.StatusNotFound, "NOT_FOUND", "Provider not found")
	}
	hasAccess, err := p.hasProviderAccess(ctx.GoContext(), adapter, userID, provider)
	if err != nil {
		return nil, err
	}
	if !hasAccess {
		return nil, apiError(http.StatusForbidden, "FORBIDDEN", "You don't have access to this provider")
	}
	return provider, nil
}

func (p *plugin) hasProviderAccess(
	ctx context.Context,
	adapter storage.TransactionAdapter,
	userID string,
	provider storage.Record,
) (bool, error) {
	organizationID := recordStringValue(provider, "organizationId")
	if organizationID == "" || !p.hasPlugin("organization") {
		return recordStringValue(provider, "userId") == userID, nil
	}
	member, err := adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "userId", Value: userID}, {Field: "organizationId", Value: organizationID},
		},
	})
	if err != nil {
		return false, err
	}
	return member != nil && hasOrganizationAdminRole(member), nil
}

func sessionUserID(ctx *engine.Context) (string, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session.User == nil {
		return "", apiError(http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	userID := recordStringValue(session.User, "id")
	if userID == "" {
		return "", apiError(http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	return userID, nil
}

func sanitizeSSOProvider(provider storage.Record, baseURL string) map[string]any {
	oidcConfig := decodeStoredOIDCConfig(provider["oidcConfig"])
	samlConfig := decodeStoredSAMLConfig(provider["samlConfig"])
	providerType := "oidc"
	if samlConfig != nil {
		providerType = "saml"
	}
	result := map[string]any{
		"providerId": recordStringValue(provider, "providerId"),
		"type":       providerType, "issuer": recordStringValue(provider, "issuer"),
		"domain":         recordStringValue(provider, "domain"),
		"organizationId": nil, "domainVerified": recordBoolValue(provider, "domainVerified"),
	}
	if organizationID := recordStringValue(provider, "organizationId"); organizationID != "" {
		result["organizationId"] = organizationID
	}
	if oidcConfig != nil {
		result["oidcConfig"] = map[string]any{
			"discoveryEndpoint": oidcConfig.DiscoveryEndpoint,
			"clientIdLastFour":  maskSSOClientID(oidcConfig.ClientID),
			"pkce":              oidcConfig.PKCE, "authorizationEndpoint": oidcConfig.AuthorizationEndpoint,
			"tokenEndpoint": oidcConfig.TokenEndpoint, "userInfoEndpoint": oidcConfig.UserInfoEndpoint,
			"jwksEndpoint": oidcConfig.JWKSEndpoint, "scopes": oidcConfig.Scopes,
			"tokenEndpointAuthentication": oidcConfig.TokenEndpointAuthentication,
		}
	}
	if samlConfig != nil {
		result["samlConfig"] = map[string]any{
			"entryPoint": samlConfig.EntryPoint, "callbackUrl": samlConfig.CallbackURL,
			"idpInitiatedCallbackUrl": samlConfig.IDPInitiatedCallbackURL,
			"audience":                samlConfig.Audience, "wantAssertionsSigned": samlConfig.WantAssertionsSigned,
			"authnRequestsSigned": samlConfig.AuthnRequestsSigned,
			"identifierFormat":    samlConfig.IdentifierFormat,
			"signatureAlgorithm":  samlConfig.SignatureAlgorithm,
			"digestAlgorithm":     samlConfig.DigestAlgorithm,
			"certificate":         sanitizeSAMLCertificate(samlConfig.Certificate),
		}
	}
	result["spMetadataUrl"] = baseURL + "/sso/saml2/sp/metadata?providerId=" +
		url.QueryEscape(recordStringValue(provider, "providerId"))
	return result
}

func sanitizeSAMLCertificate(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return map[string]any{"error": "Failed to parse certificate"}
	}
	if !strings.Contains(value, "-----BEGIN") {
		value = "-----BEGIN CERTIFICATE-----\n" + value + "\n-----END CERTIFICATE-----"
	}
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return map[string]any{"error": "Failed to parse certificate"}
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return map[string]any{"error": "Failed to parse certificate"}
	}
	digest := sha256.Sum256(certificate.Raw)
	fingerprint := strings.ToUpper(hex.EncodeToString(digest[:]))
	parts := make([]string, 0, len(fingerprint)/2)
	for index := 0; index < len(fingerprint); index += 2 {
		parts = append(parts, fingerprint[index:index+2])
	}
	return map[string]any{
		"fingerprintSha256": strings.Join(parts, ":"),
		"notBefore":         certificate.NotBefore.String(), "notAfter": certificate.NotAfter.String(),
		"publicKeyAlgorithm": certificate.PublicKeyAlgorithm.String(),
	}
}

func maskSSOClientID(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	return "****" + value[len(value)-4:]
}

func requiredProviderBodyString(body map[string]any, key string) (string, error) {
	value, ok := body[key].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
	}
	return value, nil
}

func mergeTypedConfig[T any](current T, updates map[string]any) (map[string]any, error) {
	encoded, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	merged := map[string]any{}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if err := decoder.Decode(&merged); err != nil {
		return nil, err
	}
	for key, value := range updates {
		merged[key] = value
	}
	return merged, nil
}

func decodeJSONMap(input map[string]any, output any) error {
	encoded, err := json.Marshal(input)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, output)
}

func oidcIdentityBoundaryChanged(current, updated OIDCConfig) bool {
	return current.AuthorizationEndpoint != updated.AuthorizationEndpoint ||
		current.ClientID != updated.ClientID || current.DiscoveryEndpoint != updated.DiscoveryEndpoint ||
		current.JWKSEndpoint != updated.JWKSEndpoint || current.TokenEndpoint != updated.TokenEndpoint ||
		current.UserInfoEndpoint != updated.UserInfoEndpoint || current.Mapping.ID != updated.Mapping.ID
}

func samlIdentityBoundaryChanged(current, updated SAMLConfig) bool {
	if current.Audience != updated.Audience || current.CallbackURL != updated.CallbackURL ||
		current.EntryPoint != updated.EntryPoint || current.IdentifierFormat != updated.IdentifierFormat ||
		current.Mapping.ID != updated.Mapping.ID {
		return true
	}
	currentIDP, updatedIDP := samlIDPBoundary(current.IDPMetadata), samlIDPBoundary(updated.IDPMetadata)
	currentSP, updatedSP := samlSPBoundary(current.SPMetadata), samlSPBoundary(updated.SPMetadata)
	return !reflect.DeepEqual(currentIDP, updatedIDP) || !reflect.DeepEqual(currentSP, updatedSP)
}

func samlIDPBoundary(metadata *SAMLIDPMetadata) struct {
	Metadata string
	EntityID string
	SSO      []SAMLServiceEndpoint
} {
	if metadata == nil {
		return struct {
			Metadata string
			EntityID string
			SSO      []SAMLServiceEndpoint
		}{}
	}
	return struct {
		Metadata string
		EntityID string
		SSO      []SAMLServiceEndpoint
	}{metadata.Metadata, metadata.EntityID, metadata.SingleSignOnService}
}

func samlSPBoundary(metadata *SAMLSPMetadata) struct{ Metadata, EntityID string } {
	if metadata == nil {
		return struct{ Metadata, EntityID string }{}
	}
	return struct{ Metadata, EntityID string }{metadata.Metadata, metadata.EntityID}
}
