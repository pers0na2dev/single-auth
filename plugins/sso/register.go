package sso

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
	"github.com/pers0na2dev/single-auth/storage"
)

var builtInSSOAccountProviderIDs = map[string]struct{}{
	"credential":   {},
	"email-otp":    {},
	"magic-link":   {},
	"phone-number": {},
	"anonymous":    {},
	"siwe":         {},
}

func (p *plugin) register(ctx *engine.Context) (contract.Response, error) {
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session.User == nil {
		return contract.Response{}, apiError(http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	userID, _ := session.User["id"].(string)
	if userID == "" {
		return contract.Response{}, apiError(http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	adapter := p.adapter(ctx)
	if adapter == nil {
		return contract.Response{}, fmt.Errorf("sso: runtime adapter is required")
	}
	providersLimit := 10
	if p.options.ProvidersLimit != nil {
		providersLimit = *p.options.ProvidersLimit
	}
	if p.options.ProvidersLimitForUser != nil {
		resolvedLimit, limitErr := p.options.ProvidersLimitForUser(ctx.GoContext(), cloneRecord(session.User))
		if limitErr != nil {
			return contract.Response{}, limitErr
		}
		providersLimit = resolvedLimit
	}
	ownedProviders, err := adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "ssoProvider", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if len(ownedProviders) >= providersLimit {
		return contract.Response{}, apiError(
			http.StatusForbidden, "FORBIDDEN", "You have reached the maximum number of SSO providers",
		)
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	providerID, err := requiredRegisterString(body, "providerId")
	if err != nil {
		return contract.Response{}, err
	}
	issuer, err := requiredRegisterString(body, "issuer")
	if err != nil {
		return contract.Response{}, err
	}
	domain, err := requiredRegisterString(body, "domain")
	if err != nil {
		return contract.Response{}, err
	}
	if _, err = absoluteHTTPURL(issuer); err != nil {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid issuer. Must be a valid URL")
	}
	organizationID, err := optionalString(body, "organizationId")
	if err != nil {
		return contract.Response{}, err
	}
	if organizationID != "" {
		member, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "member",
			Where: []storage.Where{
				{Field: "userId", Value: userID},
				{Field: "organizationId", Value: organizationID},
			},
		})
		if findErr != nil {
			return contract.Response{}, findErr
		}
		if member == nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "You are not a member of the organization")
		}
		if p.hasPlugin("organization") && !hasOrganizationAdminRole(member) {
			return contract.Response{}, apiError(http.StatusForbidden, "FORBIDDEN", "You must be an organization owner or admin to register SSO providers")
		}
	}
	if p.providerIDReserved(providerID) {
		return contract.Response{}, apiError(http.StatusUnprocessableEntity, "UNPROCESSABLE_ENTITY", "This providerId is reserved and cannot be used for an SSO provider")
	}
	if p.hasPlugin("scim") {
		existingSCIM, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "scimProvider", Where: []storage.Where{{Field: "providerId", Value: providerID}},
		})
		if findErr != nil {
			return contract.Response{}, findErr
		}
		if existingSCIM != nil {
			return contract.Response{}, apiError(http.StatusUnprocessableEntity, "UNPROCESSABLE_ENTITY", "This providerId is already used by a SCIM provider and cannot be used for an SSO provider")
		}
	}
	existingSSO, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "ssoProvider", Where: []storage.Where{{Field: "providerId", Value: providerID}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if existingSSO != nil {
		return contract.Response{}, apiError(http.StatusUnprocessableEntity, "UNPROCESSABLE_ENTITY", "SSO provider with this providerId already exists")
	}

	oidcConfig, err := registerConfig(body, "oidcConfig")
	if err != nil {
		return contract.Response{}, err
	}
	samlConfig, err := registerConfig(body, "samlConfig")
	if err != nil {
		return contract.Response{}, err
	}
	if samlConfig != nil {
		if err = validateSAMLRegistration(samlConfig, p.options.SAML.MaxMetadataSize); err != nil {
			return contract.Response{}, err
		}
		samlConfig = cloneAnyMap(samlConfig)
		samlConfig["issuer"] = issuer
		encoded, marshalErr := json.Marshal(samlConfig)
		if marshalErr != nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid samlConfig")
		}
		var typed SAMLConfig
		if unmarshalErr := json.Unmarshal(encoded, &typed); unmarshalErr != nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid samlConfig")
		}
		if validationErr := samlprotocol.ValidateConfigAlgorithms(samlprotocol.ConfigAlgorithms{
			SignatureAlgorithm: typed.SignatureAlgorithm,
			DigestAlgorithm:    typed.DigestAlgorithm,
		}, p.options.SAML.Algorithms); validationErr != nil {
			return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", validationErr.Error())
		}
	}
	if oidcConfig != nil {
		typed, parseErr := decodeRegisterOIDCConfig(oidcConfig, issuer)
		if parseErr != nil {
			return contract.Response{}, parseErr
		}
		if override, exists := body["overrideUserInfo"].(bool); exists && override {
			typed.OverrideUserInfo = true
		}
		if p.options.DefaultOverrideUserInfo {
			typed.OverrideUserInfo = true
		}
		if validationErr := p.validateOIDCEndpoints(ctx, typed, false); validationErr != nil {
			return contract.Response{}, discoveryAPIError(validationErr)
		}
		if !typed.SkipDiscovery {
			hydrated, discoveryErr := p.discoverOIDCConfig(ctx, typed)
			if discoveryErr != nil {
				return contract.Response{}, discoveryAPIError(discoveryErr)
			}
			typed = hydrated
		} else if typed.DiscoveryEndpoint == "" {
			typed.DiscoveryEndpoint = ComputeDiscoveryURL(issuer)
		}
		typed.SkipDiscovery = false
		oidcConfig, err = oidcConfigObject(typed)
		if err != nil {
			return contract.Response{}, err
		}
	}
	encodedOIDC, err := encodeRegisterConfig(oidcConfig)
	if err != nil {
		return contract.Response{}, err
	}
	encodedSAML, err := encodeRegisterConfig(samlConfig)
	if err != nil {
		return contract.Response{}, err
	}
	data := storage.Record{
		"issuer": issuer, "domain": domain, "oidcConfig": encodedOIDC,
		"samlConfig": encodedSAML, "userId": userID, "providerId": providerID,
	}
	if organizationID != "" {
		data["organizationId"] = organizationID
	}
	if p.domainVerificationEnabled {
		data["domainVerified"] = false
	}
	created, err := adapter.Create(ctx.GoContext(), storage.CreateParams{Model: "ssoProvider", Data: data})
	if err != nil {
		return contract.Response{}, err
	}
	result := cloneRecord(created)
	if p.domainVerificationEnabled {
		token, tokenErr := p.randomToken(18)
		if tokenErr != nil {
			_ = adapter.Delete(ctx.GoContext(), storage.DeleteParams{
				Model: "ssoProvider", Where: []storage.Where{{Field: "providerId", Value: providerID}},
			})
			return contract.Response{}, fmt.Errorf("sso: generate domain verification token: %w", tokenErr)
		}
		if _, verificationErr := p.runtime.CreateVerification(
			ctx.GoContext(), p.domainVerificationIdentifier(providerID), token,
			p.runtime.Clock().UTC().Add(7*24*time.Hour),
		); verificationErr != nil {
			_ = adapter.Delete(ctx.GoContext(), storage.DeleteParams{
				Model: "ssoProvider", Where: []storage.Where{{Field: "providerId", Value: providerID}},
			})
			return contract.Response{}, verificationErr
		}
		result["domainVerificationToken"] = token
		result["domainVerified"] = false
	}
	result["oidcConfig"] = oidcConfig
	result["samlConfig"] = samlConfig
	baseURL := ""
	if p.runtime.ResolveBaseURL != nil {
		baseURL, err = p.runtime.ResolveBaseURL(ctx.Request())
		if err != nil {
			return contract.Response{}, err
		}
	}
	redirectURI := strings.TrimSpace(p.options.RedirectURI)
	if redirectURI == "" {
		redirectURI = strings.TrimSuffix(baseURL, "/") + "/sso/callback/" + providerID
	} else if parsed, parseErr := absoluteHTTPURL(redirectURI); parseErr == nil {
		redirectURI = parsed.String()
	} else {
		redirectURI = strings.TrimSuffix(baseURL, "/") + "/" + strings.TrimLeft(redirectURI, "/")
	}
	result["redirectURI"] = redirectURI
	return contract.JSONResponse(http.StatusOK, result)
}

func decodeRegisterOIDCConfig(config map[string]any, issuer string) (OIDCConfig, error) {
	for _, key := range []string{
		"authorizationEndpoint", "tokenEndpoint", "userInfoEndpoint", "jwksEndpoint", "discoveryEndpoint",
	} {
		value, exists := config[key]
		if !exists || value == nil || value == "" {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return OIDCConfig{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid oidcConfig")
		}
		parsed, parseErr := url.Parse(text)
		if parseErr != nil || !parsed.IsAbs() {
			return OIDCConfig{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid oidcConfig")
		}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return OIDCConfig{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid oidcConfig")
	}
	var result OIDCConfig
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return OIDCConfig{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid oidcConfig")
	}
	result.Issuer = issuer
	if result.PKCE == nil {
		enabled := true
		result.PKCE = &enabled
	}
	if result.TokenEndpointAuthentication == "" {
		result.TokenEndpointAuthentication = "client_secret_basic"
	}
	if err := validateOIDCCredentials(result); err != nil {
		return OIDCConfig{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid oidcConfig")
	}
	return result, nil
}

func oidcConfigObject(config OIDCConfig) (map[string]any, error) {
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("sso: encode OIDC configuration: %w", err)
	}
	result := make(map[string]any)
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("sso: decode OIDC configuration: %w", err)
	}
	return result, nil
}

func (p *plugin) adapter(ctx *engine.Context) storage.TransactionAdapter {
	if p.runtime.AdapterForContext != nil {
		if adapter := p.runtime.AdapterForContext(ctx.GoContext()); adapter != nil {
			return adapter
		}
	}
	return p.runtime.Adapter
}

func (p *plugin) hasPlugin(pluginID string) bool {
	return p.runtime.HasPlugin != nil && p.runtime.HasPlugin(pluginID)
}

func (p *plugin) providerIDReserved(providerID string) bool {
	if _, exists := builtInSSOAccountProviderIDs[providerID]; exists {
		return true
	}
	for _, provider := range p.providers {
		if provider.ProviderID == providerID {
			return true
		}
	}
	return p.runtime.ReservedProviderID != nil && p.runtime.ReservedProviderID(providerID)
}

func requiredRegisterString(body map[string]any, key string) (string, error) {
	value, err := optionalString(body, key)
	if err != nil || strings.TrimSpace(value) != "" {
		return value, err
	}
	return "", apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
}

func registerConfig(body map[string]any, key string) (map[string]any, error) {
	value, exists := body[key]
	if !exists || value == nil {
		return nil, nil
	}
	config, ok := value.(map[string]any)
	if !ok {
		return nil, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid "+key)
	}
	return config, nil
}

func validateSAMLRegistration(config map[string]any, maxMetadataSize ...int) error {
	entryPoint, _ := config["entryPoint"].(string)
	certificate, _ := config["cert"].(string)
	callbackURL, callbackOK := config["callbackUrl"].(string)
	_, spMetadataOK := config["spMetadata"].(map[string]any)
	idpMetadata, _ := config["idpMetadata"].(map[string]any)
	metadata, _ := idpMetadata["metadata"].(string)
	spMetadata, _ := config["spMetadata"].(map[string]any)
	spMetadataXML, _ := spMetadata["metadata"].(string)
	limit := metadataSizeLimit(maxMetadataSize...)
	if len([]byte(metadata)) > limit {
		return apiError(http.StatusBadRequest, "BAD_REQUEST", fmt.Sprintf("IdP metadata exceeds maximum allowed size (%d bytes)", limit))
	}
	if len([]byte(spMetadataXML)) > limit {
		return apiError(http.StatusBadRequest, "BAD_REQUEST", fmt.Sprintf("SP metadata exceeds maximum allowed size (%d bytes)", limit))
	}
	hasMetadata := strings.TrimSpace(metadata) != ""
	if !callbackOK || !spMetadataOK || callbackURL == "" ||
		(!hasMetadata && (strings.TrimSpace(entryPoint) == "" || strings.TrimSpace(certificate) == "")) {
		return apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid samlConfig")
	}
	if !hasMetadata {
		if _, err := absoluteHTTPURL(entryPoint); err != nil {
			return apiError(http.StatusBadRequest, "BAD_REQUEST", "SAML configuration requires either idpMetadata.metadata (IdP metadata XML), idpMetadata.singleSignOnService, or a valid entryPoint URL")
		}
	}
	return nil
}

func encodeRegisterConfig(config map[string]any) (any, error) {
	if config == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("sso: encode provider configuration: %w", err)
	}
	return string(encoded), nil
}

func cloneAnyMap(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func cloneRecord(input storage.Record) storage.Record {
	result := make(storage.Record, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func hasOrganizationAdminRole(member storage.Record) bool {
	role, _ := member["role"].(string)
	for _, candidate := range strings.Split(role, ",") {
		switch strings.TrimSpace(candidate) {
		case "owner", "admin":
			return true
		}
	}
	return false
}
