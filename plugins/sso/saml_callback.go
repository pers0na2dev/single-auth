package sso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
	"github.com/pers0na2dev/single-auth/storage"
)

type samlResponseInput struct {
	Response   string
	RelayState string
}

type relayStateData struct {
	CallbackURL string `json:"callbackURL"`
	ErrorURL    string `json:"errorURL"`
	ExpiresAt   int64  `json:"expiresAt"`
}

type samlAuthnRequestValue struct {
	ID         string `json:"id"`
	ProviderID string `json:"providerId"`
	CreatedAt  int64  `json:"createdAt"`
	ExpiresAt  int64  `json:"expiresAt"`
}

type verificationSAMLStore struct{ runtime Runtime }

func (store verificationSAMLStore) PutAuthnRequest(
	ctx context.Context,
	record samlprotocol.AuthnRequestRecord,
) error {
	value, err := json.Marshal(samlAuthnRequestValue{
		ID: record.RequestID, ProviderID: record.ProviderID,
		CreatedAt: record.CreatedAt.UnixMilli(), ExpiresAt: record.ExpiresAt.UnixMilli(),
	})
	if err != nil {
		return err
	}
	_, err = store.runtime.CreateVerification(
		ctx, authnRequestPrefix+record.RequestID, string(value), record.ExpiresAt,
	)
	return err
}

func (store verificationSAMLStore) ConsumeAuthnRequest(
	ctx context.Context,
	requestID string,
) (samlprotocol.AuthnRequestRecord, bool, error) {
	record, err := store.runtime.ConsumeVerification(ctx, authnRequestPrefix+requestID)
	if err != nil || record == nil {
		return samlprotocol.AuthnRequestRecord{}, false, err
	}
	var stored samlAuthnRequestValue
	if err := json.Unmarshal([]byte(recordStringValue(record, "value")), &stored); err != nil ||
		stored.ID == "" || stored.ProviderID == "" || stored.ExpiresAt == 0 {
		return samlprotocol.AuthnRequestRecord{}, false, nil
	}
	return samlprotocol.AuthnRequestRecord{
		RequestID: stored.ID, ProviderID: stored.ProviderID,
		CreatedAt: time.UnixMilli(stored.CreatedAt).UTC(),
		ExpiresAt: time.UnixMilli(stored.ExpiresAt).UTC(),
	}, true, nil
}

func (store verificationSAMLStore) ReserveAssertion(
	ctx context.Context,
	record samlprotocol.AssertionReplayRecord,
) (bool, error) {
	value, err := json.Marshal(map[string]any{
		"assertionId": record.AssertionID,
		"issuer":      record.Issuer,
		"providerId":  record.ProviderID,
		"usedAt":      record.UsedAt.UnixMilli(),
		"expiresAt":   record.ExpiresAt.UnixMilli(),
	})
	if err != nil {
		return false, err
	}
	return store.runtime.ReserveVerification(
		ctx, usedAssertionPrefix+record.AssertionID, string(value), record.ExpiresAt,
	)
}

func (p *plugin) samlCallback(ctx *engine.Context) (contract.Response, error) {
	if ctx.Request().Method() == http.MethodGet {
		return p.handleSAMLCallbackGET(ctx)
	}
	return p.handleSAMLResponse(ctx, false)
}

func (p *plugin) handleSAMLCallbackGET(ctx *engine.Context) (contract.Response, error) {
	providerID, ok := ctx.Param("providerId")
	if !ok || strings.TrimSpace(providerID) == "" {
		return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "providerId is required")
	}
	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, fmt.Errorf("sso: resolve base URL: %w", err)
	}
	baseURL = strings.TrimRight(baseURL, "/")
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return contract.Response{}, fmt.Errorf("sso: invalid resolved base URL %q", baseURL)
	}
	appOrigin := base.Scheme + "://" + base.Host
	errorURL := p.runtime.OnAPIErrorURL
	if errorURL == "" {
		errorURL = appOrigin + "/error"
	}
	currentCallbackURL := baseURL + "/sso/saml2/callback/" + url.PathEscape(providerID)
	query, err := ctx.Request().Query()
	if err != nil || len(query["RelayState"]) > 1 {
		return contract.Response{}, apiError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters")
	}
	if p.runtime.ResolveSession == nil {
		return redirectWithQuery(errorURL, map[string]string{"error": "invalid_request"}), nil
	}
	session, sessionErr := p.runtime.ResolveSession(ctx, singleauth.PluginSessionOptional)
	if sessionErr != nil || session == nil || session.Session == nil {
		return redirectWithQuery(errorURL, map[string]string{"error": "invalid_request"}), nil
	}
	redirectURL := p.safeSAMLRedirect(
		ctx.Request(), []string{query.Get("RelayState")}, currentCallbackURL, appOrigin,
	)
	return redirectResponse(redirectURL), nil
}

func (p *plugin) samlACS(ctx *engine.Context) (contract.Response, error) {
	return p.handleSAMLResponse(ctx, true)
}

func (p *plugin) handleSAMLResponse(
	ctx *engine.Context,
	acs bool,
) (contract.Response, error) {
	providerID, ok := ctx.Param("providerId")
	if !ok || strings.TrimSpace(providerID) == "" {
		return contract.Response{}, apiError(
			contract.StatusBadRequest, "BAD_REQUEST", "providerId is required",
		)
	}
	input, err := decodeSAMLResponseInput(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	if input.Response == "" {
		return contract.Response{}, apiError(
			contract.StatusBadRequest, "BAD_REQUEST", "SAMLResponse is required for POST requests",
		)
	}

	baseURL, err := p.runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, fmt.Errorf("sso: resolve base URL: %w", err)
	}
	baseURL = strings.TrimRight(baseURL, "/")
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return contract.Response{}, fmt.Errorf("sso: invalid resolved base URL %q", baseURL)
	}
	appOrigin := base.Scheme + "://" + base.Host
	callbackSuffix := "/sso/saml2/callback/" + url.PathEscape(providerID)
	if acs {
		callbackSuffix = "/sso/saml2/sp/acs/" + url.PathEscape(providerID)
	}
	currentCallbackURL := baseURL + callbackSuffix

	relay := p.relayState(ctx.GoContext(), input.RelayState, false)
	provider, findErr := p.findProvider(ctx, providerID, "")
	if findErr != nil {
		return contract.Response{}, fmt.Errorf("sso: find provider: %w", findErr)
	}
	if provider == nil || provider.SAMLConfig == nil {
		return contract.Response{}, apiError(
			contract.StatusNotFound, "NOT_FOUND", "No SAML provider found",
		)
	}
	if p.domainVerificationEnabled && !provider.DomainVerified {
		return contract.Response{}, apiError(
			contract.StatusUnauthorized, "UNAUTHORIZED", "Provider domain has not been verified",
		)
	}
	config, err := validateResolvedSAMLConfig(provider.SAMLConfig, p.options.SAML.MaxMetadataSize)
	if err != nil {
		return contract.Response{}, err
	}

	successRedirect := p.safeSAMLRedirect(
		ctx.Request(),
		[]string{
			relay.CallbackURL,
			config.IDPInitiatedCallbackURL,
			p.options.SAML.IDPInitiatedCallbackURL,
			config.CallbackURL,
		},
		currentCallbackURL,
		appOrigin,
	)
	errorRedirect := p.safeSAMLRedirect(
		ctx.Request(),
		[]string{relay.ErrorURL, successRedirect},
		currentCallbackURL,
		appOrigin,
	)

	validated, validationErr := p.validateSAMLResponse(
		ctx.GoContext(), input, providerID, currentCallbackURL, baseURL, config,
	)
	if validationErr != nil {
		if acs || callbackValidationRedirect(validationErr) {
			code, description := samlRedirectError(validationErr)
			return redirectWithQuery(errorRedirect, map[string]string{
				"error": code, "error_description": description,
			}), nil
		}
		return contract.Response{}, apiError(
			contract.StatusBadRequest,
			samlErrorCode(validationErr),
			"Invalid SAML response",
		)
	}
	if input.RelayState != "" {
		relay = p.relayState(ctx.GoContext(), input.RelayState, true)
		successRedirect = p.safeSAMLRedirect(
			ctx.Request(),
			[]string{
				relay.CallbackURL,
				config.IDPInitiatedCallbackURL,
				p.options.SAML.IDPInitiatedCallbackURL,
				config.CallbackURL,
			},
			currentCallbackURL,
			appOrigin,
		)
		errorRedirect = p.safeSAMLRedirect(
			ctx.Request(),
			[]string{relay.ErrorURL, successRedirect},
			currentCallbackURL,
			appOrigin,
		)
	}

	identity, trustedProvider, err := samlIdentity(validated.Response, provider, config, p.options)
	if err != nil {
		if acs {
			return redirectWithQuery(errorRedirect, map[string]string{
				"error": "saml_error", "error_description": err.Error(),
			}), nil
		}
		return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", err.Error())
	}
	trustProviderByName := false
	result, err := p.runtime.HandleOAuthUser(ctx, singleauth.PluginOAuthUserInput{
		Provider:            &providers.Provider{ID: providerID, Name: providerID},
		ProviderID:          providerID,
		User:                identity,
		Tokens:              oauth2.Tokens{},
		DisableSignUp:       p.options.DisableImplicitSignUp,
		CallbackURL:         successRedirect,
		IsTrustedProvider:   trustedProvider,
		TrustProviderByName: &trustProviderByName,
	})
	if err != nil {
		if typed, ok := contract.AsAPIError(err); ok {
			return redirectWithQuery(errorRedirect, map[string]string{
				"error": typed.Code, "error_description": typed.Message,
			}), nil
		}
		return contract.Response{}, err
	}
	if result.LinkError != "" {
		return redirectWithQuery(successRedirect, map[string]string{
			"error": strings.ReplaceAll(result.LinkError, " ", "_"),
		}), nil
	}
	if result.State.Session == nil || result.State.User == nil {
		return contract.Response{}, apiError(
			contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Internal Server Error",
		)
	}
	normalizedUserInfo := samlNormalizedUserInfo(identity)
	rawAttributes := samlRawAttributes(validated.Response.Assertion.Attributes)
	if p.options.ProvisionUser != nil && (result.IsRegister || p.options.ProvisionUserOnEveryLogin) {
		providerConfig := cloneSAMLProviderConfig(config)
		if err := p.options.ProvisionUser(ctx.GoContext(), ProvisionUserInput{
			User: cloneRecord(result.State.User), UserInfo: normalizedUserInfo,
			Tokens: oauth2.Tokens{},
			Provider: SSOProviderProfile{
				ProviderID: provider.ProviderID, Issuer: provider.Issuer, Domain: provider.Domain,
				OrganizationID: provider.OrganizationID, DomainVerified: provider.DomainVerified,
				OIDCConfig: cloneOIDCConfig(provider.OIDCConfig), SAMLConfig: &providerConfig,
			},
		}); err != nil {
			return contract.Response{}, err
		}
	}
	if err := p.assignOrganizationFromProvider(
		ctx, result.State.User, rawAttributes, provider, oauth2.Tokens{},
	); err != nil {
		return contract.Response{}, err
	}
	if err := p.runtime.RefreshSession(ctx, result.State, false); err != nil {
		return contract.Response{}, err
	}
	if p.options.SAML.EnableSingleLogout && validated.Response.Assertion.NameID != "" {
		_ = p.storeSAMLSession(
			ctx.GoContext(), providerID, validated.Response.Assertion.NameID,
			validated.Response.Assertion.SessionIndex, result.State.Session,
		)
	}
	return redirectResponse(successRedirect), nil
}

func samlNormalizedUserInfo(identity oauth2.UserInfo) storage.Record {
	result := storage.Record{
		"id": identity.ID, "name": identity.Name, "emailVerified": identity.EmailVerified,
	}
	if identity.Email != nil {
		result["email"] = *identity.Email
	}
	if identity.Image != "" {
		result["image"] = identity.Image
	}
	for key, value := range identity.Extra {
		result[key] = value
	}
	return result
}

func samlRawAttributes(attributes map[string][]string) storage.Record {
	result := make(storage.Record, len(attributes))
	for key, values := range attributes {
		switch len(values) {
		case 0:
			continue
		case 1:
			result[key] = values[0]
		default:
			result[key] = append([]string(nil), values...)
		}
	}
	return result
}

func cloneSAMLProviderConfig(config SAMLConfig) SAMLConfig {
	provider := cloneProviders([]DefaultProvider{{SAMLConfig: config}})[0]
	return provider.SAMLConfig
}

func (p *plugin) validateSAMLResponse(
	ctx context.Context,
	input samlResponseInput,
	providerID string,
	currentCallbackURL string,
	baseURL string,
	config SAMLConfig,
) (samlprotocol.ValidatedResponse, error) {
	idp, err := resolveSAMLIDPMaterial(config, p.options.SAML.MaxMetadataSize)
	if err != nil {
		return samlprotocol.ValidatedResponse{}, err
	}
	decryption, err := samlAssertionDecryption(config)
	if err != nil {
		return samlprotocol.ValidatedResponse{}, err
	}
	audiences, recipients, err := samlExpectedBindings(
		config, baseURL, providerID, currentCallbackURL, p.options.SAML.MaxMetadataSize,
	)
	if err != nil {
		return samlprotocol.ValidatedResponse{}, err
	}
	clockSkew := p.options.SAML.ClockSkew
	if clockSkew == 0 {
		clockSkew = samlprotocol.DefaultClockSkew
	}
	signatureRequirement := p.options.SAML.SignatureRequirement
	if signatureRequirement == "" && config.WantAssertionsSigned {
		signatureRequirement = samlprotocol.SignatureAssertion
	}
	validation := samlprotocol.ResponseValidationOptions{
		MaxResponseSize: p.options.SAML.MaxResponseSize,
		ExpectedIssuer:  idp.Issuer,
		Signatures: samlprotocol.SignatureVerificationOptions{
			Certificates: idp.Certificates,
			Requirement:  signatureRequirement,
			Algorithms:   p.options.SAML.Algorithms,
		},
		Timestamp: samlprotocol.TimestampValidationOptions{
			ClockSkew:         &clockSkew,
			RequireTimestamps: p.options.SAML.RequireTimestamps,
			Now:               p.runtime.Clock,
		},
		Binding: samlprotocol.ResponseBindingValidationOptions{
			ExpectedAudiences: audiences, ExpectedRecipients: recipients,
		},
		InResponseTo: samlprotocol.InResponseToValidationOptions{
			EnableValidation:   p.options.SAML.EnableInResponseToValidation,
			AllowIDPInitiated:  p.options.SAML.AllowIDPInitiated,
			ProviderID:         providerID,
			ExpectedRecipients: recipients,
			Store:              verificationSAMLStore{runtime: p.runtime},
			Now:                p.runtime.Clock,
		},
		Replay: samlprotocol.AssertionReplayOptions{
			ProviderID: providerID,
			Issuer:     idp.Issuer,
			ClockSkew:  &clockSkew,
			Store:      verificationSAMLStore{runtime: p.runtime},
			Now:        p.runtime.Clock,
		},
		EnableReplayProtection: p.options.SAML.EnableReplayProtection,
		Decryption:             decryption,
	}
	validated, err := samlprotocol.ValidatePOSTResponse(ctx, input.Response, input.RelayState, validation)
	if err != nil {
		return samlprotocol.ValidatedResponse{}, err
	}
	replayEnabled := p.options.SAML.EnableReplayProtection == nil || *p.options.SAML.EnableReplayProtection
	if replayEnabled && validated.Response.Assertion.ID == "" {
		return samlprotocol.ValidatedResponse{}, errors.New("SAML assertion is missing an ID required for replay protection")
	}
	return validated, nil
}

func samlAssertionDecryption(
	config SAMLConfig,
) (*samlprotocol.AssertionDecryptionOptions, error) {
	// Samlify decides whether decryption is required from the IdP setting and
	// unwraps with the Service Provider's encPrivateKey. decryptionPvk is a
	// legacy registration field in single-auth 1.6.26 and is not read by the
	// callback pipeline.
	if config.IDPMetadata == nil || !config.IDPMetadata.IsAssertionEncrypted {
		return nil, nil
	}
	if config.SPMetadata == nil || strings.TrimSpace(config.SPMetadata.EncPrivateKey) == "" {
		return nil, &samlprotocol.Error{
			Code:    "SAML_DECRYPTION_KEY_MISSING",
			Message: "No SAML assertion decryption private key is configured",
		}
	}
	privateKey, err := samlprotocol.ParseDecryptionPrivateKeyPEM(
		[]byte(config.SPMetadata.EncPrivateKey),
		config.SPMetadata.EncPrivateKeyPass,
	)
	if err != nil {
		return nil, err
	}
	return &samlprotocol.AssertionDecryptionOptions{PrivateKey: privateKey}, nil
}

func samlExpectedBindings(
	config SAMLConfig,
	baseURL string,
	providerID string,
	currentCallbackURL string,
	maxMetadataSize ...int,
) ([]string, []string, error) {
	spEntityID := serviceProviderEntityID(config)
	recipients := []string{
		currentCallbackURL,
		baseURL + "/sso/saml2/callback/" + url.PathEscape(providerID),
		baseURL + "/sso/saml2/sp/acs/" + url.PathEscape(providerID),
		config.CallbackURL,
	}
	if config.SPMetadata != nil {
		if config.SPMetadata.EntityID != "" {
			spEntityID = config.SPMetadata.EntityID
		}
		if strings.TrimSpace(config.SPMetadata.Metadata) != "" {
			document, err := samlprotocol.ParseMetadata(
				[]byte(config.SPMetadata.Metadata), metadataSizeLimit(maxMetadataSize...),
			)
			if err != nil {
				return nil, nil, err
			}
			entity, err := selectSPEntity(document, config.SPMetadata.EntityID)
			if err != nil {
				return nil, nil, err
			}
			spEntityID = entity.EntityID
			for _, endpoint := range entity.SP.AssertionConsumerServices {
				if endpoint.Binding == samlprotocol.HTTPPostBinding {
					recipients = append(recipients, endpoint.Location)
				}
			}
		}
	}
	return compactUnique([]string{spEntityID, config.Audience}), compactUnique(recipients), nil
}

func samlIdentity(
	response samlprotocol.Response,
	provider *resolvedProvider,
	config SAMLConfig,
	options Options,
) (oauth2.UserInfo, bool, error) {
	attribute := func(name string) string {
		values := response.Assertion.Attributes[name]
		if len(values) == 0 {
			return ""
		}
		return values[0]
	}
	mapping := config.Mapping
	idAttribute := mapping.ID
	if idAttribute == "" {
		idAttribute = "nameID"
	}
	emailAttribute := mapping.Email
	if emailAttribute == "" {
		emailAttribute = "email"
	}
	id := attribute(idAttribute)
	if id == "" {
		id = response.Assertion.NameID
	}
	email := attribute(emailAttribute)
	if email == "" {
		email = response.Assertion.NameID
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if id == "" || email == "" {
		return oauth2.UserInfo{}, false, errors.New("Unable to extract user ID or email from SAML response")
	}

	firstNameAttribute := mapping.FirstName
	if firstNameAttribute == "" {
		firstNameAttribute = "givenName"
	}
	lastNameAttribute := mapping.LastName
	if lastNameAttribute == "" {
		lastNameAttribute = "surname"
	}
	nameParts := make([]string, 0, 2)
	if value := attribute(firstNameAttribute); value != "" {
		nameParts = append(nameParts, value)
	}
	if value := attribute(lastNameAttribute); value != "" {
		nameParts = append(nameParts, value)
	}
	name := strings.TrimSpace(strings.Join(nameParts, " "))
	if name == "" {
		nameAttribute := mapping.Name
		if nameAttribute == "" {
			nameAttribute = "displayName"
		}
		name = attribute(nameAttribute)
	}
	if name == "" {
		name = response.Assertion.NameID
	}

	extra := make(map[string]any, len(mapping.ExtraFields))
	for key, source := range mapping.ExtraFields {
		values := response.Assertion.Attributes[source]
		if len(values) == 1 {
			extra[key] = values[0]
		} else if len(values) > 1 {
			extra[key] = append([]string(nil), values...)
		}
	}
	emailVerified := false
	if options.TrustEmailVerified && mapping.EmailVerified != "" {
		emailVerified = attribute(mapping.EmailVerified) == "true"
	}
	trusted := provider.DomainVerified && validateEmailDomain(email, provider.Domain)
	return oauth2.UserInfo{
		ID: id, Name: name, Email: &email,
		EmailVerified: emailVerified, Extra: extra,
	}, trusted, nil
}

func (p *plugin) relayState(ctx context.Context, state string, consume bool) relayStateData {
	if state == "" {
		return relayStateData{}
	}
	var record storage.Record
	var err error
	if consume {
		record, err = p.runtime.ConsumeVerification(ctx, state)
	} else {
		record, err = p.runtime.PeekVerification(ctx, state)
	}
	if err != nil || record == nil {
		return relayStateData{}
	}
	var result relayStateData
	if err := json.Unmarshal([]byte(recordStringValue(record, "value")), &result); err != nil {
		return relayStateData{}
	}
	if result.ExpiresAt == 0 || result.ExpiresAt < p.runtime.Clock().UnixMilli() {
		return relayStateData{}
	}
	return result
}

func decodeSAMLResponseInput(request contract.Request) (samlResponseInput, error) {
	body := request.Body()
	if len(body) > maxRequestBodyBytes {
		return samlResponseInput{}, apiError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Request body is too large",
		)
	}
	contentType, _ := request.Headers().Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if mediaType == "application/json" || mediaType == "" && strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		var value struct {
			SAMLResponse string `json:"SAMLResponse"`
			RelayState   string `json:"RelayState"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		if err := decoder.Decode(&value); err != nil {
			return samlResponseInput{}, apiError(
				contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid JSON body",
			)
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return samlResponseInput{}, apiError(
				contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid JSON body",
			)
		}
		return samlResponseInput{Response: value.SAMLResponse, RelayState: value.RelayState}, nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil || len(values["SAMLResponse"]) > 1 || len(values["RelayState"]) > 1 {
		return samlResponseInput{}, apiError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid SAML form body",
		)
	}
	return samlResponseInput{
		Response: values.Get("SAMLResponse"), RelayState: values.Get("RelayState"),
	}, nil
}

func (p *plugin) safeSAMLRedirect(
	request contract.Request,
	candidates []string,
	currentCallbackURL string,
	appOrigin string,
) string {
	callback, _ := url.Parse(currentCallbackURL)
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if strings.HasPrefix(candidate, "/") {
			lower := strings.ToLower(candidate)
			if strings.HasPrefix(lower, "//") || strings.HasPrefix(lower, "/\\") ||
				strings.HasPrefix(lower, "/%2f") || strings.HasPrefix(lower, "/%5c") {
				continue
			}
			parsed, err := url.Parse(candidate)
			if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Path == callback.Path {
				continue
			}
			trusted, err := p.runtime.IsTrustedOrigin(request, candidate, true)
			if err == nil && trusted {
				return candidate
			}
			continue
		}
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") {
			continue
		}
		origin := parsed.Scheme + "://" + parsed.Host
		if origin == appOrigin && parsed.Path == callback.Path {
			continue
		}
		if origin == appOrigin {
			return candidate
		}
		trusted, err := p.runtime.IsTrustedOrigin(request, candidate, false)
		if err == nil && trusted {
			return candidate
		}
	}
	return appOrigin
}

func validateEmailDomain(email, domains string) bool {
	index := strings.LastIndexByte(email, '@')
	if index < 0 || index == len(email)-1 {
		return false
	}
	return domainMatches(email[index+1:], domains)
}

func compactUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func callbackValidationRedirect(err error) bool {
	switch samlErrorCode(err) {
	case "SAML_AUDIENCE_MISSING", "SAML_AUDIENCE_MISMATCH",
		"SAML_BEARER_CONFIRMATION_MISSING", "SAML_RECIPIENT_MISSING",
		"SAML_RECIPIENT_MISMATCH", "SAML_DESTINATION_MISMATCH",
		"SAML_IN_RESPONSE_TO_UNKNOWN", "SAML_IN_RESPONSE_TO_PROVIDER_MISMATCH",
		"SAML_IN_RESPONSE_TO_MISMATCH", "SAML_UNSOLICITED_RESPONSE",
		"SAML_ASSERTION_REPLAYED":
		return true
	default:
		return false
	}
}

func samlErrorCode(err error) string {
	var protocolError *samlprotocol.Error
	if errors.As(err, &protocolError) && protocolError.Code != "" {
		return protocolError.Code
	}
	var apiErr *samlprotocol.APIError
	if errors.As(err, &apiErr) {
		if code, ok := apiErr.Body["code"].(string); ok && code != "" {
			return code
		}
	}
	return "BAD_REQUEST"
}

func samlRedirectError(err error) (string, string) {
	code := samlErrorCode(err)
	description := err.Error()
	switch code {
	case "SAML_ASSERTION_REPLAYED":
		return "replay_detected", "SAML assertion has already been used"
	case "SAML_UNSOLICITED_RESPONSE":
		return "unsolicited_response", "IdP-initiated SSO not allowed"
	case "SAML_IN_RESPONSE_TO_UNKNOWN":
		return "invalid_saml_response", "Unknown or expired request ID"
	case "SAML_IN_RESPONSE_TO_PROVIDER_MISMATCH":
		return "invalid_saml_response", "Provider mismatch"
	case "SAML_AUDIENCE_MISSING", "SAML_AUDIENCE_MISMATCH",
		"SAML_BEARER_CONFIRMATION_MISSING", "SAML_RECIPIENT_MISSING",
		"SAML_RECIPIENT_MISMATCH", "SAML_DESTINATION_MISMATCH",
		"SAML_IN_RESPONSE_TO_MISMATCH":
		return "invalid_saml_response", description
	default:
		return strings.ToLower(code), description
	}
}

func redirectWithQuery(target string, values map[string]string) contract.Response {
	parsed, err := url.Parse(target)
	if err != nil {
		return redirectResponse(target)
	}
	query := parsed.Query()
	for key, value := range values {
		if value != "" {
			query.Set(key, value)
		}
	}
	parsed.RawQuery = query.Encode()
	return redirectResponse(parsed.String())
}

func redirectResponse(target string) contract.Response {
	return contract.NewResponse(
		http.StatusFound,
		contract.NewHeaders(contract.HeaderField{Name: "Location", Value: target}),
		nil,
	)
}
