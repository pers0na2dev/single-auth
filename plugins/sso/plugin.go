package sso

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	maxRequestBodyBytes        = 4 << 20
	defaultMaxMetadataSize     = 100 << 10
	defaultRelayStateTTL       = 10 * time.Minute
	defaultRequestTTL          = 5 * time.Minute
	authnRequestPrefix         = "saml-authn-request:"
	usedAssertionPrefix        = "saml-used-assertion:"
	EndpointRegisterSSO        = "registerSSOProvider"
	EndpointListSSO            = "listSSOProviders"
	EndpointGetSSO             = "getSSOProvider"
	EndpointUpdateSSO          = "updateSSOProvider"
	EndpointDeleteSSO          = "deleteSSOProvider"
	EndpointRequestDomain      = "requestDomainVerification"
	EndpointVerifyDomain       = "verifyDomain"
	EndpointSignInSSO          = "signInSSO"
	EndpointOIDCCallback       = "handleSSOCallback"
	EndpointOIDCSharedCallback = "handleSSOCallbackShared"
	EndpointSAMLCallback       = "handleSAMLCallback"
	EndpointSAMLACS            = "handleSAMLAssertionConsumerService"
	EndpointSPMetadata         = "spMetadata"
	EndpointSLO                = "sloEndpoint"
	EndpointInitiateSLO        = "initiateSLO"
)

type plugin struct {
	options                   Options
	providers                 []DefaultProvider
	runtime                   Runtime
	requestTTL                time.Duration
	domainVerificationEnabled bool
	randomMu                  sync.Mutex
	sloMu                     sync.Mutex
}

type resolvedProvider struct {
	ProviderID     string
	Issuer         string
	Domain         string
	OrganizationID string
	OIDCConfig     *OIDCConfig
	SAMLConfig     *SAMLConfig
	DomainVerified bool
}

// New validates and snapshots a transport-neutral SSO plugin.
func New(options Options) (engine.Plugin, error) {
	implementation, err := normalize(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	return implementation.descriptor(), nil
}

// MustNew is New with panic-on-configuration-error semantics.
func MustNew(options Options) engine.Plugin {
	result, err := New(options)
	if err != nil {
		panic(err)
	}
	return result
}

// NewFactory binds SSO state and AuthnRequest correlation to the root Better
// Auth verification store.
func NewFactory(options Options) singleauth.PluginFactory {
	options.Runtime = Runtime{}
	options.DefaultSSO = cloneProviders(options.DefaultSSO)
	options.ProvidersLimit = cloneInt(options.ProvidersLimit)
	options.SAML = cloneSAMLRuntimeOptions(options.SAML)
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return "sso" }

// AccountProviderIDs exposes configured default SSO provider identifiers to
// peer plugins that must prevent cross-provider account collisions.
func (factory *rootFactory) AccountProviderIDs() []string {
	if factory == nil {
		return nil
	}
	result := make([]string, 0, len(factory.options.DefaultSSO))
	for _, provider := range factory.options.DefaultSSO {
		result = append(result, provider.ProviderID)
	}
	return result
}

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return providerSchemaWithOptions(factory.options), nil
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime = Runtime{
		Clock:             host.Clock,
		Random:            host.Random,
		Adapter:           host.Adapter,
		AdapterForContext: host.AdapterForContext,
		HasPlugin:         host.HasPlugin,
		ResolveBaseURL:    host.ResolveBaseURL,
		IsTrustedOrigin:   host.IsTrustedOrigin,
		CreateOAuthState:  host.CreateOAuthState,
		ConsumeOAuthState: host.ConsumeOAuthState,
		OAuthErrorURL:     host.OAuthErrorURL,
		ReservedProviderID: func(providerID string) bool {
			if _, exists := builtInSSOAccountProviderIDs[providerID]; exists {
				return true
			}
			if _, exists := host.Options.SocialProviders[providerID]; exists {
				return true
			}
			for _, trustedProviderID := range host.Options.Account.AccountLinking.TrustedProviders {
				if providerID == trustedProviderID {
					return true
				}
			}
			return host.SocialProvider != nil && host.SocialProvider(providerID) != nil
		},
		CreateVerification:  host.CreateVerification,
		PeekVerification:    host.PeekVerification,
		ConsumeVerification: host.ConsumeVerification,
		ReserveVerification: func(
			ctx context.Context,
			identifier string,
			value string,
			expiresAt time.Time,
		) (bool, error) {
			return host.InternalAdapter.ReserveVerificationValue(ctx, singleauth.VerificationValue{
				Identifier: identifier,
				Value:      value,
				ExpiresAt:  expiresAt,
			})
		},
		HandleOAuthUser:      host.HandleOAuthUser,
		RefreshSession:       host.RefreshSession,
		NewSession:           host.NewSession,
		ResolveSession:       host.ResolveSession,
		DeleteSession:        host.DeleteSession,
		ExpireSessionCookies: host.ExpireSessionCookies,
		OnAPIErrorURL:        host.Options.OnAPIError.ErrorURL,
		UpdateVerification:   host.UpdateVerification,
		DeleteVerification:   host.DeleteVerification,
	}
	return New(options)
}

func normalize(input Options) (*plugin, error) {
	options := input
	options.DefaultSSO = cloneProviders(input.DefaultSSO)
	options.ProvidersLimit = cloneInt(input.ProvidersLimit)
	options.SAML = cloneSAMLRuntimeOptions(input.SAML)
	clock := options.Runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	randomSource := options.Runtime.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	if options.Runtime.CreateVerification == nil {
		return nil, fmt.Errorf("sso: Runtime.CreateVerification is required")
	}
	if options.Runtime.ConsumeVerification == nil {
		return nil, fmt.Errorf("sso: Runtime.ConsumeVerification is required")
	}
	if options.Runtime.PeekVerification == nil {
		return nil, fmt.Errorf("sso: Runtime.PeekVerification is required")
	}
	if options.Runtime.ReserveVerification == nil {
		return nil, fmt.Errorf("sso: Runtime.ReserveVerification is required")
	}
	if options.Runtime.ResolveBaseURL == nil {
		return nil, fmt.Errorf("sso: Runtime.ResolveBaseURL is required")
	}
	if options.Runtime.IsTrustedOrigin == nil {
		return nil, fmt.Errorf("sso: Runtime.IsTrustedOrigin is required")
	}
	if options.Runtime.HandleOAuthUser == nil {
		return nil, fmt.Errorf("sso: Runtime.HandleOAuthUser is required")
	}
	if options.Runtime.RefreshSession == nil {
		return nil, fmt.Errorf("sso: Runtime.RefreshSession is required")
	}
	if options.Runtime.CreateOAuthState == nil {
		return nil, fmt.Errorf("sso: Runtime.CreateOAuthState is required")
	}
	if options.Runtime.ConsumeOAuthState == nil {
		return nil, fmt.Errorf("sso: Runtime.ConsumeOAuthState is required")
	}
	if options.Runtime.OAuthErrorURL == nil {
		return nil, fmt.Errorf("sso: Runtime.OAuthErrorURL is required")
	}
	if options.SAML.EnableSingleLogout {
		if options.Runtime.ResolveSession == nil {
			return nil, fmt.Errorf("sso: Runtime.ResolveSession is required for SAML Single Logout")
		}
		if options.Runtime.DeleteSession == nil {
			return nil, fmt.Errorf("sso: Runtime.DeleteSession is required for SAML Single Logout")
		}
		if options.Runtime.ExpireSessionCookies == nil {
			return nil, fmt.Errorf("sso: Runtime.ExpireSessionCookies is required for SAML Single Logout")
		}
		if options.Runtime.UpdateVerification == nil || options.Runtime.DeleteVerification == nil {
			return nil, fmt.Errorf("sso: verification update/delete runtime is required for SAML Single Logout")
		}
	}
	requestTTL := options.SAML.RequestTTL
	if requestTTL <= 0 {
		requestTTL = defaultRequestTTL
	}
	if options.SAML.MaxMetadataSize <= 0 {
		options.SAML.MaxMetadataSize = defaultMaxMetadataSize
	}
	seen := make(map[string]struct{}, len(options.DefaultSSO))
	for index, provider := range options.DefaultSSO {
		if strings.TrimSpace(provider.ProviderID) == "" {
			return nil, fmt.Errorf("sso: defaultSSO[%d].ProviderID is required", index)
		}
		if _, exists := seen[provider.ProviderID]; exists {
			return nil, fmt.Errorf("sso: duplicate defaultSSO provider ID %q", provider.ProviderID)
		}
		seen[provider.ProviderID] = struct{}{}
		if strings.TrimSpace(provider.Domain) == "" {
			return nil, fmt.Errorf("sso: defaultSSO[%d].Domain is required", index)
		}
		hasSAML := !zeroSAMLConfig(provider.SAMLConfig)
		hasOIDC := provider.OIDCConfig != nil
		if !hasSAML && !hasOIDC {
			return nil, fmt.Errorf("sso: defaultSSO[%d] requires an OIDC or SAML configuration", index)
		}
		if hasSAML {
			if err := validateSAMLMetadataSize(provider.SAMLConfig, options.SAML.MaxMetadataSize); err != nil {
				return nil, fmt.Errorf("sso: defaultSSO[%d] SAML configuration: %w", index, err)
			}
			if err := samlprotocol.ValidateConfigAlgorithms(samlprotocol.ConfigAlgorithms{
				SignatureAlgorithm: provider.SAMLConfig.SignatureAlgorithm,
				DigestAlgorithm:    provider.SAMLConfig.DigestAlgorithm,
			}, options.SAML.Algorithms); err != nil {
				return nil, fmt.Errorf("sso: defaultSSO[%d] SAML configuration: %w", index, err)
			}
			spEntityID := serviceProviderEntityID(provider.SAMLConfig)
			hasIDPMetadata := provider.SAMLConfig.IDPMetadata != nil &&
				strings.TrimSpace(provider.SAMLConfig.IDPMetadata.Metadata) != ""
			if spEntityID == "" || provider.SAMLConfig.CallbackURL == "" ||
				(!hasIDPMetadata && (provider.SAMLConfig.EntryPoint == "" || provider.SAMLConfig.Certificate == "")) {
				return nil, fmt.Errorf("sso: defaultSSO[%d] has an incomplete SAML configuration", index)
			}
			if !hasIDPMetadata {
				if _, err := absoluteHTTPURL(provider.SAMLConfig.EntryPoint); err != nil {
					return nil, fmt.Errorf("sso: defaultSSO[%d] entry point: %w", index, err)
				}
			}
			if _, err := absoluteHTTPURL(provider.SAMLConfig.CallbackURL); err != nil {
				return nil, fmt.Errorf("sso: defaultSSO[%d] callback URL: %w", index, err)
			}
		}
		if hasOIDC {
			if err := validateConfiguredOIDC(*provider.OIDCConfig, true); err != nil {
				return nil, fmt.Errorf("sso: defaultSSO[%d] OIDC configuration: %w", index, err)
			}
		}
	}
	options.Runtime.Clock = clock
	options.Runtime.Random = randomSource
	return &plugin{
		options:                   options,
		providers:                 options.DefaultSSO,
		runtime:                   options.Runtime,
		requestTTL:                requestTTL,
		domainVerificationEnabled: options.DomainVerification.Enabled,
	}, nil
}

func (p *plugin) descriptor() engine.Plugin {
	descriptor := engine.Plugin{
		ID: "sso", Version: Version, Schema: providerSchemaWithOptions(p.options),
		Endpoints: []engine.Endpoint{
			{
				Name: EndpointRegisterSSO, Path: "/sso/register",
				Methods: []string{http.MethodPost}, OperationID: EndpointRegisterSSO,
				Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware}, Handler: p.register,
			},
			{
				Name: EndpointListSSO, Path: "/sso/providers",
				Methods: []string{http.MethodGet}, OperationID: EndpointListSSO,
				Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware}, Handler: p.listProviders,
			},
			{
				Name: EndpointGetSSO, Path: "/sso/get-provider",
				Methods: []string{http.MethodGet}, OperationID: EndpointGetSSO,
				Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware}, Handler: p.getProvider,
			},
			{
				Name: EndpointUpdateSSO, Path: "/sso/update-provider",
				Methods: []string{http.MethodPost}, OperationID: EndpointUpdateSSO,
				Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware}, Handler: p.updateProvider,
			},
			{
				Name: EndpointDeleteSSO, Path: "/sso/delete-provider",
				Methods: []string{http.MethodPost}, OperationID: EndpointDeleteSSO,
				Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware}, Handler: p.deleteProvider,
			},
			{
				Name: EndpointSignInSSO, Path: "/sign-in/sso",
				Methods: []string{http.MethodPost}, OperationID: "signInWithSSO",
				Handler: p.signIn,
			},
			{
				Name: EndpointOIDCCallback, Path: "/sso/callback/:providerId",
				Methods: []string{http.MethodGet}, OperationID: EndpointOIDCCallback,
				Handler: p.oidcCallback,
			},
			{
				Name: EndpointOIDCSharedCallback, Path: "/sso/callback",
				Methods: []string{http.MethodGet}, OperationID: EndpointOIDCSharedCallback,
				Handler: p.oidcSharedCallback,
			},
			{
				Name: EndpointSAMLCallback, Path: "/sso/saml2/callback/:providerId",
				Methods: []string{http.MethodGet, http.MethodPost}, OperationID: EndpointSAMLCallback,
				Handler: p.samlCallback,
			},
			{
				Name: EndpointSAMLACS, Path: "/sso/saml2/sp/acs/:providerId",
				Methods: []string{http.MethodPost}, OperationID: EndpointSAMLACS,
				Handler: p.samlACS,
			},
			{
				Name: EndpointSPMetadata, Path: "/sso/saml2/sp/metadata",
				Methods: []string{http.MethodGet}, OperationID: "getSSOServiceProviderMetadata",
				Handler: p.spMetadata,
			},
			{
				Name: EndpointSLO, Path: "/sso/saml2/sp/slo/:providerId",
				Methods: []string{http.MethodGet, http.MethodPost}, OperationID: EndpointSLO,
				Handler: p.slo,
			},
			{
				Name: EndpointInitiateSLO, Path: "/sso/saml2/logout/:providerId",
				Methods: []string{http.MethodPost}, OperationID: EndpointInitiateSLO,
				Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware}, Handler: p.initiateSLO,
			},
		},
		SkipOriginCheckPaths: []string{
			"/sso/saml2/callback", "/sso/saml2/sp/acs", "/sso/saml2/sp/slo",
		},
	}
	descriptor.Hooks.After = append(descriptor.Hooks.After, engine.AfterHook{
		Name: "sso-assign-organization-by-domain",
		Matcher: func(ctx *engine.Context) (bool, error) {
			return strings.HasPrefix(ctx.Path(), "/callback/"), nil
		},
		Handler: p.assignOrganizationByDomainAfterCallback,
	})
	if p.domainVerificationEnabled {
		descriptor.Endpoints = append(descriptor.Endpoints,
			engine.Endpoint{
				Name: EndpointRequestDomain, Path: "/sso/request-domain-verification",
				Methods: []string{http.MethodPost}, OperationID: EndpointRequestDomain,
				Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware}, Handler: p.requestDomainVerification,
			},
			engine.Endpoint{
				Name: EndpointVerifyDomain, Path: "/sso/verify-domain",
				Methods: []string{http.MethodPost}, OperationID: EndpointVerifyDomain,
				Use: []engine.EndpointMiddlewareFunc{singleauth.SessionMiddleware}, Handler: p.verifyDomain,
			},
		)
	}
	if p.options.SAML.EnableSingleLogout {
		descriptor.Hooks.Before = append(descriptor.Hooks.Before, engine.BeforeHook{
			Name: "sso-saml-session-cleanup-on-sign-out",
			Matcher: func(ctx *engine.Context) (bool, error) {
				return ctx.RoutePath() == "/sign-out", nil
			},
			Handler: p.cleanupSAMLSessionOnSignOut,
		})
	}
	return descriptor
}

func (p *plugin) signIn(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	callbackURL, ok := body["callbackURL"].(string)
	if !ok || callbackURL == "" {
		return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "callbackURL is required")
	}
	errorCallbackURL, err := optionalString(body, "errorCallbackURL")
	if err != nil {
		return contract.Response{}, err
	}
	providerID, err := optionalString(body, "providerId")
	if err != nil {
		return contract.Response{}, err
	}
	domain, err := optionalString(body, "domain")
	if err != nil {
		return contract.Response{}, err
	}
	email, err := optionalString(body, "email")
	if err != nil {
		return contract.Response{}, err
	}
	if domain == "" && email != "" {
		parts := strings.Split(email, "@")
		if len(parts) > 1 {
			domain = parts[1]
		}
	}
	organizationSlug, err := optionalString(body, "organizationSlug")
	if err != nil {
		return contract.Response{}, err
	}
	organizationID := ""
	if organizationSlug != "" {
		adapter := p.adapter(ctx)
		if adapter != nil {
			organization, findErr := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
				Model: "organization", Where: []storage.Where{{Field: "slug", Value: organizationSlug}},
			})
			if findErr != nil {
				return contract.Response{}, findErr
			}
			organizationID = recordStringValue(organization, "id")
		}
	}
	if providerID == "" && domain == "" && organizationID == "" {
		return contract.Response{}, apiError(
			contract.StatusBadRequest,
			"BAD_REQUEST",
			"email, domain or providerId is required",
		)
	}
	provider, err := p.findProvider(ctx, providerID, domain, organizationID)
	if err != nil {
		return contract.Response{}, fmt.Errorf("sso: find provider: %w", err)
	}
	if provider == nil {
		return contract.Response{}, apiError(contract.StatusNotFound, "NOT_FOUND", "No provider found for the issuer")
	}
	if p.domainVerificationEnabled && !provider.DomainVerified {
		return contract.Response{}, apiError(contract.StatusUnauthorized, "UNAUTHORIZED", "Provider domain has not been verified")
	}
	providerType, err := optionalString(body, "providerType")
	if err != nil {
		return contract.Response{}, err
	}
	if providerType != "" && providerType != "oidc" && providerType != "saml" {
		return contract.Response{}, apiError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid providerType")
	}
	if providerType == "oidc" && provider.OIDCConfig == nil {
		return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "OIDC provider is not configured")
	}
	if providerType == "saml" && provider.SAMLConfig == nil {
		return contract.Response{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "SAML provider is not configured")
	}
	if provider.OIDCConfig != nil && providerType != "saml" {
		newUserURL, optionalErr := optionalString(body, "newUserCallbackURL")
		if optionalErr != nil {
			return contract.Response{}, optionalErr
		}
		loginHint, optionalErr := optionalString(body, "loginHint")
		if optionalErr != nil {
			return contract.Response{}, optionalErr
		}
		requestSignUp, optionalErr := optionalBoolPointer(body, "requestSignUp")
		if optionalErr != nil {
			return contract.Response{}, optionalErr
		}
		scopes, optionalErr := optionalStringSlice(body, "scopes")
		if optionalErr != nil {
			return contract.Response{}, optionalErr
		}
		return p.startOIDC(ctx, provider, oidcSignInInput{
			CallbackURL: callbackURL, ErrorURL: errorCallbackURL,
			NewUserURL: newUserURL, RequestSignUp: requestSignUp,
			Scopes: scopes, LoginHint: firstNonEmpty(loginHint, email),
		})
	}
	samlConfig, err := validateResolvedSAMLConfig(provider.SAMLConfig, p.options.SAML.MaxMetadataSize)
	if err != nil {
		return contract.Response{}, err
	}
	entryPoint, err := resolveSAMLRedirectSSO(samlConfig, p.options.SAML.MaxMetadataSize)
	if err != nil {
		return contract.Response{}, invalidSAMLConfigurationError()
	}

	now := p.runtime.Clock().UTC()
	relayState, err := p.randomToken(32)
	if err != nil {
		return contract.Response{}, fmt.Errorf("sso: generate relay state: %w", err)
	}
	relayData := map[string]any{
		"callbackURL": callbackURL,
		"expiresAt":   now.Add(defaultRelayStateTTL).UnixMilli(),
	}
	if errorCallbackURL != "" {
		relayData["errorURL"] = errorCallbackURL
	}
	relayRecord, err := json.Marshal(relayData)
	if err != nil {
		return contract.Response{}, err
	}
	if _, err := p.runtime.CreateVerification(
		ctx.GoContext(), relayState, string(relayRecord), now.Add(defaultRelayStateTTL),
	); err != nil {
		return contract.Response{}, fmt.Errorf("sso: create relay state verification: %w", err)
	}

	allowCreate := true
	request, err := samlprotocol.NewAuthnRequest(samlprotocol.AuthnRequestOptions{
		Destination:                 entryPoint,
		AssertionConsumerServiceURL: samlConfig.CallbackURL,
		Issuer:                      serviceProviderEntityID(samlConfig),
		IssueInstant:                now,
		ProtocolBinding:             samlprotocol.HTTPPostBinding,
		NameIDPolicyFormat:          samlConfig.IdentifierFormat,
		AllowCreate:                 &allowCreate,
	})
	if err != nil {
		return contract.Response{}, err
	}
	authnRecord, err := json.Marshal(map[string]any{
		"id":         request.ID,
		"providerId": provider.ProviderID,
		"createdAt":  now.UnixMilli(),
		"expiresAt":  now.Add(p.requestTTL).UnixMilli(),
	})
	if err != nil {
		return contract.Response{}, err
	}
	if _, err := p.runtime.CreateVerification(
		ctx.GoContext(), authnRequestPrefix+request.ID, string(authnRecord), now.Add(p.requestTTL),
	); err != nil {
		return contract.Response{}, fmt.Errorf("sso: create AuthnRequest verification: %w", err)
	}
	entryPoint, err = samlEntryPointWithAdditionalParams(entryPoint, samlConfig.AdditionalParams)
	if err != nil {
		return contract.Response{}, invalidSAMLConfigurationError()
	}
	signer, err := samlAuthnRequestSigner(samlConfig)
	if err != nil {
		return contract.Response{}, invalidSAMLConfigurationError()
	}
	redirectURL, err := samlprotocol.BuildRedirectURL(
		ctx.GoContext(), entryPoint,
		samlprotocol.SAMLRequestParameter, request.XML, relayState, signer, samlConfig.SignatureAlgorithm,
	)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"url": redirectURL, "redirect": true,
	})
}

func (p *plugin) findProvider(ctx *engine.Context, providerID, domain string, organizationID ...string) (*resolvedProvider, error) {
	for index := range p.providers {
		provider := &p.providers[index]
		if providerID != "" && provider.ProviderID == providerID {
			resolved := &resolvedProvider{
				ProviderID: provider.ProviderID, Domain: provider.Domain,
				DomainVerified: p.domainVerificationEnabled,
			}
			if !zeroSAMLConfig(provider.SAMLConfig) {
				config := provider.SAMLConfig
				resolved.SAMLConfig = &config
				resolved.Issuer = config.Issuer
			}
			if provider.OIDCConfig != nil {
				resolved.OIDCConfig = cloneOIDCConfig(provider.OIDCConfig)
				resolved.Issuer = resolved.OIDCConfig.Issuer
			}
			return resolved, nil
		}
	}
	if providerID == "" {
		for index := range p.providers {
			provider := &p.providers[index]
			if domainMatches(domain, provider.Domain) {
				resolved := &resolvedProvider{
					ProviderID: provider.ProviderID, Domain: provider.Domain,
					DomainVerified: p.domainVerificationEnabled,
				}
				if !zeroSAMLConfig(provider.SAMLConfig) {
					config := provider.SAMLConfig
					resolved.SAMLConfig = &config
					resolved.Issuer = config.Issuer
				}
				if provider.OIDCConfig != nil {
					resolved.OIDCConfig = cloneOIDCConfig(provider.OIDCConfig)
					resolved.Issuer = resolved.OIDCConfig.Issuer
				}
				return resolved, nil
			}
		}
	}

	adapter := p.adapter(ctx)
	if adapter == nil {
		return nil, nil
	}
	parse := func(record storage.Record) (*resolvedProvider, error) {
		if record == nil {
			return nil, nil
		}
		provider := &resolvedProvider{
			ProviderID:     recordStringValue(record, "providerId"),
			Issuer:         recordStringValue(record, "issuer"),
			Domain:         recordStringValue(record, "domain"),
			OrganizationID: recordStringValue(record, "organizationId"),
			DomainVerified: recordBoolValue(record, "domainVerified"),
		}
		provider.OIDCConfig = decodeStoredOIDCConfig(record["oidcConfig"])
		provider.SAMLConfig = decodeStoredSAMLConfig(record["samlConfig"])
		if provider.OIDCConfig != nil && provider.OIDCConfig.Issuer == "" {
			provider.OIDCConfig.Issuer = provider.Issuer
		}
		return provider, nil
	}

	if providerID != "" {
		record, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "ssoProvider", Where: []storage.Where{{Field: "providerId", Value: providerID}},
		})
		if err != nil {
			return nil, err
		}
		return parse(record)
	}
	if len(organizationID) > 0 && organizationID[0] != "" {
		record, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "ssoProvider", Where: []storage.Where{{Field: "organizationId", Value: organizationID[0]}},
		})
		if err != nil {
			return nil, err
		}
		return parse(record)
	}
	if domain == "" {
		return nil, nil
	}
	record, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "ssoProvider", Where: []storage.Where{{Field: "domain", Value: domain}},
	})
	if err != nil {
		return nil, err
	}
	if record != nil {
		return parse(record)
	}
	records, err := adapter.FindMany(ctx.GoContext(), storage.FindManyParams{Model: "ssoProvider"})
	if err != nil {
		return nil, err
	}
	for _, candidate := range records {
		if domainMatches(domain, recordStringValue(candidate, "domain")) {
			return parse(candidate)
		}
	}
	return nil, nil
}

func decodeStoredOIDCConfig(raw any) *OIDCConfig {
	if raw == nil {
		return nil
	}
	if config, ok := raw.(OIDCConfig); ok {
		return cloneOIDCConfig(&config)
	}
	if config, ok := raw.(*OIDCConfig); ok {
		return cloneOIDCConfig(config)
	}
	encoded, ok := encodedConfigBytes(raw)
	if !ok {
		return nil
	}
	var config OIDCConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		return nil
	}
	return cloneOIDCConfig(&config)
}

func decodeStoredSAMLConfig(raw any) *SAMLConfig {
	if raw == nil {
		return nil
	}
	if config, ok := raw.(SAMLConfig); ok {
		return &config
	}
	if config, ok := raw.(*SAMLConfig); ok {
		if config == nil {
			return nil
		}
		clone := *config
		return &clone
	}

	var encoded []byte
	switch value := raw.(type) {
	case string:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		encoded = []byte(value)
	case []byte:
		if len(bytes.TrimSpace(value)) == 0 {
			return nil
		}
		encoded = append([]byte(nil), value...)
	case json.RawMessage:
		if len(bytes.TrimSpace(value)) == 0 {
			return nil
		}
		encoded = append([]byte(nil), value...)
	default:
		var err error
		encoded, err = json.Marshal(value)
		if err != nil {
			return nil
		}
	}
	if bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) {
		return nil
	}
	var config SAMLConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		return nil
	}
	return &config
}

func encodedConfigBytes(raw any) ([]byte, bool) {
	var encoded []byte
	switch value := raw.(type) {
	case string:
		if strings.TrimSpace(value) == "" {
			return nil, false
		}
		encoded = []byte(value)
	case []byte:
		if len(bytes.TrimSpace(value)) == 0 {
			return nil, false
		}
		encoded = append([]byte(nil), value...)
	case json.RawMessage:
		if len(bytes.TrimSpace(value)) == 0 {
			return nil, false
		}
		encoded = append([]byte(nil), value...)
	default:
		var err error
		encoded, err = json.Marshal(value)
		if err != nil {
			return nil, false
		}
	}
	if bytes.Equal(bytes.TrimSpace(encoded), []byte("null")) {
		return nil, false
	}
	return encoded, true
}

func validateResolvedSAMLConfig(config *SAMLConfig, maxMetadataSize ...int) (SAMLConfig, error) {
	if config == nil {
		return SAMLConfig{}, apiError(contract.StatusBadRequest, "BAD_REQUEST", "Invalid SSO provider")
	}
	result := *config
	spEntityID := serviceProviderEntityID(result)
	if spEntityID == "" || result.CallbackURL == "" {
		return SAMLConfig{}, invalidSAMLConfigurationError()
	}
	if _, err := absoluteHTTPURL(result.CallbackURL); err != nil {
		return SAMLConfig{}, invalidSAMLConfigurationError()
	}
	if err := validateSAMLMetadataSize(result, metadataSizeLimit(maxMetadataSize...)); err != nil {
		return SAMLConfig{}, invalidSAMLConfigurationError()
	}
	if _, err := resolveSAMLRedirectSSO(result, metadataSizeLimit(maxMetadataSize...)); err != nil {
		return SAMLConfig{}, invalidSAMLConfigurationError()
	}
	return result, nil
}

func invalidSAMLConfigurationError() *contract.APIError {
	return apiError(contract.StatusBadRequest, "BAD_REQUEST", "Invalid SAML configuration")
}

func recordStringValue(record storage.Record, key string) string {
	value, _ := record[key].(string)
	return value
}

func recordBoolValue(record storage.Record, key string) bool {
	value, _ := record[key].(bool)
	return value
}

func (p *plugin) randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	p.randomMu.Lock()
	_, err := io.ReadFull(p.runtime.Random, buffer)
	p.randomMu.Unlock()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func decodeObject(ctx *engine.Context) (map[string]any, error) {
	raw := ctx.Request().Body()
	if len(raw) > maxRequestBodyBytes {
		return nil, apiError(contract.StatusBadRequest, "VALIDATION_ERROR", "Request body is too large")
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	object := map[string]any{}
	if err := decoder.Decode(&object); err != nil {
		return nil, apiError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid JSON body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, apiError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid JSON body")
	}
	return object, nil
}

func optionalString(object map[string]any, key string) (string, error) {
	value, exists := object[key]
	if !exists || value == nil {
		return "", nil
	}
	result, ok := value.(string)
	if !ok {
		return "", apiError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid "+key)
	}
	return result, nil
}

func domainMatches(searchDomain, domainList string) bool {
	search := strings.TrimSpace(strings.ToLower(searchDomain))
	if search == "" {
		return false
	}
	domains, ok := parseProviderDomains(domainList)
	if !ok {
		return false
	}
	for _, domain := range domains {
		if search == domain || strings.HasSuffix(search, "."+domain) {
			return true
		}
	}
	return false
}

func parseProviderDomains(domainList string) ([]string, bool) {
	seen := make(map[string]struct{})
	domains := make([]string, 0)
	for _, candidate := range strings.Split(domainList, ",") {
		domain := normalizeDomain(candidate)
		if domain == "" {
			if strings.TrimSpace(candidate) == "" {
				continue
			}
			return nil, false
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	return domains, len(domains) > 0
}

func normalizeDomain(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	value = strings.TrimSuffix(value, ".")
	if strings.ContainsAny(value, "/?#@") {
		return ""
	}
	return value
}

func absoluteHTTPURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("must be an absolute http or https URL")
	}
	return parsed, nil
}

func apiError(status int, code, message string) *contract.APIError {
	return contract.NewAPIError(status, code, message)
}

func cloneProviders(input []DefaultProvider) []DefaultProvider {
	result := make([]DefaultProvider, len(input))
	for index, provider := range input {
		clone := provider
		clone.OIDCConfig = cloneOIDCConfig(provider.OIDCConfig)
		clone.SAMLConfig.Mapping.ExtraFields = cloneStringMap(provider.SAMLConfig.Mapping.ExtraFields)
		clone.SAMLConfig.AdditionalParams = cloneAnyMap(provider.SAMLConfig.AdditionalParams)
		if provider.SAMLConfig.IDPMetadata != nil {
			metadata := *provider.SAMLConfig.IDPMetadata
			metadata.SingleSignOnService = append(
				[]SAMLServiceEndpoint(nil), provider.SAMLConfig.IDPMetadata.SingleSignOnService...,
			)
			metadata.SingleLogoutService = append(
				[]SAMLServiceEndpoint(nil), provider.SAMLConfig.IDPMetadata.SingleLogoutService...,
			)
			clone.SAMLConfig.IDPMetadata = &metadata
		}
		if provider.SAMLConfig.SPMetadata != nil {
			metadata := *provider.SAMLConfig.SPMetadata
			clone.SAMLConfig.SPMetadata = &metadata
		}
		result[index] = clone
	}
	return result
}

func cloneSAMLRuntimeOptions(input SAMLRuntimeOptions) SAMLRuntimeOptions {
	result := input
	result.EnableInResponseToValidation = cloneBool(input.EnableInResponseToValidation)
	result.AllowIDPInitiated = cloneBool(input.AllowIDPInitiated)
	result.EnableReplayProtection = cloneBool(input.EnableReplayProtection)
	result.Algorithms.AllowedSignatureAlgorithms = append(
		[]string(nil), input.Algorithms.AllowedSignatureAlgorithms...,
	)
	result.Algorithms.AllowedDigestAlgorithms = append(
		[]string(nil), input.Algorithms.AllowedDigestAlgorithms...,
	)
	result.Algorithms.AllowedKeyEncryptionAlgorithms = append(
		[]string(nil), input.Algorithms.AllowedKeyEncryptionAlgorithms...,
	)
	result.Algorithms.AllowedDataEncryptionAlgorithms = append(
		[]string(nil), input.Algorithms.AllowedDataEncryptionAlgorithms...,
	)
	return result
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func providerSchema(domainVerificationEnabled bool) storage.Schema {
	optional := storage.Bool(false)
	fields := map[string]storage.FieldAttribute{
		"issuer":     {Type: storage.FieldString},
		"oidcConfig": {Type: storage.FieldString, Required: optional},
		"samlConfig": {Type: storage.FieldString, Required: optional},
		"userId": {
			Type:       storage.FieldString,
			References: &storage.Reference{Model: "user", Field: "id"},
		},
		"providerId":     {Type: storage.FieldString, Unique: true},
		"organizationId": {Type: storage.FieldString, Required: optional},
		"domain":         {Type: storage.FieldString},
	}
	if domainVerificationEnabled {
		fields["domainVerified"] = storage.FieldAttribute{
			Type: storage.FieldBoolean, Required: optional,
		}
	}
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"ssoProvider": {
			ModelName: "ssoProvider",
			Fields:    fields,
		},
	}}
}

func providerSchemaWithOptions(options Options) storage.Schema {
	schema := providerSchema(options.DomainVerification.Enabled)
	model := schema.Models["ssoProvider"]
	if strings.TrimSpace(options.ModelName) != "" {
		model.ModelName = options.ModelName
	}
	physicalNames := map[string]string{
		"issuer": options.Fields.Issuer, "oidcConfig": options.Fields.OIDCConfig,
		"samlConfig": options.Fields.SAMLConfig, "userId": options.Fields.UserID,
		"providerId": options.Fields.ProviderID, "organizationId": options.Fields.OrganizationID,
		"domain": options.Fields.Domain,
	}
	for canonical, physical := range physicalNames {
		if strings.TrimSpace(physical) == "" {
			continue
		}
		field := model.Fields[canonical]
		field.FieldName = physical
		model.Fields[canonical] = field
	}
	schema.Models["ssoProvider"] = model
	return schema
}
