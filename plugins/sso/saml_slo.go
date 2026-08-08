package sso

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	samlprotocol "github.com/pers0na2dev/single-auth/protocol/saml"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	defaultLogoutRequestTTL = 5 * time.Minute
	logoutRequestPrefix     = "saml-logout-request:"
	logoutReplayPrefix      = "saml-logout-message:"
)

type sloInput struct {
	SAMLRequest      string
	SAMLResponse     string
	RelayState       string
	requestFromBody  bool
	responseFromBody bool
}

type pendingLogoutRequest struct {
	ProviderID  string `json:"providerId"`
	CallbackURL string `json:"callbackURL"`
}

type samlLogoutMaterial struct {
	Issuer       string
	Certificates []*x509.Certificate
	Services     []samlprotocol.Endpoint
}

type samlSPLogoutSigningMaterial struct {
	Signer       crypto.Signer
	Certificates []*x509.Certificate
}

func (p *plugin) slo(ctx *engine.Context) (contract.Response, error) {
	if !p.options.SAML.EnableSingleLogout {
		return contract.Response{}, apiError(
			http.StatusBadRequest, "BAD_REQUEST", "Single Logout is not enabled",
		)
	}
	providerID, ok := ctx.Param("providerId")
	if !ok || strings.TrimSpace(providerID) == "" {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "providerId is required")
	}
	input, err := decodeSLOInput(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	baseURL, currentSLO, appOrigin, err := p.sloURLs(ctx.Request(), providerID)
	if err != nil {
		return contract.Response{}, err
	}
	if input.SAMLRequest == "" && input.SAMLResponse == "" {
		safe := p.safeSAMLRedirect(ctx.Request(), []string{input.RelayState}, currentSLO, appOrigin)
		return redirectWithQuery(safe, map[string]string{
			"error": "invalid_request", "error_description": "missing_logout_data",
		}), nil
	}
	provider, err := p.findProvider(ctx, providerID, "")
	if err != nil {
		return contract.Response{}, fmt.Errorf("sso: find provider: %w", err)
	}
	if provider == nil || provider.SAMLConfig == nil {
		return contract.Response{}, apiError(http.StatusNotFound, "NOT_FOUND", "SAML provider not found")
	}
	if serviceProviderEntityID(*provider.SAMLConfig) == "" {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid SAML configuration")
	}
	material, err := resolveSAMLIDPLogoutMaterial(*provider.SAMLConfig, p.options.SAML.MaxMetadataSize)
	if err != nil {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid SAML configuration")
	}
	if input.SAMLResponse != "" {
		return p.handleLogoutResponse(ctx, input, providerID, currentSLO, appOrigin, material)
	}
	return p.handleLogoutRequest(
		ctx, input, providerID, baseURL, currentSLO, material, *provider.SAMLConfig,
	)
}

func (p *plugin) initiateSLO(ctx *engine.Context) (contract.Response, error) {
	if !p.options.SAML.EnableSingleLogout {
		return contract.Response{}, apiError(
			http.StatusBadRequest, "BAD_REQUEST", "Single Logout is not enabled",
		)
	}
	session, ok := singleauth.SessionFromEndpointContext(ctx)
	if !ok || session.Session == nil || session.User == nil {
		return contract.Response{}, apiError(http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	callbackURL, err := optionalString(body, "callbackURL")
	if err != nil {
		return contract.Response{}, err
	}
	providerID, ok := ctx.Param("providerId")
	if !ok || strings.TrimSpace(providerID) == "" {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "providerId is required")
	}
	baseURL, currentSLO, _, err := p.sloURLs(ctx.Request(), providerID)
	if err != nil {
		return contract.Response{}, err
	}
	if callbackURL == "" {
		callbackURL = baseURL
	}
	provider, err := p.findProvider(ctx, providerID, "")
	if err != nil {
		return contract.Response{}, fmt.Errorf("sso: find provider: %w", err)
	}
	if provider == nil || provider.SAMLConfig == nil {
		return contract.Response{}, apiError(http.StatusNotFound, "NOT_FOUND", "SAML provider not found")
	}
	config := *provider.SAMLConfig
	if serviceProviderEntityID(config) == "" {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid SAML configuration")
	}
	if err := samlprotocol.ValidateConfigAlgorithms(samlprotocol.ConfigAlgorithms{
		SignatureAlgorithm: config.SignatureAlgorithm, DigestAlgorithm: config.DigestAlgorithm,
	}, p.options.SAML.Algorithms); err != nil {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid SAML configuration")
	}
	material, err := resolveSAMLIDPLogoutMaterial(config, p.options.SAML.MaxMetadataSize)
	if err != nil {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid SAML configuration")
	}
	idpEndpoint, ok := samlLogoutEndpoint(material.Services, samlprotocol.HTTPRedirectBinding, false)
	if !ok {
		return contract.Response{}, apiError(
			http.StatusBadRequest, "BAD_REQUEST", "IdP does not support Single Logout Service",
		)
	}

	sessionID := recordStringValue(session.Session, "id")
	sessionToken := recordStringValue(session.Session, "token")
	nameID := recordStringValue(session.User, "email")
	var sessionIndex, forwardKey string
	var storedRecord samlSessionRecord
	if sessionID != "" {
		reverse, findErr := p.runtime.PeekVerification(ctx.GoContext(), samlSessionByIDPrefix+sessionID)
		if findErr != nil {
			return contract.Response{}, findErr
		}
		if reverse != nil {
			candidateKey := recordStringValue(reverse, "value")
			forward, _ := p.runtime.PeekVerification(ctx.GoContext(), candidateKey)
			if candidate, valid := decodeSAMLSessionRecord(forward); valid &&
				candidate.SessionID == sessionID && candidate.SessionToken == sessionToken &&
				candidate.ProviderID == providerID {
				storedRecord, forwardKey = candidate, candidateKey
				nameID, sessionIndex = candidate.NameID, candidate.SessionIndex
			}
		}
	}
	if nameID == "" || sessionToken == "" {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid SAML session")
	}
	requestID, err := p.samlLogoutID()
	if err != nil {
		return contract.Response{}, err
	}
	request, err := samlprotocol.NewLogoutRequest(samlprotocol.LogoutRequestOptions{
		ID: requestID, Issuer: serviceProviderEntityID(config), Destination: idpEndpoint,
		NameID: nameID, SessionIndex: sessionIndex, IssueInstant: p.runtime.Clock(),
	})
	if err != nil {
		return contract.Response{}, err
	}
	signing, err := resolveSPLogoutSigningMaterial(config, p.options.SAML.MaxMetadataSize)
	if err != nil {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid SAML configuration")
	}
	redirect, err := samlprotocol.BuildRedirectURL(
		ctx.GoContext(), idpEndpoint, samlprotocol.SAMLRequestParameter, request.XML,
		callbackURL, signing.Signer, config.SignatureAlgorithm,
	)
	if err != nil {
		return contract.Response{}, err
	}
	pendingValue, err := json.Marshal(pendingLogoutRequest{ProviderID: providerID, CallbackURL: callbackURL})
	if err != nil {
		return contract.Response{}, err
	}
	ttl := p.options.SAML.LogoutRequestTTL
	if ttl <= 0 {
		ttl = defaultLogoutRequestTTL
	}
	pendingKey := logoutRequestPrefix + request.ID
	reserved, err := p.runtime.ReserveVerification(
		ctx.GoContext(), pendingKey, string(pendingValue), p.runtime.Clock().Add(ttl),
	)
	if err != nil {
		return contract.Response{}, err
	}
	if !reserved {
		return contract.Response{}, fmt.Errorf("sso: generated duplicate SAML LogoutRequest ID")
	}
	if err := p.runtime.DeleteSession(ctx.GoContext(), sessionToken); err != nil {
		_ = p.runtime.DeleteVerification(ctx.GoContext(), pendingKey)
		return contract.Response{}, err
	}
	if forwardKey != "" {
		p.sloMu.Lock()
		_ = p.deleteSAMLSessionRecords(ctx.GoContext(), forwardKey, storedRecord)
		p.sloMu.Unlock()
	}
	p.runtime.ExpireSessionCookies(ctx)
	_ = currentSLO
	return redirectResponse(redirect), nil
}

func (p *plugin) handleLogoutResponse(
	ctx *engine.Context,
	input sloInput,
	providerID, currentSLO, appOrigin string,
	material samlLogoutMaterial,
) (contract.Response, error) {
	response, bindingSigned, relayState, err := parseBoundLogoutResponse(
		ctx.Request(), input, material.Certificates, p.options.SAML,
	)
	if err != nil || samlprotocol.ValidateLogoutResponse(ctx.GoContext(), response, bindingSigned,
		samlprotocol.LogoutValidationOptions{
			ExpectedIssuer: material.Issuer, ExpectedDestination: currentSLO,
			RequireSignature: p.options.SAML.WantLogoutResponseSigned,
			Certificates:     material.Certificates, Algorithms: p.options.SAML.Algorithms,
			ClockSkew: p.options.SAML.ClockSkew, Now: p.runtime.Clock,
			MaxMessageSize: p.options.SAML.MaxResponseSize,
		}) != nil {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid LogoutResponse")
	}
	if response.StatusCode != samlprotocol.StatusSuccess {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Logout failed at IdP")
	}
	pendingKey := logoutRequestPrefix + response.InResponseTo
	pendingRow, err := p.runtime.PeekVerification(ctx.GoContext(), pendingKey)
	if err != nil {
		return contract.Response{}, err
	}
	pending, ok := decodePendingLogoutRequest(pendingRow)
	if !ok || pending.ProviderID != providerID || relayState != pending.CallbackURL {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid LogoutResponse")
	}
	consumed, err := p.runtime.ConsumeVerification(ctx.GoContext(), pendingKey)
	if err != nil {
		return contract.Response{}, err
	}
	consumedPending, ok := decodePendingLogoutRequest(consumed)
	if !ok || consumedPending != pending {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid LogoutResponse")
	}
	p.runtime.ExpireSessionCookies(ctx)
	safe := p.safeSAMLRedirect(ctx.Request(), []string{relayState}, currentSLO, appOrigin)
	return redirectResponse(safe), nil
}

func (p *plugin) handleLogoutRequest(
	ctx *engine.Context,
	input sloInput,
	providerID, _ string,
	currentSLO string,
	material samlLogoutMaterial,
	config SAMLConfig,
) (contract.Response, error) {
	request, bindingSigned, relayState, binding, err := parseBoundLogoutRequest(
		ctx.Request(), input, material.Certificates, p.options.SAML,
	)
	if err != nil || samlprotocol.ValidateLogoutRequest(ctx.GoContext(), request, bindingSigned,
		samlprotocol.LogoutValidationOptions{
			ExpectedIssuer: material.Issuer, ExpectedDestination: currentSLO,
			RequireSignature: p.options.SAML.WantLogoutRequestSigned,
			Certificates:     material.Certificates, Algorithms: p.options.SAML.Algorithms,
			ClockSkew: p.options.SAML.ClockSkew, Now: p.runtime.Clock,
			MaxMessageSize: p.options.SAML.MaxResponseSize,
		}) != nil {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid LogoutRequest")
	}
	if err := samlprotocol.ValidateConfigAlgorithms(samlprotocol.ConfigAlgorithms{
		SignatureAlgorithm: config.SignatureAlgorithm, DigestAlgorithm: config.DigestAlgorithm,
	}, p.options.SAML.Algorithms); err != nil {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid SAML configuration")
	}
	replayKey := logoutReplayPrefix + providerID + ":" + request.ID
	ttl := p.options.SAML.LogoutRequestTTL
	if ttl <= 0 {
		ttl = defaultLogoutRequestTTL
	}
	reserved, err := p.runtime.ReserveVerification(
		ctx.GoContext(), replayKey, material.Issuer, p.runtime.Clock().Add(ttl),
	)
	if err != nil {
		return contract.Response{}, err
	}
	if !reserved {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid LogoutRequest")
	}
	rollbackReplay := true
	defer func() {
		if rollbackReplay {
			_ = p.runtime.DeleteVerification(ctx.GoContext(), replayKey)
		}
	}()

	idpEndpoint, ok := samlLogoutEndpoint(material.Services, binding, true)
	if !ok {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid LogoutRequest")
	}
	responseID, err := p.samlLogoutID()
	if err != nil {
		return contract.Response{}, err
	}
	response, err := samlprotocol.NewLogoutResponse(samlprotocol.LogoutResponseOptions{
		ID: responseID, Issuer: serviceProviderEntityID(config), Destination: idpEndpoint,
		InResponseTo: request.ID, IssueInstant: p.runtime.Clock(),
	})
	if err != nil {
		return contract.Response{}, err
	}
	signing, err := resolveSPLogoutSigningMaterial(config, p.options.SAML.MaxMetadataSize)
	if err != nil {
		return contract.Response{}, apiError(http.StatusBadRequest, "BAD_REQUEST", "Invalid SAML configuration")
	}
	result, err := buildBoundLogoutResponse(
		ctx.GoContext(), binding, idpEndpoint, response.XML, relayState, signing, config,
		p.options.SAML.Algorithms,
	)
	if err != nil {
		return contract.Response{}, err
	}

	forwardKey := samlSessionKey(providerID, request.NameID)
	forward, err := p.runtime.PeekVerification(ctx.GoContext(), forwardKey)
	if err != nil {
		return contract.Response{}, err
	}
	stored, valid := decodeSAMLSessionRecord(forward)
	indexMatches := valid && (len(request.SessionIndexes) == 0 || stored.SessionIndex == "" ||
		slices.Contains(request.SessionIndexes, stored.SessionIndex))
	if valid && (stored.ProviderID != providerID || stored.NameID != request.NameID) {
		indexMatches = false
	}
	current, _ := p.runtime.ResolveSession(ctx, singleauth.PluginSessionOptional)
	if valid && indexMatches {
		if err := p.runtime.DeleteSession(ctx.GoContext(), stored.SessionToken); err != nil {
			return contract.Response{}, err
		}
		p.sloMu.Lock()
		cleanupErr := p.deleteSAMLSessionRecords(ctx.GoContext(), forwardKey, stored)
		p.sloMu.Unlock()
		if cleanupErr != nil {
			return contract.Response{}, cleanupErr
		}
		if current != nil && current.Session != nil &&
			(recordStringValue(current.Session, "id") == stored.SessionID ||
				recordStringValue(current.Session, "token") == stored.SessionToken) {
			p.runtime.ExpireSessionCookies(ctx)
		}
	}
	rollbackReplay = false
	return result, nil
}

func parseBoundLogoutRequest(
	request contract.Request,
	input sloInput,
	certificates []*x509.Certificate,
	options SAMLRuntimeOptions,
) (samlprotocol.LogoutRequest, bool, string, string, error) {
	if !input.requestFromBody {
		message, err := samlprotocol.ParseRedirectBinding(
			request.RawQuery(), certificatePublicKeys(certificates), options.Algorithms,
			options.MaxResponseSize,
		)
		if err != nil || message.Parameter != samlprotocol.SAMLRequestParameter {
			return samlprotocol.LogoutRequest{}, false, "", "", fmt.Errorf("invalid SAML Redirect LogoutRequest")
		}
		parsed, err := samlprotocol.ParseLogoutRequest(message.XML, options.MaxResponseSize)
		return parsed, message.Signed, message.RelayState, samlprotocol.HTTPRedirectBinding, err
	}
	xmlData, err := samlprotocol.DecodePOSTMessage(input.SAMLRequest, options.MaxResponseSize)
	if err != nil {
		return samlprotocol.LogoutRequest{}, false, "", "", err
	}
	parsed, err := samlprotocol.ParseLogoutRequest(xmlData, options.MaxResponseSize)
	return parsed, false, input.RelayState, samlprotocol.HTTPPostBinding, err
}

func parseBoundLogoutResponse(
	request contract.Request,
	input sloInput,
	certificates []*x509.Certificate,
	options SAMLRuntimeOptions,
) (samlprotocol.LogoutResponse, bool, string, error) {
	if !input.responseFromBody {
		message, err := samlprotocol.ParseRedirectBinding(
			request.RawQuery(), certificatePublicKeys(certificates), options.Algorithms,
			options.MaxResponseSize,
		)
		if err != nil || message.Parameter != samlprotocol.SAMLResponseParameter {
			return samlprotocol.LogoutResponse{}, false, "", fmt.Errorf("invalid SAML Redirect LogoutResponse")
		}
		parsed, err := samlprotocol.ParseLogoutResponse(message.XML, options.MaxResponseSize)
		return parsed, message.Signed, message.RelayState, err
	}
	xmlData, err := samlprotocol.DecodePOSTMessage(input.SAMLResponse, options.MaxResponseSize)
	if err != nil {
		return samlprotocol.LogoutResponse{}, false, "", err
	}
	parsed, err := samlprotocol.ParseLogoutResponse(xmlData, options.MaxResponseSize)
	return parsed, false, input.RelayState, err
}

func buildBoundLogoutResponse(
	ctx context.Context,
	binding, endpoint string,
	xmlData []byte,
	relayState string,
	signing samlSPLogoutSigningMaterial,
	config SAMLConfig,
	algorithms samlprotocol.AlgorithmValidationOptions,
) (contract.Response, error) {
	if binding == samlprotocol.HTTPRedirectBinding {
		target, err := samlprotocol.BuildRedirectURL(
			ctx, endpoint, samlprotocol.SAMLResponseParameter, xmlData, relayState,
			signing.Signer, config.SignatureAlgorithm,
		)
		if err != nil {
			return contract.Response{}, err
		}
		return redirectResponse(target), nil
	}
	if signing.Signer != nil {
		var err error
		xmlData, err = samlprotocol.SignXMLMessage(xmlData, samlprotocol.XMLSigningOptions{
			Signer: signing.Signer, Certificates: signing.Certificates,
			SignatureAlgorithm: config.SignatureAlgorithm, Algorithms: algorithms,
		})
		if err != nil {
			return contract.Response{}, err
		}
	}
	form, err := samlprotocol.BuildPOSTForm(
		endpoint, samlprotocol.SAMLResponseParameter,
		samlprotocol.EncodePOSTMessage(xmlData), relayState,
	)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.NewResponse(http.StatusOK, contract.NewHeaders(
		contract.HeaderField{Name: "Content-Type", Value: "text/html; charset=utf-8"},
		contract.HeaderField{Name: "Cache-Control", Value: "no-store"},
	), []byte(form)), nil
}

func resolveSAMLIDPLogoutMaterial(config SAMLConfig, maxMetadataSize ...int) (samlLogoutMaterial, error) {
	if config.IDPMetadata != nil && strings.TrimSpace(config.IDPMetadata.Metadata) != "" {
		document, err := samlprotocol.ParseMetadata(
			[]byte(config.IDPMetadata.Metadata), metadataSizeLimit(maxMetadataSize...),
		)
		if err != nil {
			return samlLogoutMaterial{}, err
		}
		entity, err := selectIDPEntity(document, config.IDPMetadata.EntityID)
		if err != nil {
			return samlLogoutMaterial{}, err
		}
		certificates := entity.IDP.SigningCertificates()
		if len(certificates) == 0 {
			return samlLogoutMaterial{}, fmt.Errorf("SAML IdP metadata has no signing certificate")
		}
		return samlLogoutMaterial{
			Issuer: entity.EntityID, Certificates: certificates,
			Services: append([]samlprotocol.Endpoint(nil), entity.IDP.SingleLogoutServices...),
		}, nil
	}
	issuer := strings.TrimSpace(config.Issuer)
	certificateValue := config.Certificate
	var services []samlprotocol.Endpoint
	if config.IDPMetadata != nil {
		if config.IDPMetadata.EntityID != "" {
			issuer = strings.TrimSpace(config.IDPMetadata.EntityID)
		}
		if config.IDPMetadata.Certificate != "" {
			certificateValue = config.IDPMetadata.Certificate
		}
		for _, service := range config.IDPMetadata.SingleLogoutService {
			services = append(services, samlprotocol.Endpoint{
				Binding: service.Binding, Location: service.Location,
				ResponseLocation: service.ResponseLocation,
			})
		}
	}
	if issuer == "" {
		return samlLogoutMaterial{}, fmt.Errorf("SAML IdP issuer is missing")
	}
	certificates, err := samlprotocol.ParseCertificatesPEM([]byte(certificateValue))
	if err != nil {
		return samlLogoutMaterial{}, err
	}
	return samlLogoutMaterial{Issuer: issuer, Certificates: certificates, Services: services}, nil
}

func resolveSPLogoutSigningMaterial(config SAMLConfig, maxMetadataSize ...int) (samlSPLogoutSigningMaterial, error) {
	privateKey, password := config.PrivateKey, ""
	var certificates []*x509.Certificate
	if config.SPMetadata != nil {
		if config.SPMetadata.PrivateKey != "" {
			privateKey, password = config.SPMetadata.PrivateKey, config.SPMetadata.PrivateKeyPass
		}
		if strings.TrimSpace(config.SPMetadata.Metadata) != "" {
			document, err := samlprotocol.ParseMetadata(
				[]byte(config.SPMetadata.Metadata), metadataSizeLimit(maxMetadataSize...),
			)
			if err != nil {
				return samlSPLogoutSigningMaterial{}, err
			}
			entity, err := selectSPEntity(document, config.SPMetadata.EntityID)
			if err != nil {
				return samlSPLogoutSigningMaterial{}, err
			}
			certificates = entity.SP.SigningCertificates()
		}
	}
	if strings.TrimSpace(privateKey) == "" {
		return samlSPLogoutSigningMaterial{Certificates: certificates}, nil
	}
	signer, err := samlprotocol.ParsePrivateKeyPEM([]byte(privateKey), password)
	if err != nil {
		return samlSPLogoutSigningMaterial{}, err
	}
	if len(certificates) != 0 {
		matching := certificates[:0]
		signerKey, marshalErr := x509.MarshalPKIXPublicKey(signer.Public())
		if marshalErr != nil {
			return samlSPLogoutSigningMaterial{}, marshalErr
		}
		for _, certificate := range certificates {
			certificateKey, marshalErr := x509.MarshalPKIXPublicKey(certificate.PublicKey)
			if marshalErr == nil && string(certificateKey) == string(signerKey) {
				matching = append(matching, certificate)
			}
		}
		if len(matching) == 0 {
			return samlSPLogoutSigningMaterial{}, fmt.Errorf("SAML SP private key does not match its signing certificate")
		}
		certificates = matching
	}
	return samlSPLogoutSigningMaterial{Signer: signer, Certificates: certificates}, nil
}

func samlLogoutEndpoint(services []samlprotocol.Endpoint, binding string, response bool) (string, bool) {
	for _, service := range services {
		if service.Binding != binding {
			continue
		}
		location := service.Location
		if response && service.ResponseLocation != "" {
			location = service.ResponseLocation
		}
		if _, err := absoluteHTTPURL(location); err == nil {
			return location, true
		}
	}
	return "", false
}

func certificatePublicKeys(certificates []*x509.Certificate) []crypto.PublicKey {
	result := make([]crypto.PublicKey, 0, len(certificates))
	for _, certificate := range certificates {
		if certificate != nil {
			result = append(result, certificate.PublicKey)
		}
	}
	return result
}

func (p *plugin) sloURLs(request contract.Request, providerID string) (string, string, string, error) {
	baseURL, err := p.runtime.ResolveBaseURL(request)
	if err != nil {
		return "", "", "", fmt.Errorf("sso: resolve base URL: %w", err)
	}
	baseURL = strings.TrimRight(baseURL, "/")
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", "", fmt.Errorf("sso: invalid resolved base URL %q", baseURL)
	}
	current := baseURL + "/sso/saml2/sp/slo/" + url.PathEscape(providerID)
	return baseURL, current, parsed.Scheme + "://" + parsed.Host, nil
}

func (p *plugin) samlLogoutID() (string, error) {
	token, err := p.randomToken(20)
	if err != nil {
		return "", err
	}
	return "_" + token, nil
}

func decodePendingLogoutRequest(record storage.Record) (pendingLogoutRequest, bool) {
	if record == nil {
		return pendingLogoutRequest{}, false
	}
	value := recordStringValue(record, "value")
	var pending pendingLogoutRequest
	if err := json.Unmarshal([]byte(value), &pending); err != nil {
		// Read single-auth's legacy value-only record during rolling upgrades.
		if value == "" {
			return pendingLogoutRequest{}, false
		}
		pending.ProviderID = value
	}
	return pending, pending.ProviderID != ""
}

func decodeSLOInput(request contract.Request) (sloInput, error) {
	query, err := request.Query()
	if err != nil || duplicateSLOValues(query) {
		return sloInput{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters")
	}
	result := sloInput{
		SAMLRequest: query.Get("SAMLRequest"), SAMLResponse: query.Get("SAMLResponse"),
		RelayState: query.Get("RelayState"),
	}
	if request.Method() != http.MethodPost || len(strings.TrimSpace(string(request.Body()))) == 0 {
		return result, nil
	}
	if len(request.Body()) > maxRequestBodyBytes {
		return sloInput{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Request body is too large")
	}
	contentType, _ := request.Headers().Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)
	var body sloInput
	switch {
	case mediaType == "application/json" || mediaType == "" && strings.HasPrefix(strings.TrimSpace(string(request.Body())), "{"):
		decoder := json.NewDecoder(strings.NewReader(string(request.Body())))
		if err := decoder.Decode(&body); err != nil {
			return sloInput{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid JSON body")
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return sloInput{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid JSON body")
		}
	case mediaType == "application/x-www-form-urlencoded" || mediaType == "":
		values, err := url.ParseQuery(string(request.Body()))
		if err != nil || duplicateSLOValues(values) {
			return sloInput{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid SAML form body")
		}
		body = sloInput{
			SAMLRequest: values.Get("SAMLRequest"), SAMLResponse: values.Get("SAMLResponse"),
			RelayState: values.Get("RelayState"),
		}
	default:
		return sloInput{}, apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Unsupported content type")
	}
	if body.SAMLRequest != "" {
		result.SAMLRequest = body.SAMLRequest
	}
	if body.SAMLResponse != "" {
		result.SAMLResponse = body.SAMLResponse
	}
	if body.RelayState != "" {
		result.RelayState = body.RelayState
	}
	result.requestFromBody = body.SAMLRequest != ""
	result.responseFromBody = body.SAMLResponse != ""
	return result, nil
}

func duplicateSLOValues(values url.Values) bool {
	for _, name := range []string{"SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"} {
		if len(values[name]) > 1 {
			return true
		}
	}
	return false
}
