package sso

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	defaultDomainVerificationPrefix = "single-auth-token"
	maxDNSLabelLength               = 63
	domainVerificationTTL           = 7 * 24 * time.Hour
)

func (p *plugin) domainVerificationIdentifier(providerID string) string {
	prefix := strings.TrimSpace(p.options.DomainVerification.TokenPrefix)
	if prefix == "" {
		prefix = defaultDomainVerificationPrefix
	}
	return "_" + prefix + "-" + providerID
}

func (p *plugin) requestDomainVerification(ctx *engine.Context) (contract.Response, error) {
	providerID, err := providerIDFromBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	provider, err := p.checkProviderAccess(ctx, providerID)
	if err != nil {
		return contract.Response{}, err
	}
	if recordBoolValue(provider, "domainVerified") {
		return contract.Response{}, apiError(http.StatusConflict, "DOMAIN_VERIFIED", "Domain has already been verified")
	}
	identifier := p.domainVerificationIdentifier(providerID)
	active, err := p.runtime.PeekVerification(ctx.GoContext(), identifier)
	if err != nil {
		return contract.Response{}, err
	}
	if active != nil && verificationExpiresAfter(active, p.runtime.Clock().UTC()) {
		return contract.JSONResponse(http.StatusCreated, map[string]any{
			"domainVerificationToken": recordStringValue(active, "value"),
		})
	}
	token, err := p.randomToken(18)
	if err != nil {
		return contract.Response{}, fmt.Errorf("sso: generate domain verification token: %w", err)
	}
	if _, err := p.runtime.CreateVerification(
		ctx.GoContext(), identifier, token, p.runtime.Clock().UTC().Add(domainVerificationTTL),
	); err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(http.StatusCreated, map[string]any{"domainVerificationToken": token})
}

func (p *plugin) verifyDomain(ctx *engine.Context) (contract.Response, error) {
	providerID, err := providerIDFromBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	provider, err := p.checkProviderAccess(ctx, providerID)
	if err != nil {
		return contract.Response{}, err
	}
	if recordBoolValue(provider, "domainVerified") {
		return contract.Response{}, apiError(http.StatusConflict, "DOMAIN_VERIFIED", "Domain has already been verified")
	}
	identifier := p.domainVerificationIdentifier(providerID)
	if len(identifier) > maxDNSLabelLength {
		return contract.Response{}, apiError(
			http.StatusBadRequest, "IDENTIFIER_TOO_LONG",
			fmt.Sprintf("Verification identifier exceeds the DNS label limit of %d characters", maxDNSLabelLength),
		)
	}
	active, err := p.runtime.PeekVerification(ctx.GoContext(), identifier)
	if err != nil {
		return contract.Response{}, err
	}
	if active == nil || !verificationExpiresAfter(active, p.runtime.Clock().UTC()) {
		return contract.Response{}, apiError(http.StatusNotFound, "NO_PENDING_VERIFICATION", "No pending domain verification exists")
	}
	domains, valid := parseProviderDomains(recordStringValue(provider, "domain"))
	if !valid {
		return contract.Response{}, apiError(http.StatusBadRequest, "INVALID_DOMAIN", "Invalid domain")
	}
	lookup := p.options.DomainVerification.LookupTXT
	if lookup == nil {
		lookup = func(ctx context.Context, name string) ([]string, error) {
			return net.DefaultResolver.LookupTXT(ctx, name)
		}
	}
	verificationValue := recordStringValue(active, "value")
	wantedRecord := identifier + "=" + verificationValue
	for _, domain := range domains {
		records, lookupErr := lookup(ctx.GoContext(), identifier+"."+domain)
		if lookupErr != nil || !containsDomainVerificationRecord(records, wantedRecord, verificationValue) {
			return contract.Response{}, apiError(
				http.StatusBadGateway, "DOMAIN_VERIFICATION_FAILED",
				fmt.Sprintf("Unable to verify domain ownership for %s. Try again later", domain),
			)
		}
	}
	adapter := p.adapter(ctx)
	if adapter == nil {
		return contract.Response{}, fmt.Errorf("sso: runtime adapter is required")
	}
	if _, err := adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "ssoProvider", Where: []storage.Where{{Field: "providerId", Value: providerID}},
		Update: storage.Record{"domainVerified": true},
	}); err != nil {
		return contract.Response{}, err
	}
	return contract.NewResponse(http.StatusNoContent, contract.Headers{}, nil), nil
}

func providerIDFromBody(ctx *engine.Context) (string, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return "", err
	}
	providerID, err := optionalString(body, "providerId")
	if err != nil || strings.TrimSpace(providerID) == "" {
		return "", apiError(http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
	}
	return providerID, nil
}

func containsDomainVerificationRecord(records []string, wanted, value string) bool {
	for _, record := range records {
		record = strings.TrimSpace(record)
		if record == wanted || record == value {
			return true
		}
	}
	return false
}

func verificationExpiresAfter(record storage.Record, now time.Time) bool {
	switch value := record["expiresAt"].(type) {
	case time.Time:
		return value.After(now)
	case *time.Time:
		return value != nil && value.After(now)
	case int64:
		return time.UnixMilli(value).After(now)
	case int:
		return time.UnixMilli(int64(value)).After(now)
	case float64:
		return time.UnixMilli(int64(value)).After(now)
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, value)
		return err == nil && parsed.After(now)
	default:
		return false
	}
}
