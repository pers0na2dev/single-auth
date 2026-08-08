package sso

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/storage"
)

// OrganizationAssignmentUser contains the single-auth user fields required by
// domain-based organization provisioning. Fields preserves caller-defined
// user fields for custom role selection.
type OrganizationAssignmentUser struct {
	ID     string
	Email  string
	Fields storage.Record
}

// OrganizationRoleInput is passed to a custom domain-provisioning role
// resolver. UserInfo is empty for domain assignment, matching single-auth.
type OrganizationRoleInput struct {
	User     OrganizationAssignmentUser
	UserInfo storage.Record
	Provider storage.Record
	Token    *oauth2.Tokens
}

// OrganizationProvisioningOptions controls automatic membership creation.
type OrganizationProvisioningOptions struct {
	Disabled    bool
	DefaultRole string
	GetRole     func(context.Context, OrganizationRoleInput) (string, error)
}

// AssignOrganizationByDomainOptions mirrors single-auth's domain assignment
// options for non-SSO sign-in methods.
type AssignOrganizationByDomainOptions struct {
	User                      OrganizationAssignmentUser
	Provisioning              OrganizationProvisioningOptions
	DomainVerificationEnabled bool
}

// AssignOrganizationFromProviderOptions provisions membership from the SSO
// provider that has already completed an OIDC or SAML identity flow.
type AssignOrganizationFromProviderOptions struct {
	User         OrganizationAssignmentUser
	UserInfo     storage.Record
	Provider     storage.Record
	Tokens       *oauth2.Tokens
	Provisioning OrganizationProvisioningOptions
}

// OrganizationAssignmentContext contains the endpoint-context facilities used
// by AssignOrganizationByDomain.
type OrganizationAssignmentContext struct {
	Adapter   storage.TransactionAdapter
	HasPlugin func(string) bool
	Clock     func() time.Time
}

func (p *plugin) assignOrganizationByDomainAfterCallback(
	ctx *engine.Context,
	_ contract.Response,
) (*contract.Response, error) {
	if p.runtime.NewSession == nil {
		return nil, nil
	}
	newSession := p.runtime.NewSession(ctx)
	if newSession == nil || newSession.User == nil {
		return nil, nil
	}
	return nil, AssignOrganizationByDomain(ctx.GoContext(), OrganizationAssignmentContext{
		Adapter: p.adapter(ctx), HasPlugin: p.runtime.HasPlugin, Clock: p.runtime.Clock,
	}, AssignOrganizationByDomainOptions{
		User: OrganizationAssignmentUser{
			ID:     recordStringValue(newSession.User, "id"),
			Email:  recordStringValue(newSession.User, "email"),
			Fields: cloneRecord(newSession.User),
		},
		Provisioning:              p.options.OrganizationProvisioning,
		DomainVerificationEnabled: p.domainVerificationEnabled,
	})
}

// AssignOrganizationFromProvider creates the provider-linked organization
// membership once. It is transport-neutral and deliberately idempotent.
func AssignOrganizationFromProvider(
	ctx context.Context,
	runtime OrganizationAssignmentContext,
	options AssignOrganizationFromProviderOptions,
) error {
	if options.Provisioning.Disabled || runtime.HasPlugin == nil ||
		!runtime.HasPlugin("organization") {
		return nil
	}
	if runtime.Adapter == nil {
		return fmt.Errorf("sso: organization assignment adapter is required")
	}
	organizationID, _ := options.Provider["organizationId"].(string)
	if organizationID == "" || options.User.ID == "" {
		return nil
	}
	existing, err := runtime.Adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "organizationId", Value: organizationID},
			{Field: "userId", Value: options.User.ID},
		},
	})
	if err != nil || existing != nil {
		return err
	}
	role := options.Provisioning.DefaultRole
	if options.Provisioning.GetRole != nil {
		role, err = options.Provisioning.GetRole(ctx, OrganizationRoleInput{
			User: options.User, UserInfo: cloneRecord(options.UserInfo),
			Provider: cloneRecord(options.Provider), Token: options.Tokens,
		})
		if err != nil {
			return err
		}
	}
	if role == "" {
		role = "member"
	}
	clock := runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	_, err = runtime.Adapter.Create(ctx, storage.CreateParams{
		Model: "member", Data: storage.Record{
			"organizationId": organizationID, "userId": options.User.ID,
			"role": role, "createdAt": clock(),
		},
	})
	return err
}

// AssignOrganizationByDomain assigns a user to the organization attached to
// the first matching SSO provider, with the same verification and membership
// guards as single-auth 1.6.26.
func AssignOrganizationByDomain(
	ctx context.Context,
	runtime OrganizationAssignmentContext,
	options AssignOrganizationByDomainOptions,
) error {
	if options.Provisioning.Disabled {
		return nil
	}
	if runtime.HasPlugin == nil || !runtime.HasPlugin("organization") {
		return nil
	}
	if runtime.Adapter == nil {
		return fmt.Errorf("sso: organization assignment adapter is required")
	}

	emailParts := strings.Split(options.User.Email, "@")
	if len(emailParts) < 2 || emailParts[1] == "" {
		return nil
	}
	domain := emailParts[1]
	where := []storage.Where{{Field: "domain", Value: domain}}
	if options.DomainVerificationEnabled {
		where = append(where, storage.Where{Field: "domainVerified", Value: true})
	}
	provider, err := runtime.Adapter.FindOne(ctx, storage.FindOneParams{
		Model: "ssoProvider",
		Where: where,
	})
	if err != nil {
		return err
	}
	if provider == nil {
		providerWhere := make([]storage.Where, 0, 1)
		if options.DomainVerificationEnabled {
			providerWhere = append(providerWhere, storage.Where{Field: "domainVerified", Value: true})
		}
		providers, findErr := runtime.Adapter.FindMany(ctx, storage.FindManyParams{
			Model: "ssoProvider",
			Where: providerWhere,
		})
		if findErr != nil {
			return findErr
		}
		for _, candidate := range providers {
			providerDomain, _ := candidate["domain"].(string)
			if domainMatches(domain, providerDomain) {
				provider = candidate
				break
			}
		}
	}
	if provider == nil {
		return nil
	}
	organizationID, _ := provider["organizationId"].(string)
	if organizationID == "" {
		return nil
	}

	member, err := runtime.Adapter.FindOne(ctx, storage.FindOneParams{
		Model: "member",
		Where: []storage.Where{
			{Field: "organizationId", Value: organizationID},
			{Field: "userId", Value: options.User.ID},
		},
	})
	if err != nil {
		return err
	}
	if member != nil {
		return nil
	}

	role := options.Provisioning.DefaultRole
	if options.Provisioning.GetRole != nil {
		role, err = options.Provisioning.GetRole(ctx, OrganizationRoleInput{
			User: options.User, UserInfo: storage.Record{}, Provider: provider,
		})
		if err != nil {
			return err
		}
	} else if role == "" {
		role = "member"
	}
	clock := runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	_, err = runtime.Adapter.Create(ctx, storage.CreateParams{
		Model: "member",
		Data: storage.Record{
			"organizationId": organizationID,
			"userId":         options.User.ID,
			"role":           role,
			"createdAt":      clock(),
		},
	})
	return err
}
