package sso

import (
	"context"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

func TestAssignOrganizationFromOIDCProviderIsIdempotentAndPassesContext(t *testing.T) {
	organizationSchema, err := organization.Schema(organization.Options{})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := storage.CoreSchema().Merge(providerSchema(false))
	if err != nil {
		t.Fatal(err)
	}
	schema, err = schema.Merge(organizationSchema)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 10, 6, 0, 0, 0, time.UTC)
	adapter, err := memory.New(
		memory.WithSchema(schema),
		memory.WithClock(func() time.Time { return now }),
		memory.WithDatabase(memory.Database{
			"user": {{
				"id": "oidc-user", "name": "OIDC User", "email": "user@corp.example",
				"emailVerified": true, "createdAt": now, "updatedAt": now,
			}},
			"organization": {{
				"id": "corp-org", "name": "Corp", "slug": "corp", "createdAt": now,
			}},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	tokens := &oauth2.Tokens{AccessToken: "access", Scopes: []string{"openid"}}
	roleCalls := 0
	options := AssignOrganizationFromProviderOptions{
		User: OrganizationAssignmentUser{
			ID: "oidc-user", Email: "user@corp.example", Fields: storage.Record{"name": "OIDC User"},
		},
		UserInfo: storage.Record{"department": "security"},
		Provider: storage.Record{
			"providerId": "enterprise", "organizationId": "corp-org", "domain": "corp.example",
		},
		Tokens: tokens,
		Provisioning: OrganizationProvisioningOptions{GetRole: func(_ context.Context, input OrganizationRoleInput) (string, error) {
			roleCalls++
			if input.User.ID != "oidc-user" || input.UserInfo["department"] != "security" ||
				input.Provider["providerId"] != "enterprise" || input.Token == nil || input.Token.AccessToken != "access" {
				t.Fatalf("role input=%#v", input)
			}
			return "admin", nil
		}},
	}
	runtime := OrganizationAssignmentContext{
		Adapter: adapter, HasPlugin: func(id string) bool { return id == "organization" },
		Clock: func() time.Time { return now },
	}
	if err := AssignOrganizationFromProvider(t.Context(), runtime, options); err != nil {
		t.Fatal(err)
	}
	if err := AssignOrganizationFromProvider(t.Context(), runtime, options); err != nil {
		t.Fatal(err)
	}
	members, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "member"})
	if err != nil {
		t.Fatal(err)
	}
	if roleCalls != 1 || len(members) != 1 || members[0]["organizationId"] != "corp-org" || members[0]["role"] != "admin" {
		t.Fatalf("roleCalls=%d members=%#v", roleCalls, members)
	}
}
