package sso

import (
	"reflect"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

type ssoOrgAssignmentValue struct {
	MemberCount     int
	OrganizationIDs []string
	Roles           []string
}

type ssoOrgAssignmentAction func(*testing.T) (*ssoOrgAssignmentValue, error)

type ssoOrgAssignmentScenario struct {
	Providers                 []storage.Record
	Organizations             []storage.Record
	Members                   []storage.Record
	Email                     string
	DomainVerificationEnabled bool
}

func ssoOrgAssignmentProvider() storage.Record {
	return storage.Record{
		"id": "provider-1", "providerId": "test-provider",
		"issuer": "https://idp.example.com", "domain": "example.com",
		"domainVerified": false, "organizationId": "org-1", "userId": "user-1",
	}
}

func ssoOrgAssignmentOrganization(id, name, slug string) storage.Record {
	return storage.Record{
		"id": id, "name": name, "slug": slug,
		"createdAt": time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC),
	}
}

func runSSOOrgAssignmentScenario(
	t *testing.T,
	scenario ssoOrgAssignmentScenario,
) (*ssoOrgAssignmentValue, error) {
	t.Helper()
	organizationSchema, err := organization.Schema(organization.Options{})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := storage.CoreSchema().Merge(providerSchema(true))
	if err != nil {
		t.Fatal(err)
	}
	schema, err = schema.Merge(organizationSchema)
	if err != nil {
		t.Fatal(err)
	}
	fixedNow := time.Date(2026, time.August, 9, 12, 34, 56, 0, time.UTC)
	database := memory.Database{
		"user": {
			{
				"id": "user-1", "email": scenario.Email, "name": "Alice",
				"emailVerified": true, "createdAt": fixedNow, "updatedAt": fixedNow,
			},
		},
		"ssoProvider":  scenario.Providers,
		"organization": scenario.Organizations,
		"member":       scenario.Members,
	}
	adapter, err := memory.New(
		memory.WithSchema(schema),
		memory.WithDatabase(database),
		memory.WithClock(func() time.Time { return fixedNow }),
		memory.WithIDGenerator(func(model string) (any, error) {
			return "generated-" + model, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	err = AssignOrganizationByDomain(t.Context(), OrganizationAssignmentContext{
		Adapter: adapter,
		HasPlugin: func(id string) bool {
			return id == "organization"
		},
		Clock: func() time.Time { return fixedNow },
	}, AssignOrganizationByDomainOptions{
		User: OrganizationAssignmentUser{
			ID: "user-1", Email: scenario.Email,
			Fields: storage.Record{"name": "Alice", "emailVerified": true},
		},
		DomainVerificationEnabled: scenario.DomainVerificationEnabled,
	})
	if err != nil {
		return nil, err
	}
	members, err := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "member", Where: []storage.Where{{Field: "userId", Value: "user-1"}},
	})
	if err != nil {
		return nil, err
	}
	value := &ssoOrgAssignmentValue{
		MemberCount: len(members), OrganizationIDs: make([]string, 0, len(members)),
		Roles: make([]string, 0, len(members)),
	}
	for _, member := range members {
		organizationID, _ := member["organizationId"].(string)
		role, _ := member["role"].(string)
		value.OrganizationIDs = append(value.OrganizationIDs, organizationID)
		value.Roles = append(value.Roles, role)
	}
	return value, nil
}

func ssoOrgAssignmentCases() map[string]ssoOrgAssignmentAction {
	verified := func() storage.Record {
		provider := ssoOrgAssignmentProvider()
		provider["domainVerified"] = true
		return provider
	}
	org := func() []storage.Record {
		return []storage.Record{ssoOrgAssignmentOrganization("org-1", "Test Org", "test-org")}
	}
	return map[string]ssoOrgAssignmentAction{
		"should NOT assign user to org when provider domain is unverified": func(t *testing.T) (*ssoOrgAssignmentValue, error) {
			return runSSOOrgAssignmentScenario(t, ssoOrgAssignmentScenario{
				Providers: []storage.Record{ssoOrgAssignmentProvider()}, Organizations: org(),
				Email: "alice@example.com", DomainVerificationEnabled: true,
			})
		},
		"should assign user to org when provider domain is verified": func(t *testing.T) (*ssoOrgAssignmentValue, error) {
			return runSSOOrgAssignmentScenario(t, ssoOrgAssignmentScenario{
				Providers: []storage.Record{verified()}, Organizations: org(),
				Email: "alice@example.com", DomainVerificationEnabled: true,
			})
		},
		"should assign user when a verified provider's normalized domain set includes the email domain": func(t *testing.T) (*ssoOrgAssignmentValue, error) {
			provider := verified()
			provider["domain"] = "https://attacker.com/path,victim.com"
			return runSSOOrgAssignmentScenario(t, ssoOrgAssignmentScenario{
				Providers: []storage.Record{provider}, Organizations: org(),
				Email: "alice@victim.com", DomainVerificationEnabled: true,
			})
		},
		"should NOT assign user when the email domain is malformed": func(t *testing.T) (*ssoOrgAssignmentValue, error) {
			provider := verified()
			provider["domain"] = "victim.com"
			return runSSOOrgAssignmentScenario(t, ssoOrgAssignmentScenario{
				Providers: []storage.Record{provider}, Organizations: org(),
				Email: "alice@https://victim.com/path", DomainVerificationEnabled: true,
			})
		},
		"should NOT assign user when email domain does not match any provider": func(t *testing.T) (*ssoOrgAssignmentValue, error) {
			return runSSOOrgAssignmentScenario(t, ssoOrgAssignmentScenario{
				Providers: []storage.Record{verified()}, Organizations: org(),
				Email: "alice@other-domain.com", DomainVerificationEnabled: true,
			})
		},
		"should NOT assign user when provider has no organizationId": func(t *testing.T) (*ssoOrgAssignmentValue, error) {
			provider := verified()
			provider["organizationId"] = nil
			return runSSOOrgAssignmentScenario(t, ssoOrgAssignmentScenario{
				Providers: []storage.Record{provider}, Email: "alice@example.com",
				DomainVerificationEnabled: true,
			})
		},
		"should NOT assign user when provider has no domainVerified field (verification enabled)": func(t *testing.T) (*ssoOrgAssignmentValue, error) {
			provider := verified()
			delete(provider, "domainVerified")
			return runSSOOrgAssignmentScenario(t, ssoOrgAssignmentScenario{
				Providers: []storage.Record{provider}, Organizations: org(),
				Email: "alice@example.com", DomainVerificationEnabled: true,
			})
		},
		"should assign user when verification is disabled (no domainVerified check)": func(t *testing.T) (*ssoOrgAssignmentValue, error) {
			return runSSOOrgAssignmentScenario(t, ssoOrgAssignmentScenario{
				Providers: []storage.Record{ssoOrgAssignmentProvider()}, Organizations: org(),
				Email: "alice@example.com", DomainVerificationEnabled: false,
			})
		},
		"should NOT assign user when already a member of the org": func(t *testing.T) (*ssoOrgAssignmentValue, error) {
			return runSSOOrgAssignmentScenario(t, ssoOrgAssignmentScenario{
				Providers: []storage.Record{verified()}, Organizations: org(),
				Members: []storage.Record{{
					"id": "member-1", "organizationId": "org-1", "userId": "user-1",
					"role": "admin", "createdAt": time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC),
				}},
				Email: "alice@example.com", DomainVerificationEnabled: true,
			})
		},
		"should only find verified provider when multiple providers claim same domain": func(t *testing.T) (*ssoOrgAssignmentValue, error) {
			attacker := ssoOrgAssignmentProvider()
			attacker["id"] = "attacker-provider"
			attacker["providerId"] = "attacker-provider"
			attacker["issuer"] = "https://attacker.com"
			attacker["organizationId"] = "attacker-org"
			legit := verified()
			legit["id"] = "legit-provider"
			legit["providerId"] = "legit-provider"
			legit["organizationId"] = "legit-org"
			return runSSOOrgAssignmentScenario(t, ssoOrgAssignmentScenario{
				Providers: []storage.Record{attacker, legit},
				Organizations: []storage.Record{
					ssoOrgAssignmentOrganization("legit-org", "Legit Org", "legit-org"),
					ssoOrgAssignmentOrganization("attacker-org", "Attacker Org", "attacker-org"),
				},
				Email: "alice@example.com", DomainVerificationEnabled: true,
			})
		},
	}
}

func TestSSOOrganizationAssignmentBehavior(t *testing.T) {
	cases := ssoOrgAssignmentCases()
	if len(cases) != len(ssoOrgAssignmentExpectedCases) {
		t.Fatalf("SSO organization-assignment cases=%d expectations=%d", len(cases), len(ssoOrgAssignmentExpectedCases))
	}
	for _, testCase := range ssoOrgAssignmentExpectedCases {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			action, exists := cases[testCase.Name]
			if !exists {
				t.Fatalf("missing SSO organization-assignment case %q", testCase.Name)
			}
			delete(cases, testCase.Name)
			value, err := action(t)
			if testCase.WantError == "" {
				if err != nil {
					t.Fatalf("organization assignment failed: %v", err)
				}
			} else if err == nil || err.Error() != testCase.WantError {
				t.Fatalf("organization assignment error=%v want=%q", err, testCase.WantError)
			}
			if !reflect.DeepEqual(value, testCase.Want) {
				t.Fatalf("SSO organization-assignment value mismatch\nactual: %#v\nwant:   %#v", value, testCase.Want)
			}
		})
	}
	if len(cases) != 0 {
		t.Fatalf("SSO organization-assignment cases without expectations: %#v", cases)
	}
}
