package sso

type ssoOrgAssignmentExpectedCase struct {
	Name      string
	Want      *ssoOrgAssignmentValue
	WantError string
}

var ssoOrgAssignmentExpectedCases = []ssoOrgAssignmentExpectedCase{
	{
		Name: "should NOT assign user to org when provider domain is unverified",
		Want: &ssoOrgAssignmentValue{MemberCount: 0, OrganizationIDs: []string{}, Roles: []string{}},
	},
	{
		Name: "should NOT assign user when already a member of the org",
		Want: &ssoOrgAssignmentValue{MemberCount: 1, OrganizationIDs: []string{"org-1"}, Roles: []string{"admin"}},
	},
	{
		Name: "should NOT assign user when email domain does not match any provider",
		Want: &ssoOrgAssignmentValue{MemberCount: 0, OrganizationIDs: []string{}, Roles: []string{}},
	},
	{
		Name: "should NOT assign user when provider has no domainVerified field (verification enabled)",
		Want: &ssoOrgAssignmentValue{MemberCount: 0, OrganizationIDs: []string{}, Roles: []string{}},
	},
	{
		Name: "should NOT assign user when provider has no organizationId",
		Want: &ssoOrgAssignmentValue{MemberCount: 0, OrganizationIDs: []string{}, Roles: []string{}},
	},
	{
		Name: "should NOT assign user when the email domain is malformed",
		Want: &ssoOrgAssignmentValue{MemberCount: 0, OrganizationIDs: []string{}, Roles: []string{}},
	},
	{
		Name: "should assign user to org when provider domain is verified",
		Want: &ssoOrgAssignmentValue{MemberCount: 1, OrganizationIDs: []string{"org-1"}, Roles: []string{"member"}},
	},
	{
		Name: "should assign user when a verified provider's normalized domain set includes the email domain",
		Want: &ssoOrgAssignmentValue{MemberCount: 1, OrganizationIDs: []string{"org-1"}, Roles: []string{"member"}},
	},
	{
		Name: "should assign user when verification is disabled (no domainVerified check)",
		Want: &ssoOrgAssignmentValue{MemberCount: 1, OrganizationIDs: []string{"org-1"}, Roles: []string{"member"}},
	},
	{
		Name: "should only find verified provider when multiple providers claim same domain",
		Want: &ssoOrgAssignmentValue{MemberCount: 1, OrganizationIDs: []string{"legit-org"}, Roles: []string{"member"}},
	},
}
