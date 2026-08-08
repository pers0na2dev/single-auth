package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/internal/conformancetest"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/plugins/admin"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/plugins/sso"
	"github.com/pers0na2dev/single-auth/storage"
)

const scimUsersPaddedDefaultBearerToken = "dGhlLXNjaW0tdG9rZW46dGhlLXNjaW0tcHJvdmlkZXI="

type scimUsersCase func(*testing.T, string)

type scimUsersScenario struct {
	Suite string
	Name  string
	Run   scimUsersCase
}

type scimUsersSetup struct {
	SCIM          Options
	Organization  organization.Options
	DatabaseHooks singleauth.DatabaseHooks
	Admin         bool
	Teams         bool
	Secondary     *scimUsersSecondaryStore
}

type scimUsersHarness struct {
	auth      *singleauth.Auth
	adapter   storage.Adapter
	clock     time.Time
	roundTrip scimManagementRoundTrip
}

type scimUsersSecondaryStore struct {
	mu     sync.Mutex
	values map[string]string
}

func newSCIMUsersSecondaryStore() *scimUsersSecondaryStore {
	return &scimUsersSecondaryStore{values: map[string]string{}}
}

func (store *scimUsersSecondaryStore) Get(_ context.Context, key string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.values[key], nil
}

func (store *scimUsersSecondaryStore) Set(_ context.Context, key, value string, _ int64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.values[key] = value
	return nil
}

func (store *scimUsersSecondaryStore) Delete(_ context.Context, key string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.values, key)
	return nil
}

func (store *scimUsersSecondaryStore) Has(key string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, exists := store.values[key]
	return exists
}

func TestSCIMUsersBehaviorAcrossTransports(t *testing.T) {
	scenarios := scimUsersScenarios()
	if len(scenarios) != 29 {
		t.Fatalf("SCIM users scenario count=%d, want 29", len(scenarios))
	}
	seen := make(map[string]struct{}, len(scenarios))
	for _, scenario := range scenarios {
		scenario := scenario
		key := scenario.Suite + "::" + scenario.Name
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate SCIM users scenario %q", key)
		}
		seen[key] = struct{}{}
		t.Run(key, func(t *testing.T) {
			for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
				transport := transport
				t.Run(transport, func(t *testing.T) {
					scenario.Run(t, transport)
					conformancetest.Log(t, key, conformancetest.Dimension{
						Transport: transport, StorageBackend: "memory",
					})
				})
			}
		})
	}
}

func TestSCIMDefaultProviderBearerWireForms(t *testing.T) {
	generated := EncodeBearerToken("the-scim-token", "the-scim-provider", "")
	if generated == scimUsersPaddedDefaultBearerToken || strings.HasSuffix(generated, "=") {
		t.Fatalf("generated bearer token=%q must remain the distinct unpadded wire form", generated)
	}
	forms := map[string]string{
		"padded":        scimUsersPaddedDefaultBearerToken,
		"generated-raw": generated,
	}
	for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			for name, token := range forms {
				name, token := name, token
				t.Run(name, func(t *testing.T) {
					h := newSCIMUsersHarness(t, transport, scimUsersSetup{SCIM: Options{DefaultSCIM: []Provider{{
						ProviderID: "the-scim-provider", SCIMToken: "the-scim-token",
					}}}})
					status, body := h.listUsers(t, token, "")
					requireSCIMUsersList(t, status, body, nil)
				})
			}
		})
	}
}

type scimUsersOrganizationDeleteState struct {
	Token        string
	UserID       string
	Member       storage.Record
	User         storage.Record
	Organization storage.Record
	Account      storage.Record
	TeamMember   storage.Record
}

func seedSCIMUsersOrganizationDelete(
	t *testing.T,
	h scimUsersHarness,
	organizationID, providerID string,
) scimUsersOrganizationDeleteState {
	t.Helper()
	actor := h.signUp(t, "organization-delete-owner")
	h.seedOrganization(t, organizationID, actor)
	token := h.generateToken(t, actor, providerID, organizationID)
	created := h.createUser(t, token, map[string]any{
		"userName": "organization-delete-user",
		"emails":   []map[string]any{{"value": "organization-delete-user@scim.test"}},
	})
	userID := created["id"].(string)
	if _, err := h.adapter.Create(t.Context(), storage.CreateParams{
		Model: "team", ForceAllowID: true,
		Data: storage.Record{
			"id": "organization-delete-team", "name": "organization delete team",
			"organizationId": organizationID, "createdAt": h.clock,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapter.Create(t.Context(), storage.CreateParams{Model: "teamMember", Data: storage.Record{
		"teamId": "organization-delete-team", "userId": userID, "createdAt": h.clock,
	}}); err != nil {
		t.Fatal(err)
	}
	state := scimUsersOrganizationDeleteState{Token: token, UserID: userID}
	state.Member = findSCIMUsersRecord(t, h.adapter, "member", []storage.Where{
		{Field: "organizationId", Value: organizationID}, {Field: "userId", Value: userID},
	})
	state.User = findSCIMUsersRecord(t, h.adapter, "user", []storage.Where{{Field: "id", Value: userID}})
	state.Organization = findSCIMUsersRecord(t, h.adapter, "organization", []storage.Where{{Field: "id", Value: organizationID}})
	state.Account = findSCIMUsersRecord(t, h.adapter, "account", []storage.Where{
		{Field: "providerId", Value: providerID}, {Field: "userId", Value: userID},
	})
	state.TeamMember = findSCIMUsersRecord(t, h.adapter, "teamMember", []storage.Where{
		{Field: "teamId", Value: "organization-delete-team"}, {Field: "userId", Value: userID},
	})
	for label, record := range map[string]storage.Record{
		"member": state.Member, "user": state.User, "organization": state.Organization,
		"account": state.Account, "teamMember": state.TeamMember,
	} {
		if record == nil {
			t.Fatalf("missing %s fixture", label)
		}
	}
	return state
}

func scimUsersRecordExists(
	ctx context.Context,
	adapter storage.Adapter,
	model string,
	where []storage.Where,
) (bool, error) {
	record, err := adapter.FindOne(ctx, storage.FindOneParams{Model: model, Where: where})
	return record != nil, err
}

func scimUsersOrganizationDeleteRecordsPresent(
	ctx context.Context,
	adapter storage.Adapter,
	state scimUsersOrganizationDeleteState,
) (bool, error) {
	checks := []struct {
		model string
		where []storage.Where
	}{
		{"member", []storage.Where{{Field: "id", Value: recordString(state.Member, "id")}}},
		{"teamMember", []storage.Where{{Field: "id", Value: recordString(state.TeamMember, "id")}}},
		{"account", []storage.Where{{Field: "id", Value: recordString(state.Account, "id")}}},
	}
	for _, check := range checks {
		exists, err := scimUsersRecordExists(ctx, adapter, check.model, check.where)
		if err != nil || !exists {
			return false, err
		}
	}
	return true, nil
}

func scimUsersOrganizationDeleteRecordsAbsent(
	ctx context.Context,
	adapter storage.Adapter,
	state scimUsersOrganizationDeleteState,
) (bool, error) {
	checks := []struct {
		model string
		where []storage.Where
	}{
		{"member", []storage.Where{{Field: "id", Value: recordString(state.Member, "id")}}},
		{"teamMember", []storage.Where{{Field: "id", Value: recordString(state.TeamMember, "id")}}},
		{"account", []storage.Where{{Field: "id", Value: recordString(state.Account, "id")}}},
	}
	for _, check := range checks {
		exists, err := scimUsersRecordExists(ctx, adapter, check.model, check.where)
		if err != nil || exists {
			return false, err
		}
	}
	return true, nil
}

func TestSCIMOrganizationDeleteRemoveMemberHookLifecycle(t *testing.T) {
	for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			var h scimUsersHarness
			var state scimUsersOrganizationDeleteState
			var before, after organization.RemoveMemberHookData
			calls := []string{}
			hooks := organization.OrganizationHooks{
				BeforeRemoveMember: func(ctx context.Context, data organization.RemoveMemberHookData) error {
					calls = append(calls, "before")
					before = organization.RemoveMemberHookData{
						Member: cloneSCIMRecord(data.Member), User: cloneSCIMRecord(data.User),
						Organization: cloneSCIMRecord(data.Organization),
					}
					present, err := scimUsersOrganizationDeleteRecordsPresent(ctx, h.adapter, state)
					if err != nil || !present {
						return fmt.Errorf("beforeRemoveMember ran after storage deletion: present=%v err=%v", present, err)
					}
					data.Member["sharedHookPayload"] = true
					return nil
				},
				AfterRemoveMember: func(ctx context.Context, data organization.RemoveMemberHookData) error {
					calls = append(calls, "after")
					if data.Member["sharedHookPayload"] != true {
						return errors.New("afterRemoveMember did not receive the shared deletion payload")
					}
					after = organization.RemoveMemberHookData{
						Member: cloneSCIMRecord(data.Member), User: cloneSCIMRecord(data.User),
						Organization: cloneSCIMRecord(data.Organization),
					}
					absent, err := scimUsersOrganizationDeleteRecordsAbsent(ctx, h.adapter, state)
					if err != nil || !absent {
						return fmt.Errorf("afterRemoveMember ran before transaction commit: absent=%v err=%v", absent, err)
					}
					return nil
				},
			}
			h = newSCIMUsersHarness(t, transport, scimUsersSetup{Organization: organization.Options{
				Teams: organization.TeamsOptions{Enabled: true}, Hooks: hooks,
			}})
			state = seedSCIMUsersOrganizationDelete(t, h, "hook-lifecycle-org", "hook-lifecycle-provider")
			status, body := h.deleteUser(t, state.Token, state.UserID)
			if status != http.StatusNoContent || len(body) != 0 {
				t.Fatalf("hook lifecycle delete status/body=%d/%#v", status, body)
			}
			if !reflect.DeepEqual(calls, []string{"before", "after"}) {
				t.Fatalf("remove member hook order=%#v", calls)
			}
			if !reflect.DeepEqual(before.Member, state.Member) || !reflect.DeepEqual(before.User, state.User) ||
				!reflect.DeepEqual(before.Organization, state.Organization) {
				t.Fatalf("beforeRemoveMember payload=%#v, want member=%#v user=%#v org=%#v", before, state.Member, state.User, state.Organization)
			}
			delete(after.Member, "sharedHookPayload")
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("afterRemoveMember payload=%#v, want shared payload %#v", after, before)
			}
		})
	}
}

func TestSCIMOrganizationDeleteTransactionRollback(t *testing.T) {
	failure := errors.New("simulated SCIM account delete failure")
	for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			calls := []string{}
			setup := scimUsersSetup{
				Organization: organization.Options{
					Teams: organization.TeamsOptions{Enabled: true},
					Hooks: organization.OrganizationHooks{
						BeforeRemoveMember: func(context.Context, organization.RemoveMemberHookData) error {
							calls = append(calls, "before")
							return nil
						},
						AfterRemoveMember: func(context.Context, organization.RemoveMemberHookData) error {
							calls = append(calls, "after")
							return nil
						},
					},
				},
				DatabaseHooks: singleauth.DatabaseHooks{
					"account": {Delete: singleauth.DatabaseOperationHooks{Before: func(
						data storage.Record,
						_ singleauth.DatabaseHookContext,
					) (singleauth.DatabaseHookResult, error) {
						if recordString(data, "providerId") == "rollback-provider" {
							return singleauth.DatabaseHookResult{}, failure
						}
						return singleauth.DatabaseHookResult{}, nil
					}}},
				},
			}
			h := newSCIMUsersHarness(t, transport, setup)
			state := seedSCIMUsersOrganizationDelete(t, h, "rollback-org", "rollback-provider")
			status, body := h.deleteUser(t, state.Token, state.UserID)
			if status != http.StatusInternalServerError {
				t.Fatalf("rollback failure status/body=%d/%#v", status, body)
			}
			if !reflect.DeepEqual(calls, []string{"before"}) {
				t.Fatalf("rollback hook order=%#v, want before only", calls)
			}
			present, err := scimUsersOrganizationDeleteRecordsPresent(t.Context(), h.adapter, state)
			if err != nil || !present {
				t.Fatalf("transaction did not restore member/team/account: present=%v err=%v", present, err)
			}
			getStatus, resource := h.getUser(t, state.Token, state.UserID)
			if getStatus != http.StatusOK || resource["id"] != state.UserID {
				t.Fatalf("rolled-back SCIM user status/resource=%d/%#v", getStatus, resource)
			}
		})
	}
}

func TestSCIMOrganizationDeleteAfterHookFailureKeepsCommit(t *testing.T) {
	failure := errors.New("simulated afterRemoveMember failure")
	for _, transport := range []string{"net/http", "fasthttp", "fiber"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			calls := []string{}
			h := newSCIMUsersHarness(t, transport, scimUsersSetup{Organization: organization.Options{
				Teams: organization.TeamsOptions{Enabled: true},
				Hooks: organization.OrganizationHooks{
					BeforeRemoveMember: func(context.Context, organization.RemoveMemberHookData) error {
						calls = append(calls, "before")
						return nil
					},
					AfterRemoveMember: func(context.Context, organization.RemoveMemberHookData) error {
						calls = append(calls, "after")
						return failure
					},
				},
			}})
			state := seedSCIMUsersOrganizationDelete(t, h, "after-hook-org", "after-hook-provider")
			status, body := h.deleteUser(t, state.Token, state.UserID)
			if status != http.StatusInternalServerError {
				t.Fatalf("after hook failure status/body=%d/%#v", status, body)
			}
			if !reflect.DeepEqual(calls, []string{"before", "after"}) {
				t.Fatalf("after failure hook order=%#v", calls)
			}
			absent, err := scimUsersOrganizationDeleteRecordsAbsent(t.Context(), h.adapter, state)
			if err != nil || !absent {
				t.Fatalf("after hook failure rolled back committed storage: absent=%v err=%v", absent, err)
			}
		})
	}
}

func scimUsersScenarios() []scimUsersScenario {
	result := make([]scimUsersScenario, 0, 29)
	add := func(suite, title string, run scimUsersCase) {
		result = append(result, scimUsersScenario{Suite: suite, Name: title, Run: run})
	}
	listSuite := "SCIM > GET /scim/v2/Users"
	add(listSuite, "should return the list of users", scimUsersCaseList)
	add(listSuite, "should return an empty list when no users have been provisioned or belong to the organization", scimUsersCaseListEmpty)
	add(listSuite, "should only allow access to users that belong to the same provider", scimUsersCaseListProviderIsolation)
	add(listSuite, "should only allow access to users that belong to the same provider and organization", scimUsersCaseListProviderOrganizationIsolation)
	add(listSuite, "should filter the list of users", scimUsersCaseListFilter)
	add(listSuite, "should not allow anonymous access", scimUsersCaseListAnonymous)
	getSuite := "SCIM > GET /scim/v2/Users/:userId"
	add(getSuite, "should return a single user resource", scimUsersCaseGet)
	add(getSuite, "should only allow access to users that belong to the same provider", scimUsersCaseGetProviderIsolation)
	add(getSuite, "should only allow access to users that belong to the same provider and organization", scimUsersCaseGetProviderOrganizationIsolation)
	add(getSuite, "should return not found for missing users", scimUsersCaseGetMissing)
	add(getSuite, "should not allow anonymous access", scimUsersCaseGetAnonymous)
	deleteSuite := "SCIM > DELETE /scim/v2/Users/:userId"
	add(deleteSuite, "should delete an existing user", scimUsersCaseDelete)
	add(deleteSuite, "should not allow anonymous access", scimUsersCaseDeleteAnonymous)
	add(deleteSuite, "should not delete a missing user", scimUsersCaseDeleteMissing)
	add(deleteSuite, "should clear secondary storage sessions when deleting a user via SCIM", scimUsersCaseDeleteSecondarySessions)
	add(deleteSuite, "should deprovision (not delete the global user) for an org-scoped DELETE", scimUsersCaseDeleteOrganizationDeprovision)
	add(deleteSuite, "removes team memberships when an org-scoped SCIM delete removes the member", scimUsersCaseDeleteTeamMemberships)
	defaultSuite := "SCIM > Default SCIM provider"
	add(defaultSuite, "should work with a default SCIM provider", scimUsersCaseDefaultProvider)
	add(defaultSuite, "should reject invalid SCIM tokens", scimUsersCaseDefaultProviderInvalidToken)
	writeSuite := "SCIM write-path access and validation"
	add(writeSuite, "unlinks the provider account instead of globally deleting a user with other identities", scimUsersCaseUnlinkMultipleIdentities)
	add(writeSuite, "deletes the global user when this provider's account is their sole identity", scimUsersCaseDeleteSoleIdentity)
	add(writeSuite, "resets emailVerified when a SCIM email change is applied", scimUsersCaseResetEmailVerified)
	add(writeSuite, "rejects reassigning an email another user already holds with a 409 uniqueness conflict", scimUsersCaseRejectDuplicateEmail)
	add(writeSuite, "honors active:false by banning the user and reporting the real state (admin plugin)", scimUsersCaseActiveAdmin)
	add(writeSuite, "normalizes email casing when checking uniqueness on update", scimUsersCaseRejectDuplicateEmailCaseInsensitive)
	add(writeSuite, "rejects active:false rather than silently dropping it when the admin plugin is absent", scimUsersCaseRejectActiveWithoutAdmin)
	add(writeSuite, "provisions a deactivated user when created with active:false (admin plugin)", scimUsersCaseCreateInactiveAdmin)
	add(writeSuite, "rejects create with active:false before persisting when the admin plugin is absent", scimUsersCaseRejectCreateInactiveWithoutAdmin)
	add(writeSuite, "revokes sessions when create links and deactivates a pre-existing user", scimUsersCaseLinkInactiveRevokesSessions)
	return result
}

func newSCIMUsersHarness(t *testing.T, transport string, setup scimUsersSetup) scimUsersHarness {
	t.Helper()
	fixedNow := time.Date(2026, time.August, 9, 20, 0, 0, 0, time.UTC)
	organizationOptions := setup.Organization
	if setup.Teams {
		organizationOptions.Teams.Enabled = true
	}
	factories := []singleauth.PluginFactory{
		sso.NewFactory(sso.Options{}), NewFactory(setup.SCIM), organization.NewFactory(organizationOptions),
	}
	if setup.Admin {
		factories = append(factories, admin.NewFactory(admin.Options{}))
	}
	rateLimitEnabled := false
	authOptions := singleauth.Options{
		BaseURL: "http://auth.example.test", Secret: "0123456789abcdef0123456789abcdef",
		Clock: func() time.Time { return fixedNow }, RateLimit: singleauth.RateLimitOptions{Enabled: &rateLimitEnabled},
		Logger:        logger.Options{Disabled: true},
		DatabaseHooks: setup.DatabaseHooks,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(value string) (string, error) { return "hashed:" + value, nil },
				Verify: func(hash, value string) bool { return hash == "hashed:"+value },
			},
		},
		PluginFactories: factories,
	}
	if setup.Secondary != nil {
		authOptions.SecondaryStorage = setup.Secondary
	}
	auth, err := singleauth.New(authOptions)
	if err != nil {
		t.Fatal(err)
	}
	return scimUsersHarness{
		auth: auth, adapter: auth.Adapter(), clock: fixedNow,
		roundTrip: newSCIMManagementRoundTrip(t, auth, transport),
	}
}

func (h scimUsersHarness) exchange(
	t *testing.T,
	method, path, cookie string,
	headers http.Header,
	body any,
) (int, http.Header, map[string]any) {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	status, responseHeaders, raw := h.roundTrip(
		t, method, "http://auth.example.test/api/auth"+path, cookie, headers, encoded,
	)
	decoded := map[string]any{}
	if len(raw) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			t.Fatalf("decode %s %s status=%d body=%q: %v", method, path, status, raw, err)
		}
	}
	return status, responseHeaders, decoded
}

func (h scimUsersHarness) signUp(t *testing.T, localPart string) scimManagementIdentity {
	t.Helper()
	email := localPart + "@scim.test"
	status, headers, body := h.exchange(t, http.MethodPost, "/sign-up/email", "", nil, map[string]any{
		"email": email, "password": "password123", "name": localPart,
	})
	if status != http.StatusOK {
		t.Fatalf("sign up status=%d body=%#v", status, body)
	}
	user, _ := body["user"].(map[string]any)
	userID, _ := user["id"].(string)
	cookie := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	if userID == "" || cookie == "" {
		t.Fatalf("sign up user/cookie=%#v/%q", user, cookie)
	}
	return scimManagementIdentity{ID: userID, Email: email, Cookie: cookie}
}

func (h scimUsersHarness) seedOrganization(t *testing.T, organizationID string, owner scimManagementIdentity) {
	t.Helper()
	if _, err := h.adapter.Create(t.Context(), storage.CreateParams{
		Model: "organization", ForceAllowID: true,
		Data: storage.Record{"id": organizationID, "name": organizationID, "slug": organizationID, "createdAt": h.clock},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapter.Create(t.Context(), storage.CreateParams{Model: "member", Data: storage.Record{
		"organizationId": organizationID, "userId": owner.ID, "role": "owner", "createdAt": h.clock,
	}}); err != nil {
		t.Fatal(err)
	}
}

func (h scimUsersHarness) generateToken(t *testing.T, actor scimManagementIdentity, providerID, organizationID string) string {
	t.Helper()
	body := map[string]any{"providerId": providerID}
	if organizationID != "" {
		body["organizationId"] = organizationID
	}
	status, _, response := h.exchange(t, http.MethodPost, "/scim/generate-token", actor.Cookie, nil, body)
	return requireGeneratedToken(t, status, response)
}

func scimUsersAuthorization(token string) http.Header {
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	return headers
}

func (h scimUsersHarness) createUser(t *testing.T, token string, body map[string]any) map[string]any {
	t.Helper()
	status, headers, response := h.exchange(t, http.MethodPost, "/scim/v2/Users", "", scimUsersAuthorization(token), body)
	if status != http.StatusCreated {
		t.Fatalf("create SCIM user status=%d body=%#v", status, response)
	}
	if id, _ := response["id"].(string); id == "" || headers.Get("Location") == "" {
		t.Fatalf("create SCIM user response/location=%#v/%q", response, headers.Get("Location"))
	}
	return response
}

func (h scimUsersHarness) listUsers(t *testing.T, token, filter string) (int, map[string]any) {
	t.Helper()
	path := "/scim/v2/Users"
	if filter != "" {
		path += "?filter=" + url.QueryEscape(filter)
	}
	status, _, response := h.exchange(t, http.MethodGet, path, "", scimUsersAuthorization(token), nil)
	return status, response
}

func (h scimUsersHarness) getUser(t *testing.T, token, userID string) (int, map[string]any) {
	t.Helper()
	status, _, response := h.exchange(t, http.MethodGet, "/scim/v2/Users/"+url.PathEscape(userID), "", scimUsersAuthorization(token), nil)
	return status, response
}

func (h scimUsersHarness) updateUser(t *testing.T, token, userID string, body map[string]any) (int, map[string]any) {
	t.Helper()
	status, _, response := h.exchange(t, http.MethodPut, "/scim/v2/Users/"+url.PathEscape(userID), "", scimUsersAuthorization(token), body)
	return status, response
}

func (h scimUsersHarness) patchUser(t *testing.T, token, userID string, body map[string]any) (int, map[string]any) {
	t.Helper()
	status, _, response := h.exchange(t, http.MethodPatch, "/scim/v2/Users/"+url.PathEscape(userID), "", scimUsersAuthorization(token), body)
	return status, response
}

func (h scimUsersHarness) deleteUser(t *testing.T, token, userID string) (int, map[string]any) {
	t.Helper()
	status, _, response := h.exchange(t, http.MethodDelete, "/scim/v2/Users/"+url.PathEscape(userID), "", scimUsersAuthorization(token), nil)
	return status, response
}

func newSCIMUsersTokenHarness(
	t *testing.T,
	transport string,
	setup scimUsersSetup,
	providerID string,
) (scimUsersHarness, scimManagementIdentity, string) {
	t.Helper()
	h := newSCIMUsersHarness(t, transport, setup)
	actor := h.signUp(t, "provisioner")
	token := h.generateToken(t, actor, providerID, "")
	return h, actor, token
}

func scimUsersResources(t *testing.T, body map[string]any) []any {
	t.Helper()
	resources, ok := body["Resources"].([]any)
	if !ok {
		t.Fatalf("SCIM users response=%#v, want Resources array", body)
	}
	return resources
}

func requireSCIMUsersList(t *testing.T, status int, body map[string]any, want []map[string]any) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("SCIM users list status=%d body=%#v", status, body)
	}
	resources := scimUsersResources(t, body)
	wantResources := make([]any, len(want))
	for index := range want {
		wantResources[index] = want[index]
	}
	schemas := scimUsersStringSlice(body["schemas"])
	if body["totalResults"] != json.Number(fmt.Sprint(len(want))) ||
		body["itemsPerPage"] != json.Number(fmt.Sprint(len(want))) ||
		body["startIndex"] != json.Number("1") ||
		!reflect.DeepEqual(schemas, []string{listResponseSchema}) ||
		!reflect.DeepEqual(resources, wantResources) {
		t.Fatalf("SCIM users list=%#v, want resources=%#v", body, want)
	}
}

func requireSCIMUsersError(t *testing.T, status int, body map[string]any, wantStatus int, detail, scimType string) {
	t.Helper()
	if status != wantStatus || body["status"] != fmt.Sprint(wantStatus) || body["detail"] != detail ||
		!reflect.DeepEqual(scimUsersStringSlice(body["schemas"]), []string{ErrorSchema}) {
		t.Fatalf("SCIM error status/body=%d/%#v, want %d %q", status, body, wantStatus, detail)
	}
	if scimType == "" {
		if value, exists := body["scimType"]; exists && value != "" {
			t.Fatalf("SCIM error scimType=%#v, want omitted", value)
		}
	} else if body["scimType"] != scimType {
		t.Fatalf("SCIM error scimType=%#v, want %q", body["scimType"], scimType)
	}
}

func scimUsersStringSlice(value any) []string {
	raw, _ := value.([]any)
	result := make([]string, 0, len(raw))
	for _, entry := range raw {
		if text, ok := entry.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func scimUsersCaseList(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "the-saml-provider-1")
	userA := h.createUser(t, token, map[string]any{"userName": "user-a"})
	userB := h.createUser(t, token, map[string]any{"userName": "user-b"})
	status, body := h.listUsers(t, token, "")
	requireSCIMUsersList(t, status, body, []map[string]any{userA, userB})
}

func scimUsersCaseListEmpty(t *testing.T, transport string) {
	h, actor, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "the-saml-provider-1")
	status, body := h.listUsers(t, token, "")
	requireSCIMUsersList(t, status, body, nil)
	h.seedOrganization(t, "org-a", actor)
	h.seedOrganization(t, "org-b", actor)
	tokenA := h.generateToken(t, actor, "provider-org-a", "org-a")
	tokenB := h.generateToken(t, actor, "provider-org-b", "org-b")
	h.createUser(t, tokenA, map[string]any{"userName": "user-a"})
	status, body = h.listUsers(t, tokenB, "")
	requireSCIMUsersList(t, status, body, nil)
}

func scimUsersCaseListProviderIsolation(t *testing.T, transport string) {
	h := newSCIMUsersHarness(t, transport, scimUsersSetup{})
	actor := h.signUp(t, "provider-isolation")
	tokenA := h.generateToken(t, actor, "provider-a", "")
	tokenB := h.generateToken(t, actor, "provider-b", "")
	userA := h.createUser(t, tokenB, map[string]any{"userName": "user-a"})
	userB := h.createUser(t, tokenA, map[string]any{"userName": "user-b"})
	userC := h.createUser(t, tokenB, map[string]any{"userName": "user-c"})
	status, body := h.listUsers(t, tokenA, "")
	requireSCIMUsersList(t, status, body, []map[string]any{userB})
	status, body = h.listUsers(t, tokenB, "")
	requireSCIMUsersList(t, status, body, []map[string]any{userA, userC})
}

func scimUsersCaseListProviderOrganizationIsolation(t *testing.T, transport string) {
	h := newSCIMUsersHarness(t, transport, scimUsersSetup{})
	actor := h.signUp(t, "provider-org-isolation")
	h.seedOrganization(t, "org:a", actor)
	h.seedOrganization(t, "org:b", actor)
	tokenA := h.generateToken(t, actor, "provider-a", "org:a")
	tokenB := h.generateToken(t, actor, "provider-b", "org:b")
	userA := h.createUser(t, tokenB, map[string]any{"userName": "user-a"})
	userB := h.createUser(t, tokenA, map[string]any{"userName": "user-b"})
	userC := h.createUser(t, tokenB, map[string]any{"userName": "user-c"})
	status, body := h.listUsers(t, tokenA, "")
	requireSCIMUsersList(t, status, body, []map[string]any{userB})
	status, body = h.listUsers(t, tokenB, "")
	requireSCIMUsersList(t, status, body, []map[string]any{userA, userC})
}

func scimUsersCaseListFilter(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "filter-provider")
	userA := h.createUser(t, token, map[string]any{"userName": "user-a"})
	h.createUser(t, token, map[string]any{"userName": "user-b"})
	h.createUser(t, token, map[string]any{"userName": "user-c"})
	status, body := h.listUsers(t, token, `userName eq "user-A"`)
	requireSCIMUsersList(t, status, body, []map[string]any{userA})
}

func scimUsersCaseListAnonymous(t *testing.T, transport string) {
	h := newSCIMUsersHarness(t, transport, scimUsersSetup{})
	status, _, body := h.exchange(t, http.MethodGet, "/scim/v2/Users", "", nil, nil)
	requireSCIMUsersError(t, status, body, http.StatusUnauthorized, "SCIM token is required", "")
}

func scimUsersCaseGet(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "get-provider")
	created := h.createUser(t, token, map[string]any{"userName": "the-username"})
	status, retrieved := h.getUser(t, token, created["id"].(string))
	if status != http.StatusOK || !reflect.DeepEqual(retrieved, created) {
		t.Fatalf("get SCIM user status/resource=%d/%#v, want %#v", status, retrieved, created)
	}
}

func scimUsersCaseGetProviderIsolation(t *testing.T, transport string) {
	h := newSCIMUsersHarness(t, transport, scimUsersSetup{})
	actor := h.signUp(t, "get-provider-isolation")
	tokenA := h.generateToken(t, actor, "provider-a", "")
	tokenB := h.generateToken(t, actor, "provider-b", "")
	userA := h.createUser(t, tokenB, map[string]any{"userName": "user-a"})
	userB := h.createUser(t, tokenA, map[string]any{"userName": "user-b"})
	status, resource := h.getUser(t, tokenA, userB["id"].(string))
	if status != http.StatusOK || !reflect.DeepEqual(resource, userB) {
		t.Fatalf("provider A get status/resource=%d/%#v", status, resource)
	}
	status, body := h.getUser(t, tokenB, userB["id"].(string))
	requireSCIMUsersError(t, status, body, http.StatusNotFound, "User not found", "")
	status, resource = h.getUser(t, tokenB, userA["id"].(string))
	if status != http.StatusOK || !reflect.DeepEqual(resource, userA) {
		t.Fatalf("provider B get status/resource=%d/%#v", status, resource)
	}
	status, body = h.getUser(t, tokenA, userA["id"].(string))
	requireSCIMUsersError(t, status, body, http.StatusNotFound, "User not found", "")
}

func scimUsersCaseGetProviderOrganizationIsolation(t *testing.T, transport string) {
	h := newSCIMUsersHarness(t, transport, scimUsersSetup{})
	actor := h.signUp(t, "get-provider-org-isolation")
	h.seedOrganization(t, "get-org-a", actor)
	h.seedOrganization(t, "get-org-b", actor)
	tokenA := h.generateToken(t, actor, "provider-a", "get-org-a")
	tokenB := h.generateToken(t, actor, "provider-b", "get-org-b")
	userA := h.createUser(t, tokenB, map[string]any{"userName": "user-a"})
	userB := h.createUser(t, tokenA, map[string]any{"userName": "user-b"})
	status, resource := h.getUser(t, tokenA, userB["id"].(string))
	if status != http.StatusOK || !reflect.DeepEqual(resource, userB) {
		t.Fatalf("org provider A get status/resource=%d/%#v", status, resource)
	}
	status, body := h.getUser(t, tokenB, userB["id"].(string))
	requireSCIMUsersError(t, status, body, http.StatusNotFound, "User not found", "")
	status, resource = h.getUser(t, tokenB, userA["id"].(string))
	if status != http.StatusOK || !reflect.DeepEqual(resource, userA) {
		t.Fatalf("org provider B get status/resource=%d/%#v", status, resource)
	}
	status, body = h.getUser(t, tokenA, userA["id"].(string))
	requireSCIMUsersError(t, status, body, http.StatusNotFound, "User not found", "")
}

func scimUsersCaseGetMissing(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "missing-provider")
	status, body := h.getUser(t, token, "missing")
	requireSCIMUsersError(t, status, body, http.StatusNotFound, "User not found", "")
}

func scimUsersCaseGetAnonymous(t *testing.T, transport string) {
	h := newSCIMUsersHarness(t, transport, scimUsersSetup{})
	status, _, body := h.exchange(t, http.MethodGet, "/scim/v2/Users/whatever", "", nil, nil)
	requireSCIMUsersError(t, status, body, http.StatusUnauthorized, "SCIM token is required", "")
}

func scimUsersCaseDelete(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "delete-provider")
	created := h.createUser(t, token, map[string]any{"userName": "the-username"})
	userID := created["id"].(string)
	status, body := h.deleteUser(t, token, userID)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("delete SCIM user status/body=%d/%#v", status, body)
	}
	status, body = h.getUser(t, token, userID)
	requireSCIMUsersError(t, status, body, http.StatusNotFound, "User not found", "")
}

func scimUsersCaseDeleteAnonymous(t *testing.T, transport string) {
	h := newSCIMUsersHarness(t, transport, scimUsersSetup{})
	status, _, body := h.exchange(t, http.MethodDelete, "/scim/v2/Users/whatever", "", nil, nil)
	requireSCIMUsersError(t, status, body, http.StatusUnauthorized, "SCIM token is required", "")
}

func scimUsersCaseDeleteMissing(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "delete-missing-provider")
	status, body := h.deleteUser(t, token, "missing")
	requireSCIMUsersError(t, status, body, http.StatusNotFound, "User not found", "")
}

func scimUsersCaseDeleteSecondarySessions(t *testing.T, transport string) {
	secondary := newSCIMUsersSecondaryStore()
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{Secondary: secondary}, "secondary-provider")
	created := h.createUser(t, token, map[string]any{"userName": "scim-victim@test.com"})
	userID := created["id"].(string)
	session, err := h.auth.InternalAdapter().CreateSession(t.Context(), userID, singleauth.InternalSessionCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sessionToken := recordString(session, "token")
	if sessionToken == "" || !secondary.Has(sessionToken) {
		t.Fatalf("secondary session token/store=%q/%v", sessionToken, secondary.Has(sessionToken))
	}
	status, body := h.deleteUser(t, token, userID)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("secondary delete status/body=%d/%#v", status, body)
	}
	if secondary.Has(sessionToken) {
		t.Fatalf("secondary session %q survived SCIM delete", sessionToken)
	}
}

func scimUsersCaseDeleteOrganizationDeprovision(t *testing.T, transport string) {
	h := newSCIMUsersHarness(t, transport, scimUsersSetup{})
	actor := h.signUp(t, "org-deprovisioner")
	h.seedOrganization(t, "org:deprovision", actor)
	token := h.generateToken(t, actor, "provider-deprovision", "org:deprovision")
	created := h.createUser(t, token, map[string]any{
		"userName": "scim-user", "emails": []map[string]any{{"value": "scim-user@email.com"}},
	})
	userID := created["id"].(string)
	member := findSCIMUsersRecord(t, h.adapter, "member", []storage.Where{
		{Field: "organizationId", Value: "org:deprovision"}, {Field: "userId", Value: userID},
	})
	if member == nil {
		t.Fatal("SCIM create did not provision organization membership")
	}
	status, body := h.deleteUser(t, token, userID)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("org deprovision status/body=%d/%#v", status, body)
	}
	if user := findSCIMUsersRecord(t, h.adapter, "user", []storage.Where{{Field: "id", Value: userID}}); user == nil {
		t.Fatal("org-scoped delete removed global user")
	}
	if member = findSCIMUsersRecord(t, h.adapter, "member", []storage.Where{
		{Field: "organizationId", Value: "org:deprovision"}, {Field: "userId", Value: userID},
	}); member != nil {
		t.Fatalf("org membership survived deprovision: %#v", member)
	}
	if account := findSCIMUsersRecord(t, h.adapter, "account", []storage.Where{
		{Field: "providerId", Value: "provider-deprovision"}, {Field: "userId", Value: userID},
	}); account != nil {
		t.Fatalf("SCIM account survived deprovision: %#v", account)
	}
	status, body = h.getUser(t, token, userID)
	requireSCIMUsersError(t, status, body, http.StatusNotFound, "User not found", "")
}

func scimUsersCaseDeleteTeamMemberships(t *testing.T, transport string) {
	h := newSCIMUsersHarness(t, transport, scimUsersSetup{Teams: true})
	actor := h.signUp(t, "team-deprovisioner")
	h.seedOrganization(t, "team-org", actor)
	token := h.generateToken(t, actor, "provider-team-cleanup", "team-org")
	created := h.createUser(t, token, map[string]any{
		"userName": "scim-team-user", "emails": []map[string]any{{"value": "scim-team-user@email.com"}},
	})
	userID := created["id"].(string)
	if _, err := h.adapter.Create(t.Context(), storage.CreateParams{
		Model: "team", ForceAllowID: true,
		Data: storage.Record{"id": "team-1", "name": "the-team", "organizationId": "team-org", "createdAt": h.clock},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.adapter.Create(t.Context(), storage.CreateParams{Model: "teamMember", Data: storage.Record{
		"teamId": "team-1", "userId": userID, "createdAt": h.clock,
	}}); err != nil {
		t.Fatal(err)
	}
	if member := findSCIMUsersRecord(t, h.adapter, "teamMember", []storage.Where{
		{Field: "teamId", Value: "team-1"}, {Field: "userId", Value: userID},
	}); member == nil {
		t.Fatal("team membership fixture missing")
	}
	status, body := h.deleteUser(t, token, userID)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("team deprovision status/body=%d/%#v", status, body)
	}
	if member := findSCIMUsersRecord(t, h.adapter, "member", []storage.Where{
		{Field: "organizationId", Value: "team-org"}, {Field: "userId", Value: userID},
	}); member != nil {
		t.Fatalf("organization member survived team deprovision: %#v", member)
	}
	if teamMember := findSCIMUsersRecord(t, h.adapter, "teamMember", []storage.Where{
		{Field: "teamId", Value: "team-1"}, {Field: "userId", Value: userID},
	}); teamMember != nil {
		t.Fatalf("team member survived SCIM deprovision: %#v", teamMember)
	}
}

func scimUsersCaseDefaultProvider(t *testing.T, transport string) {
	setup := scimUsersSetup{SCIM: Options{DefaultSCIM: []Provider{{
		ProviderID: "the-scim-provider", SCIMToken: "the-scim-token",
	}}}}
	h := newSCIMUsersHarness(t, transport, setup)
	token := scimUsersPaddedDefaultBearerToken
	created := h.createUser(t, token, map[string]any{"userName": "the-username"})
	userID := created["id"].(string)
	status, resource := h.getUser(t, token, userID)
	if status != http.StatusOK || !reflect.DeepEqual(resource, created) {
		t.Fatalf("default provider get status/resource=%d/%#v", status, resource)
	}
	status, list := h.listUsers(t, token, "")
	requireSCIMUsersList(t, status, list, []map[string]any{created})
	status, updated := h.updateUser(t, token, userID, map[string]any{"userName": "new-username"})
	if status != http.StatusOK || updated["userName"] != "new-username" {
		t.Fatalf("default provider update status/resource=%d/%#v", status, updated)
	}
	status, body := h.deleteUser(t, token, userID)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("default provider delete status/body=%d/%#v", status, body)
	}
}

func scimUsersCaseDefaultProviderInvalidToken(t *testing.T, transport string) {
	h := newSCIMUsersHarness(t, transport, scimUsersSetup{SCIM: Options{DefaultSCIM: []Provider{{
		ProviderID: "the-scim-provider", SCIMToken: "the-scim-token",
	}}}})
	status, _, body := h.exchange(t, http.MethodPost, "/scim/v2/Users", "", scimUsersAuthorization("invalid-scim-token"), map[string]any{
		"userName": "the-username",
	})
	requireSCIMUsersError(t, status, body, http.StatusUnauthorized, "Invalid SCIM token", "")
}

func findSCIMUsersRecord(t *testing.T, adapter storage.Adapter, model string, where []storage.Where) storage.Record {
	t.Helper()
	record, err := adapter.FindOne(t.Context(), storage.FindOneParams{Model: model, Where: where})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func scimUsersCaseUnlinkMultipleIdentities(t *testing.T, transport string) {
	setup := scimUsersSetup{SCIM: Options{LinkExistingUsers: LinkExistingUsersOptions{Enabled: true}}}
	h := newSCIMUsersHarness(t, transport, setup)
	actor := h.signUp(t, "unlink-provisioner")
	token := h.generateToken(t, actor, "scim-a", "")
	victim := h.signUp(t, "unlink-victim")
	provisioned := h.createUser(t, token, map[string]any{
		"userName": "victim", "emails": []map[string]any{{"value": victim.Email}},
	})
	if provisioned["id"] != victim.ID {
		t.Fatalf("linked SCIM user id=%#v, want existing %q", provisioned["id"], victim.ID)
	}
	status, body := h.deleteUser(t, token, victim.ID)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("unlink status/body=%d/%#v", status, body)
	}
	if user := findSCIMUsersRecord(t, h.adapter, "user", []storage.Where{{Field: "id", Value: victim.ID}}); user == nil {
		t.Fatal("unlink deleted the global user")
	}
	accounts, err := h.adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "account", Where: []storage.Where{{Field: "userId", Value: victim.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	providers := make([]string, 0, len(accounts))
	for _, account := range accounts {
		providers = append(providers, recordString(account, "providerId"))
	}
	sort.Strings(providers)
	if !reflect.DeepEqual(providers, []string{"credential"}) {
		t.Fatalf("remaining account providers=%#v, want credential", providers)
	}
}

func scimUsersCaseDeleteSoleIdentity(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "scim-a")
	provisioned := h.createUser(t, token, map[string]any{
		"userName": "solo", "emails": []map[string]any{{"value": "solo@email.com"}},
	})
	userID := provisioned["id"].(string)
	status, body := h.deleteUser(t, token, userID)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("sole delete status/body=%d/%#v", status, body)
	}
	if user := findSCIMUsersRecord(t, h.adapter, "user", []storage.Where{{Field: "id", Value: userID}}); user != nil {
		t.Fatalf("sole-identity user survived SCIM delete: %#v", user)
	}
}

func scimUsersCaseResetEmailVerified(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "scim-a")
	provisioned := h.createUser(t, token, map[string]any{
		"userName": "before", "emails": []map[string]any{{"value": "before@email.com"}},
	})
	userID := provisioned["id"].(string)
	if _, err := h.adapter.Update(t.Context(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		Update: storage.Record{"emailVerified": true},
	}); err != nil {
		t.Fatal(err)
	}
	status, body := h.updateUser(t, token, userID, map[string]any{
		"userName": "after", "emails": []map[string]any{{"value": "after@email.com"}},
	})
	if status != http.StatusOK {
		t.Fatalf("email change status/body=%d/%#v", status, body)
	}
	user := findSCIMUsersRecord(t, h.adapter, "user", []storage.Where{{Field: "id", Value: userID}})
	if verified, _ := user["emailVerified"].(bool); verified {
		t.Fatalf("emailVerified remained true after SCIM email change: %#v", user)
	}
}

func scimUsersCaseRejectDuplicateEmail(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "scim-a")
	h.createUser(t, token, map[string]any{
		"userName": "user-a", "emails": []map[string]any{{"value": "a@email.com"}},
	})
	userB := h.createUser(t, token, map[string]any{
		"userName": "user-b", "emails": []map[string]any{{"value": "b@email.com"}},
	})
	status, body := h.updateUser(t, token, userB["id"].(string), map[string]any{
		"userName": "user-b", "emails": []map[string]any{{"value": "a@email.com"}},
	})
	requireSCIMUsersError(t, status, body, http.StatusConflict, "Email already in use", "uniqueness")
}

func scimUsersCaseActiveAdmin(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{Admin: true}, "scim-a")
	provisioned := h.createUser(t, token, map[string]any{
		"userName": "deact", "emails": []map[string]any{{"value": "deact@email.com"}},
	})
	userID := provisioned["id"].(string)
	status, deactivated := h.updateUser(t, token, userID, map[string]any{
		"userName": "deact", "emails": []map[string]any{{"value": "deact@email.com"}}, "active": false,
	})
	if status != http.StatusOK || deactivated["active"] != false {
		t.Fatalf("deactivate status/resource=%d/%#v", status, deactivated)
	}
	banned := findSCIMUsersRecord(t, h.adapter, "user", []storage.Where{{Field: "id", Value: userID}})
	if banned["banned"] != true || recordString(banned, "banReason") == "" {
		t.Fatalf("SCIM deactivation state=%#v", banned)
	}
	status, body := h.patchUser(t, token, userID, map[string]any{
		"schemas":    []string{PatchOpSchema},
		"Operations": []map[string]any{{"op": "replace", "path": "/active", "value": true}},
	})
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("reactivate status/body=%d/%#v", status, body)
	}
	cleared := findSCIMUsersRecord(t, h.adapter, "user", []storage.Where{{Field: "id", Value: userID}})
	if cleared["banned"] != false || cleared["banReason"] != nil {
		t.Fatalf("SCIM reactivation state=%#v", cleared)
	}
}

func scimUsersCaseRejectDuplicateEmailCaseInsensitive(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "scim-a")
	h.createUser(t, token, map[string]any{
		"userName": "user-a", "emails": []map[string]any{{"value": "a@email.com"}},
	})
	userB := h.createUser(t, token, map[string]any{
		"userName": "user-b", "emails": []map[string]any{{"value": "b@email.com"}},
	})
	status, body := h.updateUser(t, token, userB["id"].(string), map[string]any{
		"userName": "user-b", "emails": []map[string]any{{"value": "A@Email.com"}},
	})
	requireSCIMUsersError(t, status, body, http.StatusConflict, "Email already in use", "uniqueness")
}

func scimUsersCaseRejectActiveWithoutAdmin(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "scim-a")
	provisioned := h.createUser(t, token, map[string]any{
		"userName": "noadmin", "emails": []map[string]any{{"value": "noadmin@email.com"}},
	})
	status, body := h.updateUser(t, token, provisioned["id"].(string), map[string]any{
		"userName": "noadmin", "emails": []map[string]any{{"value": "noadmin@email.com"}}, "active": false,
	})
	if status != http.StatusBadRequest || !strings.Contains(fmt.Sprint(body["detail"]), "admin plugin") || body["status"] != "400" {
		t.Fatalf("active:false without admin status/body=%d/%#v", status, body)
	}
}

func scimUsersCaseCreateInactiveAdmin(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{Admin: true}, "scim-a")
	created := h.createUser(t, token, map[string]any{
		"userName": "born-off", "emails": []map[string]any{{"value": "born-off@email.com"}}, "active": false,
	})
	if created["active"] != false {
		t.Fatalf("inactive create resource=%#v", created)
	}
	user := findSCIMUsersRecord(t, h.adapter, "user", []storage.Where{{Field: "id", Value: created["id"]}})
	if user["banned"] != true {
		t.Fatalf("inactive create persisted user=%#v", user)
	}
}

func scimUsersCaseRejectCreateInactiveWithoutAdmin(t *testing.T, transport string) {
	h, _, token := newSCIMUsersTokenHarness(t, transport, scimUsersSetup{}, "scim-a")
	status, _, body := h.exchange(t, http.MethodPost, "/scim/v2/Users", "", scimUsersAuthorization(token), map[string]any{
		"userName": "never", "emails": []map[string]any{{"value": "never@email.com"}}, "active": false,
	})
	if status != http.StatusBadRequest || !strings.Contains(fmt.Sprint(body["detail"]), "admin plugin") || body["status"] != "400" {
		t.Fatalf("inactive create without admin status/body=%d/%#v", status, body)
	}
	if user := findSCIMUsersRecord(t, h.adapter, "user", []storage.Where{{Field: "email", Value: "never@email.com"}}); user != nil {
		t.Fatalf("rejected inactive create persisted user=%#v", user)
	}
}

func scimUsersCaseLinkInactiveRevokesSessions(t *testing.T, transport string) {
	setup := scimUsersSetup{
		SCIM: Options{LinkExistingUsers: LinkExistingUsersOptions{Enabled: true}}, Admin: true,
	}
	h := newSCIMUsersHarness(t, transport, setup)
	actor := h.signUp(t, "link-inactive-provisioner")
	token := h.generateToken(t, actor, "scim-a", "")
	existing := h.signUp(t, "existing")
	if _, err := h.auth.InternalAdapter().CreateSession(t.Context(), existing.ID, singleauth.InternalSessionCreateOptions{}); err != nil {
		t.Fatal(err)
	}
	sessionsBefore, err := h.adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "session", Where: []storage.Where{{Field: "userId", Value: existing.ID}},
	})
	if err != nil || len(sessionsBefore) == 0 {
		t.Fatalf("existing sessions before link=%d err=%v", len(sessionsBefore), err)
	}
	created := h.createUser(t, token, map[string]any{
		"userName": "existing", "emails": []map[string]any{{"value": existing.Email}}, "active": false,
	})
	if created["id"] != existing.ID || created["active"] != false {
		t.Fatalf("linked inactive resource=%#v, want user %q", created, existing.ID)
	}
	sessionsAfter, err := h.adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "session", Where: []storage.Where{{Field: "userId", Value: existing.ID}},
	})
	if err != nil || len(sessionsAfter) != 0 {
		t.Fatalf("existing sessions after link=%d err=%v", len(sessionsAfter), err)
	}
	user := findSCIMUsersRecord(t, h.adapter, "user", []storage.Where{{Field: "id", Value: existing.ID}})
	if user["banned"] != true {
		t.Fatalf("linked existing user not banned: %#v", user)
	}
}
