package organization_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/storage"
)

const organizationProductionFixSecret = "organization-production-fixes-secret"

func TestCreateOrganizationSessionPrecedenceAndActiveState(t *testing.T) {
	auth, _ := newOrganizationProductionFixAuth(t, organization.Options{
		Teams: organization.TeamsOptions{Enabled: true},
	})
	owner := organizationProductionSignUp(t, auth, "Owner", "owner@production.test", model.Value[string]{})
	other := organizationProductionSignUp(t, auth, "Other", "other@production.test", model.Value[string]{})
	signIn, err := auth.API().SignInEmail(t.Context(), singleauth.SignInEmailInput{
		Email: "owner@production.test", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookieHeader := cookies.ApplySetCookies("", signIn.Headers.Values("Set-Cookie"))
	if cookieHeader == "" || signIn.Token == "" {
		t.Fatalf("sign-in cookie=%q token=%q", cookieHeader, signIn.Token)
	}

	httpCreated := organizationProductionHTTPCreate(t, auth, cookieHeader, map[string]any{
		"name": "HTTP Organization", "slug": "http-organization", "userId": other.ID,
	})
	assertOrganizationCreator(t, auth, httpCreated, owner.ID, other.ID)
	assertOrganizationSessionState(t, auth, signIn.Token, httpCreated)

	ownerHeaders := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader})
	directWithSession, err := auth.API().Call(t.Context(), "createOrganization", singleauth.DirectCallInput{
		Method:  http.MethodPost,
		Headers: ownerHeaders,
		Body: map[string]any{
			"name": "Direct Session Organization", "slug": "direct-session-organization", "userId": other.ID,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	directWithSessionID := organizationProductionObjectID(t, directWithSession.Value)
	assertOrganizationCreator(t, auth, directWithSessionID, owner.ID, other.ID)

	directSystem, err := auth.API().Call(t.Context(), "createOrganization", singleauth.DirectCallInput{
		Method: http.MethodPost,
		Body: map[string]any{
			"name": "Direct System Organization", "slug": "direct-system-organization", "userId": other.ID,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	directSystemID := organizationProductionObjectID(t, directSystem.Value)
	assertOrganizationCreator(t, auth, directSystemID, other.ID, owner.ID)
}

func TestCreateOrganizationAuthenticatedDirectCallCannotUseSystemBypass(t *testing.T) {
	allowed := false
	auth, _ := newOrganizationProductionFixAuth(t, organization.Options{
		AllowUserToCreateOrganization: &allowed,
	})
	organizationProductionSignUp(t, auth, "Restricted Owner", "restricted-owner@production.test", model.Value[string]{})
	other := organizationProductionSignUp(t, auth, "Restricted Other", "restricted-other@production.test", model.Value[string]{})
	signIn, err := auth.API().SignInEmail(t.Context(), singleauth.SignInEmailInput{
		Email: "restricted-owner@production.test", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookieHeader := cookies.ApplySetCookies("", signIn.Headers.Values("Set-Cookie"))
	_, err = auth.API().Call(t.Context(), "createOrganization", singleauth.DirectCallInput{
		Method:  http.MethodPost,
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader}),
		Body: map[string]any{
			"name": "Forbidden Session Organization", "slug": "forbidden-session-organization", "userId": other.ID,
		},
	})
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Status != contract.StatusForbidden || apiError.Code != organization.ErrorOrganizationCreateForbidden {
		t.Fatalf("authenticated direct create error = %#v", err)
	}

	systemResult, err := auth.API().Call(t.Context(), "createOrganization", singleauth.DirectCallInput{
		Method: http.MethodPost,
		Body: map[string]any{
			"name": "Allowed System Organization", "slug": "allowed-system-organization", "userId": other.ID,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	systemOrganizationID := organizationProductionObjectID(t, systemResult.Value)
	assertOrganizationCreator(t, auth, systemOrganizationID, other.ID, "missing-user-id")
}

func TestFullOrganizationMembersIncludePublicUserProjection(t *testing.T) {
	auth, plugin := newOrganizationProductionFixAuth(t, organization.Options{})
	image := "https://cdn.production.test/owner.png"
	owner := organizationProductionSignUp(
		t, auth, "Projection Owner", "projection@production.test", model.Present(image),
	)
	created, err := plugin.CreateOrganization(t.Context(), organization.CreateOrganizationInput{
		Name: "Projection Organization", Slug: "projection-organization", UserID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	full, err := plugin.GetFullOrganization(t.Context(), organization.GetFullOrganizationInput{
		UserID: owner.ID, OrganizationID: created.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if full == nil || len(full.Members) != 1 || full.Members[0].User == nil {
		t.Fatalf("full organization members = %#v", full)
	}
	user := full.Members[0].User
	if user.ID != owner.ID || user.Name != owner.Name || user.Email != owner.Email ||
		user.Image == nil || *user.Image != image {
		t.Fatalf("member user projection = %#v", user)
	}
	encoded, err := json.Marshal(full.Members[0])
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	projected, ok := raw["user"].(map[string]any)
	if !ok || len(projected) != 4 || projected["id"] != owner.ID ||
		projected["name"] != owner.Name || projected["email"] != owner.Email || projected["image"] != image {
		t.Fatalf("serialized member user projection = %#v", raw["user"])
	}
}

func TestGetActiveMemberHTTPIncludesPublicUserProjection(t *testing.T) {
	auth, _ := newOrganizationProductionFixAuth(t, organization.Options{})
	image := "https://cdn.production.test/active-owner.png"
	owner := organizationProductionSignUp(
		t, auth, "Active Owner", "active-owner@production.test", model.Present(image),
	)
	signIn, err := auth.API().SignInEmail(t.Context(), singleauth.SignInEmailInput{
		Email: owner.Email, Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookieHeader := cookies.ApplySetCookies("", signIn.Headers.Values("Set-Cookie"))
	organizationProductionHTTPCreate(t, auth, cookieHeader, map[string]any{
		"name": "Active Member Organization", "slug": "active-member-organization",
	})

	request := httptest.NewRequest(
		http.MethodGet,
		"http://auth.example.test/api/auth/organization/get-active-member",
		nil,
	)
	request.Header.Set("Cookie", cookieHeader)
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("get active member status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var member map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &member); err != nil {
		t.Fatal(err)
	}
	user, ok := member["user"].(map[string]any)
	if !ok || len(user) != 4 || user["id"] != owner.ID || user["name"] != owner.Name ||
		user["email"] != owner.Email || user["image"] != image {
		t.Fatalf("active member user projection = %#v; member=%#v", member["user"], member)
	}
}

func TestOrganizationLifecycleHookPayloadsMatchReference(t *testing.T) {
	fixed := time.Date(2026, time.August, 9, 12, 30, 0, 0, time.UTC)
	var beforeOrganization storage.Record
	var beforeInvitation storage.Record
	events := make([]string, 0, 2)
	options := organization.Options{
		Hooks: organization.OrganizationHooks{
			BeforeCreateOrganization: func(_ context.Context, data organization.BeforeCreateOrganizationData) (storage.Record, error) {
				beforeOrganization = cloneOrganizationProductionRecord(data.Organization)
				return storage.Record{
					"createdAt": fixed.Add(-24 * time.Hour),
					"metadata":  map[string]any{"fromHook": true},
				}, nil
			},
			BeforeCreateInvitation: func(_ context.Context, data organization.BeforeCreateInvitationData) (storage.Record, error) {
				beforeInvitation = cloneOrganizationProductionRecord(data.Invitation)
				return storage.Record{
					"id":        "hook-invitation-id",
					"expiresAt": fixed.Add(7 * 24 * time.Hour),
				}, nil
			},
			AfterCreateInvitation: func(context.Context, organization.AfterCreateInvitationData) error {
				events = append(events, "after")
				return nil
			},
		},
		SendInvitationEmail: func(context.Context, organization.Invitation) error {
			events = append(events, "email")
			return nil
		},
	}
	auth, plugin := newOrganizationProductionFixAuthWithClock(t, options, func() time.Time { return fixed })
	owner := organizationProductionSignUp(t, auth, "Hook Owner", "hooks@production.test", model.Value[string]{})
	created, err := plugin.CreateOrganization(t.Context(), organization.CreateOrganizationInput{
		Name: "Hook Organization", Slug: "hook-organization", UserID: owner.ID,
		Metadata: map[string]any{"input": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := beforeOrganization["createdAt"]; exists {
		t.Fatalf("beforeCreateOrganization unexpectedly received createdAt: %#v", beforeOrganization)
	}
	if metadata, ok := beforeOrganization["metadata"].(map[string]any); !ok || metadata["input"] != true {
		t.Fatalf("beforeCreateOrganization metadata = %#v", beforeOrganization["metadata"])
	}
	if !created.CreatedAt.Equal(fixed) || created.Metadata["fromHook"] != true {
		t.Fatalf("created organization = %#v", created.Organization)
	}

	invitation, err := plugin.CreateInvitation(t.Context(), organization.CreateInvitationInput{
		OrganizationID: created.ID, InviterID: owner.ID,
		Email: "INVITED@PRODUCTION.TEST", Role: "member",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantInvitationKeys := []string{"email", "inviterId", "organizationId", "role", "teamIds"}
	actualInvitationKeys := make([]string, 0, len(beforeInvitation))
	for key := range beforeInvitation {
		actualInvitationKeys = append(actualInvitationKeys, key)
	}
	sort.Strings(actualInvitationKeys)
	if !reflect.DeepEqual(actualInvitationKeys, wantInvitationKeys) {
		t.Fatalf("beforeCreateInvitation keys = %#v, want %#v; payload=%#v", actualInvitationKeys, wantInvitationKeys, beforeInvitation)
	}
	teamIDs, ok := beforeInvitation["teamIds"].([]string)
	if !ok || len(teamIDs) != 0 || beforeInvitation["email"] != "invited@production.test" ||
		beforeInvitation["role"] != "member" || beforeInvitation["organizationId"] != created.ID ||
		beforeInvitation["inviterId"] != owner.ID {
		t.Fatalf("beforeCreateInvitation payload = %#v", beforeInvitation)
	}
	if invitation.ID != "hook-invitation-id" || !invitation.ExpiresAt.Equal(fixed.Add(7*24*time.Hour)) {
		t.Fatalf("created invitation = %#v", invitation)
	}
	if !reflect.DeepEqual(events, []string{"email", "after"}) {
		t.Fatalf("invitation lifecycle order = %#v", events)
	}
}

func TestCreateOrganizationMemberAndTeamHooksExcludeCreatedAtPayload(t *testing.T) {
	fixed := time.Date(2026, time.August, 9, 14, 0, 0, 0, time.UTC)
	poisoned := fixed.Add(-7 * 24 * time.Hour)
	var beforeMember storage.Record
	var beforeTeam storage.Record
	auth, plugin := newOrganizationProductionFixAuthWithClock(t, organization.Options{
		Teams: organization.TeamsOptions{Enabled: true},
		Hooks: organization.OrganizationHooks{
			BeforeAddMember: func(_ context.Context, data organization.BeforeAddMemberData) (storage.Record, error) {
				beforeMember = cloneOrganizationProductionRecord(data.Member)
				return storage.Record{"role": "hook-role", "createdAt": poisoned}, nil
			},
			BeforeCreateTeam: func(_ context.Context, data organization.BeforeCreateTeamData) (storage.Record, error) {
				beforeTeam = cloneOrganizationProductionRecord(data.Team)
				return storage.Record{"name": "Hook Team", "createdAt": poisoned}, nil
			},
		},
	}, func() time.Time { return fixed })
	owner := organizationProductionSignUp(t, auth, "Lifecycle Owner", "lifecycle@production.test", model.Value[string]{})
	created, err := plugin.CreateOrganization(t.Context(), organization.CreateOrganizationInput{
		Name: "Lifecycle Organization", Slug: "lifecycle-organization", UserID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := beforeMember["createdAt"]; exists {
		t.Fatalf("beforeAddMember unexpectedly received createdAt: %#v", beforeMember)
	}
	if _, exists := beforeTeam["createdAt"]; exists {
		t.Fatalf("beforeCreateTeam unexpectedly received createdAt: %#v", beforeTeam)
	}
	member, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "member", Where: []storage.Where{{Field: "organizationId", Value: created.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	memberCreatedAt, memberCreatedAtOK := member["createdAt"].(time.Time)
	if member == nil || member["role"] != "hook-role" || !memberCreatedAtOK || !memberCreatedAt.Equal(fixed) {
		t.Fatalf("persisted member = %#v", member)
	}
	team, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "team", Where: []storage.Where{{Field: "organizationId", Value: created.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	teamCreatedAt, teamCreatedAtOK := team["createdAt"].(time.Time)
	if team == nil || team["name"] != "Hook Team" || !teamCreatedAtOK || !teamCreatedAt.Equal(poisoned) {
		t.Fatalf("persisted team = %#v", team)
	}
}

func TestTeamUpdatedAtIsOmittedWhenAbsentAndEmittedWhenPresent(t *testing.T) {
	fixed := time.Date(2026, time.August, 9, 15, 0, 0, 0, time.UTC)
	auth, plugin := newOrganizationProductionFixAuthWithClock(t, organization.Options{
		Teams: organization.TeamsOptions{Enabled: true},
	}, func() time.Time { return fixed })
	owner := organizationProductionSignUp(t, auth, "Team Owner", "team-owner@production.test", model.Value[string]{})
	created, err := plugin.CreateOrganization(t.Context(), organization.CreateOrganizationInput{
		Name: "Optional Team Timestamp", Slug: "optional-team-timestamp", UserID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	teams, err := plugin.ListOrganizationTeams(t.Context(), created.ID)
	if err != nil || len(teams) != 1 {
		t.Fatalf("teams = %#v, %v", teams, err)
	}
	if teams[0].UpdatedAt != nil {
		t.Fatalf("absent updatedAt became %#v", teams[0].UpdatedAt)
	}
	withoutUpdatedAt, err := json.Marshal(teams[0])
	if err != nil {
		t.Fatal(err)
	}
	var without map[string]any
	if err := json.Unmarshal(withoutUpdatedAt, &without); err != nil {
		t.Fatal(err)
	}
	if _, exists := without["updatedAt"]; exists {
		t.Fatalf("absent updatedAt serialized: %s", withoutUpdatedAt)
	}

	present := fixed.Add(2 * time.Hour)
	updated, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "team", Where: []storage.Where{{Field: "id", Value: teams[0].ID}},
		Update: storage.Record{"updatedAt": present},
	})
	if err != nil || updated == nil {
		t.Fatalf("update team = %#v, %v", updated, err)
	}
	teams, err = plugin.ListOrganizationTeams(t.Context(), created.ID)
	if err != nil || len(teams) != 1 || teams[0].UpdatedAt == nil || !teams[0].UpdatedAt.Equal(present) {
		t.Fatalf("updated teams = %#v, %v", teams, err)
	}
	withUpdatedAt, err := json.Marshal(teams[0])
	if err != nil {
		t.Fatal(err)
	}
	var with map[string]any
	if err := json.Unmarshal(withUpdatedAt, &with); err != nil {
		t.Fatal(err)
	}
	if with["updatedAt"] != present.Format(time.RFC3339) {
		t.Fatalf("present updatedAt serialization = %s", withUpdatedAt)
	}
}

func newOrganizationProductionFixAuth(
	t *testing.T,
	options organization.Options,
) (*singleauth.Auth, *organization.Plugin) {
	t.Helper()
	return newOrganizationProductionFixAuthWithClock(t, options, time.Now)
}

func newOrganizationProductionFixAuthWithClock(
	t *testing.T,
	options organization.Options,
	clock func() time.Time,
) (*singleauth.Auth, *organization.Plugin) {
	t.Helper()
	plugin := organization.MustNew(options)
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://auth.example.test",
		Secret:  organizationProductionFixSecret,
		Clock:   clock,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return "hash:" + password, nil },
				Verify: func(hash, password string) bool { return hash == "hash:"+password },
			},
		},
		PluginFactories: []singleauth.PluginFactory{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth, plugin
}

func organizationProductionSignUp(
	t *testing.T,
	auth *singleauth.Auth,
	name string,
	email string,
	image model.Value[string],
) model.User {
	t.Helper()
	result, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: name, Email: email, Password: "password123", Image: image,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.User
}

func organizationProductionHTTPCreate(
	t *testing.T,
	auth *singleauth.Auth,
	cookieHeader string,
	body map[string]any,
) string {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"http://auth.example.test/api/auth/organization/create",
		bytes.NewReader(encoded),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://auth.example.test")
	request.Header.Set("Cookie", cookieHeader)
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("create organization status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	return organizationProductionObjectID(t, decoded)
}

func organizationProductionObjectID(t *testing.T, value any) string {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("organization value = %#v", value)
	}
	id, _ := object["id"].(string)
	if id == "" {
		t.Fatalf("organization object = %#v", object)
	}
	return id
}

func assertOrganizationCreator(
	t *testing.T,
	auth *singleauth.Auth,
	organizationID string,
	wantUserID string,
	forbiddenUserID string,
) {
	t.Helper()
	member, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "organizationId", Value: organizationID},
			{Field: "userId", Value: wantUserID},
		},
	})
	if err != nil || member == nil {
		t.Fatalf("creator membership = %#v, %v", member, err)
	}
	forbidden, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "member", Where: []storage.Where{
			{Field: "organizationId", Value: organizationID},
			{Field: "userId", Value: forbiddenUserID},
		},
	})
	if err != nil || forbidden != nil {
		t.Fatalf("unexpected impersonated membership = %#v, %v", forbidden, err)
	}
}

func assertOrganizationSessionState(
	t *testing.T,
	auth *singleauth.Auth,
	sessionToken string,
	organizationID string,
) {
	t.Helper()
	session, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: sessionToken}},
	})
	if err != nil || session == nil || session["activeOrganizationId"] != organizationID {
		t.Fatalf("active session = %#v, %v", session, err)
	}
	teams, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
		Model: "team", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
	})
	if err != nil || len(teams) != 1 || session["activeTeamId"] != teams[0]["id"] {
		t.Fatalf("active team session=%#v teams=%#v err=%v", session, teams, err)
	}
}

func cloneOrganizationProductionRecord(input storage.Record) storage.Record {
	result := make(storage.Record, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
