package organization_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestOrganizationTeamsAcrossTransports(t *testing.T) {
	for _, transport := range organizationCRUDTransports() {
		transport := transport
		t.Run(string(transport), func(t *testing.T) {
			runOrganizationTeamsTransportScenario(t)
		})
	}
}

func TestOrganizationTeamLimitsAreAtomicForConcurrentDirectCalls(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		defaultTeamEnabled := false
		var callbackMu sync.Mutex
		maximumTeamsCalls := 0
		maximumMembersCalls := 0
		harness := newOrganizationCRUDHarness(t, organization.Options{
			Teams: organization.TeamsOptions{
				Enabled: true, DefaultTeamEnabled: &defaultTeamEnabled,
				MaximumTeamsFunc: func(_ context.Context, data organization.MaximumTeamsData) (int, error) {
					callbackMu.Lock()
					maximumTeamsCalls++
					callbackMu.Unlock()
					if data.OrganizationID == "" {
						return 0, fmt.Errorf("maximumTeams callback received an empty organization id")
					}
					return 1, nil
				},
				MaximumMembersPerTeamFunc: func(_ context.Context, data organization.MaximumMembersPerTeamData) (int, error) {
					callbackMu.Lock()
					maximumMembersCalls++
					callbackMu.Unlock()
					if data.TeamID == "" || data.OrganizationID == "" || data.Session.User["id"] == nil {
						return 0, fmt.Errorf("maximumMembersPerTeam callback data=%#v", data)
					}
					return 1, nil
				},
			},
		})
		createdOrganization := harness.createHTTP(t, harness.owner, "Concurrent Teams", "concurrent-teams", nil)
		organizationID := organizationCRUDString(t, createdOrganization, "id")

		teamStatuses := concurrentOrganizationDirectStatuses(t, 2, func(index int) (int, error) {
			result, err := harness.auth.API().Call(t.Context(), "createTeam", singleauth.DirectCallInput{
				Method: http.MethodPost,
				Body: map[string]any{
					"name": "Concurrent " + string(rune('A'+index)), "organizationId": organizationID,
				},
			})
			return result.Response.Status(), err
		})
		requireConcurrentOrganizationStatuses(t, teamStatuses, http.StatusOK, http.StatusBadRequest)
		teams, err := harness.auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
			Model: "team", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
		})
		if err != nil || len(teams) != 1 {
			t.Fatalf("concurrent teams=%#v err=%v", teams, err)
		}
		teamID := organizationCRUDString(t, map[string]any(teams[0]), "id")

		first := harness.signUp(t, "concurrent-first@example.test", "Concurrent First")
		second := harness.signUp(t, "concurrent-second@example.test", "Concurrent Second")
		harness.addMemberDirect(t, organizationID, first)
		harness.addMemberDirect(t, organizationID, second)
		headers := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: harness.owner.Cookie})
		memberStatuses := concurrentOrganizationDirectStatuses(t, 2, func(index int) (int, error) {
			userID := first.ID
			if index == 1 {
				userID = second.ID
			}
			result, err := harness.auth.API().Call(t.Context(), "addTeamMember", singleauth.DirectCallInput{
				Method: http.MethodPost, Headers: headers,
				Body: map[string]any{"teamId": teamID, "userId": userID, "organizationId": organizationID},
			})
			return result.Response.Status(), err
		})
		requireConcurrentOrganizationStatuses(t, memberStatuses, http.StatusOK, http.StatusForbidden)
		count, err := harness.auth.Adapter().Count(t.Context(), storage.CountParams{
			Model: "teamMember", Where: []storage.Where{{Field: "teamId", Value: teamID}},
		})
		if err != nil || count != 1 {
			t.Fatalf("concurrent team member count=%d err=%v", count, err)
		}
		callbackMu.Lock()
		defer callbackMu.Unlock()
		if maximumTeamsCalls != 2 || maximumMembersCalls != 2 {
			t.Fatalf("limit callbacks teams=%d members=%d", maximumTeamsCalls, maximumMembersCalls)
		}
	})
}

func TestOrganizationTeamEndpointsAreConditional(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		response := harness.exchange(t, http.MethodGet, "/organization/list-teams", harness.owner.Cookie, nil)
		requireOrganizationCoreAPIError(t, response, http.StatusNotFound, "NOT_FOUND")
	})
}

func TestOrganizationTeamEndpointManifest(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		harness := newOrganizationCRUDHarness(t, organization.Options{
			Teams: organization.TeamsOptions{Enabled: true},
		})
		want := map[string]struct {
			path   string
			method string
		}{
			"createTeam":            {path: "/organization/create-team", method: http.MethodPost},
			"removeTeam":            {path: "/organization/remove-team", method: http.MethodPost},
			"updateTeam":            {path: "/organization/update-team", method: http.MethodPost},
			"listOrganizationTeams": {path: "/organization/list-teams", method: http.MethodGet},
			"setActiveTeam":         {path: "/organization/set-active-team", method: http.MethodPost},
			"listUserTeams":         {path: "/organization/list-user-teams", method: http.MethodGet},
			"listTeamMembers":       {path: "/organization/list-team-members", method: http.MethodGet},
			"addTeamMember":         {path: "/organization/add-team-member", method: http.MethodPost},
			"removeTeamMember":      {path: "/organization/remove-team-member", method: http.MethodPost},
		}
		for name, expected := range want {
			endpoint, ok := harness.auth.Registry().Endpoint(name)
			if !ok || endpoint.Path != expected.path || len(endpoint.Methods) != 1 || endpoint.Methods[0] != expected.method {
				t.Fatalf("endpoint %s=%#v exists=%v want path=%q method=%q", name, endpoint, ok, expected.path, expected.method)
			}
		}
		if _, exists := harness.auth.Registry().Endpoint("getFullTeam"); exists {
			t.Fatal("invented getFullTeam endpoint is registered; single-auth 1.6.26 has no such route")
		}
	})
}

func TestOrganizationCustomDefaultTeamCreator(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		var callbackMu sync.Mutex
		beforeCalled := false
		afterCalled := false
		harness := newOrganizationCRUDHarness(t, organization.Options{
			Teams: organization.TeamsOptions{
				Enabled: true,
				CustomCreateDefaultTeam: func(
					ctx context.Context,
					adapter storage.TransactionAdapter,
					organizationRecord storage.Record,
				) (storage.Record, error) {
					organizationID, _ := organizationRecord["id"].(string)
					name, _ := organizationRecord["name"].(string)
					if organizationID == "" || name == "" {
						return nil, fmt.Errorf("custom default team organization=%#v", organizationRecord)
					}
					return adapter.Create(ctx, storage.CreateParams{
						Model: "team", ForceAllowID: true,
						Data: storage.Record{
							"id": "custom-default-team", "name": "Custom " + name,
							"organizationId": organizationID,
							"createdAt":      time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC),
						},
					})
				},
			},
			Hooks: organization.OrganizationHooks{
				BeforeCreateTeam: func(context.Context, organization.BeforeCreateTeamData) (storage.Record, error) {
					callbackMu.Lock()
					beforeCalled = true
					callbackMu.Unlock()
					return storage.Record{"name": "Ignored by custom creator"}, nil
				},
				AfterCreateTeam: func(_ context.Context, data organization.AfterCreateTeamData) error {
					callbackMu.Lock()
					afterCalled = true
					callbackMu.Unlock()
					if data.Team.ID != "custom-default-team" {
						return fmt.Errorf("afterCreateTeam team=%#v", data.Team)
					}
					return nil
				},
			},
		})
		created := harness.createHTTP(t, harness.owner, "Custom Default", "custom-default", nil)
		organizationID := organizationCRUDString(t, created, "id")
		teams := harness.exchange(t, http.MethodGet, "/organization/list-teams?organizationId="+url.QueryEscape(organizationID), harness.owner.Cookie, nil)
		requireOrganizationCRUDStatus(t, teams, http.StatusOK)
		listed := organizationCRUDArray(t, teams.Value, "custom default teams")
		if len(listed) != 1 {
			t.Fatalf("custom default teams=%#v", listed)
		}
		team := organizationCRUDObject(t, listed[0], "custom default team")
		if team["id"] != "custom-default-team" || team["name"] != "Custom Custom Default" {
			t.Fatalf("custom default team=%#v", team)
		}
		teamMember, err := harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "teamMember", Where: []storage.Where{
				{Field: "teamId", Value: "custom-default-team"}, {Field: "userId", Value: harness.owner.ID},
			},
		})
		if err != nil || teamMember == nil {
			t.Fatalf("custom default team member=%#v err=%v", teamMember, err)
		}
		sessionValue := harness.requireSession(t, harness.owner, &organizationID)
		session := organizationCRUDObject(t, sessionValue["session"], "custom default session")
		if session["activeTeamId"] != "custom-default-team" {
			t.Fatalf("activeTeamId=%#v session=%#v", session["activeTeamId"], session)
		}
		callbackMu.Lock()
		defer callbackMu.Unlock()
		if !beforeCalled || !afterCalled {
			t.Fatalf("custom default hooks before=%v after=%v", beforeCalled, afterCalled)
		}
	})
}

func runOrganizationTeamsTransportScenario(t *testing.T) {
	defaultTeamEnabled := false
	maximumMembers := 2
	var hookMu sync.Mutex
	hookCalls := map[string]int{}
	recordHook := func(name string) {
		hookMu.Lock()
		hookCalls[name]++
		hookMu.Unlock()
	}
	harness := newOrganizationCRUDHarness(t, organization.Options{
		Teams: organization.TeamsOptions{
			Enabled: true, DefaultTeamEnabled: &defaultTeamEnabled,
			MaximumTeams: 2, MaximumMembersPerTeam: &maximumMembers,
		},
		Schema: organizationTeamAdditionalSchema(),
		Hooks: organization.OrganizationHooks{
			BeforeCreateTeam: func(_ context.Context, data organization.BeforeCreateTeamData) (storage.Record, error) {
				recordHook("before-create")
				if data.Team["createdAt"] != nil || data.Team["updatedAt"] != nil || data.OrganizationRecord["id"] == nil {
					t.Fatalf("beforeCreateTeam data=%#v", data)
				}
				return nil, nil
			},
			AfterCreateTeam: func(_ context.Context, data organization.AfterCreateTeamData) error {
				recordHook("after-create")
				if data.Team.ID == "" || data.TeamRecord["color"] == nil || data.OrganizationRecord["id"] == nil {
					t.Fatalf("afterCreateTeam data=%#v", data)
				}
				return nil
			},
			BeforeUpdateTeam: func(_ context.Context, data organization.BeforeUpdateTeamData) (storage.Record, error) {
				recordHook("before-update")
				return storage.Record{"name": "Hooked Team", "color": data.Updates["color"], "secret": "updated-secret"}, nil
			},
			AfterUpdateTeam: func(_ context.Context, data organization.AfterUpdateTeamData) error {
				recordHook("after-update")
				if data.Team["name"] != "Hooked Team" || data.Team["secret"] != "updated-secret" {
					t.Fatalf("afterUpdateTeam data=%#v", data)
				}
				return nil
			},
			BeforeDeleteTeam: func(_ context.Context, data organization.TeamLifecycleHookData) error {
				recordHook("before-delete")
				if data.Team["id"] == nil || data.Organization["id"] == nil {
					t.Fatalf("beforeDeleteTeam data=%#v", data)
				}
				return nil
			},
			AfterDeleteTeam: func(_ context.Context, data organization.TeamLifecycleHookData) error {
				recordHook("after-delete")
				return nil
			},
			BeforeAddTeamMember: func(_ context.Context, data organization.BeforeAddTeamMemberData) (storage.Record, error) {
				recordHook("before-add-member")
				return storage.Record{"userId": "ignored-by-upstream"}, nil
			},
			AfterAddTeamMember: func(_ context.Context, data organization.TeamMemberLifecycleHookData) error {
				recordHook("after-add-member")
				if data.TeamMember["id"] == nil || data.User["id"] == nil {
					t.Fatalf("afterAddTeamMember data=%#v", data)
				}
				return nil
			},
			BeforeRemoveTeamMember: func(_ context.Context, data organization.TeamMemberLifecycleHookData) error {
				recordHook("before-remove-member")
				return nil
			},
			AfterRemoveTeamMember: func(_ context.Context, data organization.TeamMemberLifecycleHookData) error {
				recordHook("after-remove-member")
				return nil
			},
		},
	})
	createdOrganization := harness.createHTTP(t, harness.owner, "Teams Org", "teams-org", nil)
	organizationID := organizationCRUDString(t, createdOrganization, "id")

	unauthorized := harness.exchange(t, http.MethodPost, "/organization/create-team", "", map[string]any{
		"name": "Unauthorized", "organizationId": organizationID, "color": "black",
	})
	requireOrganizationCoreAPIError(t, unauthorized, http.StatusUnauthorized, "UNAUTHORIZED")
	directWithHeaders, _ := harness.auth.API().Call(t.Context(), "createTeam", singleauth.DirectCallInput{
		Method:  http.MethodPost,
		Headers: contract.NewHeaders(contract.HeaderField{Name: "X-Untrusted-Direct", Value: "true"}),
		Body: map[string]any{
			"name": "Unauthorized Direct", "organizationId": organizationID, "color": "black",
		},
	})
	if directWithHeaders.Response.Status() != http.StatusUnauthorized {
		t.Fatalf("direct create with headers status=%d body=%s", directWithHeaders.Response.Status(), directWithHeaders.Response.Body())
	}

	directCreated := harness.invoke(t, "createTeam", map[string]any{
		"name": "Direct Team", "organizationId": organizationID,
		"color": "red", "secret": "direct-secret",
	})
	requireOrganizationCRUDStatus(t, directCreated, http.StatusOK)
	firstTeam := organizationCRUDObject(t, directCreated.Value, "direct createTeam")
	firstTeamID := organizationCRUDString(t, firstTeam, "id")
	requireOrganizationTeamPublicFields(t, firstTeam, organizationID, "Direct Team", "red")

	created := harness.exchange(t, http.MethodPost, "/organization/create-team", harness.owner.Cookie, map[string]any{
		"name": "HTTP Team", "organizationId": organizationID,
		"color": "blue", "secret": "http-secret",
	})
	requireOrganizationCRUDStatus(t, created, http.StatusOK)
	secondTeam := organizationCRUDObject(t, created.Value, "HTTP createTeam")
	secondTeamID := organizationCRUDString(t, secondTeam, "id")
	requireOrganizationTeamPublicFields(t, secondTeam, organizationID, "HTTP Team", "blue")

	limitReached := harness.exchange(t, http.MethodPost, "/organization/create-team", harness.owner.Cookie, map[string]any{
		"name": "Third Team", "organizationId": organizationID, "color": "green",
	})
	requireOrganizationCoreAPIError(t, limitReached, http.StatusBadRequest, organization.ErrorMaximumTeamsReached)

	listed := harness.exchange(t, http.MethodGet, "/organization/list-teams?organizationId="+url.QueryEscape(organizationID), harness.owner.Cookie, nil)
	requireOrganizationCRUDStatus(t, listed, http.StatusOK)
	if teams := organizationCRUDArray(t, listed.Value, "list teams"); len(teams) != 2 {
		t.Fatalf("list teams=%#v body=%s", teams, listed.Body)
	}

	updated := harness.exchange(t, http.MethodPost, "/organization/update-team", harness.owner.Cookie, map[string]any{
		"teamId": secondTeamID,
		"data":   map[string]any{"name": "Requested Name", "organizationId": organizationID, "color": "violet"},
	})
	requireOrganizationCRUDStatus(t, updated, http.StatusOK)
	updatedTeam := organizationCRUDObject(t, updated.Value, "update team")
	requireOrganizationTeamPublicFields(t, updatedTeam, organizationID, "Hooked Team", "violet")

	member := harness.signUp(t, "team-member@example.test", "Team Member")
	third := harness.signUp(t, "team-third@example.test", "Team Third")
	harness.addMemberDirect(t, organizationID, member)
	harness.addMemberDirect(t, organizationID, third)
	harness.setActiveHTTP(t, member, map[string]any{"organizationId": organizationID}, &organizationID)

	memberCreate := harness.exchange(t, http.MethodPost, "/organization/create-team", member.Cookie, map[string]any{
		"name": "Denied", "organizationId": organizationID, "color": "gray",
	})
	requireOrganizationCoreAPIError(t, memberCreate, http.StatusForbidden, organization.ErrorTeamCreateForbidden)
	memberUpdate := harness.exchange(t, http.MethodPost, "/organization/update-team", member.Cookie, map[string]any{
		"teamId": firstTeamID, "data": map[string]any{"organizationId": organizationID, "name": "Denied"},
	})
	requireOrganizationCoreAPIError(t, memberUpdate, http.StatusForbidden, organization.ErrorTeamUpdateForbidden)
	memberAdd := harness.exchange(t, http.MethodPost, "/organization/add-team-member", member.Cookie, map[string]any{
		"teamId": firstTeamID, "userId": member.ID, "organizationId": organizationID,
	})
	requireOrganizationCoreAPIError(t, memberAdd, http.StatusForbidden, organization.ErrorTeamMemberCreateForbidden)

	ownerTeamMember := addOrganizationTeamMember(t, harness, organizationID, firstTeamID, harness.owner.ID)
	memberTeamMember := addOrganizationTeamMember(t, harness, organizationID, firstTeamID, member.ID)
	replayedMember := addOrganizationTeamMember(t, harness, organizationID, firstTeamID, member.ID)
	if replayedMember["id"] != memberTeamMember["id"] {
		t.Fatalf("idempotent add returned %#v want id=%#v", replayedMember, memberTeamMember["id"])
	}
	if ownerTeamMember["userId"] != harness.owner.ID || memberTeamMember["userId"] != member.ID {
		t.Fatalf("team members owner=%#v member=%#v", ownerTeamMember, memberTeamMember)
	}
	memberLimit := harness.exchange(t, http.MethodPost, "/organization/add-team-member", harness.owner.Cookie, map[string]any{
		"teamId": firstTeamID, "userId": third.ID, "organizationId": organizationID,
	})
	requireOrganizationCoreAPIError(t, memberLimit, http.StatusForbidden, organization.ErrorTeamMemberLimitReached)

	memberTeams := harness.exchange(t, http.MethodGet, "/organization/list-user-teams", member.Cookie, nil)
	requireOrganizationCRUDStatus(t, memberTeams, http.StatusOK)
	if teams := organizationCRUDArray(t, memberTeams.Value, "member teams"); len(teams) != 1 || organizationCRUDObject(t, teams[0], "member team")["id"] != firstTeamID {
		t.Fatalf("member teams=%#v body=%s", teams, memberTeams.Body)
	}
	members := harness.exchange(t, http.MethodGet, "/organization/list-team-members?teamId="+url.QueryEscape(firstTeamID), member.Cookie, nil)
	requireOrganizationCRUDStatus(t, members, http.StatusOK)
	if values := organizationCRUDArray(t, members.Value, "team members"); len(values) != 2 {
		t.Fatalf("team members=%#v body=%s", values, members.Body)
	}

	active := harness.exchange(t, http.MethodPost, "/organization/set-active-team", member.Cookie, map[string]any{"teamId": firstTeamID})
	requireOrganizationCRUDStatus(t, active, http.StatusOK)
	if organizationCRUDObject(t, active.Value, "set active team")["id"] != firstTeamID || len(active.Headers.Values("Set-Cookie")) == 0 {
		t.Fatalf("set active response=%#v headers=%#v", active.Value, active.Headers)
	}
	activeMembers := harness.exchange(t, http.MethodGet, "/organization/list-team-members", member.Cookie, nil)
	requireOrganizationCRUDStatus(t, activeMembers, http.StatusOK)
	wrongTeam := harness.exchange(t, http.MethodPost, "/organization/set-active-team", member.Cookie, map[string]any{"teamId": secondTeamID})
	requireOrganizationCoreAPIError(t, wrongTeam, http.StatusForbidden, organization.ErrorUserNotTeamMember)
	persistedMemberSession, err := harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: member.Token}},
	})
	if err != nil || persistedMemberSession["activeTeamId"] != firstTeamID {
		t.Fatalf("failed set-active changed session=%#v err=%v", persistedMemberSession, err)
	}

	// The owner's active team is still empty; make it active first to exercise
	// the exact single-auth deletion guard.
	ownerActive := harness.exchange(t, http.MethodPost, "/organization/set-active-team", harness.owner.Cookie, map[string]any{"teamId": firstTeamID})
	requireOrganizationCRUDStatus(t, ownerActive, http.StatusOK)
	removeActive := harness.exchange(t, http.MethodPost, "/organization/remove-team", harness.owner.Cookie, map[string]any{
		"teamId": firstTeamID, "organizationId": organizationID,
	})
	requireOrganizationCoreAPIError(t, removeActive, http.StatusForbidden, organization.ErrorTeamDeleteActiveForbidden)
	cleared := harness.exchange(t, http.MethodPost, "/organization/set-active-team", harness.owner.Cookie, map[string]any{"teamId": nil})
	requireOrganizationCRUDStatus(t, cleared, http.StatusOK)
	if cleared.Value != nil {
		t.Fatalf("clear active team=%#v body=%s", cleared.Value, cleared.Body)
	}
	clearedAgain := harness.exchange(t, http.MethodPost, "/organization/set-active-team", harness.owner.Cookie, map[string]any{"teamId": nil})
	requireOrganizationCRUDStatus(t, clearedAgain, http.StatusOK)
	if clearedAgain.Value != nil || len(clearedAgain.Headers.Values("Set-Cookie")) != 0 {
		t.Fatalf("idempotent clear response=%#v headers=%#v", clearedAgain.Value, clearedAgain.Headers)
	}

	removedMember := harness.exchange(t, http.MethodPost, "/organization/remove-team-member", harness.owner.Cookie, map[string]any{
		"teamId": firstTeamID, "userId": member.ID, "organizationId": organizationID,
	})
	requireOrganizationCRUDStatus(t, removedMember, http.StatusOK)
	addOrganizationTeamMember(t, harness, organizationID, firstTeamID, third.ID)
	staleActiveMembership := harness.exchange(t, http.MethodGet, "/organization/list-team-members", member.Cookie, nil)
	requireOrganizationCoreAPIError(t, staleActiveMembership, http.StatusBadRequest, organization.ErrorUserNotTeamMember)

	invitee := harness.signUp(t, "team-invitee@example.test", "Team Invitee")
	noActiveTeam := harness.exchange(t, http.MethodGet, "/organization/list-team-members", invitee.Cookie, nil)
	requireOrganizationCoreAPIError(t, noActiveTeam, http.StatusBadRequest, organization.ErrorNoActiveTeam)
	nonMemberList := harness.exchange(t, http.MethodGet, "/organization/list-teams?organizationId="+url.QueryEscape(organizationID), invitee.Cookie, nil)
	requireOrganizationCoreAPIError(t, nonMemberList, http.StatusForbidden, organization.ErrorOrganizationAccessForbidden)
	if _, err := harness.auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "teamMember", Data: storage.Record{
			"teamId": secondTeamID, "userId": invitee.ID,
		},
	}); err != nil {
		t.Fatal(err)
	}
	strayTeams := harness.exchange(t, http.MethodGet, "/organization/list-user-teams", invitee.Cookie, nil)
	requireOrganizationCRUDStatus(t, strayTeams, http.StatusOK)
	if teams := organizationCRUDArray(t, strayTeams.Value, "stray user teams"); len(teams) != 0 {
		t.Fatalf("stray team membership leaked metadata: %#v", teams)
	}
	strayMembers := harness.exchange(t, http.MethodGet, "/organization/list-team-members?teamId="+url.QueryEscape(secondTeamID), invitee.Cookie, nil)
	requireOrganizationCoreAPIError(t, strayMembers, http.StatusBadRequest, organization.ErrorUserNotTeamMember)
	invited := harness.exchange(t, http.MethodPost, "/organization/invite-member", harness.owner.Cookie, map[string]any{
		"organizationId": organizationID, "email": invitee.Email, "role": "member", "teamId": firstTeamID,
	})
	requireOrganizationCRUDStatus(t, invited, http.StatusOK)
	invitationID := organizationCRUDString(t, organizationCRUDObject(t, invited.Value, "team invitation"), "id")

	removed := harness.exchange(t, http.MethodPost, "/organization/remove-team", harness.owner.Cookie, map[string]any{
		"teamId": firstTeamID, "organizationId": organizationID,
	})
	requireOrganizationCRUDStatus(t, removed, http.StatusOK)
	persistedInvitation, err := harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "invitation", Where: []storage.Where{{Field: "id", Value: invitationID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if value, exists := persistedInvitation["teamId"]; exists && value != nil && value != "" {
		t.Fatalf("removed team remained on invitation: %#v", persistedInvitation)
	}
	for _, model := range []string{"team", "teamMember"} {
		where := []storage.Where{{Field: "id", Value: firstTeamID}}
		if model == "teamMember" {
			where = []storage.Where{{Field: "teamId", Value: firstTeamID}}
		}
		count, countErr := harness.auth.Adapter().Count(t.Context(), storage.CountParams{Model: model, Where: where})
		if countErr != nil || count != 0 {
			t.Fatalf("%s cascade count=%d err=%v", model, count, countErr)
		}
	}

	replacement := harness.invoke(t, "createTeam", map[string]any{
		"name": "Replacement", "organizationId": organizationID, "color": "gold",
	})
	requireOrganizationCRUDStatus(t, replacement, http.StatusOK)
	replacementID := organizationCRUDString(t, organizationCRUDObject(t, replacement.Value, "replacement team"), "id")
	directRemoved := harness.invoke(t, "removeTeam", map[string]any{
		"teamId": replacementID, "organizationId": organizationID,
	})
	requireOrganizationCRUDStatus(t, directRemoved, http.StatusOK)
	lastTeam := harness.exchange(t, http.MethodPost, "/organization/remove-team", harness.owner.Cookie, map[string]any{
		"teamId": secondTeamID, "organizationId": organizationID,
	})
	requireOrganizationCoreAPIError(t, lastTeam, http.StatusBadRequest, organization.ErrorUnableToRemoveLastTeam)

	otherOrganization := harness.createHTTP(t, harness.owner, "Other Teams Org", "other-teams-org", nil)
	otherOrganizationID := organizationCRUDString(t, otherOrganization, "id")
	otherCreated := harness.invoke(t, "createTeam", map[string]any{
		"name": "Other Team", "organizationId": otherOrganizationID, "color": "silver",
	})
	requireOrganizationCRUDStatus(t, otherCreated, http.StatusOK)
	otherTeamID := organizationCRUDString(t, organizationCRUDObject(t, otherCreated.Value, "other team"), "id")
	crossUpdate := harness.exchange(t, http.MethodPost, "/organization/update-team", harness.owner.Cookie, map[string]any{
		"teamId": otherTeamID, "data": map[string]any{"organizationId": organizationID, "name": "Cross Org"},
	})
	requireOrganizationCoreAPIError(t, crossUpdate, http.StatusBadRequest, organization.ErrorTeamNotFound)
	crossRemove := harness.exchange(t, http.MethodPost, "/organization/remove-team", harness.owner.Cookie, map[string]any{
		"teamId": otherTeamID, "organizationId": organizationID,
	})
	requireOrganizationCoreAPIError(t, crossRemove, http.StatusBadRequest, organization.ErrorTeamNotFound)
	crossActive := harness.exchange(t, http.MethodPost, "/organization/set-active-team", harness.owner.Cookie, map[string]any{"teamId": secondTeamID})
	requireOrganizationCoreAPIError(t, crossActive, http.StatusBadRequest, organization.ErrorTeamNotFound)

	malformed := harness.exchangeEncoded(t, http.MethodPost, "/organization/create-team", harness.owner.Cookie, true, []byte("{"))
	if malformed.Status != http.StatusBadRequest {
		t.Fatalf("malformed create-team status=%d body=%s", malformed.Status, malformed.Body)
	}
	invalidSetActive := harness.exchange(t, http.MethodPost, "/organization/set-active-team", harness.owner.Cookie, map[string]any{"teamId": 42})
	requireOrganizationCoreAPIError(t, invalidSetActive, http.StatusBadRequest, "VALIDATION_ERROR")

	hookMu.Lock()
	defer hookMu.Unlock()
	for _, name := range []string{
		"before-create", "after-create", "before-update", "after-update",
		"before-delete", "after-delete", "before-add-member", "after-add-member",
		"before-remove-member", "after-remove-member",
	} {
		if hookCalls[name] == 0 {
			t.Fatalf("hook %s was not called: %#v", name, hookCalls)
		}
	}
}

func organizationTeamAdditionalSchema() storage.Schema {
	optional := storage.Bool(false)
	hidden := storage.Bool(false)
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"team": {Fields: map[string]storage.FieldAttribute{
			"color":  {Type: storage.FieldString, Required: optional},
			"secret": {Type: storage.FieldString, Required: optional, Returned: hidden},
		}},
	}}
}

func requireOrganizationTeamPublicFields(
	t *testing.T,
	team map[string]any,
	organizationID string,
	name string,
	color string,
) {
	t.Helper()
	if team["organizationId"] != organizationID || team["name"] != name || team["color"] != color {
		t.Fatalf("team=%#v want org=%q name=%q color=%q", team, organizationID, name, color)
	}
	if team["secret"] != nil {
		t.Fatalf("returned:false team field leaked: %#v", team)
	}
	requireOrganizationCRUDTimestamp(t, team, "createdAt")
}

func addOrganizationTeamMember(
	t *testing.T,
	harness *organizationCRUDHarness,
	organizationID string,
	teamID string,
	userID string,
) map[string]any {
	t.Helper()
	response := harness.exchange(t, http.MethodPost, "/organization/add-team-member", harness.owner.Cookie, map[string]any{
		"teamId": teamID, "userId": userID, "organizationId": organizationID,
	})
	requireOrganizationCRUDStatus(t, response, http.StatusOK)
	return organizationCRUDObject(t, response.Value, "add team member")
}

type concurrentOrganizationStatus struct {
	status int
	err    error
}

func concurrentOrganizationDirectStatuses(
	t *testing.T,
	count int,
	call func(int) (int, error),
) []concurrentOrganizationStatus {
	t.Helper()
	start := make(chan struct{})
	results := make(chan concurrentOrganizationStatus, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			status, err := call(index)
			results <- concurrentOrganizationStatus{status: status, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	statuses := make([]concurrentOrganizationStatus, 0, count)
	for result := range results {
		statuses = append(statuses, result)
	}
	return statuses
}

func requireConcurrentOrganizationStatuses(
	t *testing.T,
	actual []concurrentOrganizationStatus,
	want ...int,
) {
	t.Helper()
	counts := make(map[int]int, len(actual))
	for _, result := range actual {
		if result.status == 0 {
			t.Fatalf("direct call returned no response: %v", result.err)
		}
		counts[result.status]++
	}
	for _, status := range want {
		if counts[status] != 1 {
			t.Fatalf("concurrent statuses=%#v want one %d; results=%#v", counts, status, actual)
		}
	}
}
