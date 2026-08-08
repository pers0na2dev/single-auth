package organization_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestOrganizationInvitationLifecycleAcrossNetHTTPFastHTTPAndFiber(t *testing.T) {
	for _, transport := range organizationCRUDTransports() {
		transport := transport
		t.Run(string(transport), func(t *testing.T) {
			harness := newOrganizationCRUDHarness(t, organization.Options{})
			created := harness.createHTTP(t, harness.owner, "Invitation Organization", "invitation-organization", nil)
			organizationID := organizationCRUDString(t, created, "id")

			recipient := harness.signUp(t, "mixed.recipient@example.test", "Mixed Recipient")
			pending := inviteOrganizationUser(
				t, harness, organizationID, "MiXeD.ReCiPiEnT@Example.Test", "member",
			)
			invitationID := organizationCRUDString(t, pending, "id")
			if pending["email"] != recipient.Email || pending["status"] != "pending" {
				t.Fatalf("created invitation=%#v recipient=%#v", pending, recipient)
			}

			got := harness.exchange(
				t, http.MethodGet,
				"/organization/get-invitation?id="+url.QueryEscape(invitationID),
				recipient.Cookie, nil,
			)
			requireOrganizationCRUDStatus(t, got, http.StatusOK)
			gotInvitation := organizationCRUDObject(t, got.Value, "get invitation")
			if gotInvitation["id"] != invitationID ||
				gotInvitation["organizationName"] != "Invitation Organization" ||
				gotInvitation["organizationSlug"] != "invitation-organization" ||
				gotInvitation["inviterEmail"] != harness.owner.Email {
				t.Fatalf("get invitation=%#v body=%s", gotInvitation, got.Body)
			}

			unverifiedList := harness.exchange(
				t, http.MethodGet, "/organization/list-user-invitations", recipient.Cookie, nil,
			)
			requireOrganizationCRUDWireError(
				t, unverifiedList, http.StatusForbidden,
				organization.ErrorInvitationListUnverified,
				"Email verification required to view or list invitations for the session email",
			)
			markOrganizationUserEmailVerified(t, harness, recipient.ID)
			userList := harness.exchange(
				t, http.MethodGet, "/organization/list-user-invitations", recipient.Cookie, nil,
			)
			requireOrganizationCRUDStatus(t, userList, http.StatusOK)
			userInvitations := organizationCRUDArray(t, userList.Value, "user invitations")
			if len(userInvitations) != 1 {
				t.Fatalf("user invitations=%#v body=%s", userInvitations, userList.Body)
			}
			userInvitation := organizationCRUDObject(t, userInvitations[0], "user invitation")
			if userInvitation["id"] != invitationID ||
				userInvitation["organizationName"] != "Invitation Organization" ||
				userInvitation["status"] != "pending" {
				t.Fatalf("user invitation=%#v body=%s", userInvitation, userList.Body)
			}

			accepted := harness.exchange(
				t, http.MethodPost, "/organization/accept-invitation", recipient.Cookie,
				map[string]any{"invitationId": invitationID},
			)
			requireOrganizationCRUDStatus(t, accepted, http.StatusOK)
			acceptedBody := organizationCRUDObject(t, accepted.Value, "accept invitation")
			acceptedInvitation := organizationCRUDObject(t, acceptedBody["invitation"], "accepted invitation")
			acceptedMember := organizationCRUDObject(t, acceptedBody["member"], "accepted member")
			if acceptedInvitation["status"] != "accepted" ||
				acceptedMember["organizationId"] != organizationID ||
				acceptedMember["userId"] != recipient.ID || acceptedMember["role"] != "member" {
				t.Fatalf("accept response=%#v body=%s", acceptedBody, accepted.Body)
			}
			harness.requireSession(t, recipient, &organizationID)

			replayed := harness.exchange(
				t, http.MethodPost, "/organization/accept-invitation", recipient.Cookie,
				map[string]any{"invitationId": invitationID},
			)
			requireOrganizationCRUDWireError(
				t, replayed, http.StatusBadRequest, organization.ErrorInvitationNotFound,
				"Invitation not found",
			)
			afterAcceptList := harness.exchange(
				t, http.MethodGet, "/organization/list-user-invitations", recipient.Cookie, nil,
			)
			requireOrganizationCRUDStatus(t, afterAcceptList, http.StatusOK)
			if invitations := organizationCRUDArray(t, afterAcceptList.Value, "post-accept invitations"); len(invitations) != 0 {
				t.Fatalf("post-accept invitations=%#v", invitations)
			}

			rejectee := harness.signUp(t, "rejectee@example.test", "Rejectee")
			rejectInvitation := inviteOrganizationUser(
				t, harness, organizationID, strings.ToUpper(rejectee.Email), "member",
			)
			rejectInvitationID := organizationCRUDString(t, rejectInvitation, "id")
			if _, err := harness.auth.Adapter().Update(t.Context(), storage.UpdateParams{
				Model: "invitation", Where: []storage.Where{{Field: "id", Value: rejectInvitationID}},
				Update: storage.Record{"expiresAt": time.Now().Add(-time.Hour)},
			}); err != nil {
				t.Fatal(err)
			}
			rejected := harness.exchange(
				t, http.MethodPost, "/organization/reject-invitation", rejectee.Cookie,
				map[string]any{"invitationId": rejectInvitationID},
			)
			requireOrganizationCRUDStatus(t, rejected, http.StatusOK)
			rejectedBody := organizationCRUDObject(t, rejected.Value, "reject invitation")
			rejectedInvitation := organizationCRUDObject(t, rejectedBody["invitation"], "rejected invitation")
			if rejectedInvitation["status"] != "rejected" || rejectedBody["member"] != nil {
				t.Fatalf("reject response=%#v body=%s", rejectedBody, rejected.Body)
			}
			replayedReject := harness.exchange(
				t, http.MethodPost, "/organization/reject-invitation", rejectee.Cookie,
				map[string]any{"invitationId": rejectInvitationID},
			)
			requireOrganizationCRUDWireError(
				t, replayedReject, http.StatusBadRequest, organization.ErrorInvitationNotFound,
				"Invitation not found",
			)

			cancelRecipient := harness.signUp(t, "cancel-recipient@example.test", "Cancel Recipient")
			cancelInvitation := inviteOrganizationUser(
				t, harness, organizationID, cancelRecipient.Email, "member",
			)
			cancelInvitationID := organizationCRUDString(t, cancelInvitation, "id")
			nonMemberCancel := harness.exchange(
				t, http.MethodPost, "/organization/cancel-invitation", cancelRecipient.Cookie,
				map[string]any{"invitationId": cancelInvitationID},
			)
			requireOrganizationCRUDWireError(
				t, nonMemberCancel, http.StatusBadRequest, organization.ErrorMemberNotFound,
				"Member not found",
			)
			for attempt := 0; attempt < 2; attempt++ {
				canceled := harness.exchange(
					t, http.MethodPost, "/organization/cancel-invitation", harness.owner.Cookie,
					map[string]any{"invitationId": cancelInvitationID},
				)
				requireOrganizationCRUDStatus(t, canceled, http.StatusOK)
				canceledInvitation := organizationCRUDObject(t, canceled.Value, "canceled invitation")
				if canceledInvitation["status"] != "canceled" {
					t.Fatalf("cancel attempt %d response=%#v", attempt, canceledInvitation)
				}
			}

			organizationList := harness.exchange(
				t, http.MethodGet,
				"/organization/list-invitations?organizationId="+url.QueryEscape(organizationID),
				harness.owner.Cookie, nil,
			)
			requireOrganizationCRUDStatus(t, organizationList, http.StatusOK)
			listed := organizationCRUDArray(t, organizationList.Value, "organization invitations")
			if len(listed) != 3 {
				t.Fatalf("organization invitation count=%d want 3 body=%s", len(listed), organizationList.Body)
			}
			statuses := make(map[string]string, len(listed))
			for _, raw := range listed {
				invitation := organizationCRUDObject(t, raw, "listed invitation")
				statuses[organizationCRUDString(t, invitation, "id")] = organizationCRUDString(t, invitation, "status")
			}
			if statuses[invitationID] != "accepted" || statuses[rejectInvitationID] != "rejected" ||
				statuses[cancelInvitationID] != "canceled" {
				t.Fatalf("listed statuses=%#v", statuses)
			}
		})
	}
}

func TestInvitationByIDEmailVerificationGateTracksRootGenerateID(t *testing.T) {
	harness := newCustomGenerateIDOrganizationHarness(t, organization.Options{})
	recipient := harness.signUp(t, "unverified-recipient@example.test", "Unverified Recipient")

	operations := []struct {
		name        string
		method      string
		path        func(string) string
		body        func(string) any
		wantCode    string
		wantMessage string
	}{
		{
			name: "accept", method: http.MethodPost,
			path:        func(string) string { return "/organization/accept-invitation" },
			body:        func(id string) any { return map[string]any{"invitationId": id} },
			wantCode:    organization.ErrorInvitationEmailUnverified,
			wantMessage: "Email verification required before accepting or rejecting invitation",
		},
		{
			name: "reject", method: http.MethodPost,
			path:        func(string) string { return "/organization/reject-invitation" },
			body:        func(id string) any { return map[string]any{"invitationId": id} },
			wantCode:    organization.ErrorInvitationEmailUnverified,
			wantMessage: "Email verification required before accepting or rejecting invitation",
		},
		{
			name: "get", method: http.MethodGet,
			path: func(id string) string {
				return "/organization/get-invitation?id=" + url.QueryEscape(id)
			},
			body:        func(string) any { return nil },
			wantCode:    organization.ErrorInvitationListUnverified,
			wantMessage: "Email verification required to view or list invitations for the session email",
		},
	}
	for index, operation := range operations {
		created := harness.createHTTP(
			t, harness.owner, fmt.Sprintf("Custom ID Organization %d", index),
			fmt.Sprintf("custom-id-organization-%d", index), nil,
		)
		invitation := inviteOrganizationUser(
			t, harness, organizationCRUDString(t, created, "id"), recipient.Email, "member",
		)
		invitationID := organizationCRUDString(t, invitation, "id")
		response := harness.exchange(
			t, operation.method, operation.path(invitationID), recipient.Cookie,
			operation.body(invitationID),
		)
		requireOrganizationCRUDWireError(
			t, response, http.StatusForbidden, operation.wantCode, operation.wantMessage,
		)
		persisted, err := harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "invitation", Where: []storage.Where{{Field: "id", Value: invitationID}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if persisted == nil || persisted["status"] != "pending" {
			t.Fatalf("%s consumed gated invitation: %#v", operation.name, persisted)
		}
	}
}

func TestInvitationByIDExplicitFalseOverridesCustomRootGenerateIDGate(t *testing.T) {
	requireVerification := false
	harness := newCustomGenerateIDOrganizationHarness(t, organization.Options{
		RequireEmailVerificationOnInvitation: &requireVerification,
	})
	created := harness.createHTTP(t, harness.owner, "Explicit Gate Organization", "explicit-gate-organization", nil)
	organizationID := organizationCRUDString(t, created, "id")
	recipient := harness.signUp(t, "explicit-false@example.test", "Explicit False")
	invitation := inviteOrganizationUser(t, harness, organizationID, recipient.Email, "member")

	response := harness.exchange(
		t, http.MethodPost, "/organization/accept-invitation", recipient.Cookie,
		map[string]any{"invitationId": organizationCRUDString(t, invitation, "id")},
	)
	requireOrganizationCRUDStatus(t, response, http.StatusOK)
}

func TestInvitationByIDBuiltInOpaqueIDsAllowUnverifiedRecipientByDefault(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		created := harness.createHTTP(t, harness.owner, "Opaque ID Organization", "opaque-id-organization", nil)
		organizationID := organizationCRUDString(t, created, "id")
		recipient := harness.signUp(t, "opaque-id-recipient@example.test", "Opaque ID Recipient")
		invitation := inviteOrganizationUser(t, harness, organizationID, recipient.Email, "member")

		response := harness.exchange(
			t, http.MethodPost, "/organization/accept-invitation", recipient.Cookie,
			map[string]any{"invitationId": organizationCRUDString(t, invitation, "id")},
		)
		requireOrganizationCRUDStatus(t, response, http.StatusOK)
	})
}

func TestInvitationByIDExplicitTrueOverridesBuiltInOpaqueIDDefault(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		requireVerification := true
		harness := newOrganizationCRUDHarness(t, organization.Options{
			RequireEmailVerificationOnInvitation: &requireVerification,
		})
		created := harness.createHTTP(t, harness.owner, "Explicit Gate Organization", "explicit-true-gate-organization", nil)
		organizationID := organizationCRUDString(t, created, "id")
		recipient := harness.signUp(t, "explicit-true@example.test", "Explicit True")
		invitation := inviteOrganizationUser(t, harness, organizationID, recipient.Email, "member")

		response := harness.exchange(
			t, http.MethodPost, "/organization/accept-invitation", recipient.Cookie,
			map[string]any{"invitationId": organizationCRUDString(t, invitation, "id")},
		)
		requireOrganizationCRUDWireError(
			t, response, http.StatusForbidden, organization.ErrorInvitationEmailUnverified,
			"Email verification required before accepting or rejecting invitation",
		)
	})
}

func TestCreateInvitationRejectsForeignAndReservedTeamIDsAcrossTransports(t *testing.T) {
	for _, transport := range organizationCRUDTransports() {
		transport := transport
		t.Run(string(transport), func(t *testing.T) {
			harness := newOrganizationCRUDHarness(t, organization.Options{
				Teams: organization.TeamsOptions{Enabled: true},
			})
			first := harness.createHTTP(t, harness.owner, "First Team Organization", "first-team-organization", nil)
			second := harness.createHTTP(t, harness.owner, "Second Team Organization", "second-team-organization", nil)
			firstOrganizationID := organizationCRUDString(t, first, "id")
			secondOrganizationID := organizationCRUDString(t, second, "id")

			teamsResponse := harness.exchange(
				t, http.MethodGet,
				"/organization/list-teams?organizationId="+url.QueryEscape(firstOrganizationID),
				harness.owner.Cookie, nil,
			)
			requireOrganizationCRUDStatus(t, teamsResponse, http.StatusOK)
			teams := organizationCRUDArray(t, teamsResponse.Value, "first organization teams")
			if len(teams) != 1 {
				t.Fatalf("first organization teams=%#v", teams)
			}
			foreignTeamID := organizationCRUDString(
				t, organizationCRUDObject(t, teams[0], "first organization team"), "id",
			)

			foreign := harness.exchange(
				t, http.MethodPost, "/organization/invite-member", harness.owner.Cookie,
				map[string]any{
					"organizationId": secondOrganizationID,
					"email":          "foreign-team-invitee@example.test",
					"role":           "member",
					"teamId":         foreignTeamID,
				},
			)
			requireOrganizationCRUDWireError(
				t, foreign, http.StatusBadRequest, organization.ErrorTeamNotFound, "Team not found",
			)

			reserved := harness.exchange(
				t, http.MethodPost, "/organization/invite-member", harness.owner.Cookie,
				map[string]any{
					"organizationId": firstOrganizationID,
					"email":          "reserved-team-invitee@example.test",
					"role":           "member",
					"teamId":         foreignTeamID + ",another-team",
				},
			)
			requireOrganizationCRUDWireError(
				t, reserved, http.StatusBadRequest, organization.ErrorInvalidTeamID,
				"Team id contains a reserved character",
			)
		})
	}
}

func TestListUserInvitationsAllowsOnlyDirectServerEmailQuery(t *testing.T) {
	harness := newCustomGenerateIDOrganizationHarness(t, organization.Options{})
	created := harness.createHTTP(t, harness.owner, "Direct List Organization", "direct-list-organization", nil)
	organizationID := organizationCRUDString(t, created, "id")
	const recipientEmail = "direct-list-recipient@example.test"
	invitation := inviteOrganizationUser(t, harness, organizationID, recipientEmail, "member")

	direct, err := harness.auth.API().Call(t.Context(), "listUserInvitations", singleauth.DirectCallInput{
		Method: http.MethodGet,
		Query:  url.Values{"email": []string{strings.ToUpper(recipientEmail)}},
	})
	if err != nil {
		t.Fatalf("direct list user invitations: %v", err)
	}
	directInvitations := organizationCRUDArray(t, direct.Value, "direct user invitations")
	if len(directInvitations) != 1 {
		t.Fatalf("direct user invitations=%#v", directInvitations)
	}
	directInvitation := organizationCRUDObject(t, directInvitations[0], "direct user invitation")
	if directInvitation["id"] != invitation["id"] ||
		directInvitation["organizationName"] != "Direct List Organization" {
		t.Fatalf("direct user invitation=%#v", directInvitation)
	}

	httpResponse := harness.exchange(
		t, http.MethodGet,
		"/organization/list-user-invitations?email="+url.QueryEscape(recipientEmail),
		harness.owner.Cookie, nil,
	)
	requireOrganizationCRUDWireError(
		t, httpResponse, http.StatusBadRequest, "BAD_REQUEST",
		"User email cannot be passed for client side API calls.",
	)
}

func inviteOrganizationUser(
	t *testing.T,
	harness *organizationCRUDHarness,
	organizationID string,
	email string,
	role string,
) map[string]any {
	t.Helper()
	response := harness.exchange(
		t, http.MethodPost, "/organization/invite-member", harness.owner.Cookie,
		map[string]any{"organizationId": organizationID, "email": email, "role": role},
	)
	requireOrganizationCRUDStatus(t, response, http.StatusOK)
	return organizationCRUDObject(t, response.Value, "create invitation")
}

func markOrganizationUserEmailVerified(
	t *testing.T,
	harness *organizationCRUDHarness,
	userID string,
) {
	t.Helper()
	updated, err := harness.auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		Update: storage.Record{"emailVerified": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated == nil || updated["emailVerified"] != true {
		t.Fatalf("email verification update=%#v", updated)
	}
}

func newCustomGenerateIDOrganizationHarness(
	t *testing.T,
	options organization.Options,
) *organizationCRUDHarness {
	t.Helper()
	var sequence atomic.Uint64
	plugin := organization.MustNew(options)
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL:          "http://auth.example.test",
		Secret:           "organization-custom-id-secret-32-bytes",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		GenerateID: func(model string, _ int) (string, bool, error) {
			return fmt.Sprintf("%s-custom-%d", model, sequence.Add(1)), true, nil
		},
		PluginFactories: []singleauth.PluginFactory{plugin},
	})
	harness := &organizationCRUDHarness{
		auth: auth, transport: organizationCRUDNetHTTP,
	}
	harness.owner = harness.signUp(t, "owner@example.test", "Owner")
	return harness
}
