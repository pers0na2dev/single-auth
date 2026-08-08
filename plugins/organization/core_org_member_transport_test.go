package organization_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestOrganizationCoreMemberEndpointsAcrossTransports(t *testing.T) {
	for _, transport := range organizationCRUDTransports() {
		transport := transport
		t.Run(string(transport), func(t *testing.T) {
			var hookMu sync.Mutex
			var beforeRole organization.UpdateMemberRoleBeforeData
			var afterRole organization.UpdateMemberRoleAfterData
			var beforeDelete organization.DeleteOrganizationHookData
			var afterDelete organization.DeleteOrganizationHookData
			harness := newOrganizationCRUDHarness(t, organization.Options{
				Schema: organizationCoreMemberAdditionalSchema(),
				Hooks: organization.OrganizationHooks{
					BeforeUpdateMemberRole: func(_ context.Context, data organization.UpdateMemberRoleBeforeData) (storage.Record, error) {
						hookMu.Lock()
						beforeRole = data
						hookMu.Unlock()
						return nil, nil
					},
					AfterUpdateMemberRole: func(_ context.Context, data organization.UpdateMemberRoleAfterData) error {
						hookMu.Lock()
						afterRole = data
						hookMu.Unlock()
						return nil
					},
					BeforeDeleteOrganization: func(_ context.Context, data organization.DeleteOrganizationHookData) error {
						hookMu.Lock()
						beforeDelete = data
						hookMu.Unlock()
						return nil
					},
					AfterDeleteOrganization: func(_ context.Context, data organization.DeleteOrganizationHookData) error {
						hookMu.Lock()
						afterDelete = data
						hookMu.Unlock()
						return nil
					},
				},
			})

			unauthorizedSlug := harness.exchange(t, http.MethodPost, "/organization/check-slug", "", map[string]any{
				"slug": "core-one",
			})
			requireOrganizationCRUDStatus(t, unauthorizedSlug, http.StatusUnauthorized)
			availableSlug := harness.exchange(t, http.MethodPost, "/organization/check-slug", harness.owner.Cookie, map[string]any{
				"slug": "core-one",
			})
			requireOrganizationCRUDStatus(t, availableSlug, http.StatusOK)
			if organizationCRUDObject(t, availableSlug.Value, "check-slug")["status"] != true {
				t.Fatalf("check-slug body=%s", availableSlug.Body)
			}
			invalidSlug := harness.exchange(t, http.MethodPost, "/organization/check-slug", harness.owner.Cookie, map[string]any{
				"slug": nil,
			})
			requireOrganizationCoreAPIError(t, invalidSlug, http.StatusBadRequest, "VALIDATION_ERROR")

			first := harness.createHTTP(t, harness.owner, "Core One", "core-one", nil)
			firstID := organizationCRUDString(t, first, "id")
			second := harness.createHTTP(t, harness.owner, "Core Two", "core-two", nil)
			secondID := organizationCRUDString(t, second, "id")
			firstOwnerMember := organizationCRUDObject(
				t, organizationCRUDArray(t, first["members"], "first members")[0], "first owner",
			)
			secondOwnerMember := organizationCRUDObject(
				t, organizationCRUDArray(t, second["members"], "second members")[0], "second owner",
			)
			updateOrganizationCoreMemberRecord(t, harness, "organization", firstID, storage.Record{
				"publicLabel": "visible-first", "secretLabel": "hidden-first",
			})
			updateOrganizationCoreMemberRecord(t, harness, "organization", secondID, storage.Record{
				"publicLabel": "visible-second", "secretLabel": "hidden-second",
			})

			takenSlug := harness.exchange(t, http.MethodPost, "/organization/check-slug", harness.owner.Cookie, map[string]any{
				"slug": "core-one",
			})
			requireOrganizationCoreAPIError(t, takenSlug, http.StatusBadRequest, organization.ErrorOrganizationSlugTaken)

			listed := harness.exchange(t, http.MethodGet, "/organization/list", harness.owner.Cookie, nil)
			requireOrganizationCRUDStatus(t, listed, http.StatusOK)
			listedOrganizations := organizationCRUDArray(t, listed.Value, "list organizations")
			if len(listedOrganizations) != 2 {
				t.Fatalf("list organizations=%#v body=%s", listedOrganizations, listed.Body)
			}
			for _, rawOrganization := range listedOrganizations {
				listedOrganization := organizationCRUDObject(t, rawOrganization, "listed organization")
				if listedOrganization["secretLabel"] != nil {
					t.Fatalf("hidden organization field leaked: %#v", listedOrganization)
				}
				if listedOrganization["id"] == firstID && listedOrganization["publicLabel"] != "visible-first" {
					t.Fatalf("first additional field missing: %#v", listedOrganization)
				}
			}

			memberActor := harness.signUp(t, "core-member@example.test", "Core Member")
			member := harness.addMemberDirect(t, firstID, memberActor)
			memberID := organizationCRUDString(t, member, "id")
			updateOrganizationCoreMemberRecord(t, harness, "member", memberID, storage.Record{
				"rank": 20, "publicNote": "member-visible", "secretNote": "member-hidden",
			})
			otherActor := harness.signUp(t, "core-other@example.test", "Core Other")
			otherMember := harness.addMemberDirect(t, firstID, otherActor)
			otherMemberID := organizationCRUDString(t, otherMember, "id")
			updateOrganizationCoreMemberRecord(t, harness, "member", otherMemberID, storage.Record{
				"rank": 10, "publicNote": "other-visible", "secretNote": "other-hidden",
			})
			updateOrganizationCoreMemberRecord(t, harness, "member", organizationCRUDString(t, firstOwnerMember, "id"), storage.Record{
				"rank": 30, "publicNote": "owner-visible", "secretNote": "owner-hidden",
			})

			ownerPermission := harness.exchange(t, http.MethodPost, "/organization/has-permission", harness.owner.Cookie, map[string]any{
				"organizationId": firstID,
				"permissions":    map[string][]string{"member": {"update"}, "invitation": {"create"}},
			})
			requireOrganizationCRUDStatus(t, ownerPermission, http.StatusOK)
			if organizationCRUDObject(t, ownerPermission.Value, "owner permission")["success"] != true {
				t.Fatalf("owner permission body=%s", ownerPermission.Body)
			}
			legacyPermission := harness.exchange(t, http.MethodPost, "/organization/has-permission", memberActor.Cookie, map[string]any{
				"organizationId": firstID,
				"permission":     map[string][]string{"ac": {"read"}},
			})
			requireOrganizationCRUDStatus(t, legacyPermission, http.StatusOK)
			if organizationCRUDObject(t, legacyPermission.Value, "legacy permission")["success"] != true {
				t.Fatalf("legacy permission body=%s", legacyPermission.Body)
			}
			memberPermission := harness.exchange(t, http.MethodPost, "/organization/has-permission", memberActor.Cookie, map[string]any{
				"organizationId": firstID,
				"permissions":    map[string][]string{"member": {"update"}},
			})
			requireOrganizationCRUDStatus(t, memberPermission, http.StatusOK)
			if organizationCRUDObject(t, memberPermission.Value, "member permission")["success"] != false {
				t.Fatalf("member permission body=%s", memberPermission.Body)
			}
			ambiguousPermission := harness.exchange(t, http.MethodPost, "/organization/has-permission", harness.owner.Cookie, map[string]any{
				"organizationId": firstID,
				"permission":     map[string][]string{"ac": {"read"}},
				"permissions":    map[string][]string{"ac": {"read"}},
			})
			requireOrganizationCoreAPIError(t, ambiguousPermission, http.StatusBadRequest, "VALIDATION_ERROR")

			updatedRole := harness.exchange(t, http.MethodPost, "/organization/update-member-role", harness.owner.Cookie, map[string]any{
				"organizationId": firstID, "memberId": memberID, "role": []string{"member", "admin"},
			})
			requireOrganizationCRUDStatus(t, updatedRole, http.StatusOK)
			updatedMember := organizationCRUDObject(t, updatedRole.Value, "updated member")
			if updatedMember["role"] != "member,admin" || updatedMember["publicNote"] != "member-visible" || updatedMember["secretNote"] != nil {
				t.Fatalf("updated member=%#v body=%s", updatedMember, updatedRole.Body)
			}
			hookMu.Lock()
			if beforeRole.Member["secretNote"] != "member-hidden" || beforeRole.NewRole != "member,admin" ||
				afterRole.PreviousRole != "member" || afterRole.Member["role"] != "member,admin" {
				t.Fatalf("role hooks before=%#v after=%#v", beforeRole, afterRole)
			}
			hookMu.Unlock()

			unknownRole := harness.exchange(t, http.MethodPost, "/organization/update-member-role", harness.owner.Cookie, map[string]any{
				"organizationId": firstID, "memberId": memberID, "role": "drizzle-admin",
			})
			requireOrganizationCoreAPIError(t, unknownRole, http.StatusBadRequest, organization.ErrorRoleNotFound)
			crossOrganization := harness.exchange(t, http.MethodPost, "/organization/update-member-role", harness.owner.Cookie, map[string]any{
				"organizationId": firstID, "memberId": secondOwnerMember["id"], "role": "member",
			})
			requireOrganizationCoreAPIError(t, crossOrganization, http.StatusForbidden, organization.ErrorMemberUpdateForbidden)
			nonOwnerUpdatingOwner := harness.exchange(t, http.MethodPost, "/organization/update-member-role", otherActor.Cookie, map[string]any{
				"organizationId": firstID, "memberId": firstOwnerMember["id"], "role": "admin",
			})
			requireOrganizationCoreAPIError(t, nonOwnerUpdatingOwner, http.StatusForbidden, organization.ErrorMemberUpdateForbidden)
			lastOwnerDemotion := harness.exchange(t, http.MethodPost, "/organization/update-member-role", harness.owner.Cookie, map[string]any{
				"organizationId": firstID, "memberId": firstOwnerMember["id"], "role": "admin",
			})
			requireOrganizationCoreAPIError(t, lastOwnerDemotion, http.StatusBadRequest, organization.ErrorOrganizationWithoutOwner)

			memberQuery := url.Values{
				"organizationId": {firstID}, "sortBy": {"rank"}, "sortDirection": {"desc"},
				"limit": {"1"}, "offset": {"1"},
			}
			listedMembers := harness.exchange(t, http.MethodGet, "/organization/list-members?"+memberQuery.Encode(), harness.owner.Cookie, nil)
			requireOrganizationCRUDStatus(t, listedMembers, http.StatusOK)
			listedMembersBody := organizationCRUDObject(t, listedMembers.Value, "list members")
			if listedMembersBody["total"] != json.Number("3") {
				t.Fatalf("list members total=%#v body=%s", listedMembersBody["total"], listedMembers.Body)
			}
			page := organizationCRUDArray(t, listedMembersBody["members"], "list members page")
			if len(page) != 1 {
				t.Fatalf("list members page=%#v", page)
			}
			pageMember := organizationCRUDObject(t, page[0], "paged member")
			if pageMember["id"] != memberID || pageMember["publicNote"] != "member-visible" || pageMember["secretNote"] != nil {
				t.Fatalf("paged member=%#v", pageMember)
			}
			organizationCRUDObject(t, pageMember["user"], "paged member user")

			filterQuery := url.Values{
				"organizationId": {firstID}, "filterField": {"role"},
				"filterOperator": {"starts_with"}, "filterValue": {"member,ad"},
			}
			filteredMembers := harness.exchange(t, http.MethodGet, "/organization/list-members?"+filterQuery.Encode(), harness.owner.Cookie, nil)
			requireOrganizationCRUDStatus(t, filteredMembers, http.StatusOK)
			filteredBody := organizationCRUDObject(t, filteredMembers.Value, "filtered members")
			if filteredBody["total"] != json.Number("1") || len(organizationCRUDArray(t, filteredBody["members"], "filtered page")) != 1 {
				t.Fatalf("filtered members body=%s", filteredMembers.Body)
			}
			invalidFilter := harness.exchange(t, http.MethodGet, "/organization/list-members?organizationId="+url.QueryEscape(firstID)+"&filterOperator=sql_magic", harness.owner.Cookie, nil)
			requireOrganizationCoreAPIError(t, invalidFilter, http.StatusBadRequest, "VALIDATION_ERROR")

			roleQuery := url.Values{
				"organizationId": {secondID}, "organizationSlug": {"core-one"}, "userId": {memberActor.ID},
			}
			activeRole := harness.exchange(t, http.MethodGet, "/organization/get-active-member-role?"+roleQuery.Encode(), harness.owner.Cookie, nil)
			requireOrganizationCRUDStatus(t, activeRole, http.StatusOK)
			if organizationCRUDObject(t, activeRole.Value, "active role")["role"] != "member,admin" {
				t.Fatalf("active role body=%s", activeRole.Body)
			}

			stranger := harness.signUp(t, "core-stranger@example.test", "Core Stranger")
			forbiddenList := harness.exchange(t, http.MethodGet, "/organization/list-members?organizationId="+url.QueryEscape(firstID), stranger.Cookie, nil)
			requireOrganizationCoreAPIError(t, forbiddenList, http.StatusForbidden, organization.ErrorNotMemberOfOrganization)

			harness.setActiveHTTP(t, memberActor, map[string]any{"organizationId": firstID}, &firstID)
			left := harness.exchange(t, http.MethodPost, "/organization/leave", memberActor.Cookie, map[string]any{"organizationId": firstID})
			requireOrganizationCRUDStatus(t, left, http.StatusOK)
			if organizationCRUDObject(t, left.Value, "leave response")["id"] != memberID {
				t.Fatalf("leave body=%s", left.Body)
			}
			harness.requireSession(t, memberActor, nil)
			lastOwnerLeave := harness.exchange(t, http.MethodPost, "/organization/leave", harness.owner.Cookie, map[string]any{"organizationId": firstID})
			requireOrganizationCoreAPIError(t, lastOwnerLeave, http.StatusBadRequest, organization.ErrorOnlyOwner)

			strangerDelete := harness.exchange(t, http.MethodPost, "/organization/delete", stranger.Cookie, map[string]any{"organizationId": firstID})
			requireOrganizationCoreAPIError(t, strangerDelete, http.StatusBadRequest, organization.ErrorUserNotOrganizationMember)
			memberDelete := harness.exchange(t, http.MethodPost, "/organization/delete", otherActor.Cookie, map[string]any{"organizationId": firstID})
			requireOrganizationCoreAPIError(t, memberDelete, http.StatusForbidden, organization.ErrorOrganizationDeleteForbidden)

			if _, err := harness.auth.Adapter().Create(t.Context(), storage.CreateParams{
				Model: "invitation", Data: storage.Record{
					"organizationId": firstID, "email": "cascade@example.test", "role": "member",
					"status": "pending", "inviterId": harness.owner.ID,
					"expiresAt": time.Now().UTC().Add(time.Hour), "createdAt": time.Now().UTC(),
				},
			}); err != nil {
				t.Fatal(err)
			}
			harness.setActiveHTTP(t, harness.owner, map[string]any{"organizationId": firstID}, &firstID)
			deleted := harness.exchange(t, http.MethodPost, "/organization/delete", harness.owner.Cookie, map[string]any{"organizationId": firstID})
			requireOrganizationCRUDStatus(t, deleted, http.StatusOK)
			deletedOrganization := organizationCRUDObject(t, deleted.Value, "deleted organization")
			if deletedOrganization["publicLabel"] != "visible-first" || deletedOrganization["secretLabel"] != nil {
				t.Fatalf("deleted organization=%#v", deletedOrganization)
			}
			harness.requireSession(t, harness.owner, nil)
			requireOrganizationCoreMemberDeleted(t, harness, firstID)
			hookMu.Lock()
			if beforeDelete.Organization["publicLabel"] != "visible-first" || beforeDelete.Organization["secretLabel"] != nil ||
				afterDelete.Organization["id"] != firstID {
				t.Fatalf("delete hooks before=%#v after=%#v", beforeDelete, afterDelete)
			}
			hookMu.Unlock()

			remaining := harness.exchange(t, http.MethodGet, "/organization/list", harness.owner.Cookie, nil)
			requireOrganizationCRUDStatus(t, remaining, http.StatusOK)
			remainingOrganizations := organizationCRUDArray(t, remaining.Value, "remaining organizations")
			if len(remainingOrganizations) != 1 || organizationCRUDObject(t, remainingOrganizations[0], "remaining organization")["id"] != secondID {
				t.Fatalf("remaining organizations=%#v body=%s", remainingOrganizations, remaining.Body)
			}
		})
	}
}

func TestOrganizationCoreDirectAndDeletionDisabledDistinctions(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
			harness := newOrganizationCRUDHarness(t, organization.Options{})
			directSlug := harness.invokeOrganizationCore(t, "checkOrganizationSlug", nil, map[string]any{"slug": "direct-slug"}, false)
			requireOrganizationCRUDStatus(t, directSlug, http.StatusOK)
			if organizationCRUDObject(t, directSlug.Value, "direct check-slug")["status"] != true {
				t.Fatalf("direct check-slug body=%s", directSlug.Body)
			}
			directSlugWithHeaders := harness.invokeOrganizationCore(
				t, "checkOrganizationSlug", nil, map[string]any{"slug": "direct-slug"}, true,
			)
			requireOrganizationCRUDStatus(t, directSlugWithHeaders, http.StatusUnauthorized)
			directList := harness.invokeOrganizationCore(t, "listOrganizations", nil, nil, false)
			requireOrganizationCRUDStatus(t, directList, http.StatusUnauthorized)
			authenticatedList := harness.invokeOrganizationCore(t, "listOrganizations", &harness.owner, nil, false)
			requireOrganizationCRUDStatus(t, authenticatedList, http.StatusOK)
		})
	})

	for _, transport := range organizationCRUDTransports() {
		transport := transport
		t.Run("deletion-disabled/"+string(transport), func(t *testing.T) {
			disabled := newOrganizationCRUDHarness(t, organization.Options{DisableOrganizationDeletion: true})
			response := disabled.exchange(t, http.MethodPost, "/organization/delete", "", map[string]any{"organizationId": "missing"})
			requireOrganizationCoreAPIError(t, response, http.StatusNotFound, organization.ErrorOrganizationDeletionDisabled)
		})
	}
}

func TestConcurrentOwnerDemotionsPreserveAnOwner(t *testing.T) {
	t.Run(string(organizationCRUDNetHTTP), func(t *testing.T) {
		harness := newOrganizationCRUDHarness(t, organization.Options{})
		created := harness.createHTTP(t, harness.owner, "Concurrent Owners", "concurrent-owners", nil)
		organizationID := organizationCRUDString(t, created, "id")
		firstMember := organizationCRUDObject(
			t, organizationCRUDArray(t, created["members"], "concurrent owner members")[0], "first owner member",
		)
		secondOwner := harness.signUp(t, "concurrent-owner@example.test", "Concurrent Owner")
		secondMemberResponse := harness.invoke(t, "addMember", map[string]any{
			"organizationId": organizationID, "userId": secondOwner.ID, "role": "owner",
		})
		requireOrganizationCRUDStatus(t, secondMemberResponse, http.StatusOK)
		secondMember := organizationCRUDObject(t, secondMemberResponse.Value, "second owner member")

		type demotionAttempt struct {
			status int
			body   []byte
		}
		invoke := func(actor organizationCRUDActor, memberID string) demotionAttempt {
			encoded, _ := json.Marshal(map[string]any{
				"organizationId": organizationID, "memberId": memberID, "role": "member",
			})
			request := contract.NewRequest(http.MethodPost, "/:direct", contract.RequestOptions{
				Context: context.Background(), Scheme: "http", Host: "auth.example.test",
				Headers: contract.NewHeaders(
					contract.HeaderField{Name: "Cookie", Value: actor.Cookie},
					contract.HeaderField{Name: "Content-Type", Value: "application/json"},
				),
				Body: encoded,
			})
			response, _ := harness.auth.Invoke("updateMemberRole", engine.DirectInput{Request: request})
			return demotionAttempt{status: response.Status(), body: append([]byte(nil), response.Body()...)}
		}

		start := make(chan struct{})
		results := make(chan demotionAttempt, 2)
		var wait sync.WaitGroup
		for _, attempt := range []struct {
			actor    organizationCRUDActor
			memberID string
		}{
			{actor: harness.owner, memberID: organizationCRUDString(t, firstMember, "id")},
			{actor: secondOwner, memberID: organizationCRUDString(t, secondMember, "id")},
		} {
			attempt := attempt
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				results <- invoke(attempt.actor, attempt.memberID)
			}()
		}
		close(start)
		wait.Wait()
		close(results)

		successes := 0
		lastOwnerFailures := 0
		for result := range results {
			switch result.status {
			case http.StatusOK:
				successes++
			case http.StatusBadRequest:
				var body map[string]any
				if err := json.Unmarshal(result.body, &body); err != nil {
					t.Fatal(err)
				}
				if body["code"] != organization.ErrorOrganizationWithoutOwner {
					t.Fatalf("concurrent demotion error=%#v raw=%s", body, result.body)
				}
				lastOwnerFailures++
			default:
				t.Fatalf("concurrent demotion status=%d body=%s", result.status, result.body)
			}
		}
		if successes != 1 || lastOwnerFailures != 1 {
			t.Fatalf("demotions successes=%d lastOwnerFailures=%d", successes, lastOwnerFailures)
		}
		members, err := harness.auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
			Model: "member", Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
		})
		if err != nil {
			t.Fatal(err)
		}
		owners := 0
		for _, member := range members {
			role, _ := member["role"].(string)
			for _, candidate := range strings.Split(role, ",") {
				if candidate == "owner" {
					owners++
				}
			}
		}
		if owners != 1 {
			t.Fatalf("owners=%d members=%#v", owners, members)
		}
	})
}

func organizationCoreMemberAdditionalSchema() storage.Schema {
	optional := storage.Bool(false)
	hidden := storage.Bool(false)
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"organization": {Fields: map[string]storage.FieldAttribute{
			"publicLabel": {Type: storage.FieldString, Required: optional},
			"secretLabel": {Type: storage.FieldString, Required: optional, Returned: hidden},
		}},
		"member": {Fields: map[string]storage.FieldAttribute{
			"rank":       {Type: storage.FieldNumber, Required: optional, Sortable: true},
			"publicNote": {Type: storage.FieldString, Required: optional},
			"secretNote": {Type: storage.FieldString, Required: optional, Returned: hidden},
		}},
	}}
}

func updateOrganizationCoreMemberRecord(
	t *testing.T,
	harness *organizationCRUDHarness,
	model string,
	id string,
	update storage.Record,
) {
	t.Helper()
	record, err := harness.auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: model, Where: []storage.Where{{Field: "id", Value: id}}, Update: update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatalf("update %s %q returned nil", model, id)
	}
}

func requireOrganizationCoreMemberDeleted(t *testing.T, harness *organizationCRUDHarness, organizationID string) {
	t.Helper()
	organizationRecord, err := harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "organization", Where: []storage.Where{{Field: "id", Value: organizationID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if organizationRecord != nil {
		t.Fatalf("organization still exists: %#v", organizationRecord)
	}
	for _, model := range []string{"member", "invitation"} {
		count, err := harness.auth.Adapter().Count(t.Context(), storage.CountParams{
			Model: model, Where: []storage.Where{{Field: "organizationId", Value: organizationID}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s count=%d after organization delete", model, count)
		}
	}
}

func (harness *organizationCRUDHarness) invokeOrganizationCore(
	t *testing.T,
	name string,
	actor *organizationCRUDActor,
	body any,
	forceContentType bool,
) organizationCRUDWireResponse {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	headers := contract.Headers{}
	if actor != nil {
		headers.Add("Cookie", actor.Cookie)
	}
	if forceContentType {
		headers.Add("Content-Type", "application/json")
	}
	request := contract.NewRequest(http.MethodPost, "/:direct", contract.RequestOptions{
		Context: t.Context(), Scheme: "http", Host: "auth.example.test", Headers: headers, Body: encoded,
	})
	response, _ := harness.auth.Invoke(name, engine.DirectInput{Request: request})
	result := organizationCRUDWireResponse{
		Status: response.Status(), Headers: make(http.Header), Body: append([]byte(nil), response.Body()...),
	}
	for _, field := range response.Headers().Fields() {
		result.Headers.Add(field.Name, field.Value)
	}
	if len(bytes.TrimSpace(result.Body)) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(result.Body))
		decoder.UseNumber()
		if err := decoder.Decode(&result.Value); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func requireOrganizationCoreAPIError(
	t *testing.T,
	response organizationCRUDWireResponse,
	wantStatus int,
	wantCode string,
) {
	t.Helper()
	requireOrganizationCRUDStatus(t, response, wantStatus)
	body := organizationCRUDObject(t, response.Value, "organization core API error")
	if body["code"] != wantCode {
		t.Fatalf("API error=%#v want code=%q raw=%s", body, wantCode, response.Body)
	}
	if message, ok := body["message"].(string); !ok || message == "" {
		t.Fatalf("API error message=%#v raw=%s", body["message"], response.Body)
	}
}
