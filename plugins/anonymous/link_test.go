package anonymous

import (
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestPostLinkCallbackThenCleanup(t *testing.T) {
	var callbackCount atomic.Int64
	var callbackData LinkAccountData
	var existedDuringCallback bool
	harness := newAnonymousHarness(t, func(options *Options, harness *anonymousHarness) {
		options.OnLinkAccount = func(data LinkAccountData) error {
			callbackCount.Add(1)
			callbackData = data
			oldID, _ := recordString(data.AnonymousUser.User, "id")
			stored, err := harness.adapter.FindOne(data.Context.GoContext(), storage.FindOneParams{
				Model: "user", Where: []storage.Where{{Field: "id", Value: oldID}},
			})
			existedDuringCallback = err == nil && stored != nil
			return nil
		}
	})
	harness.seedUser(t, "anon-user", "anon@example.com", true)
	harness.seedSession(t, "anon-user", "old-token")
	harness.seedUser(t, "linked-user", "linked@example.com", false)
	harness.seedSession(t, "linked-user", "new-token")

	response, err := dispatchLinkEndpoint(t, harness, "/sign-in/fake", "old-token", "new-token")
	if err != nil || response.Status() != http.StatusOK {
		t.Fatalf("link response status=%d body=%s err=%v", response.Status(), response.Body(), err)
	}
	if callbackCount.Load() != 1 || !existedDuringCallback {
		t.Fatalf("callback count=%d existed=%v", callbackCount.Load(), existedDuringCallback)
	}
	if callbackData.AnonymousUser.User["id"] != "anon-user" ||
		callbackData.AnonymousUser.Session["token"] != "old-token" ||
		callbackData.NewUser.User["id"] != "linked-user" ||
		callbackData.NewUser.Session["token"] != "new-token" {
		t.Fatalf("callback data = %#v", callbackData)
	}
	stored, findErr := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "anon-user"}},
	})
	if findErr != nil || stored != nil {
		t.Fatalf("post-link anonymous user = %#v, err=%v", stored, findErr)
	}
}

func TestPostLinkCleanupSafeguards(t *testing.T) {
	tests := []struct {
		name      string
		newUserID string
		newAnon   bool
		disable   bool
	}{
		{name: "same user", newUserID: "anon-user", newAnon: true},
		{name: "new session is anonymous", newUserID: "other-anon", newAnon: true},
		{name: "deletion disabled", newUserID: "linked-user", disable: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var callbacks atomic.Int64
			harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
				options.DisableDeleteAnonymousUser = test.disable
				options.OnLinkAccount = func(LinkAccountData) error {
					callbacks.Add(1)
					return nil
				}
			})
			harness.seedUser(t, "anon-user", "anon@example.com", true)
			harness.seedSession(t, "anon-user", "old-token")
			if test.newUserID != "anon-user" {
				harness.seedUser(t, test.newUserID, test.newUserID+"@example.com", test.newAnon)
			}
			harness.seedSession(t, test.newUserID, "new-token")
			response, err := dispatchLinkEndpoint(t, harness, "/sign-up/fake", "old-token", "new-token")
			if err != nil || response.Status() != http.StatusOK {
				t.Fatalf("link status=%d body=%s err=%v", response.Status(), response.Body(), err)
			}
			if callbacks.Load() != 1 {
				t.Fatalf("callback count = %d", callbacks.Load())
			}
			stored, findErr := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
				Model: "user", Where: []storage.Where{{Field: "id", Value: "anon-user"}},
			})
			if findErr != nil || stored == nil {
				t.Fatalf("guarded anonymous user = %#v, err=%v", stored, findErr)
			}
		})
	}
}

func TestPostLinkCallbackFailurePreventsCleanup(t *testing.T) {
	sentinel := errors.New("transfer failed")
	harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
		options.OnLinkAccount = func(LinkAccountData) error { return sentinel }
	})
	harness.seedUser(t, "anon-user", "anon@example.com", true)
	harness.seedSession(t, "anon-user", "old-token")
	harness.seedUser(t, "linked-user", "linked@example.com", false)
	harness.seedSession(t, "linked-user", "new-token")

	response, err := dispatchLinkEndpoint(t, harness, "/verify-email", "old-token", "new-token")
	if !errors.Is(err, sentinel) || response.Status() != http.StatusInternalServerError ||
		responseErrorCode(t, response) != "INTERNAL_SERVER_ERROR" {
		t.Fatalf("callback failure status=%d body=%s err=%v", response.Status(), response.Body(), err)
	}
	stored, findErr := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "anon-user"}},
	})
	if findErr != nil || stored == nil {
		t.Fatalf("callback-failed anonymous user = %#v, err=%v", stored, findErr)
	}
}

func TestPostLinkDeleteFailureIsLoggedAndSwallowed(t *testing.T) {
	sentinel := errors.New("cleanup failed")
	var logs atomic.Int64
	harness := newAnonymousHarness(t, func(options *Options, harness *anonymousHarness) {
		options.Runtime.Adapter = deleteFailingAdapter{Adapter: harness.adapter, err: sentinel}
		options.Runtime.Error = func(message string, arguments ...any) {
			if message == "Failed to clean up anonymous user during post-link cleanup" && len(arguments) == 1 {
				logs.Add(1)
			}
		}
	})
	harness.seedUser(t, "anon-user", "anon@example.com", true)
	harness.seedSession(t, "anon-user", "old-token")
	harness.seedUser(t, "linked-user", "linked@example.com", false)
	harness.seedSession(t, "linked-user", "new-token")

	response, err := dispatchLinkEndpoint(t, harness, "/callback/provider", "old-token", "new-token")
	if err != nil || response.Status() != http.StatusOK {
		t.Fatalf("swallowed cleanup status=%d body=%s err=%v", response.Status(), response.Body(), err)
	}
	if logs.Load() != 1 {
		t.Fatalf("cleanup logs = %d", logs.Load())
	}
	stored, findErr := harness.adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "anon-user"}},
	})
	if findErr != nil || stored == nil {
		t.Fatalf("failed-cleanup anonymous user = %#v, err=%v", stored, findErr)
	}
}

func TestPostLinkRequiresSessionCookieAndPreviousAnonymousSession(t *testing.T) {
	var callbacks atomic.Int64
	harness := newAnonymousHarness(t, func(options *Options, _ *anonymousHarness) {
		options.OnLinkAccount = func(LinkAccountData) error { callbacks.Add(1); return nil }
	})
	harness.seedUser(t, "regular-user", "regular@example.com", false)
	harness.seedSession(t, "regular-user", "old-token")
	harness.seedUser(t, "linked-user", "linked@example.com", false)
	harness.seedSession(t, "linked-user", "new-token")

	response, err := dispatchLinkEndpoint(t, harness, "/sign-in/fake", "old-token", "")
	if err != nil || response.Status() != http.StatusOK {
		t.Fatalf("no-cookie link status=%d body=%s err=%v", response.Status(), response.Body(), err)
	}
	response, err = dispatchLinkEndpoint(t, harness, "/sign-in/fake", "old-token", "new-token")
	if err != nil || response.Status() != http.StatusOK || callbacks.Load() != 0 {
		t.Fatalf("regular previous status=%d body=%s callbacks=%d err=%v", response.Status(), response.Body(), callbacks.Load(), err)
	}
}

func dispatchLinkEndpoint(
	t *testing.T,
	harness *anonymousHarness,
	path, oldToken, newToken string,
) (contract.Response, error) {
	t.Helper()
	core := engine.Endpoint{
		Name: "fakeLinkEndpoint", Path: path, Methods: []string{http.MethodPost},
		Handler: func(ctx *engine.Context) (contract.Response, error) {
			if newToken != "" {
				session, findErr := harness.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
					Model: "session", Where: []storage.Where{{Field: "token", Value: newToken}},
				})
				if findErr != nil {
					return contract.Response{}, findErr
				}
				userID, _ := recordString(session, "userId")
				user, findErr := harness.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
					Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
				})
				if findErr != nil {
					return contract.Response{}, findErr
				}
				setDefaultNewSession(ctx, &SessionState{Session: session, User: user})
				ctx.AddSetCookie("single-auth.session_token=" + newToken + "; Path=/; HttpOnly")
			}
			return contract.JSONResponse(http.StatusOK, map[string]any{"ok": true})
		},
	}
	registry, err := engine.NewRegistry([]engine.Endpoint{core}, harness.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	request := contract.NewRequest(http.MethodPost, "/api/auth"+path, contract.RequestOptions{
		Scheme: "http", Host: "localhost",
		Headers: requestHeaders("single-auth.session_token=" + oldToken),
	})
	return dispatcher.Dispatch(request)
}
