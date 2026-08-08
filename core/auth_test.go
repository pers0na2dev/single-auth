package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestCredentialSessionHTTPVerticalSlice(t *testing.T) {
	clock := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	auth, err := New(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		Session: SessionOptions{
			CookieCache: CookieCacheOptions{Enabled: true},
		},
		Clock: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}

	signUpBody := []byte(`{"name":"Ada","email":"ADA@example.com","password":"password123"}`)
	signUp := httptest.NewRequest(http.MethodPost, "http://example.test/api/auth/sign-up/email", bytes.NewReader(signUpBody))
	signUp.Header.Set("Content-Type", "application/json")
	signUp.Header.Set("User-Agent", "single-auth-test")
	signUp.RemoteAddr = "192.0.2.4:1234"
	signUpRecorder := httptest.NewRecorder()
	auth.ServeHTTP(signUpRecorder, signUp)
	if signUpRecorder.Code != http.StatusOK {
		t.Fatalf("sign up status = %d, body = %s", signUpRecorder.Code, signUpRecorder.Body.String())
	}
	var signUpResult struct {
		Token string         `json:"token"`
		User  map[string]any `json:"user"`
	}
	if err := json.Unmarshal(signUpRecorder.Body.Bytes(), &signUpResult); err != nil {
		t.Fatal(err)
	}
	if signUpResult.Token == "" || signUpResult.User["email"] != "ada@example.com" {
		t.Fatalf("unexpected sign up result: %#v", signUpResult)
	}
	cookieHeader := cookies.ApplySetCookies("", signUpRecorder.Header().Values("Set-Cookie"))
	if cookieHeader == "" {
		t.Fatal("sign up did not set cookies")
	}

	getSession := httptest.NewRequest(http.MethodGet, "http://example.test/api/auth/get-session", nil)
	getSession.Header.Set("Cookie", cookieHeader)
	getSessionRecorder := httptest.NewRecorder()
	auth.ServeHTTP(getSessionRecorder, getSession)
	if getSessionRecorder.Code != http.StatusOK {
		t.Fatalf("get session status = %d", getSessionRecorder.Code)
	}
	var sessionResult map[string]any
	if err := json.Unmarshal(getSessionRecorder.Body.Bytes(), &sessionResult); err != nil {
		t.Fatal(err)
	}
	if sessionResult["session"] == nil || sessionResult["user"] == nil {
		t.Fatalf("unexpected session: %#v", sessionResult)
	}

	signOut := httptest.NewRequest(http.MethodPost, "http://example.test/api/auth/sign-out", nil)
	signOut.Header.Set("Cookie", cookieHeader)
	signOut.Header.Set("Origin", "http://example.test")
	signOutRecorder := httptest.NewRecorder()
	auth.ServeHTTP(signOutRecorder, signOut)
	if signOutRecorder.Code != http.StatusOK {
		t.Fatalf("sign out status = %d", signOutRecorder.Code)
	}

	// The stale cache cookie is intentionally still valid in this synthetic
	// request; apply the response deletions like a browser before checking.
	cookieHeader = cookies.ApplySetCookies(cookieHeader, signOutRecorder.Header().Values("Set-Cookie"))
	afterSignOut := httptest.NewRequest(http.MethodGet, "http://example.test/api/auth/get-session", nil)
	afterSignOut.Header.Set("Cookie", cookieHeader)
	afterRecorder := httptest.NewRecorder()
	auth.ServeHTTP(afterRecorder, afterSignOut)
	if afterRecorder.Body.String() != "null" {
		t.Fatalf("session after sign out = %s", afterRecorder.Body.String())
	}
}

func TestCredentialDirectAPIUsesSameEndpoint(t *testing.T) {
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
	})
	request := contract.NewRequest(http.MethodPost, "/sign-up/email", contract.RequestOptions{
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"}),
		Body:    []byte(`{"name":"Grace","email":"grace@example.com","password":"password123"}`),
	})
	response, err := auth.Invoke("signUpEmail", engine.DirectInput{Request: request})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status() != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Status(), response.Body())
	}
	if len(response.Headers().Values("Set-Cookie")) == 0 {
		t.Fatal("direct API did not preserve endpoint Set-Cookie")
	}
}

type typedDirectAPIUser struct {
	ID                  string
	Email               string
	OnboardingCompleted model.Value[bool]
}

func decodeTypedDirectAPIUser(user model.User) (typedDirectAPIUser, error) {
	onboarding, err := DecodeUserField[bool](user.AdditionalFields, "onboardingCompleted")
	if err != nil {
		return typedDirectAPIUser{}, err
	}
	return typedDirectAPIUser{
		ID: user.ID, Email: user.Email, OnboardingCompleted: onboarding,
	}, nil
}

func TestTypedDirectAPI(t *testing.T) {
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		Schema: storage.Schema{Models: map[string]storage.ModelSchema{
			"user": {Fields: map[string]storage.FieldAttribute{
				"onboardingCompleted": {
					Type: storage.FieldBoolean, Required: storage.Bool(false),
					Input: storage.Bool(false), Returned: storage.Bool(true),
					DefaultValue: storage.StaticValue(false),
				},
			}},
		}},
	})
	typedAuth, err := NewTypedAuth(auth, decodeTypedDirectAPIUser)
	if err != nil {
		t.Fatal(err)
	}
	api := typedAuth.API()
	signUp, err := api.SignUpEmail(t.Context(), SignUpEmailInput{
		Name: "Lin", Email: "lin@example.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if signUp.Token == nil || signUp.User.Email != "lin@example.com" {
		t.Fatalf("unexpected sign-up result: %#v", signUp)
	}
	signIn, err := api.SignInEmail(t.Context(), SignInEmailInput{
		Email: "lin@example.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookieHeader := cookies.ApplySetCookies("", signIn.Headers.Values("Set-Cookie"))
	session, err := api.GetSession(t.Context(), GetSessionInput{
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if session == nil || signIn.User.ID != signUp.User.ID || session.User.ID != signUp.User.ID ||
		session.Session.Token != signIn.Token {
		t.Fatalf("unexpected session: %#v", session)
	}
	for _, user := range []typedDirectAPIUser{signUp.User, signIn.User, session.User} {
		value, present := user.OnboardingCompleted.Get()
		if !present || value {
			t.Fatalf("typed production user lost onboardingCompleted=false: %#v", user)
		}
	}

	wrongTypeAuth, err := NewTypedAuth(auth, func(user model.User) (typedDirectAPIUser, error) {
		_, decodeErr := DecodeUserField[string](user.AdditionalFields, "onboardingCompleted")
		return typedDirectAPIUser{}, decodeErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongTypeAuth.API().SignInEmail(t.Context(), SignInEmailInput{
		Email: "lin@example.com", Password: "password123",
	}); err == nil || !strings.Contains(err.Error(), `user field "onboardingCompleted" has type bool`) {
		t.Fatalf("typed API wrong-type decoder error = %v", err)
	}
}

func TestDecodeUserFieldTriStateAndWrongType(t *testing.T) {
	absent, err := DecodeUserField[bool](nil, "onboardingCompleted")
	if err != nil || absent.IsSet() {
		t.Fatalf("absent field = %#v, %v", absent, err)
	}
	nullValue, err := DecodeUserField[bool](model.Fields{
		"onboardingCompleted": model.Null[any](),
	}, "onboardingCompleted")
	if err != nil || !nullValue.IsNull() {
		t.Fatalf("null field = %#v, %v", nullValue, err)
	}
	present, err := DecodeUserField[bool](model.Fields{
		"onboardingCompleted": model.Present[any](false),
	}, "onboardingCompleted")
	value, ok := present.Get()
	if err != nil || !ok || value {
		t.Fatalf("present field = %#v, %v", present, err)
	}
	if _, err := DecodeUserField[bool](model.Fields{
		"onboardingCompleted": model.Present[any]("false"),
	}, "onboardingCompleted"); err == nil ||
		!strings.Contains(err.Error(), `user field "onboardingCompleted" has type string`) {
		t.Fatalf("wrong-type field error = %v", err)
	}
}

func TestDuplicateSignUpMatchesDefaultDisclosure(t *testing.T) {
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
	})
	body := []byte(`{"name":"Same","email":"same@example.com","password":"password123"}`)
	for attempt := 0; attempt < 2; attempt++ {
		request := contract.NewRequest(http.MethodPost, "/api/auth/sign-up/email", contract.RequestOptions{
			Headers: contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"}),
			Body:    body,
		})
		response, dispatchErr := auth.Dispatch(request)
		if attempt == 0 {
			if dispatchErr != nil || response.Status() != http.StatusOK {
				t.Fatalf("first attempt: status=%d err=%v body=%s", response.Status(), dispatchErr, response.Body())
			}
			continue
		}
		apiError, ok := contract.AsAPIError(dispatchErr)
		if !ok || apiError.Status != 422 || apiError.Code != string(ErrorUserAlreadyExistsAnotherEmail) {
			t.Fatalf("second attempt: status=%d err=%#v body=%s", response.Status(), dispatchErr, response.Body())
		}
	}
}

func TestCredentialCSRFAndRedirectValidation(t *testing.T) {
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		TrustedOrigins:   []string{"https://app.example.com"},
	})
	body := []byte(`{"email":"user@example.com","password":"password123"}`)
	crossSite := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/auth/sign-in/email", bytes.NewReader(body))
	crossSite.Header.Set("Content-Type", "application/json")
	crossSite.Header.Set("Origin", "https://evil.example")
	crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	crossSite.Header.Set("Sec-Fetch-Mode", "navigate")
	crossSite.Header.Set("Sec-Fetch-Dest", "document")
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, crossSite)
	if recorder.Code != http.StatusForbidden || !bytes.Contains(recorder.Body.Bytes(), []byte(ErrorCrossSiteNavigationLoginBlocked)) {
		t.Fatalf("cross-site response: status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	badCallbackBody := []byte(`{"email":"user@example.com","password":"password123","callbackURL":"https://evil.example/steal"}`)
	badCallback := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/auth/sign-in/email", bytes.NewReader(badCallbackBody))
	badCallback.Header.Set("Content-Type", "application/json")
	badRecorder := httptest.NewRecorder()
	auth.ServeHTTP(badRecorder, badCallback)
	if badRecorder.Code != http.StatusForbidden || !bytes.Contains(badRecorder.Body.Bytes(), []byte(ErrorInvalidCallbackURL)) {
		t.Fatalf("callback response: status=%d body=%s", badRecorder.Code, badRecorder.Body.String())
	}
}
