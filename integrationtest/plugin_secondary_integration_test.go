package singleauth_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/emailotp"
	"github.com/pers0na2dev/single-auth/plugins/magiclink"
	"github.com/pers0na2dev/single-auth/plugins/passkey"
	"github.com/pers0na2dev/single-auth/storage"
)

type pluginSecondaryStore struct {
	mu     sync.Mutex
	values map[string]string
}

func newPluginSecondaryStore() *pluginSecondaryStore {
	return &pluginSecondaryStore{values: map[string]string{}}
}

func (store *pluginSecondaryStore) Get(_ context.Context, key string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.values[key], nil
}

func (store *pluginSecondaryStore) Set(_ context.Context, key, value string, _ int64) error {
	store.mu.Lock()
	store.values[key] = value
	store.mu.Unlock()
	return nil
}

func (store *pluginSecondaryStore) Delete(_ context.Context, key string) error {
	store.mu.Lock()
	delete(store.values, key)
	store.mu.Unlock()
	return nil
}

func (store *pluginSecondaryStore) GetAndDelete(_ context.Context, key string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value := store.values[key]
	delete(store.values, key)
	return value, nil
}

func (store *pluginSecondaryStore) verificationCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	count := 0
	for key := range store.values {
		if strings.HasPrefix(key, "verification:") {
			count++
		}
	}
	return count
}

func pluginPOST(t *testing.T, auth *singleauth.Auth, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://auth.example.test/api/auth"+path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	return recorder
}

func assertNoDatabaseVerifications(t *testing.T, auth *singleauth.Auth) {
	t.Helper()
	rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "verification"})
	if err != nil || len(rows) != 0 {
		t.Fatalf("database verification rows = %#v, %v", rows, err)
	}
}

func TestPluginFactoriesUseRootSecondaryVerificationStorage(t *testing.T) {
	t.Run("email otp", func(t *testing.T) {
		secondary := newPluginSecondaryStore()
		var sent emailotp.OTPMessage
		auth := singleauth.MustNew(singleauth.Options{
			BaseURL: "http://auth.example.test", Secret: "0123456789abcdef0123456789abcdef",
			SecondaryStorage: secondary,
			PluginFactories: []singleauth.PluginFactory{emailotp.NewFactory(emailotp.Options{
				SendVerificationOTP: func(_ context.Context, message emailotp.OTPMessage, _ *engine.Context) error {
					sent = message
					return nil
				},
			})},
		})
		response := pluginPOST(t, auth, "/email-otp/send-verification-otp", `{"email":"secondary-otp@example.com","type":"sign-in"}`)
		if response.Code != http.StatusOK || sent.OTP == "" || secondary.verificationCount() != 1 {
			t.Fatalf("send status=%d message=%#v verification keys=%d", response.Code, sent, secondary.verificationCount())
		}
		assertNoDatabaseVerifications(t, auth)
		response = pluginPOST(t, auth, "/sign-in/email-otp", `{"email":"secondary-otp@example.com","otp":"`+sent.OTP+`","name":"Secondary OTP"}`)
		if response.Code != http.StatusOK || secondary.verificationCount() != 0 {
			t.Fatalf("verify status=%d body=%s verification keys=%d", response.Code, response.Body.String(), secondary.verificationCount())
		}
	})

	t.Run("magic link", func(t *testing.T) {
		secondary := newPluginSecondaryStore()
		var sent magiclink.MagicLinkMessage
		auth := singleauth.MustNew(singleauth.Options{
			BaseURL: "http://auth.example.test", Secret: "0123456789abcdef0123456789abcdef",
			SecondaryStorage: secondary,
			PluginFactories: []singleauth.PluginFactory{magiclink.NewFactory(magiclink.Options{
				SendMagicLink: func(_ context.Context, message magiclink.MagicLinkMessage, _ *engine.Context) error {
					sent = message
					return nil
				},
			})},
		})
		response := pluginPOST(t, auth, "/sign-in/magic-link", `{"email":"secondary-magic@example.com","name":"Secondary Magic"}`)
		if response.Code != http.StatusOK || sent.URL == "" || secondary.verificationCount() != 1 {
			t.Fatalf("send status=%d message=%#v verification keys=%d", response.Code, sent, secondary.verificationCount())
		}
		assertNoDatabaseVerifications(t, auth)
		verify := httptest.NewRequest(http.MethodGet, sent.URL, nil)
		verifyRecorder := httptest.NewRecorder()
		auth.ServeHTTP(verifyRecorder, verify)
		if verifyRecorder.Code != http.StatusFound || secondary.verificationCount() != 0 {
			t.Fatalf("verify status=%d body=%s verification keys=%d", verifyRecorder.Code, verifyRecorder.Body.String(), secondary.verificationCount())
		}
	})

	t.Run("passkey challenge", func(t *testing.T) {
		secondary := newPluginSecondaryStore()
		auth := singleauth.MustNew(singleauth.Options{
			BaseURL: "http://auth.example.test", Secret: "0123456789abcdef0123456789abcdef",
			SecondaryStorage: secondary,
			PluginFactories:  []singleauth.PluginFactory{passkey.NewFactory(passkey.Options{})},
		})
		request := httptest.NewRequest(
			http.MethodGet,
			"http://auth.example.test/api/auth/passkey/generate-authenticate-options",
			nil,
		)
		recorder := httptest.NewRecorder()
		auth.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || secondary.verificationCount() != 1 {
			t.Fatalf("challenge status=%d body=%s verification keys=%d", recorder.Code, recorder.Body.String(), secondary.verificationCount())
		}
		assertNoDatabaseVerifications(t, auth)
	})
}
