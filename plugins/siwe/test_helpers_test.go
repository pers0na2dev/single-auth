package siwe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	testWalletAddress = "0x000000000000000000000000000000000000dEaD"
	testSecondWallet  = "0x000000000000000000000000000000000000bEEF"
	testDomain        = "example.com"
	testNonce         = "A1b2C3d4E5f6G7h8J"
	testSecret        = "0123456789abcdef0123456789abcdef"
)

type testMessageOptions struct {
	Domain         string
	Address        string
	ChainID        int64
	Nonce          string
	ExpirationTime string
	NotBefore      string
}

func testMessage(input testMessageOptions) string {
	domain := input.Domain
	if domain == "" {
		domain = testDomain
	}
	address := input.Address
	if address == "" {
		address = testWalletAddress
	}
	chainID := input.ChainID
	if chainID == 0 {
		chainID = 1
	}
	nonce := input.Nonce
	if nonce == "" {
		nonce = testNonce
	}
	message := fmt.Sprintf(
		"%s wants you to sign in with your Ethereum account:\n%s\n\nSign in.\n\nURI: https://%s\nVersion: 1\nChain ID: %d\nNonce: %s\nIssued At: 2024-01-01T00:00:00.000Z",
		domain, address, domain, chainID, nonce,
	)
	if input.ExpirationTime != "" {
		message += "\nExpiration Time: " + input.ExpirationTime
	}
	if input.NotBefore != "" {
		message += "\nNot Before: " + input.NotBefore
	}
	return message
}

func defaultTestOptions() Options {
	return Options{
		Domain: testDomain,
		GetNonce: func(context.Context) (string, error) {
			return testNonce, nil
		},
		VerifyMessage: func(_ context.Context, input VerifyMessageArgs) (bool, error) {
			return input.Signature == "valid_signature", nil
		},
	}
}

func newTestAuth(t *testing.T, pluginOptions Options) *singleauth.Auth {
	t.Helper()
	return newTestAuthWithRoot(t, pluginOptions, singleauth.Options{})
}

func newTestAuthWithRoot(
	t *testing.T, pluginOptions Options, root singleauth.Options,
) *singleauth.Auth {
	t.Helper()
	root.BaseURL = "http://localhost:3000"
	root.Secret = testSecret
	root.PluginFactories = append(root.PluginFactories, NewFactory(pluginOptions))
	auth, err := singleauth.New(root)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func callSIWE(
	t *testing.T, auth *singleauth.Auth, path string, body map[string]any,
) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost, "http://localhost:3000/api/auth"+path, bytes.NewReader(encoded),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	decoded := map[string]any{}
	if recorder.Body.Len() != 0 {
		if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
		}
	}
	return recorder, decoded
}

func requestNonce(t *testing.T, auth *singleauth.Auth, address string, chainID int64) {
	t.Helper()
	response, body := callSIWE(t, auth, "/siwe/nonce", map[string]any{
		"walletAddress": address, "chainId": chainID,
	})
	if response.Code != http.StatusOK || body["nonce"] != testNonce {
		t.Fatalf("nonce status=%d body=%#v", response.Code, body)
	}
}

func verifyWallet(
	t *testing.T, auth *singleauth.Auth, address string, chainID int64,
	message, signature string, email *string,
) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	body := map[string]any{
		"message": message, "signature": signature,
		"walletAddress": address, "chainId": chainID,
	}
	if email != nil {
		body["email"] = *email
	}
	return callSIWE(t, auth, "/siwe/verify", body)
}

func records(
	t *testing.T, auth *singleauth.Auth, model string, where []storage.Where,
) []storage.Record {
	t.Helper()
	rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: model, Where: where})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func seedUser(t *testing.T, auth *singleauth.Auth, id, email string) storage.Record {
	t.Helper()
	now := time.Now().UTC()
	user, err := auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "user", ForceAllowID: true,
		Data: storage.Record{
			"id": id, "name": id, "email": email, "emailVerified": true,
			"createdAt": now, "updatedAt": now,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func responseCode(body map[string]any) string {
	value, _ := body["code"].(string)
	return value
}

func responseMessage(body map[string]any) string {
	value, _ := body["message"].(string)
	return value
}

func responseUserID(body map[string]any) string {
	user, _ := body["user"].(map[string]any)
	value, _ := user["id"].(string)
	return value
}

func boolPointer(value bool) *bool { return &value }

func rootWithClock(now time.Time) singleauth.Options {
	return singleauth.Options{Clock: func() time.Time { return now }}
}
