package siwe

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestPluginDescriptorMatchesFrozenSIWE(t *testing.T) {
	auth := newTestAuth(t, defaultTestOptions())
	registry := auth.Registry()
	want := map[string]struct {
		path string
		name string
	}{
		"getSiweNonce":      {path: "/siwe/nonce", name: "getSiweNonce"},
		"getNonce":          {path: "/siwe/get-nonce", name: "getNonce"},
		"verifySiweMessage": {path: "/siwe/verify", name: "verifySiweMessage"},
	}
	for endpointName, expected := range want {
		endpoint, ok := registry.Endpoint(endpointName)
		if !ok || endpoint.Name != expected.name || endpoint.Path != expected.path ||
			!reflect.DeepEqual(endpoint.Methods, []string{"POST"}) {
			t.Fatalf("endpoint %s = %#v, exists=%v", endpointName, endpoint, ok)
		}
	}
	if got := NewFactory(defaultTestOptions()).PluginID(); got != "siwe" {
		t.Fatalf("factory plugin ID = %q", got)
	}
}

func TestSIWESchemaMatchesFrozenModel(t *testing.T) {
	schema := Schema()
	model, ok := schema.Models["walletAddress"]
	if !ok || model.ModelName != "walletAddress" {
		t.Fatalf("walletAddress model = %#v", model)
	}
	if len(model.Fields) != 5 {
		t.Fatalf("walletAddress fields = %#v", model.Fields)
	}
	userID := model.Fields["userId"]
	if userID.Type != storage.FieldString || !userID.Index || userID.References == nil ||
		userID.References.Model != "user" || userID.References.Field != "id" {
		t.Fatalf("userId schema = %#v", userID)
	}
	if model.Fields["address"].Type != storage.FieldString ||
		model.Fields["chainId"].Type != storage.FieldNumber ||
		model.Fields["isPrimary"].Type != storage.FieldBoolean ||
		model.Fields["createdAt"].Type != storage.FieldDate {
		t.Fatalf("walletAddress schema = %#v", model.Fields)
	}
	first := Schema()
	first.Models["walletAddress"] = storage.ModelSchema{}
	if second := Schema(); len(second.Models["walletAddress"].Fields) != 5 {
		t.Fatal("Schema returned shared mutable state")
	}
}

func TestSIWEConfigurationFailsClosed(t *testing.T) {
	base := defaultTestOptions()
	tests := []struct {
		name   string
		mutate func(*Options)
		want   string
	}{
		{"domain", func(options *Options) { options.Domain = "" }, "Domain is required"},
		{"nonce callback", func(options *Options) { options.GetNonce = nil }, "GetNonce is required"},
		{"verifier", func(options *Options) { options.VerifyMessage = nil }, "VerifyMessage is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := base
			test.mutate(&options)
			err := newTestAuthError(options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestFactorySnapshotsAnonymousAndSchemaOptions(t *testing.T) {
	anonymous := false
	options := defaultTestOptions()
	options.Anonymous = &anonymous
	options.Schema = storage.Schema{Models: map[string]storage.ModelSchema{
		"walletAddress": {ModelName: "wallet_address"},
	}}
	factory := NewFactory(options).(*rootFactory)
	anonymous = true
	model := options.Schema.Models["walletAddress"]
	model.ModelName = "mutated"
	options.Schema.Models["walletAddress"] = model
	if factory.options.Anonymous == nil || *factory.options.Anonymous ||
		factory.options.Schema.Models["walletAddress"].ModelName != "wallet_address" {
		t.Fatalf("factory retained caller-owned options: %#v", factory.options)
	}
}

func TestVerifierFailureIsRedactedAndBurnsNonce(t *testing.T) {
	options := defaultTestOptions()
	options.VerifyMessage = func(context.Context, VerifyMessageArgs) (bool, error) {
		return false, errors.New("private verifier detail")
	}
	auth := newTestAuth(t, options)
	requestNonce(t, auth, testWalletAddress, 1)
	response, body := verifyWallet(
		t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
		"valid_signature", nil,
	)
	if response.Code != 401 || responseCode(body) != "UNAUTHORIZED" ||
		responseMessage(body) != "Something went wrong. Please try again later." ||
		strings.Contains(response.Body.String(), "private verifier detail") {
		t.Fatalf("status=%d body=%#v", response.Code, body)
	}
	retry, retryBody := verifyWallet(
		t, auth, testWalletAddress, 1, testMessage(testMessageOptions{}),
		"valid_signature", nil,
	)
	if retry.Code != 401 || responseCode(retryBody) != "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE" {
		t.Fatalf("retry status=%d body=%#v", retry.Code, retryBody)
	}
}

func newTestAuthError(options Options) error {
	factory := NewFactory(options)
	_, err := factory.Schema()
	if err != nil {
		return err
	}
	_, err = New(options)
	return err
}
