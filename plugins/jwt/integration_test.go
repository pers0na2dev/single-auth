package jwt

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

func rootOptions(factory singleauth.PluginFactory) singleauth.Options {
	return singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: testSecret,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return "hash:" + password, nil },
				Verify: func(hash, password string) bool { return hash == "hash:"+password },
			},
		},
		PluginFactories: []singleauth.PluginFactory{factory},
	}
}

func TestRootFactoryTokenJWKSVerifyAndSessionHeader(t *testing.T) {
	auth, err := singleauth.New(rootOptions(NewFactory(Options{})))
	if err != nil {
		t.Fatal(err)
	}
	signUp, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "JWT User", Email: "jwt@example.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := cookies.ApplySetCookies("", signUp.Headers.Values("Set-Cookie"))
	headers := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookie})

	tokenResult, err := auth.API().Call(t.Context(), "getToken", singleauth.DirectCallInput{
		Method: http.MethodGet, Scheme: "http", Host: "localhost:3000", Headers: headers,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := tokenResult.Value.(map[string]any)["token"].(string)
	_, payload := tokenParts(t, token)
	if payload["sub"] != payload["id"] || payload["iss"] != "http://localhost:3000" {
		t.Fatalf("token payload = %#v", payload)
	}

	jwksResult, err := auth.API().Call(t.Context(), "getJwks", singleauth.DirectCallInput{
		Method: http.MethodGet, Scheme: "http", Host: "localhost:3000",
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := jwksResult.Value.(map[string]any)["keys"].([]any)
	if len(keys) != 1 || keys[0].(map[string]any)["kid"] == "" {
		t.Fatalf("jwks = %#v", jwksResult.Value)
	}

	verifyResult, err := auth.API().Call(t.Context(), "verifyJWT", singleauth.DirectCallInput{
		Method: http.MethodPost, Scheme: "http", Host: "localhost:3000",
		Body: map[string]any{"token": token},
	})
	if err != nil {
		t.Fatal(err)
	}
	verified := verifyResult.Value.(map[string]any)["payload"].(map[string]any)
	if verified["sub"] != payload["sub"] {
		t.Fatalf("verified payload = %#v", verified)
	}

	sessionResult, err := auth.API().Call(t.Context(), "getSession", singleauth.DirectCallInput{
		Method: http.MethodGet, Scheme: "http", Host: "localhost:3000", Headers: headers,
	})
	if err != nil {
		t.Fatal(err)
	}
	jwtHeader, _ := sessionResult.Response.Headers().Get("set-auth-jwt")
	exposed, _ := sessionResult.Response.Headers().Get("Access-Control-Expose-Headers")
	if jwtHeader == "" || !strings.Contains(exposed, "set-auth-jwt") {
		t.Fatalf("session headers = %#v", sessionResult.Response.Headers().Fields())
	}
}

func TestRootFactoryAlgorithmAndEncryptionMatrix(t *testing.T) {
	algorithms := []KeyPairConfig{
		{Algorithm: EdDSA, Curve: "Ed25519"}, {Algorithm: ES256}, {Algorithm: ES512},
		{Algorithm: PS256}, {Algorithm: RS256},
	}
	for _, keyPair := range algorithms {
		for _, disableEncryption := range []bool{false, true} {
			name := string(keyPair.Algorithm)
			if disableEncryption {
				name += "-plain"
			}
			t.Run(name, func(t *testing.T) {
				factory := NewFactory(Options{JWKS: JWKSOptions{
					KeyPair: &keyPair, DisablePrivateKeyEncryption: disableEncryption,
				}})
				auth, err := singleauth.New(rootOptions(factory))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
					Name: "Matrix User", Email: "matrix@example.com", Password: "password123",
				}); err != nil {
					t.Fatal(err)
				}
				signIn, err := auth.API().SignInEmail(t.Context(), singleauth.SignInEmailInput{
					Email: "matrix@example.com", Password: "password123",
				})
				if err != nil {
					t.Fatal(err)
				}
				cookie := cookies.ApplySetCookies("", signIn.Headers.Values("Set-Cookie"))
				headers := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookie})
				tokenResult, err := auth.API().Call(t.Context(), "getToken", singleauth.DirectCallInput{
					Method: http.MethodGet, Scheme: "http", Host: "localhost:3000", Headers: headers,
				})
				if err != nil {
					t.Fatal(err)
				}
				token := tokenResult.Value.(map[string]any)["token"].(string)
				header, payload := tokenParts(t, token)
				if header["alg"] != string(keyPair.Algorithm) || payload["sub"] != payload["id"] {
					t.Fatalf("header=%#v payload=%#v", header, payload)
				}
				verifyResult, err := auth.API().Call(t.Context(), "verifyJWT", singleauth.DirectCallInput{
					Method: http.MethodPost, Scheme: "http", Host: "localhost:3000",
					Body: map[string]any{"token": token},
				})
				if err != nil || verifyResult.Value.(map[string]any)["payload"] == nil {
					t.Fatalf("verify=%#v err=%v", verifyResult.Value, err)
				}
				sessionResult, err := auth.API().Call(t.Context(), "getSession", singleauth.DirectCallInput{
					Method: http.MethodGet, Scheme: "http", Host: "localhost:3000", Headers: headers,
				})
				if err != nil {
					t.Fatal(err)
				}
				if jwtHeader, _ := sessionResult.Response.Headers().Get("set-auth-jwt"); jwtHeader == "" {
					t.Fatal("get-session JWT header missing")
				}
				jwksResult, err := auth.API().Call(t.Context(), "getJwks", singleauth.DirectCallInput{
					Method: http.MethodGet, Scheme: "http", Host: "localhost:3000",
				})
				if err != nil || len(jwksResult.Value.(map[string]any)["keys"].([]any)) != 1 {
					t.Fatalf("jwks=%#v err=%v", jwksResult.Value, err)
				}
			})
		}
	}
}

func TestRootFactoryRemoteURLKeepsTokenAndHeaderEndpoints(t *testing.T) {
	options := Options{JWKS: JWKSOptions{
		RemoteURL: "https://keys.example.test/.well-known/jwks.json",
		KeyPair:   &KeyPairConfig{Algorithm: ES256},
	}}
	auth, err := singleauth.New(rootOptions(NewFactory(options)))
	if err != nil {
		t.Fatal(err)
	}
	signUp, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "Remote User", Email: "remote@example.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := cookies.ApplySetCookies("", signUp.Headers.Values("Set-Cookie"))
	headers := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookie})
	tokenResult, err := auth.API().Call(t.Context(), "getToken", singleauth.DirectCallInput{
		Method: http.MethodGet, Scheme: "http", Host: "localhost:3000", Headers: headers,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := tokenResult.Value.(map[string]any)["token"].(string)
	if len(strings.Split(token, ".")) != 3 {
		t.Fatalf("token = %q", token)
	}
	_, err = auth.API().Call(t.Context(), "getJwks", singleauth.DirectCallInput{
		Method: http.MethodGet, Scheme: "http", Host: "localhost:3000",
	})
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Status != http.StatusNotFound {
		t.Fatalf("remote jwks error = %#v", err)
	}
	sessionResult, err := auth.API().Call(t.Context(), "getSession", singleauth.DirectCallInput{
		Method: http.MethodGet, Scheme: "http", Host: "localhost:3000", Headers: headers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if jwtHeader, _ := sessionResult.Response.Headers().Get("set-auth-jwt"); jwtHeader == "" {
		t.Fatal("remote URL disabled session JWT header")
	}
}

func TestRootFactoryRemoteCustomSignerReceivesSessionPayload(t *testing.T) {
	var captured map[string]any
	options := Options{
		JWKS: JWKSOptions{
			RemoteURL: "https://keys.example.test/.well-known/jwks.json",
			KeyPair:   &KeyPairConfig{Algorithm: ES256},
		},
		Token: TokenOptions{Sign: func(_ context.Context, payload map[string]any) (string, error) {
			captured = cloneMap(payload)
			header, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT"})
			body, _ := json.Marshal(payload)
			return rawURL.EncodeToString(header) + "." + rawURL.EncodeToString(body) + ".mock-signature", nil
		}},
	}
	auth, err := singleauth.New(rootOptions(NewFactory(options)))
	if err != nil {
		t.Fatal(err)
	}
	signUp, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "Remote Signer", Email: "remote-signer@example.com", Password: "password123",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := cookies.ApplySetCookies("", signUp.Headers.Values("Set-Cookie"))
	result, err := auth.API().Call(t.Context(), "getToken", singleauth.DirectCallInput{
		Method: http.MethodGet, Scheme: "http", Host: "localhost:3000",
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookie}),
	})
	if err != nil {
		t.Fatal(err)
	}
	token := result.Value.(map[string]any)["token"].(string)
	if !strings.Contains(token, "mock-signature") || captured["id"] == nil || captured["sub"] != captured["id"] {
		t.Fatalf("token=%q payload=%#v", token, captured)
	}
}

func TestRootFactoryMintsJWKSInsideActiveTransaction(t *testing.T) {
	auth, err := singleauth.New(rootOptions(NewFactory(Options{})))
	if err != nil {
		t.Fatal(err)
	}
	var token string
	err = auth.RunInTransaction(t.Context(), func(transactionContext context.Context) error {
		result, callErr := auth.API().Call(transactionContext, "signJWT", singleauth.DirectCallInput{
			Method: http.MethodPost, Scheme: "http", Host: "localhost:3000",
			Body: map[string]any{"payload": map[string]any{"sub": "transaction-user"}},
		})
		if callErr != nil {
			return callErr
		}
		token = result.Value.(map[string]any)["token"].(string)
		return nil
	})
	if err != nil || token == "" {
		t.Fatalf("transaction token=%q err=%v", token, err)
	}
	keys, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "jwks"})
	if err != nil || len(keys) != 1 {
		t.Fatalf("persisted keys = %#v err=%v", keys, err)
	}
}

func TestRootFactoryPrivateKeySecretRotation(t *testing.T) {
	schema, err := storage.CoreSchema().Merge(Schema())
	if err != nil {
		t.Fatal(err)
	}
	adapter := memory.MustNew(memory.WithSchema(schema))
	legacy := "legacy-secret-0123456789abcdef0123456789"
	v1 := "version-one-secret-0123456789abcdef012345"
	v2 := "version-two-secret-0123456789abcdef012345"

	makeAuth := func(secrets []baCrypto.SecretEntry) *singleauth.Auth {
		options := rootOptions(NewFactory(Options{}))
		options.Database = adapter
		options.Secret = legacy
		options.Secrets = secrets
		auth, createErr := singleauth.New(options)
		if createErr != nil {
			t.Fatal(createErr)
		}
		return auth
	}
	first := makeAuth([]baCrypto.SecretEntry{{Version: 1, Value: v1}})
	firstResult, err := first.API().Call(t.Context(), "signJWT", singleauth.DirectCallInput{
		Method: http.MethodPost, Scheme: "http", Host: "localhost:3000",
		Body: map[string]any{"payload": map[string]any{"sub": "rotating-user"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstToken := firstResult.Value.(map[string]any)["token"].(string)
	rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "jwks"})
	if err != nil || len(rows) != 1 {
		t.Fatalf("keys=%#v err=%v", rows, err)
	}
	var envelope string
	if err := json.Unmarshal([]byte(rows[0]["privateKey"].(string)), &envelope); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(envelope, "$ba$1$") {
		t.Fatalf("private key envelope = %q", envelope)
	}

	second := makeAuth([]baCrypto.SecretEntry{{Version: 2, Value: v2}, {Version: 1, Value: v1}})
	secondResult, err := second.API().Call(t.Context(), "signJWT", singleauth.DirectCallInput{
		Method: http.MethodPost, Scheme: "http", Host: "localhost:3000",
		Body: map[string]any{"payload": map[string]any{"sub": "rotating-user-2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	secondToken := secondResult.Value.(map[string]any)["token"].(string)
	for _, token := range []string{firstToken, secondToken} {
		verified, verifyErr := second.API().Call(t.Context(), "verifyJWT", singleauth.DirectCallInput{
			Method: http.MethodPost, Scheme: "http", Host: "localhost:3000",
			Body: map[string]any{"token": token},
		})
		if verifyErr != nil || verified.Value.(map[string]any)["payload"] == nil {
			t.Fatalf("rotated verify token=%q value=%#v err=%v", token, verified.Value, verifyErr)
		}
	}
}

func TestWrongPrivateKeySecretReturnsExactUpstreamMessage(t *testing.T) {
	clock := &testClock{now: time.Now()}
	store := &keyStore{}
	first := baseTestOptions(store, clock)
	implementation, err := normalize(first, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := implementation.signJWT(nil, map[string]any{
		"sub": "first", "iss": "http://localhost:3000", "aud": "http://localhost:3000",
	}); err != nil {
		t.Fatal(err)
	}
	second := baseTestOptions(store, clock)
	second.Runtime.Secret = "different-secret-0123456789abcdef012345"
	implementation, err = normalize(second, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = implementation.signJWT(nil, map[string]any{
		"sub": "second", "iss": "http://localhost:3000", "aud": "http://localhost:3000",
	})
	if err == nil || err.Error() != privateKeyDecryptMessage {
		t.Fatalf("decrypt error = %v", err)
	}
}
