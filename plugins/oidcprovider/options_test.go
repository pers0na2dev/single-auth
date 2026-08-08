package oidcprovider

import (
	"reflect"
	"testing"
	"time"
)

func TestFrozenDefaultOptions(t *testing.T) {
	options, err := NormalizeOptions(Options{LoginPage: "/login"})
	if err != nil {
		t.Fatal(err)
	}
	if options.AccessTokenExpiresIn != time.Hour ||
		options.RefreshTokenExpiresIn != 7*24*time.Hour ||
		options.CodeExpiresIn != 10*time.Minute || options.DefaultScope != "openid" ||
		options.AllowPlainCodeChallengeMethod || options.StoreClientSecret != ClientSecretPlain ||
		options.LoginPage != "/login" || !reflect.DeepEqual(
		options.Scopes, []string{"openid", "profile", "email", "offline_access"},
	) {
		t.Fatalf("defaults=%#v", options)
	}
}

func TestNormalizeOptionsSnapshotsMutableConfiguration(t *testing.T) {
	metadata := map[string]any{"nested": map[string]any{"value": "original"}}
	redirects := []string{"https://client.example/callback"}
	options, err := NormalizeOptions(Options{
		LoginPage: "/login", Metadata: metadata,
		Scopes: []string{"custom"},
		TrustedClients: []Client{{
			ClientID: "trusted", RedirectURLs: redirects,
			Metadata: map[string]any{"kind": "trusted"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata["nested"].(map[string]any)["value"] = "mutated"
	redirects[0] = "https://attacker.example"
	if options.Metadata["nested"].(map[string]any)["value"] != "original" ||
		options.TrustedClients[0].RedirectURLs[0] != "https://client.example/callback" {
		t.Fatalf("options were not snapshotted: %#v", options)
	}
}
