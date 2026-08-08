package oauthpopup

import (
	"strings"
	"testing"
)

func TestCompletionScriptHashIsPinned(t *testing.T) {
	if got := scriptDigest(); got != CompleteScriptCSPHash {
		t.Fatalf("completion script hash = %q, want %q", got, CompleteScriptCSPHash)
	}
}

func TestStandaloneRuntimeRequirements(t *testing.T) {
	_, err := New(Options{})
	if err == nil || !strings.Contains(err.Error(), "Runtime.Secret is required") {
		t.Fatalf("missing runtime error = %v", err)
	}
	if NewFactory().PluginID() != "oauth-popup" {
		t.Fatalf("factory ID = %q", NewFactory().PluginID())
	}
}

func TestAdditionalDataFiltersEveryInternalStateKey(t *testing.T) {
	parsed := parseAdditionalData(`{
		"callbackURL":"evil","codeVerifier":"evil","errorURL":"evil",
		"newUserURL":"evil","expiresAt":1,"oauthState":"evil",
		"link":{"userId":"other"},"requestSignUp":true,"tenant":"acme"
	}`)
	if len(parsed) != 1 || parsed["tenant"] != "acme" {
		t.Fatalf("filtered additional data = %#v", parsed)
	}
	if invalid := parseAdditionalData(`not-json`); len(invalid) != 0 {
		t.Fatalf("invalid JSON = %#v, want empty object", invalid)
	}
}
