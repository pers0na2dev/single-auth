package oidcprovider

import (
	"reflect"
	"testing"
)

func TestParsePromptSingleValue(t *testing.T) {
	result, err := ParsePrompt("login")
	if err != nil || !result.Has(PromptLogin) || len(result) != 1 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestParsePromptMultipleValues(t *testing.T) {
	result, err := ParsePrompt("login consent")
	if err != nil || !result.Has(PromptLogin) || !result.Has(PromptConsent) || len(result) != 2 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestParsePromptExtraSpaces(t *testing.T) {
	result, err := ParsePrompt("login  consent   select_account")
	if err != nil || len(result) != 3 || !result.Has(PromptLogin) ||
		!result.Has(PromptConsent) || !result.Has(PromptSelectAccount) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestParsePromptIgnoresInvalidValues(t *testing.T) {
	result, err := ParsePrompt("login invalid_prompt consent")
	if err != nil || len(result) != 2 || !result.Has(PromptLogin) || !result.Has(PromptConsent) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestParsePromptNoneAlone(t *testing.T) {
	result, err := ParsePrompt("none")
	if err != nil || len(result) != 1 || !result.Has(PromptNone) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestParsePromptRejectsNoneWithOtherPrompt(t *testing.T) {
	result, err := ParsePrompt("none login")
	if result != nil || err == nil || err.Error() != "prompt none must only be used alone" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestParsePromptRejectsNoneWithConsent(t *testing.T) {
	if _, err := ParsePrompt("none consent"); err == nil {
		t.Fatal("expected InvalidRequest")
	}
}

func TestParsePromptEmpty(t *testing.T) {
	result, err := ParsePrompt("")
	if err != nil || len(result) != 0 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestParsePromptAllValidTypes(t *testing.T) {
	result, err := ParsePrompt("login consent select_account")
	want := PromptSet{PromptLogin: {}, PromptConsent: {}, PromptSelectAccount: {}}
	if err != nil || !reflect.DeepEqual(result, want) {
		t.Fatalf("result=%#v err=%v want=%#v", result, err, want)
	}
}
