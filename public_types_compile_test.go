package singleauth_test

import (
	"reflect"
	"testing"

	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

// These tests live in singleauth_test deliberately: compilation proves that
// downstream modules can name and construct the public Go API without access
// to package internals.
func TestPublicTypeExportGoogleProfileCompileContract(t *testing.T) {
	profile := providers.GoogleProfile{
		"sub":   "google-subject",
		"email": "person@example.com",
	}
	var exported map[string]any = profile
	if reflect.TypeOf(exported).Kind() != reflect.Map || exported["sub"] != "google-subject" {
		t.Fatalf("providers.GoogleProfile is not the exported lossless profile map: %#v", exported)
	}
}

func TestPublicTypeExportJoinConfigCompileContract(t *testing.T) {
	config := storage.JoinConfig{
		From:     "user.id",
		To:       "session.userId",
		Limit:    1,
		Relation: storage.OneToOne,
	}
	var exported storage.JoinConfig = config
	if reflect.TypeOf(exported).Kind() != reflect.Struct || exported.Relation != storage.OneToOne {
		t.Fatalf("storage.JoinConfig is not the exported concrete join config: %#v", exported)
	}
}

func TestPublicTypeExportJoinOptionCompileContract(t *testing.T) {
	limit := 10
	option := storage.JoinOption{Limit: &limit}
	var exported storage.JoinOption = option
	if reflect.TypeOf(exported).Kind() != reflect.Struct || exported.Limit == nil || *exported.Limit != limit {
		t.Fatalf("storage.JoinOption is not the exported concrete join option: %#v", exported)
	}
}
