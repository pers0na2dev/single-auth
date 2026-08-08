package haveibeenpwned

import (
	"errors"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
)

func TestNewRequiresPasswordHashRegistrar(t *testing.T) {
	_, err := New(Options{})
	if err == nil || !strings.Contains(err.Error(), "Runtime.WrapPasswordHash is required") {
		t.Fatalf("error = %#v", err)
	}
}

func TestNewPropagatesPasswordHashRegistrarError(t *testing.T) {
	sentinel := errors.New("chain frozen")
	_, err := New(Options{Runtime: Runtime{
		WrapPasswordHash: func(PasswordHashWrapper) error { return sentinel },
	}})
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "install password hash wrapper") {
		t.Fatalf("error = %#v", err)
	}
}

func TestFactoryMetadataAndMissingHostSurface(t *testing.T) {
	factory := NewFactory(Options{})
	if factory.PluginID() != PluginID {
		t.Fatalf("factory id = %q", factory.PluginID())
	}
	schema, err := factory.Schema()
	if err != nil || len(schema.Models) != 0 || schema.UsePlural {
		t.Fatalf("schema = %#v err=%v", schema, err)
	}
	_, err = factory.Build(singleauth.PluginHost{})
	if err == nil || !strings.Contains(err.Error(), "host password hash wrapper is required") {
		t.Fatalf("build error = %#v", err)
	}
}
