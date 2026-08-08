package twofactor

import (
	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/storage"
)

// TypedFactory is the concrete, non-erased two-factor plugin factory used by
// typed plugin contexts. Its runtime behavior delegates to the same production
// factory as NewFactory.
type TypedFactory struct {
	factory singleauth.PluginFactory
}

func NewTypedFactory(options Options) *TypedFactory {
	return &TypedFactory{factory: NewFactory(options)}
}

func (*TypedFactory) PluginID() string { return "two-factor" }

func (factory *TypedFactory) Schema() (storage.Schema, error) {
	return factory.factory.Schema()
}

func (factory *TypedFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	return factory.factory.Build(host)
}

// UserAdditionalFields is the statically inferred user contribution of the
// two-factor plugin. model.Value preserves undefined, null, and boolean.
type UserAdditionalFields struct {
	TwoFactorEnabled model.Value[bool]
}

func DecodeUserAdditionalFields(fields model.Fields) (UserAdditionalFields, error) {
	value, err := singleauth.DecodeUserField[bool](fields, "twoFactorEnabled")
	if err != nil {
		return UserAdditionalFields{}, err
	}
	return UserAdditionalFields{TwoFactorEnabled: value}, nil
}

var _ singleauth.PluginFactory = (*TypedFactory)(nil)
