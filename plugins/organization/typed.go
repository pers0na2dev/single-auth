package organization

import (
	"context"
	"errors"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/model"
)

// SessionAdditionalFields is the statically inferred session contribution of
// the organization plugin.
type SessionAdditionalFields struct {
	ActiveOrganizationID model.Value[string]
}

func DecodeSessionAdditionalFields(fields model.Fields) (SessionAdditionalFields, error) {
	value, err := singleauth.DecodeDBField[string](fields, "activeOrganizationId")
	if err != nil {
		return SessionAdditionalFields{}, err
	}
	return SessionAdditionalFields{ActiveOrganizationID: value}, nil
}

// TypedDirectAPI preserves organization-specific server methods as a concrete
// API value suitable for composition with other differently shaped plugins.
type TypedDirectAPI struct {
	plugin *Plugin
}

func BindTypedDirectAPI(plugin *Plugin) TypedDirectAPI {
	return TypedDirectAPI{plugin: plugin}
}

func (api TypedDirectAPI) CreateOrganization(
	ctx context.Context,
	input CreateOrganizationInput,
) (CreateOrganizationResult, error) {
	if api.plugin == nil {
		return CreateOrganizationResult{}, errors.New("organization: typed direct API is not initialized")
	}
	return api.plugin.CreateOrganization(ctx, input)
}
