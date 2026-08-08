package organization

import (
	"encoding/json"

	"github.com/pers0na2dev/single-auth/core/model"
)

// marshalOrganizationJSON keeps schema-defined fields flat, matching the
// wire shape used by Better Auth. Canonical fields are marshaled first and can
// never be replaced by an AdditionalFields entry with the same name.
func marshalOrganizationJSON(
	base any,
	additional model.Fields,
	canonical map[string]any,
) ([]byte, error) {
	encoded, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	object := map[string]json.RawMessage{}
	if err := json.Unmarshal(encoded, &object); err != nil {
		return nil, err
	}
	for name, field := range additional {
		if _, exists := object[name]; exists {
			continue
		}
		value, set := field.Interface()
		if !set {
			continue
		}
		fieldJSON, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		object[name] = fieldJSON
	}
	for name, value := range canonical {
		fieldJSON, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		object[name] = fieldJSON
	}
	return json.Marshal(object)
}

func (value Organization) MarshalJSON() ([]byte, error) {
	type plain Organization
	return marshalOrganizationJSON(plain(value), value.AdditionalFields, nil)
}

func (value Member) MarshalJSON() ([]byte, error) {
	type plain Member
	return marshalOrganizationJSON(plain(value), value.AdditionalFields, nil)
}

func (value Invitation) MarshalJSON() ([]byte, error) {
	type plain Invitation
	return marshalOrganizationJSON(plain(value), value.AdditionalFields, nil)
}

func (value Team) MarshalJSON() ([]byte, error) {
	type plain Team
	return marshalOrganizationJSON(plain(value), value.AdditionalFields, nil)
}

func (value TeamMember) MarshalJSON() ([]byte, error) {
	type plain TeamMember
	return marshalOrganizationJSON(plain(value), value.AdditionalFields, nil)
}

func (value OrganizationRole) MarshalJSON() ([]byte, error) {
	type plain OrganizationRole
	return marshalOrganizationJSON(plain(value), value.AdditionalFields, nil)
}

// The result types below anonymously embed custom-marshaling base values.
// Explicit marshalers prevent method promotion from hiding their outer fields.
func (value CreateOrganizationResult) MarshalJSON() ([]byte, error) {
	type plain Organization
	return marshalOrganizationJSON(plain(value.Organization), value.AdditionalFields, map[string]any{
		"members": value.Members,
	})
}

func (value FullOrganization) MarshalJSON() ([]byte, error) {
	type plain Organization
	canonical := map[string]any{
		"members":     value.Members,
		"invitations": value.Invitations,
	}
	if len(value.Teams) > 0 {
		canonical["teams"] = value.Teams
	}
	return marshalOrganizationJSON(plain(value.Organization), value.AdditionalFields, canonical)
}

func (value InvitationDetails) MarshalJSON() ([]byte, error) {
	type plain Invitation
	return marshalOrganizationJSON(plain(value.Invitation), value.AdditionalFields, map[string]any{
		"organizationName": value.OrganizationName,
		"organizationSlug": value.OrganizationSlug,
		"inviterEmail":     value.InviterEmail,
	})
}

func (value UserInvitation) MarshalJSON() ([]byte, error) {
	type plain Invitation
	return marshalOrganizationJSON(plain(value.Invitation), value.AdditionalFields, map[string]any{
		"organizationName": value.OrganizationName,
	})
}
