package organization

import (
	"fmt"
	"time"

	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/storage"
)

var organizationBaseInputFields = map[string]struct{}{
	"id": {}, "name": {}, "slug": {}, "logo": {}, "metadata": {},
	"createdAt": {}, "updatedAt": {}, "members": {}, "userId": {},
	"keepCurrentActiveOrganization": {},
}

func (runtime *runtime) organizationAdditionalInput(
	input storage.Record,
	partial bool,
) (storage.Record, error) {
	return runtime.modelAdditionalInput(
		"organization", organizationBaseInputFields, input, partial,
	)
}

func (runtime *runtime) modelAdditionalInput(
	modelName string,
	baseFields map[string]struct{},
	input storage.Record,
	partial bool,
) (storage.Record, error) {
	modelSchema, ok := runtime.schema.Models[modelName]
	if !ok {
		return storage.Record{}, nil
	}
	result := storage.Record{}
	for name, attribute := range modelSchema.Fields {
		if _, base := baseFields[name]; base || !attribute.IsInput() {
			continue
		}
		value, present := input[name]
		if !present {
			if !partial && attribute.IsRequired() && attribute.DefaultValue == nil {
				return nil, invalidOrganizationBody(fmt.Errorf(
					"required %s field %q is missing", modelName, name,
				))
			}
			continue
		}
		normalized, err := normalizeTeamInputValue(attribute, value)
		if err != nil {
			return nil, invalidOrganizationBody(fmt.Errorf(
				"%s field %q: %w", modelName, name, err,
			))
		}
		parsed, err := storage.ToRecordSchema(
			map[string]storage.FieldAttribute{name: attribute}, true,
		).Parse(storage.Record{name: normalized})
		if err != nil {
			return nil, invalidOrganizationBody(err)
		}
		if parsedValue, exists := parsed[name]; exists {
			result[name] = parsedValue
		}
	}
	return result, nil
}

func (runtime *runtime) organizationFromRecord(record storage.Record) Organization {
	public := parseOrganizationMetadata(runtime.publicRecord("organization", record))
	result := organizationFromRecord(public)
	result.AdditionalFields = runtime.additionalModelFields("organization", public,
		"id", "name", "slug", "logo", "metadata", "createdAt", "updatedAt",
	)
	return result
}

func (runtime *runtime) memberFromRecord(record storage.Record) Member {
	public := runtime.publicRecord("member", record)
	result := memberFromRecord(public)
	result.AdditionalFields = runtime.additionalModelFields("member", public,
		"id", "organizationId", "userId", "role", "createdAt", "user",
	)
	return result
}

func (runtime *runtime) invitationFromRecord(record storage.Record) Invitation {
	public := runtime.publicRecord("invitation", record)
	result := invitationFromRecord(public)
	result.AdditionalFields = runtime.additionalModelFields("invitation", public,
		"id", "organizationId", "email", "role", "status", "teamId",
		"inviterId", "expiresAt", "createdAt",
	)
	return result
}

func (runtime *runtime) teamFromRecord(record storage.Record) Team {
	public := runtime.publicRecord("team", record)
	result := teamFromRecord(public)
	result.AdditionalFields = runtime.additionalModelFields("team", public,
		"id", "name", "organizationId", "createdAt", "updatedAt",
	)
	return result
}

func (runtime *runtime) teamMemberFromRecord(record storage.Record) TeamMember {
	public := runtime.publicRecord("teamMember", record)
	result := TeamMember{}
	result.ID, _ = recordString(public, "id")
	result.TeamID, _ = recordString(public, "teamId")
	result.UserID, _ = recordString(public, "userId")
	if createdAt, ok := public["createdAt"].(time.Time); ok {
		result.CreatedAt = &createdAt
	}
	result.AdditionalFields = runtime.additionalModelFields("teamMember", public,
		"id", "teamId", "userId", "createdAt",
	)
	return result
}

func (runtime *runtime) additionalModelFields(
	modelName string,
	record storage.Record,
	known ...string,
) model.Fields {
	if record == nil {
		return nil
	}
	modelSchema, ok := runtime.schema.Models[modelName]
	if !ok {
		return nil
	}
	knownFields := make(map[string]struct{}, len(known))
	for _, name := range known {
		knownFields[name] = struct{}{}
	}
	additional := model.Fields{}
	for name, attribute := range modelSchema.Fields {
		if _, base := knownFields[name]; base || !attribute.IsReturned() {
			continue
		}
		value, present := record[name]
		if !present {
			continue
		}
		if value == nil {
			additional.SetNull(name)
		} else {
			additional.Set(name, value)
		}
	}
	if len(additional) == 0 {
		return nil
	}
	return additional
}
