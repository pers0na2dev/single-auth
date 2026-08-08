package organization

import (
	"fmt"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

// Schema returns the canonical single-auth organization storage extension.
func Schema(options Options) (storage.Schema, error) {
	optional := storage.Bool(false)
	notInput := storage.Bool(false)
	now := func(ctx storage.ValueContext) (any, error) {
		if ctx.Now != nil {
			return ctx.Now(), nil
		}
		return time.Now(), nil
	}
	extension := storage.Schema{Models: map[string]storage.ModelSchema{
		"organization": {
			ModelName: "organization",
			Fields: map[string]storage.FieldAttribute{
				"name":      {Type: storage.FieldString, Sortable: true},
				"slug":      {Type: storage.FieldString, Unique: true, Sortable: true, Index: true},
				"logo":      {Type: storage.FieldString, Required: optional},
				"createdAt": {Type: storage.FieldDate},
				"metadata":  {Type: storage.FieldString, Required: optional},
			},
		},
		"member": {
			ModelName: "member",
			Fields: map[string]storage.FieldAttribute{
				"organizationId": {
					Type: storage.FieldString, Index: true,
					References: &storage.Reference{Model: "organization", Field: "id", OnDelete: storage.Cascade},
				},
				"userId": {
					Type: storage.FieldString, Index: true,
					References: &storage.Reference{Model: "user", Field: "id", OnDelete: storage.Cascade},
				},
				"role":      {Type: storage.FieldString, Sortable: true, DefaultValue: storage.StaticValue("member")},
				"createdAt": {Type: storage.FieldDate},
			},
		},
		"invitation": {
			ModelName: "invitation",
			Fields: map[string]storage.FieldAttribute{
				"organizationId": {
					Type: storage.FieldString, Index: true,
					References: &storage.Reference{Model: "organization", Field: "id", OnDelete: storage.Cascade},
				},
				"email":     {Type: storage.FieldString, Sortable: true, Index: true},
				"role":      {Type: storage.FieldString, Required: optional, Sortable: true},
				"status":    {Type: storage.FieldString, Sortable: true, DefaultValue: storage.StaticValue("pending")},
				"expiresAt": {Type: storage.FieldDate},
				"createdAt": {Type: storage.FieldDate, DefaultValue: now},
				"inviterId": {
					Type:       storage.FieldString,
					References: &storage.Reference{Model: "user", Field: "id", OnDelete: storage.Cascade},
				},
			},
		},
		"session": {
			Fields: map[string]storage.FieldAttribute{
				"activeOrganizationId": {
					Type: storage.FieldString, Required: optional, Input: notInput,
				},
			},
		},
	}}
	if options.DynamicAccessControl.Enabled {
		extension.Models["organizationRole"] = storage.ModelSchema{
			ModelName: "organizationRole",
			Fields: map[string]storage.FieldAttribute{
				"organizationId": {
					Type: storage.FieldString, Index: true,
					References: &storage.Reference{Model: "organization", Field: "id", OnDelete: storage.Cascade},
				},
				"role":       {Type: storage.FieldString, Index: true},
				"permission": {Type: storage.FieldString},
				"createdAt":  {Type: storage.FieldDate, DefaultValue: now},
				"updatedAt":  {Type: storage.FieldDate, Required: optional, OnUpdate: now},
			},
		}
	}
	if options.Teams.Enabled {
		session := extension.Models["session"]
		session.Fields["activeTeamId"] = storage.FieldAttribute{
			Type: storage.FieldString, Required: optional, Input: notInput,
		}
		extension.Models["session"] = session
		invitation := extension.Models["invitation"]
		invitation.Fields["teamId"] = storage.FieldAttribute{
			Type: storage.FieldString, Required: optional, Sortable: true,
		}
		extension.Models["invitation"] = invitation
		extension.Models["team"] = storage.ModelSchema{
			ModelName: "team",
			Fields: map[string]storage.FieldAttribute{
				"name": {Type: storage.FieldString, Sortable: true},
				"organizationId": {
					Type: storage.FieldString, Index: true,
					References: &storage.Reference{Model: "organization", Field: "id", OnDelete: storage.Cascade},
				},
				"createdAt": {Type: storage.FieldDate},
				"updatedAt": {Type: storage.FieldDate, Required: optional},
			},
		}
		extension.Models["teamMember"] = storage.ModelSchema{
			ModelName: "teamMember",
			Fields: map[string]storage.FieldAttribute{
				"teamId": {
					Type: storage.FieldString, Index: true,
					References: &storage.Reference{Model: "team", Field: "id", OnDelete: storage.Cascade},
				},
				"userId": {
					Type: storage.FieldString, Index: true,
					References: &storage.Reference{Model: "user", Field: "id", OnDelete: storage.Cascade},
				},
				"createdAt": {Type: storage.FieldDate, Required: optional},
			},
		}
	}
	if len(options.Schema.Models) != 0 || options.Schema.UsePlural {
		// The organization extension contains references to core models. Merging
		// and validating it in isolation would reject member.userId before the
		// core user model is present, so compose first and validate below against
		// the complete single-auth schema.
		additional := options.Schema.Clone()
		if !options.DynamicAccessControl.Enabled {
			delete(additional.Models, "organizationRole")
		}
		extension = mergeOrganizationSchema(extension, additional)
	}
	if _, err := storage.CoreSchema().Merge(extension); err != nil {
		return storage.Schema{}, fmt.Errorf("organization: schema: %w", err)
	}
	return extension.Clone(), nil
}

func mergeOrganizationSchema(base, additional storage.Schema) storage.Schema {
	merged := base.Clone()
	additional = additional.Clone()
	for name, extra := range additional.Models {
		current, exists := merged.Models[name]
		if !exists {
			current = storage.ModelSchema{ModelName: name, Fields: map[string]storage.FieldAttribute{}}
		}
		if extra.ModelName != "" {
			current.ModelName = extra.ModelName
		}
		if extra.DisableMigrations {
			current.DisableMigrations = true
		}
		if extra.Order != 0 {
			current.Order = extra.Order
		}
		if current.Fields == nil {
			current.Fields = make(map[string]storage.FieldAttribute)
		}
		for field, attribute := range extra.Fields {
			current.Fields[field] = attribute
		}
		merged.Models[name] = current
	}
	merged.UsePlural = base.UsePlural || additional.UsePlural
	return merged
}
