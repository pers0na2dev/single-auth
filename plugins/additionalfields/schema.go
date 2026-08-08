package additionalfields

import (
	"fmt"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

type compiledField struct {
	name       string
	attribute  storage.FieldAttribute
	validators FieldValidators
}

type compiledModel struct {
	fields []compiledField
	byName map[string]compiledField
}

// Processor is an immutable compiled additional-fields contract. It is safe
// for concurrent use when the configured callbacks are themselves safe.
type Processor struct {
	models map[ModelName]compiledModel
	schema storage.Schema
	clock  func() time.Time
}

// Compile validates and snapshots options for reuse by endpoint and internal
// server paths.
func Compile(input Options) (*Processor, error) {
	models := make(map[ModelName]compiledModel, 4)
	schema := storage.Schema{Models: make(map[string]storage.ModelSchema, 4)}

	for _, entry := range []struct {
		name   ModelName
		fields Fields
	}{
		{name: ModelUser, fields: input.User},
		{name: ModelSession, fields: input.Session},
		{name: ModelAccount, fields: input.Account},
		{name: ModelVerification, fields: input.Verification},
	} {
		model, err := compileModel(entry.name, entry.fields)
		if err != nil {
			return nil, err
		}
		models[entry.name] = model
		if len(model.fields) == 0 {
			continue
		}
		attributes := make(map[string]storage.FieldAttribute, len(model.fields))
		for _, field := range model.fields {
			attributes[field.name] = cloneAttribute(field.attribute)
		}
		schema.Models[string(entry.name)] = storage.ModelSchema{Fields: attributes}
	}

	// Validate extensions in the same base-model context in which Auth.New
	// merges plugin schemas. This catches invalid types, aliases, and core
	// references without mutating the caller's schema.
	if _, err := storage.CoreSchema().Merge(schema); err != nil {
		return nil, fmt.Errorf("additionalfields: schema: %w", err)
	}

	clock := input.Runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Processor{models: models, schema: schema, clock: clock}, nil
}

func compileModel(name ModelName, input Fields) (compiledModel, error) {
	result := compiledModel{
		fields: make([]compiledField, 0, len(input)),
		byName: make(map[string]compiledField, len(input)),
	}
	for index, source := range input {
		if source.Name == "" {
			return compiledModel{}, fmt.Errorf(
				"additionalfields: %s field %d has an empty name", name, index,
			)
		}
		if _, duplicate := result.byName[source.Name]; duplicate {
			return compiledModel{}, fmt.Errorf(
				"additionalfields: %s field %q is duplicated", name, source.Name,
			)
		}
		field := compiledField{
			name:       source.Name,
			attribute:  cloneAttribute(source.Attribute),
			validators: source.Validators,
		}
		result.fields = append(result.fields, field)
		result.byName[field.name] = field
	}
	return result, nil
}

// Schema returns an independent plugin schema snapshot.
func (p *Processor) Schema() storage.Schema {
	if p == nil {
		return storage.Schema{}
	}
	return p.schema.Clone()
}

func cloneAttribute(source storage.FieldAttribute) storage.FieldAttribute {
	clone := source
	clone.Enum = append([]string(nil), source.Enum...)
	if source.Required != nil {
		value := *source.Required
		clone.Required = &value
	}
	if source.Returned != nil {
		value := *source.Returned
		clone.Returned = &value
	}
	if source.Input != nil {
		value := *source.Input
		clone.Input = &value
	}
	if source.References != nil {
		reference := *source.References
		clone.References = &reference
	}
	return clone
}

func snapshotOptions(source Options) Options {
	result := source
	result.User = snapshotFields(source.User)
	result.Session = snapshotFields(source.Session)
	result.Account = snapshotFields(source.Account)
	result.Verification = snapshotFields(source.Verification)
	return result
}

func snapshotFields(source Fields) Fields {
	if source == nil {
		return nil
	}
	result := make(Fields, len(source))
	for index, field := range source {
		result[index] = field
		result[index].Attribute = cloneAttribute(field.Attribute)
	}
	return result
}

func (p *Processor) model(name ModelName) (compiledModel, error) {
	if p == nil {
		return compiledModel{}, fmt.Errorf("additionalfields: processor is nil")
	}
	model, ok := p.models[name]
	if !ok {
		return compiledModel{}, fmt.Errorf("additionalfields: unsupported model %q", name)
	}
	return model, nil
}
