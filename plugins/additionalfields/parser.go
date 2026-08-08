package additionalfields

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

// ParseInput ports parseInputData from single-auth 1.6.26. Missing map keys,
// present nil values, and present zero values remain distinct.
func (p *Processor) ParseInput(
	modelName ModelName,
	data storage.Record,
	action Action,
) (storage.Record, error) {
	model, err := p.model(modelName)
	if err != nil {
		return nil, err
	}
	if action == "" {
		action = ActionCreate
	}
	if action != ActionCreate && action != ActionUpdate {
		return nil, fmt.Errorf("additionalfields: unsupported action %q", action)
	}
	if data == nil {
		data = storage.Record{}
	}

	parsed := make(storage.Record)
	for _, field := range model.fields {
		attribute := field.attribute
		value, supplied := data[field.name]
		if supplied {
			if attribute.Input != nil && !*attribute.Input {
				if attribute.DefaultValue != nil && action != ActionUpdate {
					defaultValue, defaultErr := attribute.DefaultValue(p.valueContext())
					if defaultErr != nil {
						return nil, defaultErr
					}
					parsed[field.name] = cloneValue(defaultValue)
					continue
				}
				if javascriptTruthy(value) {
					return nil, fieldNotAllowed(field.name)
				}
				continue
			}

			if field.validators.Input != nil {
				validated, validationErr := runValidator(field.validators.Input, value)
				if validationErr != nil {
					return nil, validationErr
				}
				parsed[field.name] = cloneValue(validated)
				continue
			}

			if attribute.Transform.Input != nil {
				transformed, transformErr := attribute.Transform.Input(value)
				if transformErr != nil {
					return nil, transformErr
				}
				parsed[field.name] = cloneValue(transformed)
				continue
			}

			parsed[field.name] = cloneValue(value)
			continue
		}

		if attribute.DefaultValue != nil && action == ActionCreate {
			defaultValue, defaultErr := attribute.DefaultValue(p.valueContext())
			if defaultErr != nil {
				return nil, defaultErr
			}
			parsed[field.name] = cloneValue(defaultValue)
			continue
		}

		// Runtime parsing intentionally checks only explicit required:true.
		// The DB and generated types still treat an omitted flag as required.
		if attribute.Required != nil && *attribute.Required && action == ActionCreate {
			return nil, missingField(field.name)
		}
	}
	return parsed, nil
}

// ParseUserInput is ParseInput for the user model.
func (p *Processor) ParseUserInput(data storage.Record, action Action) (storage.Record, error) {
	return p.ParseInput(ModelUser, data, action)
}

// ParseAdditionalUserInput parses user additional fields for creation.
func (p *Processor) ParseAdditionalUserInput(data storage.Record) (storage.Record, error) {
	return p.ParseInput(ModelUser, data, ActionCreate)
}

// ParseSessionInput is ParseInput for the session model.
func (p *Processor) ParseSessionInput(data storage.Record, action Action) (storage.Record, error) {
	return p.ParseInput(ModelSession, data, action)
}

// ParseAccountInput is ParseInput for account creation.
func (p *Processor) ParseAccountInput(data storage.Record) (storage.Record, error) {
	return p.ParseInput(ModelAccount, data, ActionCreate)
}

// ParseProviderUserInput filters input:false profile keys before parsing. This
// mirrors parseAdditionalUserInputFromProviderProfile.
func (p *Processor) ParseProviderUserInput(
	profile storage.Record,
	action Action,
) (storage.Record, error) {
	model, err := p.model(ModelUser)
	if err != nil {
		return nil, err
	}
	allowed := make(storage.Record)
	for key, value := range profile {
		field, exists := model.byName[key]
		if !exists || (field.attribute.Input != nil && !*field.attribute.Input) {
			continue
		}
		allowed[key] = cloneValue(value)
	}
	return p.ParseInput(ModelUser, allowed, action)
}

// ParseAdditionalUserInputFromProviderProfile is the upstream-named alias for
// ParseProviderUserInput.
func (p *Processor) ParseAdditionalUserInputFromProviderProfile(
	profile storage.Record,
	action Action,
) (storage.Record, error) {
	return p.ParseProviderUserInput(profile, action)
}

// SessionDefaults evaluates every configured session default on each call.
func (p *Processor) SessionDefaults() (storage.Record, error) {
	model, err := p.model(ModelSession)
	if err != nil {
		return nil, err
	}
	defaults := make(storage.Record)
	for _, field := range model.fields {
		if field.attribute.DefaultValue == nil {
			continue
		}
		value, valueErr := field.attribute.DefaultValue(p.valueContext())
		if valueErr != nil {
			return nil, valueErr
		}
		defaults[field.name] = cloneValue(value)
	}
	return defaults, nil
}

// GetSessionDefaultFields is the upstream-named alias for SessionDefaults.
func (p *Processor) GetSessionDefaultFields() (storage.Record, error) {
	return p.SessionDefaults()
}

// FilterOutput removes returned:false fields and deep-copies the result,
// matching filterOutputFields(structuredClone(data), schema).
func (p *Processor) FilterOutput(
	modelName ModelName,
	data storage.Record,
) (storage.Record, error) {
	if data == nil {
		return nil, nil
	}
	model, err := p.model(modelName)
	if err != nil {
		return nil, err
	}
	filtered := cloneRecord(data)
	if core, exists := storage.CoreSchema().Models[string(modelName)]; exists {
		for name, attribute := range core.Fields {
			if _, overridden := model.byName[name]; overridden {
				continue
			}
			if attribute.Returned != nil && !*attribute.Returned {
				delete(filtered, name)
			}
		}
	}
	for _, field := range model.fields {
		if field.attribute.Returned != nil && !*field.attribute.Returned {
			delete(filtered, field.name)
		}
	}
	return filtered, nil
}

// ParseUserOutput filters one user response.
func (p *Processor) ParseUserOutput(data storage.Record) (storage.Record, error) {
	return p.FilterOutput(ModelUser, data)
}

// ParseSessionOutput filters one session response.
func (p *Processor) ParseSessionOutput(data storage.Record) (storage.Record, error) {
	return p.FilterOutput(ModelSession, data)
}

// ParseAccountOutput filters one account response, including single-auth's
// six core credential/token fields marked returned:false.
func (p *Processor) ParseAccountOutput(data storage.Record) (storage.Record, error) {
	return p.FilterOutput(ModelAccount, data)
}

// ValidateOutput explicitly executes validator.output. single-auth 1.6.26
// stores this metadata but does not invoke it from parseUserOutput or the
// adapter factory, so this method is never installed as an automatic hook.
func (p *Processor) ValidateOutput(modelName ModelName, data storage.Record) (storage.Record, error) {
	model, err := p.model(modelName)
	if err != nil {
		return nil, err
	}
	result := cloneRecord(data)
	for _, field := range model.fields {
		value, supplied := result[field.name]
		if !supplied || field.validators.Output == nil {
			continue
		}
		validated, validationErr := runValidator(field.validators.Output, value)
		if validationErr != nil {
			return nil, validationErr
		}
		result[field.name] = cloneValue(validated)
	}
	return result, nil
}

// BuildSyntheticUserOutput builds the enumeration-protection user shape used
// by sign-up. It includes single-auth's base user fields plus configured
// fields, applies defaults, supplies null for non-explicitly-required missing
// fields, filters returned:false, and preserves id when supplied.
func (p *Processor) BuildSyntheticUserOutput(data storage.Record) (storage.Record, error) {
	result := make(storage.Record)
	model, err := p.model(ModelUser)
	if err != nil {
		return nil, err
	}
	core := storage.CoreSchema().Models["user"]
	for _, name := range []string{
		"name", "email", "emailVerified", "image", "createdAt", "updatedAt",
	} {
		if _, overridden := model.byName[name]; overridden {
			continue
		}
		attribute := core.Fields[name]
		if err := p.syntheticField(result, data, name, attribute); err != nil {
			return nil, err
		}
	}
	for _, field := range model.fields {
		if err := p.syntheticField(result, data, field.name, field.attribute); err != nil {
			return nil, err
		}
	}
	if id, exists := data["id"]; exists {
		result["id"] = cloneValue(id)
	}
	return result, nil
}

func (p *Processor) syntheticField(
	result storage.Record,
	data storage.Record,
	name string,
	attribute storage.FieldAttribute,
) error {
	if attribute.Returned != nil && !*attribute.Returned {
		return nil
	}
	if value, exists := data[name]; exists {
		result[name] = cloneValue(value)
		return nil
	}
	if attribute.DefaultValue != nil {
		value, err := attribute.DefaultValue(p.valueContext())
		if err != nil {
			return err
		}
		result[name] = cloneValue(value)
		return nil
	}
	if attribute.Required == nil || !*attribute.Required {
		result[name] = nil
	}
	return nil
}

func (p *Processor) valueContext() storage.ValueContext {
	return storage.ValueContext{Now: p.clock}
}

func runValidator(validator Validator, value any) (any, error) {
	result, err := validator(cloneValue(value))
	if err != nil {
		return nil, err
	}
	if result.Async {
		return nil, contract.NewAPIError(
			contract.StatusInternalServerError,
			CodeAsyncValidationNotSupported,
			"Async validation is not supported",
		)
	}
	if result.Issues != nil {
		message := "Validation Error"
		if len(result.Issues) > 0 && result.Issues[0].Message != "" {
			message = result.Issues[0].Message
		}
		return nil, contract.NewAPIError(contract.StatusBadRequest, CodeValidation, message)
	}
	return result.Value, nil
}

func fieldNotAllowed(name string) error {
	return contract.NewAPIError(
		contract.StatusBadRequest,
		CodeFieldNotAllowed,
		fmt.Sprintf("%s is not allowed to be set", name),
	)
}

func missingField(name string) error {
	return contract.NewAPIError(
		contract.StatusBadRequest,
		CodeMissingField,
		fmt.Sprintf("%s is required", name),
	)
}

func javascriptTruthy(value any) bool {
	if value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return typed != ""
	case json.Number:
		number, err := typed.Float64()
		return err != nil || (number != 0 && !math.IsNaN(number))
	case float64:
		return typed != 0 && !math.IsNaN(typed)
	case float32:
		return typed != 0 && !math.IsNaN(float64(typed))
	case int:
		return typed != 0
	case int8:
		return typed != 0
	case int16:
		return typed != 0
	case int32:
		return typed != 0
	case int64:
		return typed != 0
	case uint:
		return typed != 0
	case uint8:
		return typed != 0
	case uint16:
		return typed != 0
	case uint32:
		return typed != 0
	case uint64:
		return typed != 0
	default:
		// JavaScript arrays and objects are truthy even when empty.
		return true
	}
}

func cloneRecord(source storage.Record) storage.Record {
	if source == nil {
		return nil
	}
	result := make(storage.Record, len(source))
	for key, value := range source {
		result[key] = cloneValue(value)
	}
	return result
}

func cloneValue(value any) any {
	if value == nil {
		return nil
	}
	if instant, ok := value.(time.Time); ok {
		return instant
	}
	return cloneReflect(reflect.ValueOf(value))
}

func cloneReflect(value reflect.Value) any {
	if !value.IsValid() {
		return nil
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return nil
		}
		return cloneReflect(value.Elem())
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type()).Interface()
		}
		clone := reflect.MakeMapWithSize(value.Type(), value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			key := iterator.Key()
			item := iterator.Value()
			cloned := cloneReflect(item)
			if cloned == nil {
				clone.SetMapIndex(key, reflect.Zero(item.Type()))
				continue
			}
			clonedValue := reflect.ValueOf(cloned)
			if clonedValue.Type().AssignableTo(item.Type()) {
				clone.SetMapIndex(key, clonedValue)
			} else if clonedValue.Type().AssignableTo(value.Type().Elem()) {
				clone.SetMapIndex(key, clonedValue)
			} else {
				clone.SetMapIndex(key, item)
			}
		}
		return clone.Interface()
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type()).Interface()
		}
		clone := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		reflect.Copy(clone, value)
		for index := 0; index < value.Len(); index++ {
			item := value.Index(index)
			cloned := cloneReflect(item)
			if cloned == nil {
				clone.Index(index).Set(reflect.Zero(item.Type()))
				continue
			}
			clonedValue := reflect.ValueOf(cloned)
			if clonedValue.Type().AssignableTo(item.Type()) {
				clone.Index(index).Set(clonedValue)
			}
		}
		return clone.Interface()
	case reflect.Array:
		clone := reflect.New(value.Type()).Elem()
		reflect.Copy(clone, value)
		return clone.Interface()
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type()).Interface()
		}
		clone := reflect.New(value.Type().Elem())
		cloned := cloneReflect(value.Elem())
		if cloned != nil {
			clonedValue := reflect.ValueOf(cloned)
			if clonedValue.Type().AssignableTo(value.Type().Elem()) {
				clone.Elem().Set(clonedValue)
			}
		}
		return clone.Interface()
	default:
		return value.Interface()
	}
}
