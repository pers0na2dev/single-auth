package storage

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AdapterAction is the operation currently being normalized by an adapter
// factory. The stable string values let custom adapters share one set of
// transport-independent transformation rules.
type AdapterAction string

const (
	ActionCreate       AdapterAction = "create"
	ActionUpdate       AdapterAction = "update"
	ActionUpdateMany   AdapterAction = "updateMany"
	ActionFindOne      AdapterAction = "findOne"
	ActionFindMany     AdapterAction = "findMany"
	ActionDelete       AdapterAction = "delete"
	ActionDeleteMany   AdapterAction = "deleteMany"
	ActionConsumeOne   AdapterAction = "consumeOne"
	ActionIncrementOne AdapterAction = "incrementOne"
	ActionCount        AdapterAction = "count"
)

// AdapterTransformContext is supplied to custom scalar transformations after
// schema aliases and the factory's built-in representation conversions have
// been applied.
type AdapterTransformContext struct {
	Action         AdapterAction
	Data           any
	Field          string
	FieldAttribute FieldAttribute
	Model          string
	Schema         Schema
}

// AdapterOutputTransformContext is the output counterpart of
// AdapterTransformContext. Field is the canonical field name exposed by the
// public Adapter contract.
type AdapterOutputTransformContext struct {
	Data           any
	Field          string
	FieldAttribute FieldAttribute
	Model          string
	Schema         Schema
	Select         []string
}

// AdapterFactoryConfig describes the compatibility boundary between the
// canonical single-auth storage contract and an adapter-native driver.
//
// A nil Capabilities value selects reference implementation's factory defaults: native
// numbers, dates, and booleans; stringified JSON and arrays; no native joins.
// Transaction callbacks receive an already factory-wrapped transaction
// adapter, just like reference implementation's DBTransactionAdapter callback.
type AdapterFactoryConfig struct {
	AdapterID   string
	AdapterName string
	Schema      Schema

	Capabilities         *Capabilities
	DefaultFindManyLimit int
	// IDGeneration mirrors advanced.database.generateId. UseNumericIDs is kept
	// as a compatibility alias for IDGenerationSerial.
	IDGeneration        IDGenerationMode
	UseNumericIDs       bool
	DisableIDGeneration bool
	Clock               func() time.Time
	// GenerateID is the end-user generator and has priority over
	// CustomIDGenerator, matching reference implementation's function-valued generateId.
	GenerateID        func(model string) (any, error)
	CustomIDGenerator IDGenerator
	Random            io.Reader
	Warn              func(message string)

	MapKeysTransformInput  map[string]string
	MapKeysTransformOutput map[string]string
	DisableTransformInput  bool
	DisableTransformOutput bool
	DisableTransformJoin   bool

	TransformInput  func(AdapterTransformContext) (any, error)
	TransformOutput func(AdapterOutputTransformContext) (any, error)
	Transaction     func(context.Context, func(TransactionAdapter) error) error
}

// CustomAdapter is the low-level operation set consumed by NewAdapterFactory.
// Its params contain physical model/field names and adapter-native values.
// ConsumeOne and IncrementOne are optional; the factory supplies compatibility
// fallbacks when they are nil.
//
// DeleteMany deliberately returns any. reference implementation accepts third-party
// adapters written in JavaScript, where an invalid document-store response can
// reach this boundary at runtime. The factory validates and narrows it to the
// public int64 contract instead of silently treating a malformed response as a
// lost consume race.
type CustomAdapter struct {
	Create     func(context.Context, CreateParams) (Record, error)
	FindOne    func(context.Context, FindOneParams) (Record, error)
	FindMany   func(context.Context, FindManyParams) ([]Record, error)
	Count      func(context.Context, CountParams) (int64, error)
	Update     func(context.Context, UpdateParams) (Record, error)
	UpdateMany func(context.Context, UpdateManyParams) (int64, error)
	Delete     func(context.Context, DeleteParams) error
	DeleteMany func(context.Context, DeleteManyParams) (any, error)

	ConsumeOne   func(context.Context, ConsumeOneParams) (Record, error)
	IncrementOne func(context.Context, IncrementOneParams) (Record, error)
}

// InvalidDeleteManyResultError reports a custom adapter that returned a value
// which cannot be represented by the public deleted-row count contract.
type InvalidDeleteManyResultError struct {
	AdapterID string
	Value     any
}

func (e *InvalidDeleteManyResultError) Error() string {
	return fmt.Sprintf(
		"storage: adapter %q returned non-numeric deleteMany result of type %T",
		e.AdapterID,
		e.Value,
	)
}

type factoryAdapter struct {
	config        AdapterFactoryConfig
	schema        Schema
	capabilities  Capabilities
	driver        CustomAdapter
	idField       IDFieldFactory
	useNumericIDs bool
}

var _ Adapter = (*factoryAdapter)(nil)

// NewAdapterFactory wraps a custom adapter with reference implementation-compatible model,
// field, value, transaction, and atomic-operation behavior.
func NewAdapterFactory(config AdapterFactoryConfig, driver CustomAdapter) (Adapter, error) {
	if strings.TrimSpace(config.AdapterID) == "" {
		return nil, errors.New("storage: adapter factory ID is empty")
	}
	if config.AdapterName == "" {
		config.AdapterName = config.AdapterID
	}
	if len(config.Schema.Models) == 0 {
		config.Schema = CoreSchema()
	}
	config.Schema = config.Schema.Clone()
	if err := config.Schema.Validate(); err != nil {
		return nil, fmt.Errorf("storage: adapter factory schema: %w", err)
	}
	if config.DefaultFindManyLimit == 0 {
		config.DefaultFindManyLimit = 100
	}
	if config.DefaultFindManyLimit < 0 {
		return nil, errors.New("storage: adapter factory default findMany limit is negative")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	config.MapKeysTransformInput = cloneStringMap(config.MapKeysTransformInput)
	config.MapKeysTransformOutput = cloneStringMap(config.MapKeysTransformOutput)
	if err := validateCustomAdapter(driver); err != nil {
		return nil, fmt.Errorf("storage: adapter factory %q: %w", config.AdapterID, err)
	}

	capabilities := Capabilities{
		NumericIDs: true,
		Dates:      true,
		Booleans:   true,
	}
	if config.Capabilities != nil {
		capabilities = *config.Capabilities
	}
	idGeneration := config.IDGeneration
	if config.UseNumericIDs {
		idGeneration = IDGenerationSerial
	}
	useNumericIDs := idGeneration == IDGenerationSerial
	if useNumericIDs && !capabilities.NumericIDs {
		return nil, fmt.Errorf(
			"storage: adapter factory %q does not support numeric IDs",
			config.AdapterID,
		)
	}
	capabilities.Transactions = config.Transaction != nil
	capabilities.AtomicConsumeOne = driver.ConsumeOne != nil
	capabilities.AtomicIncrement = driver.IncrementOne != nil

	idField := InitGetIDField(IDFieldFactoryOptions{
		Schema: config.Schema, UsePlural: config.Schema.UsePlural,
		DisableIDGeneration: config.DisableIDGeneration,
		GenerateID:          idGeneration, GenerateIDFunc: config.GenerateID,
		CustomIDGenerator: config.CustomIDGenerator,
		SupportsUUIDs:     capabilities.UUIDs, Random: config.Random, Warn: config.Warn,
	})

	return &factoryAdapter{
		config:        config,
		schema:        config.Schema.Clone(),
		capabilities:  capabilities,
		driver:        driver,
		idField:       idField,
		useNumericIDs: useNumericIDs,
	}, nil
}

func validateCustomAdapter(driver CustomAdapter) error {
	missing := make([]string, 0, 8)
	if driver.Create == nil {
		missing = append(missing, "create")
	}
	if driver.FindOne == nil {
		missing = append(missing, "findOne")
	}
	if driver.FindMany == nil {
		missing = append(missing, "findMany")
	}
	if driver.Count == nil {
		missing = append(missing, "count")
	}
	if driver.Update == nil {
		missing = append(missing, "update")
	}
	if driver.UpdateMany == nil {
		missing = append(missing, "updateMany")
	}
	if driver.Delete == nil {
		missing = append(missing, "delete")
	}
	if driver.DeleteMany == nil {
		missing = append(missing, "deleteMany")
	}
	if len(missing) != 0 {
		return fmt.Errorf("custom adapter is missing %s", strings.Join(missing, ", "))
	}
	return nil
}

func (a *factoryAdapter) ID() string { return a.config.AdapterID }

func (a *factoryAdapter) Capabilities() Capabilities { return a.capabilities }

func (a *factoryAdapter) Schema() Schema { return a.schema.Clone() }

func (a *factoryAdapter) Transaction(
	ctx context.Context,
	callback func(TransactionAdapter) error,
) error {
	if callback == nil {
		return errors.New("storage: adapter transaction callback is nil")
	}
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.config.Transaction == nil {
		return callback(a)
	}
	return a.config.Transaction(ctx, callback)
}

func (a *factoryAdapter) Create(ctx context.Context, params CreateParams) (Record, error) {
	ctx = nonNilContext(ctx)
	model, err := a.resolveModel(params.Model)
	if err != nil {
		return nil, err
	}
	data := cloneFactoryRecord(params.Data)
	if !a.config.DisableTransformInput {
		data, err = a.transformRecordInput(model, params.Data, ActionCreate, params.ForceAllowID)
		if err != nil {
			return nil, err
		}
	} else if !params.ForceAllowID {
		// reference implementation strips an unapproved caller-supplied ID before the
		// disableTransformInput branch, so disabling scalar transforms does not
		// bypass ID ownership.
		delete(data, "id")
	}
	result, err := a.driver.Create(ctx, CreateParams{
		Model: model.physical,
		Data:  data,
	})
	if err != nil {
		return nil, err
	}
	if a.config.DisableTransformOutput {
		return cloneFactoryRecord(result), nil
	}
	return a.transformRecordOutput(model, result, params.Select)
}

func (a *factoryAdapter) FindOne(ctx context.Context, params FindOneParams) (Record, error) {
	ctx = nonNilContext(ctx)
	model, err := a.resolveModel(params.Model)
	if err != nil {
		return nil, err
	}
	where, err := a.transformWhere(model, params.Where, ActionFindOne)
	if err != nil {
		return nil, err
	}
	selectFields := append([]string(nil), params.Select...)
	var plans []factoryJoinPlan
	var passJoin map[string]JoinOption
	if a.config.DisableTransformJoin {
		passJoin = cloneJoin(params.Join)
	} else {
		var prepareErr error
		plans, passJoin, prepareErr = a.prepareJoin(model, params.Join, &selectFields)
		if prepareErr != nil {
			return nil, prepareErr
		}
	}
	result, err := a.driver.FindOne(ctx, FindOneParams{
		Model: model.physical, Where: where,
		Select: selectFields, Join: passJoin,
	})
	if err != nil || result == nil {
		return nil, err
	}
	if a.config.DisableTransformOutput {
		return cloneFactoryRecord(result), nil
	}
	return a.transformRecordOutputWithJoin(ctx, model, result, selectFields, plans)
}

func (a *factoryAdapter) FindMany(ctx context.Context, params FindManyParams) ([]Record, error) {
	ctx = nonNilContext(ctx)
	model, err := a.resolveModel(params.Model)
	if err != nil {
		return nil, err
	}
	where, err := a.transformWhere(model, params.Where, ActionFindMany)
	if err != nil {
		return nil, err
	}
	limit := a.config.DefaultFindManyLimit
	if params.Limit != nil {
		limit = *params.Limit
	}
	selectFields := append([]string(nil), params.Select...)
	var plans []factoryJoinPlan
	var passJoin map[string]JoinOption
	if a.config.DisableTransformJoin {
		passJoin = cloneJoin(params.Join)
	} else {
		var prepareErr error
		plans, passJoin, prepareErr = a.prepareJoin(model, params.Join, &selectFields)
		if prepareErr != nil {
			return nil, prepareErr
		}
	}
	result, err := a.driver.FindMany(ctx, FindManyParams{
		Model: model.physical, Where: where, Limit: Int(limit),
		Select: selectFields, SortBy: cloneSort(params.SortBy),
		Offset: cloneInt(params.Offset), Join: passJoin,
	})
	if err != nil {
		return nil, err
	}
	if a.config.DisableTransformOutput {
		cloned := make([]Record, len(result))
		for index, record := range result {
			cloned[index] = cloneFactoryRecord(record)
		}
		return cloned, nil
	}
	transformed := make([]Record, 0, len(result))
	for _, record := range result {
		decoded, decodeErr := a.transformRecordOutput(model, record, selectFields)
		if decodeErr != nil {
			return nil, decodeErr
		}
		transformed = append(transformed, decoded)
	}
	if len(plans) != 0 {
		if a.capabilities.Joins {
			for index, record := range result {
				if err := a.attachNativeJoins(model, transformed[index], record, plans); err != nil {
					return nil, err
				}
			}
		} else if err := a.attachFallbackJoinsMany(ctx, model, transformed, plans); err != nil {
			return nil, err
		}
	}
	return transformed, nil
}

func (a *factoryAdapter) Count(ctx context.Context, params CountParams) (int64, error) {
	ctx = nonNilContext(ctx)
	model, err := a.resolveModel(params.Model)
	if err != nil {
		return 0, err
	}
	where, err := a.transformWhere(model, params.Where, ActionCount)
	if err != nil {
		return 0, err
	}
	return a.driver.Count(ctx, CountParams{Model: model.physical, Where: where})
}

func (a *factoryAdapter) Update(ctx context.Context, params UpdateParams) (Record, error) {
	ctx = nonNilContext(ctx)
	model, err := a.resolveModel(params.Model)
	if err != nil {
		return nil, err
	}
	where, err := a.transformWhere(model, params.Where, ActionUpdate)
	if err != nil {
		return nil, err
	}
	if len(where) == 0 {
		return nil, nil
	}
	update := cloneFactoryRecord(params.Update)
	if !a.config.DisableTransformInput {
		update, err = a.transformRecordInput(model, params.Update, ActionUpdate, false)
		if err != nil {
			return nil, err
		}
	}
	result, err := a.driver.Update(ctx, UpdateParams{
		Model: model.physical, Where: where, Update: update,
	})
	if err != nil || result == nil {
		return nil, err
	}
	if a.config.DisableTransformOutput {
		return cloneFactoryRecord(result), nil
	}
	return a.transformRecordOutput(model, result, nil)
}

func (a *factoryAdapter) UpdateMany(ctx context.Context, params UpdateManyParams) (int64, error) {
	ctx = nonNilContext(ctx)
	model, err := a.resolveModel(params.Model)
	if err != nil {
		return 0, err
	}
	where, err := a.transformWhere(model, params.Where, ActionUpdateMany)
	if err != nil {
		return 0, err
	}
	// reference implementation uses the update action for updateMany data transforms.
	update := cloneFactoryRecord(params.Update)
	if !a.config.DisableTransformInput {
		update, err = a.transformRecordInput(model, params.Update, ActionUpdate, false)
		if err != nil {
			return 0, err
		}
	}
	return a.driver.UpdateMany(ctx, UpdateManyParams{
		Model: model.physical, Where: where, Update: update,
	})
}

func (a *factoryAdapter) Delete(ctx context.Context, params DeleteParams) error {
	ctx = nonNilContext(ctx)
	model, err := a.resolveModel(params.Model)
	if err != nil {
		return err
	}
	where, err := a.transformWhere(model, params.Where, ActionDelete)
	if err != nil {
		return err
	}
	return a.driver.Delete(ctx, DeleteParams{Model: model.physical, Where: where})
}

func (a *factoryAdapter) DeleteMany(ctx context.Context, params DeleteManyParams) (int64, error) {
	ctx = nonNilContext(ctx)
	model, err := a.resolveModel(params.Model)
	if err != nil {
		return 0, err
	}
	where, err := a.transformWhere(model, params.Where, ActionDeleteMany)
	if err != nil {
		return 0, err
	}
	result, err := a.driver.DeleteMany(ctx, DeleteManyParams{Model: model.physical, Where: where})
	if err != nil {
		return 0, err
	}
	count, valid := deletedRowCount(result)
	if !valid {
		return 0, &InvalidDeleteManyResultError{AdapterID: a.config.AdapterID, Value: result}
	}
	return count, nil
}

func (a *factoryAdapter) ConsumeOne(ctx context.Context, params ConsumeOneParams) (Record, error) {
	ctx = nonNilContext(ctx)
	model, err := a.resolveModel(params.Model)
	if err != nil {
		return nil, err
	}
	if a.driver.ConsumeOne != nil {
		where, transformErr := a.transformWhere(model, params.Where, ActionConsumeOne)
		if transformErr != nil {
			return nil, transformErr
		}
		result, consumeErr := a.driver.ConsumeOne(ctx, ConsumeOneParams{
			Model: model.physical, Where: where,
		})
		if consumeErr != nil || result == nil {
			return nil, consumeErr
		}
		if a.config.DisableTransformOutput {
			return cloneFactoryRecord(result), nil
		}
		return a.transformRecordOutput(model, result, nil)
	}

	var consumed Record
	err = RunWithTransaction(ctx, a, func(transactionContext context.Context, transaction TransactionAdapter) error {
		rows, findErr := transaction.FindMany(transactionContext, FindManyParams{
			Model: params.Model, Where: cloneWhere(params.Where), Limit: Int(1),
		})
		if findErr != nil {
			return findErr
		}
		if len(rows) == 0 {
			return nil
		}
		target := rows[0]
		id, exists := target["id"]
		if !exists || id == nil {
			return fmt.Errorf("%w: consumeOne fallback result has no id", ErrInvalidQuery)
		}
		gate := append(cloneWhere(params.Where), Where{
			Field: "id", Value: id, Operator: OpEq, Connector: And, Mode: Sensitive,
		})
		deleted, deleteErr := transaction.DeleteMany(transactionContext, DeleteManyParams{
			Model: params.Model, Where: gate,
		})
		if deleteErr != nil {
			var invalid *InvalidDeleteManyResultError
			if errors.As(deleteErr, &invalid) {
				return fmt.Errorf(
					"Adapter %q returned a non-numeric value from deleteMany during the consumeOne fallback. Return the number of deleted rows, or implement a native consumeOne for atomic single-use consumption.",
					a.config.AdapterID,
				)
			}
			return deleteErr
		}
		if deleted > 0 {
			// FindMany already returned canonical, output-transformed data. Returning
			// it directly is what prevents a second output transform.
			consumed = cloneFactoryRecord(target)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return consumed, nil
}

func (a *factoryAdapter) IncrementOne(ctx context.Context, params IncrementOneParams) (Record, error) {
	ctx = nonNilContext(ctx)
	model, err := a.resolveModel(params.Model)
	if err != nil {
		return nil, err
	}
	if len(params.Increment) == 0 && len(params.Set) == 0 {
		return nil, fmt.Errorf("%w: incrementOne requires a non-empty increment or set", ErrInvalidIncrement)
	}
	if a.driver.IncrementOne != nil {
		where, transformErr := a.transformWhere(model, params.Where, ActionIncrementOne)
		if transformErr != nil {
			return nil, transformErr
		}
		increment, transformErr := a.transformIncrement(model, params.Increment)
		if transformErr != nil {
			return nil, transformErr
		}
		set := cloneFactoryRecord(params.Set)
		if !a.config.DisableTransformInput {
			set, transformErr = a.transformRecordInput(model, params.Set, ActionUpdate, true)
			if transformErr != nil {
				return nil, transformErr
			}
		}
		if len(increment) == 0 && len(set) == 0 {
			return nil, fmt.Errorf(
				"%w: incrementOne resolved to an empty update after schema transforms",
				ErrInvalidIncrement,
			)
		}
		result, incrementErr := a.driver.IncrementOne(ctx, IncrementOneParams{
			Model: model.physical, Where: where, Increment: increment, Set: set,
		})
		if incrementErr != nil || result == nil {
			return nil, incrementErr
		}
		if a.config.DisableTransformOutput {
			return cloneFactoryRecord(result), nil
		}
		return a.transformRecordOutput(model, result, nil)
	}

	var updated Record
	err = RunWithTransaction(ctx, a, func(transactionContext context.Context, transaction TransactionAdapter) error {
		rows, findErr := transaction.FindMany(transactionContext, FindManyParams{
			Model: params.Model, Where: cloneWhere(params.Where), Limit: Int(1),
		})
		if findErr != nil || len(rows) == 0 {
			return findErr
		}
		target := cloneFactoryRecord(rows[0])
		mutation := cloneFactoryRecord(params.Set)
		if mutation == nil {
			mutation = make(Record, len(params.Increment))
		}
		for field, amount := range params.Increment {
			current, ok := numericValue(target[field])
			if !ok {
				return fmt.Errorf("%w: field %s is not numeric", ErrInvalidIncrement, field)
			}
			mutation[field] = current + amount
		}
		gate := cloneWhere(params.Where)
		if id, ok := target["id"]; ok && id != nil {
			gate = append(gate, Where{Field: "id", Value: id, Operator: OpEq, Connector: And, Mode: Sensitive})
		}
		count, updateErr := transaction.UpdateMany(transactionContext, UpdateManyParams{
			Model: params.Model, Where: gate, Update: mutation,
		})
		if updateErr != nil || count == 0 {
			return updateErr
		}
		for field, value := range mutation {
			target[field] = cloneFactoryValue(value)
		}
		updated = target
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

type factoryModel struct {
	canonical string
	physical  string
	schema    ModelSchema
}

func (a *factoryAdapter) resolveModel(candidate string) (factoryModel, error) {
	table, canonical, err := a.schema.ResolveModel(candidate)
	if err != nil {
		return factoryModel{}, err
	}
	physical := table.ModelName
	if physical == "" {
		physical = canonical
	}
	if a.schema.UsePlural {
		physical += "s"
	}
	return factoryModel{canonical: canonical, physical: physical, schema: table}, nil
}

func (a *factoryAdapter) resolveField(model factoryModel, candidate string) (FieldAttribute, string, string, error) {
	attribute, canonical, err := a.schema.ResolveField(model.canonical, candidate)
	if err != nil {
		return FieldAttribute{}, "", "", err
	}
	physical := attribute.FieldName
	if physical == "" {
		physical = canonical
	}
	return attribute, canonical, physical, nil
}

func (a *factoryAdapter) inputPhysicalField(canonical, schemaPhysical string) string {
	if mapped := a.config.MapKeysTransformInput[canonical]; mapped != "" {
		return mapped
	}
	return schemaPhysical
}

func (a *factoryAdapter) idAttribute(model factoryModel, forceAllowID bool) (FieldAttribute, error) {
	if a.idField == nil {
		return FieldAttribute{Type: FieldString, FieldName: "id"}, nil
	}
	return a.idField(IDFieldOptions{
		CustomModelName: model.canonical,
		ForceAllowID:    forceAllowID,
	})
}

func (a *factoryAdapter) transformWhere(
	model factoryModel,
	where []Where,
	action AdapterAction,
) ([]Where, error) {
	if where == nil {
		return nil, nil
	}
	transformed := make([]Where, 0, len(where))
	for _, clause := range where {
		normalized, err := clause.Normalize()
		if err != nil {
			return nil, err
		}
		attribute, canonical, schemaPhysical, err := a.resolveField(model, normalized.Field)
		if err != nil {
			return nil, err
		}
		if canonical == "id" {
			attribute, err = a.idAttribute(model, true)
			if err != nil {
				return nil, err
			}
		}
		physical := a.inputPhysicalField(canonical, schemaPhysical)
		value := cloneFactoryValue(normalized.Value)
		if (canonical == "id" || (attribute.References != nil && attribute.References.Field == "id")) && a.useNumericIDs {
			value = coerceNumericID(value)
		}
		value = coerceWhereValue(attribute, value)
		value, err = encodeFactoryWhereValue(a.capabilities, attribute, value)
		if err != nil {
			return nil, fmt.Errorf("storage: transform where %s.%s: %w", model.canonical, canonical, err)
		}
		if a.config.TransformInput != nil {
			value, err = a.config.TransformInput(AdapterTransformContext{
				Action: action, Data: value, Field: physical,
				FieldAttribute: attribute, Model: model.physical, Schema: a.schema.Clone(),
			})
			if err != nil {
				return nil, fmt.Errorf("storage: custom where transform %s.%s: %w", model.canonical, canonical, err)
			}
		}
		transformed = append(transformed, Where{
			Field: physical, Value: value, Operator: normalized.Operator,
			Connector: normalized.Connector, Mode: normalized.Mode,
		})
	}
	return transformed, nil
}

func (a *factoryAdapter) transformRecordInput(
	model factoryModel,
	record Record,
	action AdapterAction,
	forceAllowID bool,
) (Record, error) {
	if record == nil {
		return nil, nil
	}
	result := make(Record)
	fieldNames := make([]string, 0, len(model.schema.Fields)+1)
	fieldNames = append(fieldNames, "id")
	for field := range model.schema.Fields {
		fieldNames = append(fieldNames, field)
	}
	sort.Strings(fieldNames)
	for _, canonical := range fieldNames {
		attribute, _, schemaPhysical, err := a.resolveField(model, canonical)
		if err != nil {
			return nil, err
		}
		physical := a.inputPhysicalField(canonical, schemaPhysical)
		value, present := lookupFactoryInputField(record, canonical, schemaPhysical, physical)
		if canonical == "id" && action == ActionCreate && present && !forceAllowID {
			present = false
		}
		if canonical == "id" {
			attribute, err = a.idAttribute(model, forceAllowID && present)
			if err != nil {
				return nil, err
			}
		}
		if !present || (value == nil && attribute.Required != nil && *attribute.Required) {
			switch {
			case action == ActionCreate && attribute.DefaultValue != nil:
				value, err = attribute.DefaultValue(ValueContext{Now: a.config.Clock})
				present = err == nil && (canonical != "id" || value != nil)
			case action == ActionUpdate && attribute.OnUpdate != nil:
				value, err = attribute.OnUpdate(ValueContext{Now: a.config.Clock})
				present = err == nil
			}
			if err != nil {
				return nil, fmt.Errorf("storage: default %s.%s: %w", model.canonical, canonical, err)
			}
		}
		transformMissing := false
		if !present && attribute.Transform.Input != nil {
			// JavaScript field transforms receive `undefined` for an omitted
			// field. nil is the Go invocation value; if all transforms leave it
			// nil, the field remains omitted rather than becoming SQL NULL.
			present = true
			transformMissing = true
		}
		if !present {
			continue
		}
		value, err = encodeFactoryInputValue(a.capabilities, attribute, value)
		if err != nil {
			return nil, fmt.Errorf("storage: transform input %s.%s: %w", model.canonical, canonical, err)
		}
		if a.config.TransformInput != nil {
			value, err = a.config.TransformInput(AdapterTransformContext{
				Action: action, Data: value, Field: physical,
				FieldAttribute: attribute, Model: model.physical, Schema: a.schema.Clone(),
			})
			if err != nil {
				return nil, fmt.Errorf("storage: custom input transform %s.%s: %w", model.canonical, canonical, err)
			}
		}
		if (canonical == "id" || transformMissing) && value == nil {
			continue
		}
		result[physical] = cloneFactoryValue(value)
	}
	return result, nil
}

func (a *factoryAdapter) transformRecordOutput(
	model factoryModel,
	record Record,
	selectFields []string,
) (Record, error) {
	if record == nil {
		return nil, nil
	}
	selected := make(map[string]struct{}, len(selectFields))
	for _, field := range selectFields {
		_, canonical, _, err := a.resolveField(model, field)
		if err != nil {
			return nil, err
		}
		selected[canonical] = struct{}{}
	}
	result := make(Record)
	fieldNames := make([]string, 0, len(model.schema.Fields)+1)
	fieldNames = append(fieldNames, "id")
	for field := range model.schema.Fields {
		fieldNames = append(fieldNames, field)
	}
	sort.Strings(fieldNames)
	for _, canonical := range fieldNames {
		if len(selected) != 0 {
			if _, ok := selected[canonical]; !ok {
				continue
			}
		}
		attribute, _, physical, err := a.resolveField(model, canonical)
		if err != nil {
			return nil, err
		}
		if canonical == "id" {
			attribute, err = a.idAttribute(model, false)
			if err != nil {
				return nil, err
			}
		}
		sourceField := reverseMappedField(a.config.MapKeysTransformOutput, physical)
		value := cloneFactoryValue(record[sourceField])
		value, err = decodeFactoryOutputValue(a.capabilities, attribute, value)
		if err != nil {
			return nil, fmt.Errorf("storage: transform output %s.%s: %w", model.canonical, canonical, err)
		}
		if canonical == "id" || (attribute.References != nil && attribute.References.Field == "id") {
			if value != nil {
				value = fmt.Sprint(value)
			}
		}
		outputField := canonical
		if mapped := a.config.MapKeysTransformOutput[canonical]; mapped != "" {
			outputField = mapped
		}
		if a.config.TransformOutput != nil {
			value, err = a.config.TransformOutput(AdapterOutputTransformContext{
				Data: value, Field: outputField, FieldAttribute: attribute,
				Model: model.physical, Schema: a.schema.Clone(), Select: append([]string(nil), selectFields...),
			})
			if err != nil {
				return nil, fmt.Errorf("storage: custom output transform %s.%s: %w", model.canonical, canonical, err)
			}
		}
		result[outputField] = cloneFactoryValue(value)
	}
	return result, nil
}

type factoryJoinPlan struct {
	joined        factoryModel
	resultField   string
	fromCanonical string
	toCanonical   string
	config        JoinConfig
}

func (a *factoryAdapter) prepareJoin(
	base factoryModel,
	requested map[string]JoinOption,
	selectFields *[]string,
) ([]factoryJoinPlan, map[string]JoinOption, error) {
	if len(requested) == 0 {
		return nil, nil, nil
	}
	keys := make([]string, 0, len(requested))
	for key := range requested {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	plans := make([]factoryJoinPlan, 0, len(keys))
	native := make(map[string]JoinOption, len(keys))
	for _, key := range keys {
		option := requested[key]
		candidate := option.Model
		if candidate == "" {
			candidate = key
		}
		joined, err := a.resolveModel(candidate)
		if err != nil {
			return nil, nil, err
		}

		type referenceCandidate struct {
			canonical string
			attribute FieldAttribute
		}
		findReferences := func(model factoryModel, target string) []referenceCandidate {
			fields := make([]string, 0, len(model.schema.Fields))
			for field := range model.schema.Fields {
				fields = append(fields, field)
			}
			sort.Strings(fields)
			matches := make([]referenceCandidate, 0, 1)
			for _, field := range fields {
				attribute := model.schema.Fields[field]
				if attribute.References == nil {
					continue
				}
				_, referenced, resolveErr := a.schema.ResolveModel(attribute.References.Model)
				if resolveErr != nil || referenced != target {
					continue
				}
				if option.RelationName != "" && attribute.References.RelationName != option.RelationName {
					continue
				}
				matches = append(matches, referenceCandidate{canonical: field, attribute: attribute})
			}
			return matches
		}

		foreignKeys := findReferences(joined, base.canonical)
		forward := len(foreignKeys) != 0
		if !forward {
			foreignKeys = findReferences(base, joined.canonical)
		}
		if len(foreignKeys) == 0 {
			return nil, nil, fmt.Errorf(
				"%w: no foreign key found for model %s and base model %s",
				ErrInvalidQuery, joined.canonical, base.canonical,
			)
		}
		if len(foreignKeys) > 1 {
			return nil, nil, fmt.Errorf(
				"%w: multiple foreign keys found for model %s and base model %s",
				ErrInvalidQuery, joined.canonical, base.canonical,
			)
		}
		foreignKey := foreignKeys[0]
		reference := foreignKey.attribute.References
		if reference == nil {
			return nil, nil, fmt.Errorf("%w: join foreign key has no reference", ErrInvalidQuery)
		}

		var fromCanonical, toCanonical string
		if forward {
			fromCanonical = reference.Field
			toCanonical = foreignKey.canonical
		} else {
			fromCanonical = foreignKey.canonical
			toCanonical = reference.Field
		}
		_, _, fromPhysical, err := a.resolveField(base, fromCanonical)
		if err != nil {
			return nil, nil, err
		}
		_, _, toPhysical, err := a.resolveField(joined, toCanonical)
		if err != nil {
			return nil, nil, err
		}
		relation := OneToMany
		if toPhysical == "id" || foreignKey.attribute.Unique {
			relation = OneToOne
		}
		limit := a.config.DefaultFindManyLimit
		if relation == OneToOne {
			limit = 1
		} else if option.Limit != nil {
			limit = *option.Limit
		}
		if selectFields != nil && *selectFields != nil && !containsString(*selectFields, fromCanonical) {
			*selectFields = append(*selectFields, fromCanonical)
		}
		plan := factoryJoinPlan{
			joined: joined, resultField: joined.canonical,
			fromCanonical: fromCanonical, toCanonical: toCanonical,
			config: JoinConfig{From: fromPhysical, To: toPhysical, Limit: limit, Relation: relation},
		}
		plans = append(plans, plan)
		native[joined.physical] = JoinOption{
			Model: joined.physical, RelationName: option.RelationName,
			Limit: Int(limit), On: &JoinOn{From: fromPhysical, To: toPhysical}, Relation: relation,
		}
	}
	if !a.capabilities.Joins {
		native = nil
	}
	return plans, native, nil
}

func (a *factoryAdapter) transformRecordOutputWithJoin(
	ctx context.Context,
	base factoryModel,
	raw Record,
	selectFields []string,
	plans []factoryJoinPlan,
) (Record, error) {
	transformed, err := a.transformRecordOutput(base, raw, selectFields)
	if err != nil || transformed == nil || len(plans) == 0 {
		return transformed, err
	}
	if a.capabilities.Joins {
		if err := a.attachNativeJoins(base, transformed, raw, plans); err != nil {
			return nil, err
		}
		return transformed, nil
	}
	for _, plan := range plans {
		value := transformed[a.outputFieldName(plan.fromCanonical)]
		joined, queryErr := a.queryFallbackJoin(ctx, plan, value)
		if queryErr != nil {
			return nil, queryErr
		}
		transformed[plan.resultField] = joined
	}
	return transformed, nil
}

func (a *factoryAdapter) attachNativeJoins(
	_ factoryModel,
	base Record,
	raw Record,
	plans []factoryJoinPlan,
) error {
	for _, plan := range plans {
		joinedValue, exists := raw[plan.joined.physical]
		if !exists && plan.joined.physical != plan.resultField {
			joinedValue = raw[plan.resultField]
		}
		if joinedValue == nil {
			if plan.config.Relation == OneToOne {
				base[plan.resultField] = nil
			} else {
				base[plan.resultField] = []Record{}
			}
			continue
		}
		rows := factoryRecords(joinedValue)
		decoded := make([]Record, 0, len(rows))
		for _, row := range rows {
			item, err := a.transformRecordOutput(plan.joined, row, nil)
			if err != nil {
				return err
			}
			decoded = append(decoded, item)
		}
		if plan.config.Relation == OneToOne {
			if len(decoded) == 0 {
				base[plan.resultField] = nil
			} else {
				base[plan.resultField] = decoded[0]
			}
		} else {
			base[plan.resultField] = decoded
		}
	}
	return nil
}

func (a *factoryAdapter) queryFallbackJoin(
	ctx context.Context,
	plan factoryJoinPlan,
	value any,
) (any, error) {
	if value == nil {
		if plan.config.Relation == OneToOne {
			return nil, nil
		}
		return []Record{}, nil
	}
	where, err := a.transformWhere(plan.joined, []Where{{
		Field: plan.toCanonical, Value: value, Operator: OpEq, Connector: And, Mode: Sensitive,
	}}, ActionFindOne)
	if err != nil {
		return nil, err
	}
	if plan.config.Relation == OneToOne {
		raw, findErr := a.driver.FindOne(ctx, FindOneParams{Model: plan.joined.physical, Where: where})
		if findErr != nil || raw == nil {
			return nil, findErr
		}
		return a.transformRecordOutput(plan.joined, raw, nil)
	}
	raw, err := a.driver.FindMany(ctx, FindManyParams{
		Model: plan.joined.physical, Where: where, Limit: Int(plan.config.Limit),
	})
	if err != nil {
		return nil, err
	}
	result := make([]Record, 0, len(raw))
	for _, row := range raw {
		decoded, decodeErr := a.transformRecordOutput(plan.joined, row, nil)
		if decodeErr != nil {
			return nil, decodeErr
		}
		result = append(result, decoded)
	}
	return result, nil
}

func (a *factoryAdapter) attachFallbackJoinsMany(
	ctx context.Context,
	_ factoryModel,
	baseRows []Record,
	plans []factoryJoinPlan,
) error {
	for _, plan := range plans {
		values := make([]any, 0, len(baseRows))
		seen := map[string]struct{}{}
		for _, row := range baseRows {
			value := row[a.outputFieldName(plan.fromCanonical)]
			if value == nil {
				continue
			}
			key := factoryValueKey(value)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			values = append(values, cloneFactoryValue(value))
		}
		if len(values) == 0 {
			for _, row := range baseRows {
				if plan.config.Relation == OneToOne {
					row[plan.resultField] = nil
				} else {
					row[plan.resultField] = []Record{}
				}
			}
			continue
		}
		where, err := a.transformWhere(plan.joined, []Where{{
			Field: plan.toCanonical, Value: values, Operator: OpIn, Connector: And, Mode: Sensitive,
		}}, ActionFindMany)
		if err != nil {
			return err
		}
		limit := plan.config.Limit
		if limit > 0 && len(values) > 1 {
			limit *= len(values)
		}
		rawRows, err := a.driver.FindMany(ctx, FindManyParams{
			Model: plan.joined.physical, Where: where, Limit: Int(limit),
		})
		if err != nil {
			return err
		}
		grouped := make(map[string][]Record, len(values))
		for _, raw := range rawRows {
			decoded, decodeErr := a.transformRecordOutput(plan.joined, raw, nil)
			if decodeErr != nil {
				return decodeErr
			}
			key := factoryValueKey(decoded[a.outputFieldName(plan.toCanonical)])
			grouped[key] = append(grouped[key], decoded)
		}
		for _, row := range baseRows {
			matches := grouped[factoryValueKey(row[a.outputFieldName(plan.fromCanonical)])]
			if plan.config.Relation == OneToOne {
				if len(matches) == 0 {
					row[plan.resultField] = nil
				} else {
					row[plan.resultField] = matches[0]
				}
			} else if matches == nil {
				row[plan.resultField] = []Record{}
			} else {
				row[plan.resultField] = matches
			}
		}
	}
	return nil
}

func (a *factoryAdapter) outputFieldName(canonical string) string {
	if mapped := a.config.MapKeysTransformOutput[canonical]; mapped != "" {
		return mapped
	}
	return canonical
}

func (a *factoryAdapter) transformIncrement(model factoryModel, increment map[string]float64) (map[string]float64, error) {
	transformed := make(map[string]float64, len(increment))
	for field, amount := range increment {
		attribute, canonical, physical, err := a.resolveField(model, field)
		if err != nil {
			return nil, err
		}
		if attribute.Type != FieldNumber {
			return nil, fmt.Errorf("%w: field %s.%s is not numeric", ErrInvalidIncrement, model.canonical, canonical)
		}
		transformed[a.inputPhysicalField(canonical, physical)] = amount
	}
	return transformed, nil
}

func coerceWhereValue(attribute FieldAttribute, value any) any {
	switch attribute.Type {
	case FieldBoolean:
		if stringValue, ok := value.(string); ok {
			return stringValue == "true"
		}
	case FieldNumber:
		if stringValue, ok := value.(string); ok {
			if parsed, valid := parseWhereNumber(stringValue); valid {
				return parsed
			}
			return value
		}
		reflected := reflect.ValueOf(value)
		if reflected.IsValid() && (reflected.Kind() == reflect.Array || reflected.Kind() == reflect.Slice) {
			parsed := make([]any, reflected.Len())
			for index := 0; index < reflected.Len(); index++ {
				stringValue, ok := reflected.Index(index).Interface().(string)
				if !ok {
					return value
				}
				number, valid := parseWhereNumber(stringValue)
				if !valid {
					return value
				}
				parsed[index] = number
			}
			return parsed
		}
	}
	return value
}

func parseWhereNumber(value string) (float64, bool) {
	if strings.TrimSpace(value) == "" {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	return parsed, err == nil && !math.IsNaN(parsed)
}

func coerceNumericID(value any) any {
	if stringValue, ok := value.(string); ok {
		if parsed, valid := parseWhereNumber(stringValue); valid {
			return parsed
		}
	}
	reflected := reflect.ValueOf(value)
	if reflected.IsValid() && (reflected.Kind() == reflect.Array || reflected.Kind() == reflect.Slice) {
		converted := make([]any, reflected.Len())
		for index := 0; index < reflected.Len(); index++ {
			converted[index] = coerceNumericID(reflected.Index(index).Interface())
		}
		return converted
	}
	return value
}

func encodeFactoryInputValue(capabilities Capabilities, attribute FieldAttribute, value any) (any, error) {
	if value != nil && attribute.Type == FieldDate {
		if encoded, ok := value.(string); ok {
			if parsed, parseErr := time.Parse(time.RFC3339Nano, encoded); parseErr == nil {
				value = parsed
			}
		}
	}
	var err error
	if attribute.Transform.Input != nil {
		value, err = attribute.Transform.Input(value)
		if err != nil {
			return nil, err
		}
	}
	if value == nil {
		return nil, nil
	}
	return encodeFactoryScalar(capabilities, attribute, value)
}

func encodeFactoryWhereValue(capabilities Capabilities, attribute FieldAttribute, value any) (any, error) {
	// reference implementation's where converter handles JSON/date/boolean storage
	// representations, but deliberately leaves string[] and number[] operands
	// alone. In particular, an `in` value is the query operand list, not one
	// array-valued cell to stringify.
	if attribute.Type == FieldStringArray || attribute.Type == FieldNumberArray {
		return value, nil
	}
	return encodeFactoryScalar(capabilities, attribute, value)
}

func encodeFactoryScalar(capabilities Capabilities, attribute FieldAttribute, value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	switch attribute.Type {
	case FieldJSON:
		if !capabilities.JSON && (reflect.TypeOf(value).Kind() == reflect.Map || reflect.TypeOf(value).Kind() == reflect.Struct || reflect.TypeOf(value).Kind() == reflect.Slice || reflect.TypeOf(value).Kind() == reflect.Array) {
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			return string(encoded), nil
		}
	case FieldStringArray, FieldNumberArray:
		if !capabilities.Arrays {
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			return string(encoded), nil
		}
	case FieldDate:
		if !capabilities.Dates {
			if date, ok := value.(time.Time); ok {
				return date.Format(time.RFC3339Nano), nil
			}
		}
	case FieldBoolean:
		if !capabilities.Booleans {
			if boolean, ok := value.(bool); ok {
				if boolean {
					return int64(1), nil
				}
				return int64(0), nil
			}
		}
	}
	return value, nil
}

func decodeFactoryOutputValue(capabilities Capabilities, attribute FieldAttribute, value any) (any, error) {
	var err error
	if attribute.Transform.Output != nil {
		value, err = attribute.Transform.Output(value)
		if err != nil {
			return nil, err
		}
	}
	if value == nil {
		return nil, nil
	}
	switch attribute.Type {
	case FieldJSON:
		if !capabilities.JSON {
			if encoded, ok := value.(string); ok {
				var decoded any
				if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
					return nil, err
				}
				value = decoded
			}
		}
	case FieldStringArray:
		if !capabilities.Arrays {
			if encoded, ok := value.(string); ok {
				var decoded []string
				if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
					return nil, err
				}
				value = decoded
			}
		}
	case FieldNumberArray:
		if !capabilities.Arrays {
			if encoded, ok := value.(string); ok {
				var decoded []float64
				if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
					return nil, err
				}
				value = decoded
			}
		}
	case FieldDate:
		if !capabilities.Dates {
			if encoded, ok := value.(string); ok {
				parsed, parseErr := time.Parse(time.RFC3339Nano, encoded)
				if parseErr != nil {
					return nil, parseErr
				}
				value = parsed
			}
		}
	case FieldBoolean:
		if !capabilities.Booleans {
			switch encoded := value.(type) {
			case int:
				value = encoded == 1
			case int32:
				value = encoded == 1
			case int64:
				value = encoded == 1
			case float32:
				value = encoded == 1
			case float64:
				value = encoded == 1
			}
		}
	}
	return value, nil
}

func deletedRowCount(value any) (int64, bool) {
	switch count := value.(type) {
	case int:
		return int64(count), count >= 0
	case int8:
		return int64(count), count >= 0
	case int16:
		return int64(count), count >= 0
	case int32:
		return int64(count), count >= 0
	case int64:
		return count, count >= 0
	case uint:
		if uint64(count) > math.MaxInt64 {
			return 0, false
		}
		return int64(count), true
	case uint8:
		return int64(count), true
	case uint16:
		return int64(count), true
	case uint32:
		return int64(count), true
	case uint64:
		if count > math.MaxInt64 {
			return 0, false
		}
		return int64(count), true
	case float32:
		converted := float64(count)
		if converted < 0 || math.IsNaN(converted) || math.IsInf(converted, 0) || math.Trunc(converted) != converted || converted > math.MaxInt64 {
			return 0, false
		}
		return int64(converted), true
	case float64:
		if count < 0 || math.IsNaN(count) || math.IsInf(count, 0) || math.Trunc(count) != count || count > math.MaxInt64 {
			return 0, false
		}
		return int64(count), true
	default:
		return 0, false
	}
}

func numericValue(value any) (float64, bool) {
	switch number := value.(type) {
	case int:
		return float64(number), true
	case int8:
		return float64(number), true
	case int16:
		return float64(number), true
	case int32:
		return float64(number), true
	case int64:
		return float64(number), true
	case uint:
		return float64(number), true
	case uint8:
		return float64(number), true
	case uint16:
		return float64(number), true
	case uint32:
		return float64(number), true
	case uint64:
		return float64(number), true
	case float32:
		return float64(number), true
	case float64:
		return number, true
	default:
		return 0, false
	}
}

type factoryTransactionState struct {
	adapter TransactionAdapter
	active  bool
}

type factoryTransactionContextKey struct{}

// CurrentTransactionAdapter returns the transaction adapter bound by
// RunWithTransaction, or fallback outside an active transaction.
func CurrentTransactionAdapter(ctx context.Context, fallback TransactionAdapter) TransactionAdapter {
	if ctx != nil {
		if state, ok := ctx.Value(factoryTransactionContextKey{}).(factoryTransactionState); ok && state.adapter != nil {
			return state.adapter
		}
	}
	return fallback
}

// RunWithTransaction mirrors reference implementation's transaction context behavior. A
// nested call reuses the active transaction instead of asking an adapter to
// open another one.
func RunWithTransaction(
	ctx context.Context,
	adapter Adapter,
	callback func(context.Context, TransactionAdapter) error,
) error {
	if adapter == nil {
		return errors.New("storage: transaction adapter is nil")
	}
	if callback == nil {
		return errors.New("storage: transaction callback is nil")
	}
	ctx = nonNilContext(ctx)
	if state, ok := ctx.Value(factoryTransactionContextKey{}).(factoryTransactionState); ok && state.active && state.adapter != nil {
		return callback(ctx, state.adapter)
	}
	err := adapter.Transaction(ctx, func(transaction TransactionAdapter) error {
		if transaction == nil {
			return errors.New("storage: transaction returned a nil adapter")
		}
		bound := context.WithValue(ctx, factoryTransactionContextKey{}, factoryTransactionState{
			adapter: transaction,
			active:  true,
		})
		return callback(bound, transaction)
	})
	if errors.Is(err, ErrTransactionsUnsupported) {
		return callback(ctx, adapter)
	}
	return err
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func lookupFactoryField(record Record, primary, secondary string) (any, bool) {
	if value, ok := record[primary]; ok {
		return cloneFactoryValue(value), true
	}
	if secondary != primary {
		if value, ok := record[secondary]; ok {
			return cloneFactoryValue(value), true
		}
	}
	return nil, false
}

func lookupFactoryInputField(record Record, names ...string) (any, bool) {
	for _, name := range names {
		if name == "" {
			continue
		}
		if value, ok := record[name]; ok {
			return cloneFactoryValue(value), true
		}
	}
	return nil, false
}

func reverseMappedField(mapping map[string]string, target string) string {
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if mapping[key] == target {
			return key
		}
	}
	return target
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func factoryRecords(value any) []Record {
	switch typed := value.(type) {
	case Record:
		return []Record{cloneFactoryRecord(typed)}
	case map[string]any:
		return []Record{cloneFactoryRecord(Record(typed))}
	case []Record:
		result := make([]Record, len(typed))
		for index, record := range typed {
			result[index] = cloneFactoryRecord(record)
		}
		return result
	case []map[string]any:
		result := make([]Record, len(typed))
		for index, record := range typed {
			result[index] = cloneFactoryRecord(Record(record))
		}
		return result
	case []any:
		result := make([]Record, 0, len(typed))
		for _, item := range typed {
			result = append(result, factoryRecords(item)...)
		}
		return result
	default:
		return nil
	}
}

func factoryValueKey(value any) string {
	encoded, err := json.Marshal(value)
	if err == nil {
		return fmt.Sprintf("%T:%s", value, encoded)
	}
	return fmt.Sprintf("%T:%v", value, value)
}

func cloneStringMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	clone := make(map[string]string, len(value))
	for key, entry := range value {
		clone[key] = entry
	}
	return clone
}

func cloneFactoryRecord(record Record) Record {
	if record == nil {
		return nil
	}
	clone := make(Record, len(record))
	for key, value := range record {
		clone[key] = cloneFactoryValue(value)
	}
	return clone
}

func cloneFactoryValue(value any) any {
	switch typed := value.(type) {
	case Record:
		return cloneFactoryRecord(typed)
	case map[string]any:
		clone := make(map[string]any, len(typed))
		for key, entry := range typed {
			clone[key] = cloneFactoryValue(entry)
		}
		return clone
	case []any:
		clone := make([]any, len(typed))
		for index, entry := range typed {
			clone[index] = cloneFactoryValue(entry)
		}
		return clone
	case []string:
		return append([]string(nil), typed...)
	case []float64:
		return append([]float64(nil), typed...)
	case []int:
		return append([]int(nil), typed...)
	default:
		return value
	}
}

func cloneWhere(where []Where) []Where {
	if where == nil {
		return nil
	}
	clone := make([]Where, len(where))
	for index, clause := range where {
		clone[index] = clause
		clone[index].Value = cloneFactoryValue(clause.Value)
	}
	return clone
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneSort(value *Sort) *Sort {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneJoin(value map[string]JoinOption) map[string]JoinOption {
	if value == nil {
		return nil
	}
	clone := make(map[string]JoinOption, len(value))
	for key, option := range value {
		cloned := JoinOption{
			Model:        option.Model,
			RelationName: option.RelationName,
			Limit:        cloneInt(option.Limit),
			Relation:     option.Relation,
		}
		if option.On != nil {
			on := *option.On
			cloned.On = &on
		}
		clone[key] = cloned
	}
	return clone
}
