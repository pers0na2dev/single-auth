package core

import (
	"context"
	"fmt"
	"sync"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/instrumentation"
	"github.com/pers0na2dev/single-auth/storage"
)

// DatabaseHookContext describes one upstream implementation database lifecycle callback.
// Endpoint is nil when an adapter operation is initiated outside dispatch.
type DatabaseHookContext struct {
	Context   context.Context
	Endpoint  *engine.Context
	Source    string
	Model     string
	Operation string
}

// DatabaseHookResult is the Go equivalent of upstream implementation's false or
// {data: ...} before-hook result. Data is merged over the current write.
type DatabaseHookResult struct {
	Cancel bool
	Data   storage.Record
}

type DatabaseBeforeHook func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error)
type DatabaseAfterHook func(any, DatabaseHookContext) error

type DatabaseOperationHooks struct {
	Before DatabaseBeforeHook
	After  DatabaseAfterHook
}

type DatabaseModelHooks struct {
	Create DatabaseOperationHooks
	Update DatabaseOperationHooks
	Delete DatabaseOperationHooks
}

// DatabaseHooks maps canonical model names to create/update/delete lifecycle
// callbacks. Core and plugin models use the same hook machinery.
type DatabaseHooks map[string]DatabaseModelHooks

type databaseHookEntry struct {
	source string
	hooks  DatabaseHooks
}

type databaseHookRegistry struct {
	mu      sync.RWMutex
	entries []databaseHookEntry
	frozen  bool
}

func newDatabaseHookRegistry() *databaseHookRegistry { return &databaseHookRegistry{} }

func (registry *databaseHookRegistry) add(source string, hooks DatabaseHooks) error {
	if len(hooks) == 0 {
		return nil
	}
	if source == "" {
		return fmt.Errorf("single-auth: database hook source must not be empty")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.frozen {
		return fmt.Errorf("single-auth: database hooks are already initialized")
	}
	registry.entries = append(registry.entries, databaseHookEntry{
		source: source, hooks: cloneDatabaseHooks(hooks),
	})
	return nil
}

func (registry *databaseHookRegistry) freeze() {
	registry.mu.Lock()
	registry.frozen = true
	registry.mu.Unlock()
}

func (registry *databaseHookRegistry) snapshot() []databaseHookEntry {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	result := make([]databaseHookEntry, len(registry.entries))
	copy(result, registry.entries)
	return result
}

func cloneDatabaseHooks(hooks DatabaseHooks) DatabaseHooks {
	if hooks == nil {
		return nil
	}
	clone := make(DatabaseHooks, len(hooks))
	for model, lifecycle := range hooks {
		clone[model] = lifecycle
	}
	return clone
}

type hookedAdapter struct {
	base     storage.Adapter
	registry *databaseHookRegistry
}

type hookedExecutor struct {
	base     storage.TransactionAdapter
	registry *databaseHookRegistry
	after    *databaseAfterQueue
}

type databaseCustomExecutor interface {
	storage.TransactionAdapter
	customCreate(context.Context, string, storage.Record, func(storage.TransactionAdapter, storage.Record) (storage.Record, error)) (storage.Record, error)
	afterCommit(func() error) error
}

type databaseAfterQueue struct {
	mu        sync.Mutex
	callbacks []func() error
}

var _ storage.Adapter = (*hookedAdapter)(nil)
var _ storage.TransactionAdapter = (*hookedExecutor)(nil)
var _ storage.SchemaCreator = (*hookedAdapter)(nil)

func newHookedAdapter(base storage.Adapter, registry *databaseHookRegistry) storage.Adapter {
	return &hookedAdapter{base: base, registry: registry}
}

func (adapter *hookedAdapter) ID() string { return adapter.base.ID() }

func (adapter *hookedAdapter) Capabilities() storage.Capabilities {
	return adapter.base.Capabilities()
}

func (adapter *hookedAdapter) CreateSchema(
	ctx context.Context,
	schema storage.Schema,
	path string,
) (storage.SchemaCreation, error) {
	creator, ok := adapter.base.(storage.SchemaCreator)
	if !ok {
		return storage.SchemaCreation{}, fmt.Errorf("single-auth: adapter %s does not support schema creation", adapter.ID())
	}
	return creator.CreateSchema(ctx, schema, path)
}

func (adapter *hookedAdapter) executor() *hookedExecutor {
	return &hookedExecutor{base: adapter.base, registry: adapter.registry}
}

func (adapter *hookedAdapter) customCreate(
	ctx context.Context,
	model string,
	data storage.Record,
	callback func(storage.TransactionAdapter, storage.Record) (storage.Record, error),
) (storage.Record, error) {
	return adapter.executor().customCreate(ctx, model, data, callback)
}

func (adapter *hookedAdapter) afterCommit(callback func() error) error {
	return adapter.executor().afterCommit(callback)
}

func (adapter *hookedAdapter) customDeleteMany(
	ctx context.Context,
	model string,
	rows []storage.Record,
	callback func(storage.TransactionAdapter) (int64, error),
) (int64, error) {
	return adapter.executor().customDeleteMany(ctx, model, rows, callback)
}

func (adapter *hookedAdapter) customUpdate(
	ctx context.Context,
	model string,
	update storage.Record,
	callback func(storage.TransactionAdapter, storage.Record) (storage.Record, error),
) (storage.Record, error) {
	return adapter.executor().customUpdate(ctx, model, update, callback)
}

func (adapter *hookedAdapter) customConsume(
	ctx context.Context,
	model string,
	snapshot storage.Record,
	callback func(storage.TransactionAdapter) (storage.Record, error),
) (storage.Record, error) {
	return adapter.executor().customConsume(ctx, model, snapshot, callback)
}

func (adapter *hookedAdapter) Create(ctx context.Context, params storage.CreateParams) (storage.Record, error) {
	return adapter.executor().Create(ctx, params)
}

func (adapter *hookedAdapter) FindOne(ctx context.Context, params storage.FindOneParams) (storage.Record, error) {
	return adapter.executor().FindOne(ctx, params)
}

func (adapter *hookedAdapter) FindMany(ctx context.Context, params storage.FindManyParams) ([]storage.Record, error) {
	return adapter.executor().FindMany(ctx, params)
}

func (adapter *hookedAdapter) Count(ctx context.Context, params storage.CountParams) (int64, error) {
	return adapter.executor().Count(ctx, params)
}

func (adapter *hookedAdapter) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error) {
	return adapter.executor().Update(ctx, params)
}

func (adapter *hookedAdapter) UpdateMany(ctx context.Context, params storage.UpdateManyParams) (int64, error) {
	return adapter.executor().UpdateMany(ctx, params)
}

func (adapter *hookedAdapter) Delete(ctx context.Context, params storage.DeleteParams) error {
	return adapter.executor().Delete(ctx, params)
}

func (adapter *hookedAdapter) DeleteMany(ctx context.Context, params storage.DeleteManyParams) (int64, error) {
	return adapter.executor().DeleteMany(ctx, params)
}

func (adapter *hookedAdapter) ConsumeOne(ctx context.Context, params storage.ConsumeOneParams) (storage.Record, error) {
	return adapter.executor().ConsumeOne(ctx, params)
}

func (adapter *hookedAdapter) IncrementOne(ctx context.Context, params storage.IncrementOneParams) (storage.Record, error) {
	return adapter.executor().IncrementOne(ctx, params)
}

func (adapter *hookedAdapter) Transaction(
	ctx context.Context,
	callback func(storage.TransactionAdapter) error,
) error {
	if callback == nil {
		return fmt.Errorf("single-auth: transaction callback is nil")
	}
	queue := &databaseAfterQueue{}
	err := adapter.base.Transaction(ctx, func(transaction storage.TransactionAdapter) error {
		return callback(&hookedExecutor{
			base: transaction, registry: adapter.registry, after: queue,
		})
	})
	if err != nil {
		return err
	}
	return queue.run()
}

func (queue *databaseAfterQueue) add(callback func() error) {
	queue.mu.Lock()
	queue.callbacks = append(queue.callbacks, callback)
	queue.mu.Unlock()
}

func (queue *databaseAfterQueue) run() error {
	queue.mu.Lock()
	callbacks := append([]func() error(nil), queue.callbacks...)
	queue.mu.Unlock()
	for _, callback := range callbacks {
		if err := callback(); err != nil {
			return err
		}
	}
	return nil
}

func (executor *hookedExecutor) afterCommit(callback func() error) error {
	if callback == nil {
		return nil
	}
	if executor.after != nil {
		executor.after.add(callback)
		return nil
	}
	return callback()
}

func (executor *hookedExecutor) FindOne(ctx context.Context, params storage.FindOneParams) (storage.Record, error) {
	return databaseInstrumentedExecutor{TransactionAdapter: executor.base}.FindOne(ctx, params)
}

func (executor *hookedExecutor) FindMany(ctx context.Context, params storage.FindManyParams) ([]storage.Record, error) {
	return databaseInstrumentedExecutor{TransactionAdapter: executor.base}.FindMany(ctx, params)
}

func (executor *hookedExecutor) Count(ctx context.Context, params storage.CountParams) (int64, error) {
	return databaseInstrumentedExecutor{TransactionAdapter: executor.base}.Count(ctx, params)
}

func (executor *hookedExecutor) IncrementOne(ctx context.Context, params storage.IncrementOneParams) (storage.Record, error) {
	return databaseInstrumentedExecutor{TransactionAdapter: executor.base}.IncrementOne(ctx, params)
}

func (executor *hookedExecutor) Create(ctx context.Context, params storage.CreateParams) (storage.Record, error) {
	return executor.customCreate(ctx, params.Model, params.Data, func(
		base storage.TransactionAdapter,
		data storage.Record,
	) (storage.Record, error) {
		params.Data = data
		// upstream implementation's hooked internal adapter always allows an ID supplied or
		// replaced by a create.before hook.
		params.ForceAllowID = true
		return base.Create(ctx, params)
	})
}

func (executor *hookedExecutor) customCreate(
	ctx context.Context,
	model string,
	data storage.Record,
	callback func(storage.TransactionAdapter, storage.Record) (storage.Record, error),
) (storage.Record, error) {
	data, cancelled, err := executor.before(ctx, model, "create", data, true)
	if err != nil || cancelled {
		return nil, err
	}
	created, err := callback(databaseInstrumentedExecutor{TransactionAdapter: executor.base}, data)
	if err != nil {
		return nil, err
	}
	if err := executor.afterHooks(ctx, model, "create", created); err != nil {
		return nil, err
	}
	return created, nil
}

func (executor *hookedExecutor) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error) {
	return executor.customUpdate(ctx, params.Model, params.Update, func(
		base storage.TransactionAdapter,
		data storage.Record,
	) (storage.Record, error) {
		params.Update = data
		return base.Update(ctx, params)
	})
}

func (executor *hookedExecutor) customUpdate(
	ctx context.Context,
	model string,
	update storage.Record,
	callback func(storage.TransactionAdapter, storage.Record) (storage.Record, error),
) (storage.Record, error) {
	data, cancelled, err := executor.before(ctx, model, "update", update, false)
	if err != nil || cancelled {
		return nil, err
	}
	updated, err := callback(databaseInstrumentedExecutor{TransactionAdapter: executor.base}, data)
	if err != nil {
		return nil, err
	}
	if err := executor.afterHooks(ctx, model, "update", updated); err != nil {
		return nil, err
	}
	return updated, nil
}

func (executor *hookedExecutor) UpdateMany(ctx context.Context, params storage.UpdateManyParams) (int64, error) {
	data, cancelled, err := executor.before(ctx, params.Model, "updateMany", params.Update, false)
	if err != nil || cancelled {
		return 0, err
	}
	params.Update = data
	updated, err := databaseInstrumentedExecutor{TransactionAdapter: executor.base}.UpdateMany(ctx, params)
	if err != nil {
		return 0, err
	}
	if err := executor.afterHooks(ctx, params.Model, "updateMany", updated); err != nil {
		return 0, err
	}
	return updated, nil
}

func (executor *hookedExecutor) Delete(ctx context.Context, params storage.DeleteParams) error {
	rows, _ := executor.FindMany(ctx, storage.FindManyParams{
		Model: params.Model, Where: params.Where, Limit: storage.Int(1),
	})
	if len(rows) == 0 {
		return nil
	}
	_, cancelled, err := executor.before(ctx, params.Model, "delete", rows[0], true)
	if err != nil || cancelled {
		return err
	}
	err = databaseInstrumentedExecutor{TransactionAdapter: executor.base}.Delete(ctx, params)
	if err != nil {
		return err
	}
	return executor.afterHooks(ctx, params.Model, "delete", rows[0])
}

func (executor *hookedExecutor) DeleteMany(ctx context.Context, params storage.DeleteManyParams) (int64, error) {
	rows, _ := executor.FindMany(ctx, storage.FindManyParams{
		Model: params.Model, Where: params.Where,
	})
	return executor.customDeleteMany(ctx, params.Model, rows, func(base storage.TransactionAdapter) (int64, error) {
		return base.DeleteMany(ctx, params)
	})
}

func (executor *hookedExecutor) customDeleteMany(
	ctx context.Context,
	model string,
	rows []storage.Record,
	callback func(storage.TransactionAdapter) (int64, error),
) (int64, error) {
	for _, row := range rows {
		_, cancelled, err := executor.before(ctx, model, "delete", row, true)
		if err != nil || cancelled {
			return 0, err
		}
	}
	deleted, err := callback(databaseInstrumentedExecutor{TransactionAdapter: executor.base})
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		if err := executor.afterHooks(ctx, model, "delete", row); err != nil {
			return 0, err
		}
	}
	return deleted, nil
}

func (executor *hookedExecutor) ConsumeOne(ctx context.Context, params storage.ConsumeOneParams) (storage.Record, error) {
	rows, _ := executor.FindMany(ctx, storage.FindManyParams{
		Model: params.Model, Where: params.Where, Limit: storage.Int(1),
	})
	var snapshot storage.Record
	if len(rows) > 0 {
		snapshot = rows[0]
	}
	return executor.customConsume(ctx, params.Model, snapshot, func(base storage.TransactionAdapter) (storage.Record, error) {
		return base.ConsumeOne(ctx, params)
	})
}

func (executor *hookedExecutor) customConsume(
	ctx context.Context,
	model string,
	snapshot storage.Record,
	callback func(storage.TransactionAdapter) (storage.Record, error),
) (storage.Record, error) {
	if snapshot != nil {
		_, cancelled, err := executor.before(ctx, model, "delete", snapshot, true)
		if err != nil || cancelled {
			return nil, err
		}
	}
	consumed, err := callback(databaseInstrumentedExecutor{TransactionAdapter: executor.base})
	if err != nil || consumed == nil {
		return consumed, err
	}
	if err := executor.afterHooks(ctx, model, "delete", consumed); err != nil {
		return nil, err
	}
	return consumed, nil
}

func (executor *hookedExecutor) before(
	ctx context.Context,
	model string,
	operation string,
	input storage.Record,
	chainActual bool,
) (storage.Record, bool, error) {
	actual := cloneStorageRecord(input)
	original := cloneStorageRecord(input)
	for _, entry := range executor.registry.snapshot() {
		lifecycle, exists := entry.hooks[model]
		if !exists {
			continue
		}
		hook := hooksForOperation(lifecycle, operation).Before
		if hook == nil {
			continue
		}
		data := original
		if chainActual {
			data = actual
		}
		result, err := instrumentation.WithSpanContextErr(
			ctx,
			fmt.Sprintf("db %s.before %s", operation, model),
			databaseHookSpanAttributes(operation+".before", model, entry.source),
			func(spanContext context.Context) (DatabaseHookResult, error) {
				return hook(
					cloneStorageRecord(data),
					databaseHookContext(spanContext, entry.source, model, operation),
				)
			},
		)
		if err != nil {
			return nil, false, fmt.Errorf(
				"single-auth: database hook %s %s.%s before: %w",
				entry.source, model, operation, err,
			)
		}
		if result.Cancel {
			return nil, true, nil
		}
		for field, value := range result.Data {
			actual[field] = value
		}
	}
	return actual, false, nil
}

func (executor *hookedExecutor) afterHooks(
	ctx context.Context,
	model string,
	operation string,
	value any,
) error {
	for _, entry := range executor.registry.snapshot() {
		lifecycle, exists := entry.hooks[model]
		if !exists {
			continue
		}
		hook := hooksForOperation(lifecycle, operation).After
		if hook == nil {
			continue
		}
		captured := cloneDatabaseHookValue(value)
		callback := func() error {
			_, err := instrumentation.WithSpanContextErr(
				ctx,
				fmt.Sprintf("db %s.after %s", operation, model),
				databaseHookSpanAttributes(operation+".after", model, entry.source),
				func(spanContext context.Context) (struct{}, error) {
					return struct{}{}, hook(
						captured,
						databaseHookContext(spanContext, entry.source, model, operation),
					)
				},
			)
			if err != nil {
				return fmt.Errorf(
					"single-auth: database hook %s %s.%s after: %w",
					entry.source, model, operation, err,
				)
			}
			return nil
		}
		if executor.after != nil {
			executor.after.add(callback)
			continue
		}
		if err := callback(); err != nil {
			return err
		}
	}
	return nil
}

func hooksForOperation(hooks DatabaseModelHooks, operation string) DatabaseOperationHooks {
	switch operation {
	case "create":
		return hooks.Create
	case "update":
		return hooks.Update
	case "updateMany":
		return hooks.Update
	case "delete":
		return hooks.Delete
	default:
		return DatabaseOperationHooks{}
	}
}

func withDatabaseOperationSpan[T any](
	ctx context.Context,
	operation string,
	model string,
	callback func(context.Context) (T, error),
) (T, error) {
	return instrumentation.WithSpanContextErr(
		ctx,
		fmt.Sprintf("db %s %s", operation, model),
		map[string]any{
			instrumentation.AttrDBOperationName:  operation,
			instrumentation.AttrDBCollectionName: model,
		},
		callback,
	)
}

func databaseHookSpanAttributes(operation, model, source string) map[string]any {
	return map[string]any{
		instrumentation.AttrHookType:         operation,
		instrumentation.AttrDBCollectionName: model,
		instrumentation.AttrContext:          source,
	}
}

// databaseInstrumentedExecutor is the adapter-factory instrumentation layer.
// Keeping it immediately around the low-level executor ensures custom
// callbacks emit spans only for database operations they actually perform.
type databaseInstrumentedExecutor struct {
	storage.TransactionAdapter
}

func (executor databaseInstrumentedExecutor) Create(ctx context.Context, params storage.CreateParams) (storage.Record, error) {
	return withDatabaseOperationSpan(ctx, "create", params.Model, func(spanContext context.Context) (storage.Record, error) {
		return executor.TransactionAdapter.Create(spanContext, params)
	})
}

func (executor databaseInstrumentedExecutor) FindOne(ctx context.Context, params storage.FindOneParams) (storage.Record, error) {
	return withDatabaseOperationSpan(ctx, "findOne", params.Model, func(spanContext context.Context) (storage.Record, error) {
		return executor.TransactionAdapter.FindOne(spanContext, params)
	})
}

func (executor databaseInstrumentedExecutor) FindMany(ctx context.Context, params storage.FindManyParams) ([]storage.Record, error) {
	return withDatabaseOperationSpan(ctx, "findMany", params.Model, func(spanContext context.Context) ([]storage.Record, error) {
		return executor.TransactionAdapter.FindMany(spanContext, params)
	})
}

func (executor databaseInstrumentedExecutor) Count(ctx context.Context, params storage.CountParams) (int64, error) {
	return withDatabaseOperationSpan(ctx, "count", params.Model, func(spanContext context.Context) (int64, error) {
		return executor.TransactionAdapter.Count(spanContext, params)
	})
}

func (executor databaseInstrumentedExecutor) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error) {
	return withDatabaseOperationSpan(ctx, "update", params.Model, func(spanContext context.Context) (storage.Record, error) {
		return executor.TransactionAdapter.Update(spanContext, params)
	})
}

func (executor databaseInstrumentedExecutor) UpdateMany(ctx context.Context, params storage.UpdateManyParams) (int64, error) {
	return withDatabaseOperationSpan(ctx, "updateMany", params.Model, func(spanContext context.Context) (int64, error) {
		return executor.TransactionAdapter.UpdateMany(spanContext, params)
	})
}

func (executor databaseInstrumentedExecutor) Delete(ctx context.Context, params storage.DeleteParams) error {
	_, err := withDatabaseOperationSpan(ctx, "delete", params.Model, func(spanContext context.Context) (struct{}, error) {
		return struct{}{}, executor.TransactionAdapter.Delete(spanContext, params)
	})
	return err
}

func (executor databaseInstrumentedExecutor) DeleteMany(ctx context.Context, params storage.DeleteManyParams) (int64, error) {
	return withDatabaseOperationSpan(ctx, "deleteMany", params.Model, func(spanContext context.Context) (int64, error) {
		return executor.TransactionAdapter.DeleteMany(spanContext, params)
	})
}

func (executor databaseInstrumentedExecutor) ConsumeOne(ctx context.Context, params storage.ConsumeOneParams) (storage.Record, error) {
	return withDatabaseOperationSpan(ctx, "consumeOne", params.Model, func(spanContext context.Context) (storage.Record, error) {
		return executor.TransactionAdapter.ConsumeOne(spanContext, params)
	})
}

func (executor databaseInstrumentedExecutor) IncrementOne(ctx context.Context, params storage.IncrementOneParams) (storage.Record, error) {
	return withDatabaseOperationSpan(ctx, "incrementOne", params.Model, func(spanContext context.Context) (storage.Record, error) {
		return executor.TransactionAdapter.IncrementOne(spanContext, params)
	})
}

func databaseHookContext(ctx context.Context, source, model, operation string) DatabaseHookContext {
	if ctx == nil {
		ctx = context.Background()
	}
	return DatabaseHookContext{
		Context: ctx, Endpoint: engine.ContextFrom(ctx), Source: source,
		Model: model, Operation: operation,
	}
}

func cloneDatabaseHookValue(value any) any {
	if record, ok := value.(storage.Record); ok {
		return cloneStorageRecord(record)
	}
	return value
}
