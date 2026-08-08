package memory

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/pers0na2dev/single-auth/storage"
)

type database struct {
	mu     sync.RWMutex
	tables map[string][]storage.Record
}

type executor struct {
	database *database
	config   *config
}

// Adapter is a concurrent in-memory implementation of the complete storage
// contract. Inputs and outputs are deep copied, so callers cannot race with or
// mutate stored state through retained maps and slices.
type Adapter struct {
	*executor
}

type transactionAdapter struct {
	*executor
}

var _ storage.Adapter = (*Adapter)(nil)
var _ storage.TransactionAdapter = (*transactionAdapter)(nil)

// New constructs an adapter with the five reference implementation core models.
func New(options ...Option) (*Adapter, error) {
	configuration := defaultConfig()
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&configuration); err != nil {
			return nil, err
		}
	}
	if err := configuration.schema.Validate(); err != nil {
		return nil, fmt.Errorf("memory: schema: %w", err)
	}

	tables := map[string][]storage.Record(configuration.backing)
	if tables == nil {
		tables = make(map[string][]storage.Record, len(configuration.schema.Models))
	}
	for canonical, table := range configuration.schema.Models {
		physical := table.ModelName
		if physical == "" {
			physical = canonical
		}
		if configuration.schema.UsePlural {
			physical += "s"
		}
		if _, exists := tables[physical]; !exists {
			tables[physical] = []storage.Record{}
		}
	}
	database := &database{tables: tables}
	adapter := &Adapter{executor: &executor{database: database, config: &configuration}}

	for model, rows := range configuration.initial {
		for _, row := range rows {
			if _, err := adapter.Create(context.Background(), storage.CreateParams{
				Model:        model,
				Data:         row,
				ForceAllowID: true,
			}); err != nil {
				return nil, fmt.Errorf("memory: seed %s: %w", model, err)
			}
		}
	}
	return adapter, nil
}

// MustNew is New for static configurations and tests.
func MustNew(options ...Option) *Adapter {
	adapter, err := New(options...)
	if err != nil {
		panic(err)
	}
	return adapter
}

func (a *Adapter) ID() string { return "memory" }

func (a *Adapter) Capabilities() storage.Capabilities {
	return a.config.capabilities
}

// Schema returns an isolated copy of the configured schema.
func (a *Adapter) Schema() storage.Schema {
	return a.config.schema.Clone()
}

func (e *executor) Create(ctx context.Context, params storage.CreateParams) (storage.Record, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	model, err := e.resolveModel(params.Model)
	if err != nil {
		return nil, err
	}
	encoded, err := e.encodeCreate(model, cloneRecord(params.Data), params.ForceAllowID)
	if err != nil {
		return nil, err
	}

	e.database.mu.Lock()
	rows, exists := e.database.tables[model.physical]
	if !exists {
		e.database.mu.Unlock()
		return nil, fmt.Errorf("%w: %q", storage.ErrModelNotFound, model.physical)
	}
	if err := validateUniqueRows(model, append(cloneRows(rows), cloneRecord(encoded))); err != nil {
		e.database.mu.Unlock()
		return nil, err
	}
	e.database.tables[model.physical] = append(rows, cloneRecord(encoded))
	e.database.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return e.decodeRecord(model, encoded, params.Select)
}

func (e *executor) FindOne(ctx context.Context, params storage.FindOneParams) (storage.Record, error) {
	limit := 1
	rows, err := e.findMany(ctx, storage.FindManyParams{
		Model:  params.Model,
		Where:  params.Where,
		Limit:  &limit,
		Select: append([]string(nil), params.Select...),
		Join:   params.Join,
	}, false)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

func (e *executor) FindMany(ctx context.Context, params storage.FindManyParams) ([]storage.Record, error) {
	return e.findMany(ctx, params, true)
}

func (e *executor) findMany(ctx context.Context, params storage.FindManyParams, applyDefaultLimit bool) ([]storage.Record, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	model, err := e.resolveModel(params.Model)
	if err != nil {
		return nil, err
	}
	where, err := e.encodeWhere(model, params.Where)
	if err != nil {
		return nil, err
	}
	sortBy, err := e.encodeSort(model, params.SortBy)
	if err != nil {
		return nil, err
	}
	selectFields := append([]string(nil), params.Select...)
	joins, err := e.prepareJoins(model, params.Join, &selectFields)
	if err != nil {
		return nil, err
	}

	limit := params.Limit
	if limit == nil && applyDefaultLimit {
		defaultLimit := e.config.defaultLimit
		limit = &defaultLimit
	}
	if limit != nil && *limit < 0 {
		return nil, fmt.Errorf("%w: limit must be non-negative", storage.ErrInvalidQuery)
	}
	if params.Offset != nil && *params.Offset < 0 {
		return nil, fmt.Errorf("%w: offset must be non-negative", storage.ErrInvalidQuery)
	}

	e.database.mu.RLock()
	snapshot := cloneTables(e.database.tables)
	e.database.mu.RUnlock()
	baseRows, exists := snapshot[model.physical]
	if !exists {
		return nil, fmt.Errorf("%w: %q", storage.ErrModelNotFound, model.physical)
	}
	indexes, err := filterRows(baseRows, where)
	if err != nil {
		return nil, err
	}
	filtered := make([]storage.Record, 0, len(indexes))
	for _, index := range indexes {
		filtered = append(filtered, baseRows[index])
	}
	sortRows(filtered, sortBy)
	if params.Offset != nil {
		if *params.Offset >= len(filtered) {
			filtered = nil
		} else {
			filtered = filtered[*params.Offset:]
		}
	}
	if limit != nil && *limit < len(filtered) {
		filtered = filtered[:*limit]
	}

	result := make([]storage.Record, 0, len(filtered))
	for _, raw := range filtered {
		decoded, err := e.decodeRecord(model, raw, selectFields)
		if err != nil {
			return nil, err
		}
		for _, join := range joins {
			joined, err := e.joinRecords(snapshot, raw, join)
			if err != nil {
				return nil, err
			}
			decoded[join.model.canonical] = joined
		}
		result = append(result, decoded)
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func (e *executor) Count(ctx context.Context, params storage.CountParams) (int64, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	model, err := e.resolveModel(params.Model)
	if err != nil {
		return 0, err
	}
	where, err := e.encodeWhere(model, params.Where)
	if err != nil {
		return 0, err
	}
	e.database.mu.RLock()
	rows, exists := e.database.tables[model.physical]
	if !exists {
		e.database.mu.RUnlock()
		return 0, fmt.Errorf("%w: %q", storage.ErrModelNotFound, model.physical)
	}
	indexes, err := filterRows(rows, where)
	e.database.mu.RUnlock()
	return int64(len(indexes)), err
}

func (e *executor) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	model, err := e.resolveModel(params.Model)
	if err != nil {
		return nil, err
	}
	where, err := e.encodeWhere(model, params.Where)
	if err != nil {
		return nil, err
	}
	// Singular mutation with an empty predicate fails closed. Bulk update is
	// the explicit match-all operation.
	if len(where) == 0 {
		return nil, nil
	}
	update, err := e.encodeUpdate(model, cloneRecord(params.Update))
	if err != nil {
		return nil, err
	}

	e.database.mu.Lock()
	rows, exists := e.database.tables[model.physical]
	if !exists {
		e.database.mu.Unlock()
		return nil, fmt.Errorf("%w: %q", storage.ErrModelNotFound, model.physical)
	}
	indexes, err := filterRows(rows, where)
	if err != nil {
		e.database.mu.Unlock()
		return nil, err
	}
	updatedRows := cloneRows(rows)
	for _, index := range indexes {
		for field, value := range update {
			updatedRows[index][field] = cloneValue(value)
		}
	}
	if err := validateUniqueRows(model, updatedRows); err != nil {
		e.database.mu.Unlock()
		return nil, err
	}
	e.database.tables[model.physical] = updatedRows
	var updated storage.Record
	if len(indexes) > 0 {
		updated = cloneRecord(updatedRows[indexes[0]])
	}
	e.database.mu.Unlock()
	return e.decodeRecord(model, updated, nil)
}

func (e *executor) UpdateMany(ctx context.Context, params storage.UpdateManyParams) (int64, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	model, err := e.resolveModel(params.Model)
	if err != nil {
		return 0, err
	}
	where, err := e.encodeWhere(model, params.Where)
	if err != nil {
		return 0, err
	}
	update, err := e.encodeUpdate(model, cloneRecord(params.Update))
	if err != nil {
		return 0, err
	}

	e.database.mu.Lock()
	rows, exists := e.database.tables[model.physical]
	if !exists {
		e.database.mu.Unlock()
		return 0, fmt.Errorf("%w: %q", storage.ErrModelNotFound, model.physical)
	}
	indexes, err := filterRows(rows, where)
	updatedRows := cloneRows(rows)
	if err == nil {
		for _, index := range indexes {
			for field, value := range update {
				updatedRows[index][field] = cloneValue(value)
			}
		}
		err = validateUniqueRows(model, updatedRows)
		if err == nil {
			e.database.tables[model.physical] = updatedRows
		}
	}
	e.database.mu.Unlock()
	return int64(len(indexes)), err
}

func (e *executor) Delete(ctx context.Context, params storage.DeleteParams) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	model, err := e.resolveModel(params.Model)
	if err != nil {
		return err
	}
	where, err := e.encodeWhere(model, params.Where)
	if err != nil {
		return err
	}
	if len(where) == 0 {
		return nil
	}
	_, err = e.deleteMatching(model, where, false)
	return err
}

func (e *executor) DeleteMany(ctx context.Context, params storage.DeleteManyParams) (int64, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	model, err := e.resolveModel(params.Model)
	if err != nil {
		return 0, err
	}
	where, err := e.encodeWhere(model, params.Where)
	if err != nil {
		return 0, err
	}
	return e.deleteMatching(model, where, false)
}

func (e *executor) deleteMatching(model resolvedModel, where []storage.Where, onlyOne bool) (int64, error) {
	e.database.mu.Lock()
	defer e.database.mu.Unlock()
	rows, exists := e.database.tables[model.physical]
	if !exists {
		return 0, fmt.Errorf("%w: %q", storage.ErrModelNotFound, model.physical)
	}
	kept := make([]storage.Record, 0, len(rows))
	var deleted int64
	for _, row := range rows {
		matched, err := matches(row, where)
		if err != nil {
			return 0, err
		}
		if matched && (!onlyOne || deleted == 0) {
			deleted++
			continue
		}
		kept = append(kept, row)
	}
	e.database.tables[model.physical] = kept
	return deleted, nil
}

func (e *executor) ConsumeOne(ctx context.Context, params storage.ConsumeOneParams) (storage.Record, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	model, err := e.resolveModel(params.Model)
	if err != nil {
		return nil, err
	}
	where, err := e.encodeWhere(model, params.Where)
	if err != nil {
		return nil, err
	}

	e.database.mu.Lock()
	rows, exists := e.database.tables[model.physical]
	if !exists {
		e.database.mu.Unlock()
		return nil, fmt.Errorf("%w: %q", storage.ErrModelNotFound, model.physical)
	}
	target := -1
	for index, row := range rows {
		matched, err := matches(row, where)
		if err != nil {
			e.database.mu.Unlock()
			return nil, err
		}
		if matched {
			target = index
			break
		}
	}
	if target < 0 {
		e.database.mu.Unlock()
		return nil, nil
	}
	consumed := cloneRecord(rows[target])
	e.database.tables[model.physical] = append(rows[:target], rows[target+1:]...)
	e.database.mu.Unlock()
	return e.decodeRecord(model, consumed, nil)
}

func (e *executor) IncrementOne(ctx context.Context, params storage.IncrementOneParams) (storage.Record, error) {
	if len(params.Increment) == 0 && len(params.Set) == 0 {
		return nil, fmt.Errorf("%w: increment and set are both empty", storage.ErrInvalidIncrement)
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	model, err := e.resolveModel(params.Model)
	if err != nil {
		return nil, err
	}
	where, err := e.encodeWhere(model, params.Where)
	if err != nil {
		return nil, err
	}
	increments := make(map[string]float64, len(params.Increment))
	for name, delta := range params.Increment {
		field, err := e.resolveField(model, name)
		if err != nil {
			return nil, err
		}
		increments[field.physical] = delta
	}
	var set storage.Record
	if len(params.Set) > 0 {
		set, err = e.encodeUpdate(model, cloneRecord(params.Set))
		if err != nil {
			return nil, err
		}
	}
	if len(increments) == 0 && len(set) == 0 {
		return nil, fmt.Errorf("%w: all assignments transformed away", storage.ErrInvalidIncrement)
	}

	e.database.mu.Lock()
	rows, exists := e.database.tables[model.physical]
	if !exists {
		e.database.mu.Unlock()
		return nil, fmt.Errorf("%w: %q", storage.ErrModelNotFound, model.physical)
	}
	target := -1
	for index, row := range rows {
		matched, err := matches(row, where)
		if err != nil {
			e.database.mu.Unlock()
			return nil, err
		}
		if matched {
			target = index
			break
		}
	}
	if target < 0 {
		e.database.mu.Unlock()
		return nil, nil
	}
	for field, delta := range increments {
		current := rows[target][field]
		if _, numeric := numericValue(current); !numeric {
			current = nil
		}
		next, err := addNumeric(current, delta)
		if err != nil {
			e.database.mu.Unlock()
			return nil, err
		}
		rows[target][field] = next
	}
	for field, value := range set {
		rows[target][field] = cloneValue(value)
	}
	updated := cloneRecord(rows[target])
	e.database.mu.Unlock()
	return e.decodeRecord(model, updated, nil)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("memory: nil context")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
