package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

type sqlRunner interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type executor struct {
	runner sqlRunner
	config *config
}

// Adapter is a driver-independent SQLite adapter over an already opened DB.
// The caller owns the DB and remains responsible for closing it.
type Adapter struct {
	*executor
	db        *sql.DB
	writeGate chan struct{}
}

// New validates options and binds an already opened SQLite database. It does
// not mutate the database; call EnsureSchema explicitly when schema creation is
// desired.
func New(db *sql.DB, options Options) (*Adapter, error) {
	if db == nil {
		return nil, fmt.Errorf("sqlite: database is nil")
	}
	configuration, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	adapter := &Adapter{db: db, writeGate: gate}
	adapter.executor = &executor{runner: db, config: &configuration}
	return adapter, nil
}

func (a *Adapter) ID() string { return "sqlite" }

func (a *Adapter) Capabilities() storage.Capabilities {
	return a.config.capabilities
}

// Schema returns an isolated copy of the configured schema.
func (a *Adapter) Schema() storage.Schema {
	return a.config.schema.Clone()
}

func (a *Adapter) acquireWrite(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-a.writeGate:
		return nil
	}
}

func (a *Adapter) releaseWrite() { a.writeGate <- struct{}{} }

func (a *Adapter) Create(ctx context.Context, params storage.CreateParams) (storage.Record, error) {
	if err := a.acquireWrite(ctx); err != nil {
		return nil, err
	}
	defer a.releaseWrite()
	return a.executor.Create(ctx, params)
}

func (a *Adapter) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error) {
	if err := a.acquireWrite(ctx); err != nil {
		return nil, err
	}
	defer a.releaseWrite()
	return a.executor.Update(ctx, params)
}

func (a *Adapter) UpdateMany(ctx context.Context, params storage.UpdateManyParams) (int64, error) {
	if err := a.acquireWrite(ctx); err != nil {
		return 0, err
	}
	defer a.releaseWrite()
	return a.executor.UpdateMany(ctx, params)
}

func (a *Adapter) Delete(ctx context.Context, params storage.DeleteParams) error {
	if err := a.acquireWrite(ctx); err != nil {
		return err
	}
	defer a.releaseWrite()
	return a.executor.Delete(ctx, params)
}

func (a *Adapter) DeleteMany(ctx context.Context, params storage.DeleteManyParams) (int64, error) {
	if err := a.acquireWrite(ctx); err != nil {
		return 0, err
	}
	defer a.releaseWrite()
	return a.executor.DeleteMany(ctx, params)
}

func (a *Adapter) ConsumeOne(ctx context.Context, params storage.ConsumeOneParams) (storage.Record, error) {
	if err := a.acquireWrite(ctx); err != nil {
		return nil, err
	}
	defer a.releaseWrite()
	return a.executor.ConsumeOne(ctx, params)
}

func (a *Adapter) IncrementOne(ctx context.Context, params storage.IncrementOneParams) (storage.Record, error) {
	if err := a.acquireWrite(ctx); err != nil {
		return nil, err
	}
	defer a.releaseWrite()
	return a.executor.IncrementOne(ctx, params)
}

func (e *executor) Create(ctx context.Context, params storage.CreateParams) (storage.Record, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	model, err := resolveModel(e.config, params.Model)
	if err != nil {
		return nil, err
	}
	mutation, err := encodeCreate(e.config, model, params.Data, params.ForceAllowID)
	if err != nil {
		return nil, err
	}
	fields, err := selectedFields(e.config, model, params.Select)
	if err != nil {
		return nil, err
	}
	columns := make([]string, 0, len(mutation.values)*2)
	placeholders := make([]string, 0, len(mutation.values)*2)
	args := make([]any, 0, len(mutation.values)*2)
	for _, physical := range sortedKeys(mutation.values) {
		columns = append(columns, quoteIdentifier(physical))
		placeholders = append(placeholders, "?")
		args = append(args, mutation.values[physical])
		if physical != "id" && mutation.present[physical] {
			field, fieldErr := resolvePhysicalField(model, physical)
			if fieldErr != nil {
				return nil, fieldErr
			}
			columns = append(columns, quoteIdentifier(presenceColumn(field)))
			placeholders = append(placeholders, "1")
		}
	}
	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s) RETURNING %s",
		quoteIdentifier(model.physical),
		strings.Join(columns, ", "),
		strings.Join(placeholders, ", "),
		projection(fields),
	)
	row, err := scanRecord(e.config, e.runner.QueryRowContext(ctx, query, args...), fields)
	if err != nil {
		return nil, normalizeError(ctx, "create "+model.canonical, err)
	}
	return row.decoded, nil
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
	model, err := resolveModel(e.config, params.Model)
	if err != nil {
		return nil, err
	}
	where, args, err := buildWhere(e.config, model, params.Where)
	if err != nil {
		return nil, err
	}
	order, err := buildOrder(e.config, model, params.SortBy)
	if err != nil {
		return nil, err
	}
	selected := append([]string(nil), params.Select...)
	joins, err := e.prepareJoins(model, params.Join, &selected)
	if err != nil {
		return nil, err
	}
	fields, err := selectedFields(e.config, model, selected)
	if err != nil {
		return nil, err
	}
	limit := params.Limit
	if limit == nil && applyDefaultLimit {
		value := e.config.defaultLimit
		limit = &value
	}
	if limit != nil && *limit < 0 {
		return nil, fmt.Errorf("%w: limit must be non-negative", storage.ErrInvalidQuery)
	}
	if params.Offset != nil && *params.Offset < 0 {
		return nil, fmt.Errorf("%w: offset must be non-negative", storage.ErrInvalidQuery)
	}

	query := fmt.Sprintf("SELECT %s FROM %s", projection(fields), quoteIdentifier(model.physical))
	if where != "" {
		query += " WHERE " + where
	}
	query += order
	if limit != nil {
		query += " LIMIT ?"
		args = append(args, *limit)
	} else if params.Offset != nil {
		query += " LIMIT -1"
	}
	if params.Offset != nil {
		query += " OFFSET ?"
		args = append(args, *params.Offset)
	}

	scanned, err := e.queryRecords(ctx, query, args, fields, "find "+model.canonical)
	if err != nil {
		return nil, err
	}
	result := make([]storage.Record, 0, len(scanned))
	for _, base := range scanned {
		for _, join := range joins {
			joined, joinErr := e.joinRecord(ctx, base.raw, join)
			if joinErr != nil {
				return nil, joinErr
			}
			base.decoded[join.outputKey] = joined
		}
		result = append(result, base.decoded)
	}
	return result, nil
}

func (e *executor) Count(ctx context.Context, params storage.CountParams) (int64, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	model, err := resolveModel(e.config, params.Model)
	if err != nil {
		return 0, err
	}
	where, args, err := buildWhere(e.config, model, params.Where)
	if err != nil {
		return 0, err
	}
	query := "SELECT COUNT(*) FROM " + quoteIdentifier(model.physical)
	if where != "" {
		query += " WHERE " + where
	}
	var count int64
	if err := e.runner.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, normalizeError(ctx, "count "+model.canonical, err)
	}
	return count, nil
}

func (e *executor) queryRecords(ctx context.Context, query string, args []any, fields []resolvedField, operation string) ([]scannedRecord, error) {
	rows, err := e.runner.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, normalizeError(ctx, operation, err)
	}
	defer rows.Close()
	result := make([]scannedRecord, 0)
	for rows.Next() {
		record, scanErr := scanRecord(e.config, rows, fields)
		if scanErr != nil {
			return nil, normalizeError(ctx, operation, scanErr)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, normalizeError(ctx, operation, err)
	}
	return result, nil
}

func firstRecord(records []scannedRecord) storage.Record {
	if len(records) == 0 {
		return nil
	}
	return records[0].decoded
}

func noRow(err error) bool { return errors.Is(err, sql.ErrNoRows) }
