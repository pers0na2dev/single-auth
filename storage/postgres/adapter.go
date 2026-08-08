package postgres

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

// Adapter is a driver-independent PostgreSQL adapter over an already opened
// database/sql handle. The caller owns the handle.
type Adapter struct {
	*executor
	db *sql.DB
}

// New validates options and binds db without mutating it. Call EnsureSchema
// explicitly if this adapter should create missing tables and constraints.
func New(db *sql.DB, options Options) (*Adapter, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres: database is nil")
	}
	configuration, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	adapter := &Adapter{db: db}
	adapter.executor = &executor{runner: db, config: &configuration}
	return adapter, nil
}

func (a *Adapter) ID() string { return "postgres" }

func (a *Adapter) Capabilities() storage.Capabilities { return a.config.capabilities }

// Schema returns an isolated copy of the configured schema.
func (a *Adapter) Schema() storage.Schema { return a.config.schema.Clone() }

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
	paramsList := newParameters(1)
	for _, physical := range sortedKeys(mutation.values) {
		field, fieldErr := resolvePhysicalField(model, physical)
		if fieldErr != nil {
			return nil, fieldErr
		}
		columns = append(columns, quoteIdentifier(physical))
		placeholders = append(placeholders, bindFieldValue(e.config, field, paramsList, mutation.values[physical]))
		if physical != "id" && mutation.present[physical] {
			columns = append(columns, quoteIdentifier(presenceColumn(field)))
			placeholders = append(placeholders, "TRUE")
		}
	}
	query := ""
	if len(columns) == 0 {
		query = fmt.Sprintf("INSERT INTO %s DEFAULT VALUES RETURNING %s", qualifiedTable(e.config, model), projection(fields))
	} else {
		query = fmt.Sprintf(
			"INSERT INTO %s (%s) VALUES (%s) RETURNING %s",
			qualifiedTable(e.config, model), strings.Join(columns, ", "), strings.Join(placeholders, ", "), projection(fields),
		)
	}
	row, err := scanRecord(e.config, e.runner.QueryRowContext(ctx, query, paramsList.args...), fields)
	if err != nil {
		return nil, normalizeError(ctx, "create "+model.canonical, err)
	}
	return row.decoded, nil
}

func (e *executor) FindOne(ctx context.Context, params storage.FindOneParams) (storage.Record, error) {
	limit := 1
	rows, err := e.findMany(ctx, storage.FindManyParams{
		Model: params.Model, Where: params.Where, Limit: &limit,
		Select: append([]string(nil), params.Select...), Join: params.Join,
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
	where, args, err := buildWhere(e.config, model, params.Where, 1)
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

	query := fmt.Sprintf("SELECT %s FROM %s", projection(fields), qualifiedTable(e.config, model))
	if where != "" {
		query += " WHERE " + where
	}
	query += order
	next := len(args) + 1
	if limit != nil {
		query += fmt.Sprintf(" LIMIT $%d", next)
		args = append(args, *limit)
		next++
	}
	if params.Offset != nil {
		query += fmt.Sprintf(" OFFSET $%d", next)
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
			base.decoded[join.model.canonical] = joined
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
	where, args, err := buildWhere(e.config, model, params.Where, 1)
	if err != nil {
		return 0, err
	}
	query := "SELECT COUNT(*) FROM " + qualifiedTable(e.config, model)
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

var _ storage.Adapter = (*Adapter)(nil)
