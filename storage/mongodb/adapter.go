package mongodb

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/pers0na2dev/single-auth/storage"
)

type executor struct {
	database databaseStore
	config   *config
	bind     contextBinder
}

// Adapter persists reference implementation records in an existing MongoDB database. The
// caller owns the client and database handles.
type Adapter struct {
	*executor
	transactions transactionRunner
}

type transactionAdapter struct{ *executor }

// New validates options and binds database without mutating it. Call
// EnsureSchema explicitly to create missing collections and indexes.
func New(database *mongo.Database, options Options) (*Adapter, error) {
	if database == nil {
		return nil, fmt.Errorf("mongodb: database is nil")
	}
	configuration, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	backend := &mongoDatabase{database: database}
	var transactions transactionRunner
	if configuration.capabilities.Transactions {
		transactions = &mongoTransactions{client: database.Client()}
	}
	return newAdapter(backend, transactions, configuration), nil
}

func newAdapter(database databaseStore, transactions transactionRunner, configuration config) *Adapter {
	adapter := &Adapter{transactions: transactions}
	adapter.executor = &executor{database: database, config: &configuration}
	return adapter
}

func (adapter *Adapter) ID() string { return "mongodb" }

func (adapter *Adapter) Capabilities() storage.Capabilities { return adapter.config.capabilities }

// Schema returns an isolated copy of the configured schema.
func (adapter *Adapter) Schema() storage.Schema { return adapter.config.schema.Clone() }

func (executor *executor) operationContext(ctx context.Context) (context.Context, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if executor.bind != nil {
		ctx = executor.bind(ctx)
	}
	return ctx, nil
}

func (executor *executor) Create(ctx context.Context, params storage.CreateParams) (storage.Record, error) {
	ctx, err := executor.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	model, err := resolveModel(executor.config, params.Model)
	if err != nil {
		return nil, err
	}
	mutation, err := encodeCreate(executor.config, model, params.Data, params.ForceAllowID)
	if err != nil {
		return nil, err
	}
	insertedID, err := executor.database.Collection(model.physical).InsertOne(ctx, mutation.values)
	if err != nil {
		return nil, normalizeError(ctx, "create "+model.canonical, err)
	}
	if _, exists := mutation.values["_id"]; !exists && insertedID != nil {
		mutation.values["_id"] = insertedID
	}
	return decodeDocument(executor.config, model, mutation.values, params.Select)
}

func (executor *executor) FindOne(ctx context.Context, params storage.FindOneParams) (storage.Record, error) {
	limit := 1
	records, err := executor.findMany(ctx, storage.FindManyParams{
		Model: params.Model, Where: params.Where, Limit: &limit,
		Select: append([]string(nil), params.Select...), Join: params.Join,
	}, false)
	if err != nil || len(records) == 0 {
		return nil, err
	}
	return records[0], nil
}

func (executor *executor) FindMany(ctx context.Context, params storage.FindManyParams) ([]storage.Record, error) {
	return executor.findMany(ctx, params, true)
}

func (executor *executor) findMany(ctx context.Context, params storage.FindManyParams, applyDefaultLimit bool) ([]storage.Record, error) {
	ctx, err := executor.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	model, err := resolveModel(executor.config, params.Model)
	if err != nil {
		return nil, err
	}
	filter, err := buildWhere(executor.config, model, params.Where)
	if err != nil {
		return nil, err
	}
	sort, err := buildSort(executor.config, model, params.SortBy)
	if err != nil {
		return nil, err
	}
	selected := append([]string(nil), params.Select...)
	joins, err := executor.prepareJoins(model, params.Join, &selected)
	if err != nil {
		return nil, err
	}
	fields, err := selectedFields(executor.config, model, selected)
	if err != nil {
		return nil, err
	}

	limit := params.Limit
	if limit == nil && applyDefaultLimit {
		value := executor.config.defaultLimit
		limit = &value
	}
	if limit != nil && *limit < 0 {
		return nil, fmt.Errorf("%w: limit must be non-negative", storage.ErrInvalidQuery)
	}
	if params.Offset != nil && *params.Offset < 0 {
		return nil, fmt.Errorf("%w: offset must be non-negative", storage.ErrInvalidQuery)
	}
	if limit != nil && *limit == 0 {
		return []storage.Record{}, nil
	}

	find := findOptions{projection: projection(fields), sort: sort}
	if limit != nil {
		find.hasLimit = true
		find.limit = int64(*limit)
	}
	if params.Offset != nil {
		find.hasSkip = true
		find.skip = int64(*params.Offset)
	}
	documents, err := executor.database.Collection(model.physical).Find(ctx, filter, find)
	if err != nil {
		return nil, normalizeError(ctx, "find "+model.canonical, err)
	}
	result := make([]storage.Record, 0, len(documents))
	for _, raw := range documents {
		decoded, err := decodeDocument(executor.config, model, raw, selected)
		if err != nil {
			return nil, err
		}
		for _, join := range joins {
			joined, err := executor.joinDocument(ctx, raw, join)
			if err != nil {
				return nil, err
			}
			decoded[join.model.canonical] = joined
		}
		result = append(result, decoded)
	}
	return result, nil
}

func (executor *executor) Count(ctx context.Context, params storage.CountParams) (int64, error) {
	ctx, err := executor.operationContext(ctx)
	if err != nil {
		return 0, err
	}
	model, err := resolveModel(executor.config, params.Model)
	if err != nil {
		return 0, err
	}
	filter, err := buildWhere(executor.config, model, params.Where)
	if err != nil {
		return 0, err
	}
	count, err := executor.database.Collection(model.physical).CountDocuments(ctx, filter)
	if err != nil {
		return 0, normalizeError(ctx, "count "+model.canonical, err)
	}
	return count, nil
}

var _ storage.Adapter = (*Adapter)(nil)
var _ storage.TransactionAdapter = (*transactionAdapter)(nil)
