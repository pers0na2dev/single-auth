package mongodb

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type findOptions struct {
	projection bson.D
	sort       bson.D
	limit      int64
	skip       int64
	hasLimit   bool
	hasSkip    bool
}

type updateCounts struct {
	matched  int64
	modified int64
}

type indexSpec struct {
	name   string
	field  string
	unique bool
}

type collectionStore interface {
	InsertOne(context.Context, bson.M) (any, error)
	Find(context.Context, bson.D, findOptions) ([]bson.M, error)
	CountDocuments(context.Context, bson.D) (int64, error)
	FindOneAndUpdate(context.Context, bson.D, bson.D) (bson.M, error)
	UpdateMany(context.Context, bson.D, bson.D) (updateCounts, error)
	DeleteOne(context.Context, bson.D) (int64, error)
	DeleteMany(context.Context, bson.D) (int64, error)
	FindOneAndDelete(context.Context, bson.D) (bson.M, error)
	CreateIndexes(context.Context, []indexSpec) error
}

type databaseStore interface {
	Collection(string) collectionStore
	ListCollectionNames(context.Context) ([]string, error)
	CreateCollection(context.Context, string) error
}

type contextBinder func(context.Context) context.Context

type transactionRunner interface {
	Run(context.Context, func(contextBinder) error) error
}

type mongoDatabase struct{ database *mongo.Database }

func (database *mongoDatabase) Collection(name string) collectionStore {
	return &mongoCollection{collection: database.database.Collection(name)}
}

func (database *mongoDatabase) ListCollectionNames(ctx context.Context) ([]string, error) {
	return database.database.ListCollectionNames(ctx, bson.D{})
}

func (database *mongoDatabase) CreateCollection(ctx context.Context, name string) error {
	return database.database.CreateCollection(ctx, name)
}

type mongoCollection struct{ collection *mongo.Collection }

func (collection *mongoCollection) InsertOne(ctx context.Context, document bson.M) (any, error) {
	result, err := collection.collection.InsertOne(ctx, document)
	if err != nil {
		return nil, err
	}
	return result.InsertedID, nil
}

func (collection *mongoCollection) Find(ctx context.Context, filter bson.D, spec findOptions) ([]bson.M, error) {
	builder := options.Find()
	if len(spec.projection) > 0 {
		builder.SetProjection(spec.projection)
	}
	if len(spec.sort) > 0 {
		builder.SetSort(spec.sort)
	}
	if spec.hasLimit {
		builder.SetLimit(spec.limit)
	}
	if spec.hasSkip {
		builder.SetSkip(spec.skip)
	}
	cursor, err := collection.collection.Find(ctx, filter, builder)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var documents []bson.M
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, err
	}
	if documents == nil {
		documents = []bson.M{}
	}
	return documents, nil
}

func (collection *mongoCollection) CountDocuments(ctx context.Context, filter bson.D) (int64, error) {
	return collection.collection.CountDocuments(ctx, filter)
}

func (collection *mongoCollection) FindOneAndUpdate(ctx context.Context, filter bson.D, update bson.D) (bson.M, error) {
	result := collection.collection.FindOneAndUpdate(
		ctx,
		filter,
		update,
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)
	var document bson.M
	if err := result.Decode(&document); err != nil {
		return nil, err
	}
	return document, nil
}

func (collection *mongoCollection) UpdateMany(ctx context.Context, filter bson.D, update bson.D) (updateCounts, error) {
	result, err := collection.collection.UpdateMany(ctx, filter, update)
	if err != nil {
		return updateCounts{}, err
	}
	return updateCounts{matched: result.MatchedCount, modified: result.ModifiedCount}, nil
}

func (collection *mongoCollection) DeleteOne(ctx context.Context, filter bson.D) (int64, error) {
	result, err := collection.collection.DeleteOne(ctx, filter)
	if err != nil {
		return 0, err
	}
	return result.DeletedCount, nil
}

func (collection *mongoCollection) DeleteMany(ctx context.Context, filter bson.D) (int64, error) {
	result, err := collection.collection.DeleteMany(ctx, filter)
	if err != nil {
		return 0, err
	}
	return result.DeletedCount, nil
}

func (collection *mongoCollection) FindOneAndDelete(ctx context.Context, filter bson.D) (bson.M, error) {
	result := collection.collection.FindOneAndDelete(ctx, filter)
	var document bson.M
	if err := result.Decode(&document); err != nil {
		return nil, err
	}
	return document, nil
}

func (collection *mongoCollection) CreateIndexes(ctx context.Context, specs []indexSpec) error {
	if len(specs) == 0 {
		return nil
	}
	models := make([]mongo.IndexModel, 0, len(specs))
	for _, spec := range specs {
		builder := options.Index().SetName(spec.name).SetUnique(spec.unique)
		models = append(models, mongo.IndexModel{
			Keys:    bson.D{{Key: spec.field, Value: 1}},
			Options: builder,
		})
	}
	_, err := collection.collection.Indexes().CreateMany(ctx, models)
	return err
}

type mongoTransactions struct{ client *mongo.Client }

func (transactions *mongoTransactions) Run(ctx context.Context, callback func(contextBinder) error) error {
	session, err := transactions.client.StartSession()
	if err != nil {
		return fmt.Errorf("mongodb: start session: %w", err)
	}
	defer session.EndSession(ctx)
	if err := session.StartTransaction(); err != nil {
		return fmt.Errorf("mongodb: start transaction: %w", err)
	}
	binder := func(operationContext context.Context) context.Context {
		return mongo.NewSessionContext(operationContext, session)
	}
	if err := callback(binder); err != nil {
		_ = session.AbortTransaction(context.WithoutCancel(ctx))
		return err
	}
	if err := contextError(ctx); err != nil {
		_ = session.AbortTransaction(context.WithoutCancel(ctx))
		return err
	}
	if err := session.CommitTransaction(ctx); err != nil {
		return fmt.Errorf("mongodb: commit transaction: %w", err)
	}
	return nil
}
