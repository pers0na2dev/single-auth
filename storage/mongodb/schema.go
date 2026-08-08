package mongodb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/pers0na2dev/single-auth/storage"
)

// SchemaPlan is a deterministic collection and index creation plan.
type SchemaPlan struct {
	Collections []CollectionPlan `json:"collections"`
}

// CollectionPlan describes one MongoDB collection and its secondary indexes.
type CollectionPlan struct {
	Model   string      `json:"model"`
	Name    string      `json:"name"`
	Indexes []IndexPlan `json:"indexes,omitempty"`
}

// IndexPlan describes one ascending single-field index.
type IndexPlan struct {
	Name   string `json:"name"`
	Field  string `json:"field"`
	Unique bool   `json:"unique,omitempty"`
}

type orderedModel struct {
	canonical string
	order     int
}

// PlanSchema validates schema and returns collections and indexes in stable
// order. MongoDB creates the unique _id index automatically.
func PlanSchema(schema storage.Schema) (SchemaPlan, error) {
	if len(schema.Models) == 0 {
		schema = storage.CoreSchema()
	}
	schema = schema.Clone()
	if err := schema.Validate(); err != nil {
		return SchemaPlan{}, fmt.Errorf("mongodb: schema plan: %w", err)
	}
	if err := validateMongoNames(schema); err != nil {
		return SchemaPlan{}, err
	}
	configuration := &config{schema: schema}
	models := make([]orderedModel, 0, len(schema.Models))
	for canonical, model := range schema.Models {
		if model.DisableMigrations {
			continue
		}
		models = append(models, orderedModel{canonical: canonical, order: model.Order})
	}
	sort.Slice(models, func(left, right int) bool {
		if models[left].order != models[right].order {
			return models[left].order < models[right].order
		}
		return models[left].canonical < models[right].canonical
	})

	plan := SchemaPlan{Collections: make([]CollectionPlan, 0, len(models))}
	for _, ordered := range models {
		model, err := resolveModel(configuration, ordered.canonical)
		if err != nil {
			return SchemaPlan{}, err
		}
		collection := CollectionPlan{Model: model.canonical, Name: model.physical}
		for _, field := range modelFields(model)[1:] {
			if !field.attribute.Index && !field.attribute.Unique {
				continue
			}
			collection.Indexes = append(collection.Indexes, IndexPlan{
				Name:   mongoObjectName(model.physical, field.physical),
				Field:  field.physical,
				Unique: field.attribute.Unique,
			})
		}
		plan.Collections = append(plan.Collections, collection)
	}
	return plan, nil
}

// JSON returns a stable human-readable representation useful for review and
// golden tests.
func (plan SchemaPlan) JSON() string {
	encoded, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return ""
	}
	return string(encoded) + "\n"
}

// JavaScript renders an idempotent mongosh migration artifact.
func (plan SchemaPlan) JavaScript() string {
	var output strings.Builder
	for _, collection := range plan.Collections {
		name, _ := json.Marshal(collection.Name)
		fmt.Fprintf(&output, "if (!db.getCollectionNames().includes(%s)) { db.createCollection(%s); }\n", name, name)
		for _, index := range collection.Indexes {
			field, _ := json.Marshal(index.Field)
			indexName, _ := json.Marshal(index.Name)
			fmt.Fprintf(&output, "db.getCollection(%s).createIndex({ %s: 1 }, { name: %s", name, field, indexName)
			if index.Unique {
				output.WriteString(", unique: true")
			}
			output.WriteString(" });\n")
		}
	}
	return output.String()
}

func mongoObjectName(collection, field string) string {
	raw := "single_" + collection + "_" + field + "_idx"
	if len(raw) <= 127 {
		return raw
	}
	digest := sha256.Sum256([]byte(raw))
	suffix := "_" + hex.EncodeToString(digest[:6])
	limit := 127 - len(suffix)
	prefix := raw
	for len(prefix) > limit {
		_, size := utf8.DecodeLastRuneInString(prefix)
		if size == 0 {
			break
		}
		prefix = prefix[:len(prefix)-size]
	}
	return prefix + suffix
}

// EnsureSchema creates missing collections and every configured index. It is
// safe to call repeatedly and deliberately runs outside a transaction because
// MongoDB disallows collection creation in several transaction topologies.
func (adapter *Adapter) EnsureSchema(ctx context.Context) error {
	ctx, err := adapter.operationContext(ctx)
	if err != nil {
		return err
	}
	plan, err := PlanSchema(adapter.config.schema)
	if err != nil {
		return err
	}
	names, err := adapter.database.ListCollectionNames(ctx)
	if err != nil {
		return normalizeError(ctx, "list collections", err)
	}
	existing := make(map[string]struct{}, len(names))
	for _, name := range names {
		existing[name] = struct{}{}
	}
	for _, collection := range plan.Collections {
		if _, exists := existing[collection.Name]; !exists {
			if err := adapter.database.CreateCollection(ctx, collection.Name); err != nil && !namespaceExists(err) {
				return normalizeError(ctx, "create collection "+collection.Name, err)
			}
		}
		specs := make([]indexSpec, 0, len(collection.Indexes))
		for _, index := range collection.Indexes {
			specs = append(specs, indexSpec{name: index.Name, field: index.Field, unique: index.Unique})
		}
		if err := adapter.database.Collection(collection.Name).CreateIndexes(ctx, specs); err != nil {
			return normalizeError(ctx, "create indexes "+collection.Name, err)
		}
	}
	return nil
}

func namespaceExists(err error) bool {
	var command mongo.CommandError
	return errors.As(err, &command) && command.Code == 48
}

// CreateSchema returns an idempotent mongosh artifact without modifying the
// configured database.
func (adapter *Adapter) CreateSchema(ctx context.Context, schema storage.Schema, path string) (storage.SchemaCreation, error) {
	if err := contextError(ctx); err != nil {
		return storage.SchemaCreation{}, err
	}
	plan, err := PlanSchema(schema)
	if err != nil {
		return storage.SchemaCreation{}, err
	}
	return storage.SchemaCreation{Code: plan.JavaScript(), Path: path, Append: true}, nil
}

var _ storage.SchemaCreator = (*Adapter)(nil)
var _ storage.SchemaEnsurer = (*Adapter)(nil)
