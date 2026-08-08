package storage

import (
	"fmt"
	"reflect"
)

type Operator string

const (
	OpEq         Operator = "eq"
	OpNe         Operator = "ne"
	OpLt         Operator = "lt"
	OpLTE        Operator = "lte"
	OpGt         Operator = "gt"
	OpGTE        Operator = "gte"
	OpIn         Operator = "in"
	OpNotIn      Operator = "not_in"
	OpContains   Operator = "contains"
	OpStartsWith Operator = "starts_with"
	OpEndsWith   Operator = "ends_with"
)

type Connector string

const (
	And Connector = "AND"
	Or  Connector = "OR"
)

type ComparisonMode string

const (
	Sensitive   ComparisonMode = "sensitive"
	Insensitive ComparisonMode = "insensitive"
)

// Where is one predicate in an authentication storage query. SQL and document
// adapters group every AND predicate together and
// every OR predicate together, then require both non-empty groups to match.
// The memory adapter retains its own left-to-right behavior.
// Zero-value Operator, Connector, and Mode normalize to eq, AND, and sensitive.
type Where struct {
	Field     string
	Value     any
	Operator  Operator
	Connector Connector
	Mode      ComparisonMode
}

// Normalize validates the clause and fills reference implementation defaults.
func (w Where) Normalize() (Where, error) {
	if w.Field == "" {
		return Where{}, fmt.Errorf("%w: where field is empty", ErrInvalidQuery)
	}
	if w.Operator == "" {
		w.Operator = OpEq
	}
	if w.Connector == "" {
		w.Connector = And
	}
	if w.Mode == "" {
		w.Mode = Sensitive
	}

	switch w.Operator {
	case OpEq, OpNe, OpLt, OpLTE, OpGt, OpGTE, OpIn, OpNotIn, OpContains, OpStartsWith, OpEndsWith:
	default:
		return Where{}, fmt.Errorf("%w: unsupported operator %q", ErrInvalidQuery, w.Operator)
	}
	switch w.Connector {
	case And, Or:
	default:
		return Where{}, fmt.Errorf("%w: unsupported connector %q", ErrInvalidQuery, w.Connector)
	}
	switch w.Mode {
	case Sensitive, Insensitive:
	default:
		return Where{}, fmt.Errorf("%w: unsupported comparison mode %q", ErrInvalidQuery, w.Mode)
	}
	if (w.Operator == OpIn || w.Operator == OpNotIn) && !isSlice(w.Value) {
		return Where{}, fmt.Errorf("%w: %s value must be an array", ErrInvalidQuery, w.Operator)
	}
	return w, nil
}

// GroupWhere normalizes a query and partitions it using the grouping semantics
// shared by reference implementation's database-backed adapters. The relative order inside
// each group is preserved so generated parameter bindings remain deterministic.
func GroupWhere(clauses []Where) (andClauses, orClauses []Where, err error) {
	andClauses = make([]Where, 0, len(clauses))
	orClauses = make([]Where, 0, len(clauses))
	for _, unsafe := range clauses {
		clause, normalizeErr := unsafe.Normalize()
		if normalizeErr != nil {
			return nil, nil, normalizeErr
		}
		if clause.Connector == Or {
			orClauses = append(orClauses, clause)
		} else {
			andClauses = append(andClauses, clause)
		}
	}
	return andClauses, orClauses, nil
}

type SortDirection string

const (
	Ascending  SortDirection = "asc"
	Descending SortDirection = "desc"
)

type Sort struct {
	Field     string
	Direction SortDirection
}

// JoinOption requests a relation inferred from the schema. Model allows the
// map key to be a relation alias instead of the joined model name, while
// RelationName selects one foreign key when the same models have multiple
// named relations. A nil Limit uses the adapter default. A pointer permits an
// explicit limit of zero.
type JoinOption struct {
	Model        string
	RelationName string
	Limit        *int
	// On and Relation are populated by AdapterFactory when a custom adapter
	// advertises native join support. Callers normally leave them empty and let
	// the factory infer the relationship from Schema.
	On       *JoinOn
	Relation Relation
}

// JoinOn is the physical field pair used by a native custom-adapter join.
// From belongs to the base model and To belongs to the joined model.
type JoinOn struct {
	From string
	To   string
}

type Relation string

const (
	OneToOne   Relation = "one-to-one"
	OneToMany  Relation = "one-to-many"
	ManyToMany Relation = "many-to-many"
)

// JoinConfig is the physical join description derived from JoinOption and the
// configured schema.
type JoinConfig struct {
	From     string
	To       string
	Limit    int
	Relation Relation
}

func isSlice(value any) bool {
	if value == nil {
		return false
	}
	kind := reflect.TypeOf(value).Kind()
	return kind == reflect.Array || kind == reflect.Slice
}
