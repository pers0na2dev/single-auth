package mongodb

import (
	"fmt"
	"regexp"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/pers0na2dev/single-auth/storage"
)

func buildWhere(configuration *config, model resolvedModel, clauses []storage.Where) (bson.D, error) {
	if len(clauses) == 0 {
		return bson.D{}, nil
	}
	type condition struct {
		predicate bson.D
		connector storage.Connector
	}
	conditions := make([]condition, 0, len(clauses))
	for _, unsafe := range clauses {
		clause, err := unsafe.Normalize()
		if err != nil {
			return nil, err
		}
		field, err := resolveField(configuration, model, clause.Field)
		if err != nil {
			return nil, err
		}
		predicate, err := buildPredicate(configuration, field, clause)
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, condition{predicate: predicate, connector: clause.Connector})
	}
	if len(conditions) == 1 {
		return conditions[0].predicate, nil
	}
	andPredicates := make(bson.A, 0, len(conditions))
	orPredicates := make(bson.A, 0, len(conditions))
	for _, condition := range conditions {
		if condition.connector == storage.Or {
			orPredicates = append(orPredicates, condition.predicate)
		} else {
			andPredicates = append(andPredicates, condition.predicate)
		}
	}
	expression := make(bson.D, 0, 2)
	if len(andPredicates) > 0 {
		expression = append(expression, bson.E{Key: "$and", Value: andPredicates})
	}
	if len(orPredicates) > 0 {
		expression = append(expression, bson.E{Key: "$or", Value: orPredicates})
	}
	return expression, nil
}

func buildPredicate(configuration *config, field resolvedField, clause storage.Where) (bson.D, error) {
	caseInsensitive := clause.Mode == storage.Insensitive && isStringComparisonOperand(clause.Value) && !isIDField(field)
	comparison := func(operator string, value any) (bson.D, error) {
		encoded, err := encodeQueryValue(configuration, field, value)
		if err != nil {
			return nil, err
		}
		return bson.D{{Key: field.physical, Value: bson.D{{Key: operator, Value: encoded}}}}, nil
	}

	switch clause.Operator {
	case storage.OpEq:
		encoded, err := encodeQueryValue(configuration, field, clause.Value)
		if err != nil {
			return nil, err
		}
		if caseInsensitive {
			value, ok := encoded.(string)
			if ok {
				return regexPredicate(field.physical, "^"+regexp.QuoteMeta(value)+"$", true), nil
			}
		}
		return bson.D{{Key: field.physical, Value: encoded}}, nil
	case storage.OpNe:
		encoded, err := encodeQueryValue(configuration, field, clause.Value)
		if err != nil {
			return nil, err
		}
		if caseInsensitive {
			value, ok := encoded.(string)
			if ok {
				return bson.D{{Key: field.physical, Value: bson.D{{
					Key: "$not", Value: bson.Regex{Pattern: "^" + regexp.QuoteMeta(value) + "$", Options: "i"},
				}}}}, nil
			}
		}
		return bson.D{{Key: field.physical, Value: bson.D{{Key: "$ne", Value: encoded}}}}, nil
	case storage.OpLt:
		return comparison("$lt", clause.Value)
	case storage.OpLTE:
		return comparison("$lte", clause.Value)
	case storage.OpGt:
		return comparison("$gt", clause.Value)
	case storage.OpGTE:
		return comparison("$gte", clause.Value)
	case storage.OpIn, storage.OpNotIn:
		items, err := sliceValues(clause.Value)
		if err != nil {
			return nil, err
		}
		return buildMembership(configuration, field, clause, items, caseInsensitive)
	case storage.OpContains:
		return buildContains(configuration, field, clause, caseInsensitive)
	case storage.OpStartsWith, storage.OpEndsWith:
		encoded, err := encodeQueryValue(configuration, field, clause.Value)
		if err != nil {
			return nil, err
		}
		value, ok := encoded.(string)
		if !ok {
			return nil, fmt.Errorf("%w: %s operand must be a string", storage.ErrInvalidQuery, clause.Operator)
		}
		pattern := "^" + regexp.QuoteMeta(value)
		if clause.Operator == storage.OpEndsWith {
			pattern = regexp.QuoteMeta(value) + "$"
		}
		return regexPredicate(field.physical, pattern, caseInsensitive), nil
	default:
		return nil, fmt.Errorf("%w: unsupported operator %q", storage.ErrInvalidQuery, clause.Operator)
	}
}

func buildMembership(configuration *config, field resolvedField, clause storage.Where, items []any, insensitive bool) (bson.D, error) {
	values := make(bson.A, 0, len(items))
	hasNull := false
	for _, item := range items {
		if item == nil {
			hasNull = true
			values = append(values, nil)
			continue
		}
		if insensitive {
			encoded, err := encodeQueryValue(configuration, field, item)
			if err != nil {
				return nil, err
			}
			text, ok := encoded.(string)
			if !ok {
				return nil, fmt.Errorf("%w: insensitive membership operand must contain strings", storage.ErrInvalidQuery)
			}
			values = append(values, bson.Regex{Pattern: "^" + regexp.QuoteMeta(text) + "$", Options: "i"})
			continue
		}
		encoded, err := encodeQueryValue(configuration, field, item)
		if err != nil {
			return nil, err
		}
		values = append(values, encoded)
	}

	if clause.Operator == storage.OpIn {
		return bson.D{{Key: field.physical, Value: bson.D{{Key: "$in", Value: values}}}}, nil
	}
	if len(values) == 0 {
		return bson.D{}, nil
	}
	if !hasNull {
		return bson.D{{Key: field.physical, Value: bson.D{{Key: "$nin", Value: values}}}}, nil
	}
	withoutNull := make(bson.A, 0, len(values)-1)
	for _, value := range values {
		if value != nil {
			withoutNull = append(withoutNull, value)
		}
	}
	conditions := bson.A{
		bson.D{{Key: field.physical, Value: bson.D{{Key: "$exists", Value: true}}}},
		bson.D{{Key: field.physical, Value: bson.D{{Key: "$ne", Value: nil}}}},
	}
	if len(withoutNull) > 0 {
		conditions = append(conditions, bson.D{{Key: field.physical, Value: bson.D{{Key: "$nin", Value: withoutNull}}}})
	}
	return bson.D{{Key: "$and", Value: conditions}}, nil
}

func buildContains(configuration *config, field resolvedField, clause storage.Where, insensitive bool) (bson.D, error) {
	switch field.attribute.Type {
	case storage.FieldStringArray:
		value, err := encodeArrayElement(configuration, field, clause.Value)
		if err != nil {
			return nil, err
		}
		if insensitive {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("%w: insensitive contains operand must be a string", storage.ErrInvalidQuery)
			}
			return regexPredicate(field.physical, "^"+regexp.QuoteMeta(text)+"$", true), nil
		}
		return bson.D{{Key: field.physical, Value: value}}, nil
	case storage.FieldNumberArray:
		value, err := encodeArrayElement(configuration, field, clause.Value)
		if err != nil {
			return nil, err
		}
		value, err = toBSONValue(value)
		if err != nil {
			return nil, err
		}
		return bson.D{{Key: field.physical, Value: value}}, nil
	case storage.FieldString, storage.FieldEnum, storage.FieldJSON:
		encoded, err := encodeQueryValue(configuration, field, clause.Value)
		if err != nil {
			return nil, err
		}
		value, ok := encoded.(string)
		if !ok {
			if field.attribute.Type == storage.FieldJSON {
				return bson.D{{Key: field.physical, Value: encoded}}, nil
			}
			return nil, fmt.Errorf("%w: contains operand must be a string", storage.ErrInvalidQuery)
		}
		return regexPredicate(field.physical, regexp.QuoteMeta(value), insensitive), nil
	default:
		return nil, fmt.Errorf("%w: contains is unsupported for %s", storage.ErrInvalidQuery, field.attribute.Type)
	}
}

func regexPredicate(field, pattern string, insensitive bool) bson.D {
	options := ""
	if insensitive {
		options = "i"
	}
	return bson.D{{Key: field, Value: bson.Regex{Pattern: pattern, Options: options}}}
}

func isStringComparisonOperand(value any) bool {
	if _, ok := value.(string); ok {
		return true
	}
	items, err := sliceValues(value)
	if err != nil {
		return false
	}
	for _, item := range items {
		if item == nil {
			continue
		}
		if _, ok := item.(string); !ok {
			return false
		}
	}
	return true
}

func buildSort(configuration *config, model resolvedModel, sortBy *storage.Sort) (bson.D, error) {
	if sortBy == nil {
		return nil, nil
	}
	if sortBy.Direction != storage.Ascending && sortBy.Direction != storage.Descending {
		return nil, fmt.Errorf("%w: invalid sort direction %q", storage.ErrInvalidQuery, sortBy.Direction)
	}
	field, err := resolveField(configuration, model, sortBy.Field)
	if err != nil {
		return nil, err
	}
	direction := 1
	if strings.EqualFold(string(sortBy.Direction), string(storage.Descending)) {
		direction = -1
	}
	return bson.D{{Key: field.physical, Value: direction}}, nil
}
