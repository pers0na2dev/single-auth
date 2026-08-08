package sqlite

import (
	"fmt"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

func buildWhere(configuration *config, model resolvedModel, clauses []storage.Where) (string, []any, error) {
	if len(clauses) == 0 {
		return "", nil, nil
	}
	andClauses, orClauses, err := storage.GroupWhere(clauses)
	if err != nil {
		return "", nil, err
	}
	groupExpressions := make([]string, 0, 2)
	args := make([]any, 0, len(clauses))
	for index, group := range [][]storage.Where{andClauses, orClauses} {
		predicates := make([]string, 0, len(group))
		for _, clause := range group {
			field, resolveErr := resolveField(configuration, model, clause.Field)
			if resolveErr != nil {
				return "", nil, resolveErr
			}
			predicate, predicateArgs, predicateErr := buildPredicate(configuration, field, clause, false)
			if predicateErr != nil {
				return "", nil, predicateErr
			}
			predicates = append(predicates, predicate)
			args = append(args, predicateArgs...)
		}
		if len(predicates) == 0 {
			continue
		}
		connector := storage.And
		if index == 1 {
			connector = storage.Or
		}
		groupExpressions = append(groupExpressions, foldPredicates(predicates, connector))
	}
	return foldPredicates(groupExpressions, storage.And), args, nil
}

func foldPredicates(predicates []string, connector storage.Connector) string {
	if len(predicates) == 0 {
		return ""
	}
	expression := predicates[0]
	for _, predicate := range predicates[1:] {
		expression = fmt.Sprintf("(%s %s %s)", expression, connector, predicate)
	}
	return expression
}

func buildRawEquality(field resolvedField, value any) (string, []any) {
	column := quoteIdentifier(field.physical)
	if value == nil {
		return column + " IS NULL", nil
	}
	return column + " = ?", []any{value}
}

func buildPredicate(configuration *config, field resolvedField, clause storage.Where, encoded bool) (string, []any, error) {
	column := quoteIdentifier(field.physical)
	caseInsensitive := clause.Mode == storage.Insensitive && isStringComparisonOperand(clause.Value)
	encode := func(value any) (any, error) {
		if encoded {
			return value, nil
		}
		return encodeValue(configuration, field, value)
	}
	comparison := func(operator string, value any) (string, []any, error) {
		value, err := encode(value)
		if err != nil {
			return "", nil, err
		}
		if caseInsensitive {
			return fmt.Sprintf("LOWER(%s) %s LOWER(?)", column, operator), []any{value}, nil
		}
		return fmt.Sprintf("%s %s ?", column, operator), []any{value}, nil
	}

	switch clause.Operator {
	case storage.OpEq:
		if clause.Value == nil {
			return column + " IS NULL", nil, nil
		}
		return comparison("=", clause.Value)
	case storage.OpNe:
		if clause.Value == nil {
			return column + " IS NOT NULL", nil, nil
		}
		predicate, args, err := comparison("<>", clause.Value)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("(%s IS NULL OR %s)", column, predicate), args, nil
	case storage.OpLt:
		return comparison("<", clause.Value)
	case storage.OpLTE:
		return comparison("<=", clause.Value)
	case storage.OpGt:
		return comparison(">", clause.Value)
	case storage.OpGTE:
		return comparison(">=", clause.Value)
	case storage.OpIn, storage.OpNotIn:
		items, err := sliceValues(clause.Value)
		if err != nil {
			return "", nil, err
		}
		return buildMembership(configuration, field, clause, items, encoded)
	case storage.OpContains:
		if field.attribute.Type == storage.FieldStringArray || field.attribute.Type == storage.FieldNumberArray {
			value, err := encodeArrayElement(configuration, field, clause.Value)
			if err != nil {
				return "", nil, err
			}
			if value == nil {
				return fmt.Sprintf("EXISTS (SELECT 1 FROM json_each(%s) WHERE json_each.value IS NULL)", column), nil, nil
			}
			_, stringOperand := value.(string)
			if caseInsensitive && stringOperand {
				return fmt.Sprintf("EXISTS (SELECT 1 FROM json_each(%s) WHERE LOWER(json_each.value) = LOWER(?))", column), []any{value}, nil
			}
			return fmt.Sprintf("EXISTS (SELECT 1 FROM json_each(%s) WHERE json_each.value = ?)", column), []any{value}, nil
		}
		value, err := encode(clause.Value)
		if err != nil {
			return "", nil, err
		}
		if caseInsensitive {
			return fmt.Sprintf("INSTR(LOWER(%s), LOWER(?)) > 0", column), []any{value}, nil
		}
		return fmt.Sprintf("INSTR(%s, ?) > 0", column), []any{value}, nil
	case storage.OpStartsWith:
		value, err := encode(clause.Value)
		if err != nil {
			return "", nil, err
		}
		if caseInsensitive {
			return fmt.Sprintf("SUBSTR(LOWER(%s), 1, LENGTH(LOWER(?))) = LOWER(?)", column), []any{value, value}, nil
		}
		return fmt.Sprintf("SUBSTR(%s, 1, LENGTH(?)) = ?", column), []any{value, value}, nil
	case storage.OpEndsWith:
		value, err := encode(clause.Value)
		if err != nil {
			return "", nil, err
		}
		if caseInsensitive {
			return fmt.Sprintf("SUBSTR(LOWER(%s), -LENGTH(LOWER(?))) = LOWER(?)", column), []any{value, value}, nil
		}
		return fmt.Sprintf("SUBSTR(%s, -LENGTH(?)) = ?", column), []any{value, value}, nil
	default:
		return "", nil, fmt.Errorf("%w: unsupported operator %q", storage.ErrInvalidQuery, clause.Operator)
	}
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
		if _, ok := item.(string); !ok {
			return false
		}
	}
	return true
}

func buildMembership(configuration *config, field resolvedField, clause storage.Where, items []any, encoded bool) (string, []any, error) {
	column := quoteIdentifier(field.physical)
	values := make([]any, 0, len(items))
	hasNull := false
	for _, item := range items {
		if item == nil {
			hasNull = true
			continue
		}
		value := item
		var err error
		if !encoded {
			value, err = encodeValue(configuration, field, item)
			if err != nil {
				return "", nil, err
			}
		}
		values = append(values, value)
	}
	placeholders := make([]string, len(values))
	for index := range placeholders {
		if clause.Mode == storage.Insensitive && isStringComparisonOperand(clause.Value) {
			placeholders[index] = "LOWER(?)"
		} else {
			placeholders[index] = "?"
		}
	}
	operand := column
	if clause.Mode == storage.Insensitive && isStringComparisonOperand(clause.Value) {
		operand = "LOWER(" + column + ")"
	}

	if clause.Operator == storage.OpIn {
		parts := make([]string, 0, 2)
		if len(values) > 0 {
			parts = append(parts, fmt.Sprintf("%s IN (%s)", operand, strings.Join(placeholders, ", ")))
		}
		if hasNull {
			parts = append(parts, column+" IS NULL")
		}
		if len(parts) == 0 {
			return "0", nil, nil
		}
		return "(" + strings.Join(parts, " OR ") + ")", values, nil
	}

	parts := make([]string, 0, 2)
	if len(values) > 0 {
		parts = append(parts, fmt.Sprintf("%s NOT IN (%s)", operand, strings.Join(placeholders, ", ")))
	}
	if hasNull {
		parts = append(parts, column+" IS NOT NULL")
	} else {
		parts = append(parts, column+" IS NULL")
	}
	if len(values) == 0 && !hasNull {
		return "1", nil, nil
	}
	joiner := " OR "
	if hasNull {
		joiner = " AND "
	}
	return "(" + strings.Join(parts, joiner) + ")", values, nil
}

func buildOrder(configuration *config, model resolvedModel, sortBy *storage.Sort) (string, error) {
	if sortBy == nil {
		return "", nil
	}
	if sortBy.Direction != storage.Ascending && sortBy.Direction != storage.Descending {
		return "", fmt.Errorf("%w: invalid sort direction %q", storage.ErrInvalidQuery, sortBy.Direction)
	}
	field, err := resolveField(configuration, model, sortBy.Field)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(" ORDER BY %s %s", quoteIdentifier(field.physical), strings.ToUpper(string(sortBy.Direction))), nil
}
