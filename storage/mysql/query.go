package mysql

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

type parameters struct {
	next int
	args []any
}

func newParameters(start int) *parameters {
	if start < 1 {
		start = 1
	}
	return &parameters{next: start}
}

func (p *parameters) bind(value any) string {
	p.next++
	p.args = append(p.args, value)
	return "?"
}

func buildWhere(configuration *config, model resolvedModel, clauses []storage.Where, start int) (string, []any, error) {
	if len(clauses) == 0 {
		return "", nil, nil
	}
	andClauses, orClauses, err := storage.GroupWhere(clauses)
	if err != nil {
		return "", nil, err
	}
	params := newParameters(start)
	groupExpressions := make([]string, 0, 2)
	for index, group := range [][]storage.Where{andClauses, orClauses} {
		predicates := make([]string, 0, len(group))
		for _, clause := range group {
			field, resolveErr := resolveField(configuration, model, clause.Field)
			if resolveErr != nil {
				return "", nil, resolveErr
			}
			predicate, predicateErr := buildPredicate(configuration, field, clause, params)
			if predicateErr != nil {
				return "", nil, predicateErr
			}
			predicates = append(predicates, predicate)
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
	return foldPredicates(groupExpressions, storage.And), params.args, nil
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

func buildRawEquality(field resolvedField, value any, start int) (string, []any) {
	return buildRawEqualityWithConfig(nil, field, value, start)
}

func buildRawEqualityWithConfig(configuration *config, field resolvedField, value any, start int) (string, []any) {
	column := quoteIdentifier(field.physical)
	if value == nil {
		return column + " IS NULL", nil
	}
	params := newParameters(start)
	placeholder := bindFieldValue(configuration, field, params, value)
	if isTextField(configuration, field) {
		return "BINARY " + column + " = BINARY " + placeholder, params.args
	}
	return column + " = " + placeholder, params.args
}

func bindFieldValue(_ *config, _ resolvedField, params *parameters, value any) string {
	return params.bind(value)
}

func isTextField(configuration *config, field resolvedField) bool {
	if field.canonical == "id" {
		return configuration == nil || configuration.idType != SerialID
	}
	if field.attribute.References != nil && field.attribute.References.Field == "id" {
		return configuration == nil || configuration.idType != SerialID
	}
	return field.attribute.Type == storage.FieldString || field.attribute.Type == storage.FieldEnum
}

func buildPredicate(configuration *config, field resolvedField, clause storage.Where, params *parameters) (string, error) {
	column := quoteIdentifier(field.physical)
	textComparison := isTextField(configuration, field) && isStringComparisonOperand(clause.Value)
	caseInsensitive := clause.Mode == storage.Insensitive && textComparison
	caseSensitive := clause.Mode == storage.Sensitive && textComparison
	comparison := func(operator string, value any) (string, error) {
		encoded, err := encodeValue(configuration, field, value)
		if err != nil {
			return "", err
		}
		placeholder := bindFieldValue(configuration, field, params, encoded)
		if caseInsensitive {
			return fmt.Sprintf("LOWER(%s) %s LOWER(%s)", column, operator, placeholder), nil
		}
		if caseSensitive {
			return fmt.Sprintf("BINARY %s %s BINARY %s", column, operator, placeholder), nil
		}
		return fmt.Sprintf("%s %s %s", column, operator, placeholder), nil
	}

	switch clause.Operator {
	case storage.OpEq:
		if clause.Value == nil {
			return column + " IS NULL", nil
		}
		return comparison("=", clause.Value)
	case storage.OpNe:
		if clause.Value == nil {
			return column + " IS NOT NULL", nil
		}
		predicate, err := comparison("<>", clause.Value)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(%s IS NULL OR %s)", column, predicate), nil
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
			return "", err
		}
		return buildMembership(configuration, field, clause, items, params)
	case storage.OpContains:
		return buildContains(configuration, field, clause, params)
	case storage.OpStartsWith, storage.OpEndsWith:
		encoded, err := encodeValue(configuration, field, clause.Value)
		if err != nil {
			return "", err
		}
		placeholder := params.bind(encoded)
		operand := column
		argument := placeholder
		if caseInsensitive {
			operand = "LOWER(" + operand + ")"
			argument = "LOWER(" + argument + ")"
		} else if caseSensitive {
			operand = "BINARY " + operand
			argument = "BINARY " + argument
		}
		if clause.Operator == storage.OpStartsWith {
			return fmt.Sprintf("LOCATE(%s, %s) = 1", argument, operand), nil
		}
		return fmt.Sprintf("LOCATE(REVERSE(%s), REVERSE(%s)) = 1", argument, operand), nil
	default:
		return "", fmt.Errorf("%w: unsupported operator %q", storage.ErrInvalidQuery, clause.Operator)
	}
}

func buildContains(configuration *config, field resolvedField, clause storage.Where, params *parameters) (string, error) {
	column := quoteIdentifier(field.physical)
	caseInsensitive := clause.Mode == storage.Insensitive && isStringComparisonOperand(clause.Value)
	switch field.attribute.Type {
	case storage.FieldStringArray:
		value, err := encodeArrayElement(configuration, field, clause.Value)
		if err != nil {
			return "", err
		}
		if value == nil {
			return fmt.Sprintf("JSON_CONTAINS(%s, 'null', '$') = 1", column), nil
		}
		if caseInsensitive {
			placeholder := params.bind(fmt.Sprint(value))
			return fmt.Sprintf("JSON_CONTAINS(LOWER(CAST(%s AS CHAR)), JSON_QUOTE(LOWER(%s)), '$') = 1", column, placeholder), nil
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("encode array contains operand: %w", err)
		}
		return fmt.Sprintf("JSON_CONTAINS(%s, %s, '$') = 1", column, params.bind(string(encoded))), nil
	case storage.FieldNumberArray:
		value, err := encodeArrayElement(configuration, field, clause.Value)
		if err != nil {
			return "", err
		}
		if value == nil {
			return fmt.Sprintf("JSON_CONTAINS(%s, 'null', '$') = 1", column), nil
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("encode array contains operand: %w", err)
		}
		return fmt.Sprintf("JSON_CONTAINS(%s, %s, '$') = 1", column, params.bind(string(encoded))), nil
	case storage.FieldJSON:
		raw, encoded, err := encodeJSONContainsOperand(configuration, field, clause.Value)
		if err != nil {
			return "", err
		}
		if raw == nil {
			return fmt.Sprintf("(JSON_TYPE(%s) = 'ARRAY' AND JSON_CONTAINS(%s, 'null', '$') = 1)", column, column), nil
		}
		if text, ok := raw.(string); ok {
			stringPlaceholder := params.bind(text)
			arrayPlaceholder := params.bind(text)
			container := fmt.Sprintf("JSON_UNQUOTE(%s)", column)
			stringMatch := fmt.Sprintf("LOCATE(BINARY %s, BINARY %s) > 0", stringPlaceholder, container)
			arrayArgument := "JSON_QUOTE(" + arrayPlaceholder + ")"
			if caseInsensitive {
				stringMatch = fmt.Sprintf("LOCATE(LOWER(%s), LOWER(%s)) > 0", stringPlaceholder, container)
				arrayArgument = "JSON_QUOTE(LOWER(" + arrayPlaceholder + "))"
			}
			return fmt.Sprintf("((JSON_TYPE(%s) = 'STRING' AND %s) OR (JSON_TYPE(%s) = 'ARRAY' AND JSON_CONTAINS(%s, %s, '$') = 1))", column, stringMatch, column, column, arrayArgument), nil
		}
		placeholder := params.bind(encoded)
		return fmt.Sprintf("(JSON_TYPE(%s) = 'ARRAY' AND JSON_CONTAINS(%s, %s, '$') = 1)", column, column, placeholder), nil
	default:
		value, err := encodeValue(configuration, field, clause.Value)
		if err != nil {
			return "", err
		}
		placeholder := params.bind(value)
		operand := column
		argument := placeholder
		if caseInsensitive {
			operand = "LOWER(" + operand + ")"
			argument = "LOWER(" + argument + ")"
		} else if isTextField(configuration, field) {
			operand = "BINARY " + operand
			argument = "BINARY " + argument
		}
		return fmt.Sprintf("LOCATE(%s, %s) > 0", argument, operand), nil
	}
}

func encodeJSONContainsOperand(configuration *config, field resolvedField, value any) (any, any, error) {
	attribute := field.attribute
	if attribute.Transform.Input != nil {
		transformed, err := attribute.Transform.Input(value)
		if err != nil {
			return nil, nil, err
		}
		value = transformed
		attribute.Transform.Input = nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, nil, fmt.Errorf("encode JSON contains operand: %w", err)
	}
	return value, string(encoded), nil
}

func buildMembership(configuration *config, field resolvedField, clause storage.Where, items []any, params *parameters) (string, error) {
	column := quoteIdentifier(field.physical)
	values := make([]string, 0, len(items))
	hasNull := false
	textComparison := isTextField(configuration, field) && isStringComparisonOperand(clause.Value)
	caseInsensitive := clause.Mode == storage.Insensitive && textComparison
	caseSensitive := clause.Mode == storage.Sensitive && textComparison
	for _, item := range items {
		if item == nil {
			hasNull = true
			continue
		}
		value, err := encodeValue(configuration, field, item)
		if err != nil {
			return "", err
		}
		placeholder := bindFieldValue(configuration, field, params, value)
		if caseInsensitive {
			placeholder = "LOWER(" + placeholder + ")"
		} else if caseSensitive {
			placeholder = "BINARY " + placeholder
		}
		values = append(values, placeholder)
	}
	operand := column
	if caseInsensitive {
		operand = "LOWER(" + column + ")"
	} else if caseSensitive {
		operand = "BINARY " + column
	}

	if clause.Operator == storage.OpIn {
		parts := make([]string, 0, 2)
		if len(values) > 0 {
			parts = append(parts, fmt.Sprintf("%s IN (%s)", operand, strings.Join(values, ", ")))
		}
		if hasNull {
			parts = append(parts, column+" IS NULL")
		}
		if len(parts) == 0 {
			return "FALSE", nil
		}
		return "(" + strings.Join(parts, " OR ") + ")", nil
	}

	parts := make([]string, 0, 2)
	if len(values) > 0 {
		parts = append(parts, fmt.Sprintf("%s NOT IN (%s)", operand, strings.Join(values, ", ")))
	}
	if hasNull {
		parts = append(parts, column+" IS NOT NULL")
	} else {
		parts = append(parts, column+" IS NULL")
	}
	if len(values) == 0 && !hasNull {
		return "TRUE", nil
	}
	joiner := " OR "
	if hasNull {
		joiner = " AND "
	}
	return "(" + strings.Join(parts, joiner) + ")", nil
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
