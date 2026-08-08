package mssql

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
	placeholder := fmt.Sprintf("@p%d", p.next)
	p.next++
	p.args = append(p.args, value)
	return placeholder
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
		return binaryCollation(column) + " = " + binaryCollation(placeholder), params.args
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

const mssqlBinaryCollation = "Latin1_General_100_BIN2"

func binaryCollation(expression string) string {
	return expression + " COLLATE " + mssqlBinaryCollation
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
			return fmt.Sprintf("%s %s %s", binaryCollation(column), operator, binaryCollation(placeholder)), nil
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
			operand = binaryCollation(operand)
			argument = binaryCollation(argument)
		}
		if clause.Operator == storage.OpStartsWith {
			return fmt.Sprintf("CHARINDEX(%s, %s) = 1", argument, operand), nil
		}
		return fmt.Sprintf("CHARINDEX(REVERSE(%s), REVERSE(%s)) = 1", argument, operand), nil
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
		document := jsonArrayDocument(column)
		if value == nil {
			return fmt.Sprintf("EXISTS (SELECT 1 FROM OPENJSON(%s) AS %s WHERE %s = 0)", document, quoteIdentifier("single_item"), qualifiedJSONColumn("single_item", "type")), nil
		}
		placeholder := params.bind(value)
		left := qualifiedJSONColumn("single_item", "value")
		if caseInsensitive {
			left = "LOWER(" + left + ")"
			placeholder = "LOWER(" + placeholder + ")"
		} else {
			left = binaryCollation(left)
			placeholder = binaryCollation(placeholder)
		}
		return fmt.Sprintf("EXISTS (SELECT 1 FROM OPENJSON(%s) AS %s WHERE %s = 1 AND %s = %s)", document, quoteIdentifier("single_item"), qualifiedJSONColumn("single_item", "type"), left, placeholder), nil
	case storage.FieldNumberArray:
		value, err := encodeArrayElement(configuration, field, clause.Value)
		if err != nil {
			return "", err
		}
		document := jsonArrayDocument(column)
		if value == nil {
			return fmt.Sprintf("EXISTS (SELECT 1 FROM OPENJSON(%s) AS %s WHERE %s = 0)", document, quoteIdentifier("single_item"), qualifiedJSONColumn("single_item", "type")), nil
		}
		placeholder := params.bind(value)
		return fmt.Sprintf("EXISTS (SELECT 1 FROM OPENJSON(%s) AS %s WHERE %s = 2 AND TRY_CONVERT(float, %s) = %s)", document, quoteIdentifier("single_item"), qualifiedJSONColumn("single_item", "type"), qualifiedJSONColumn("single_item", "value"), placeholder), nil
	case storage.FieldJSON:
		raw, encoded, err := encodeJSONContainsOperand(configuration, field, clause.Value)
		if err != nil {
			return "", err
		}
		document := jsonArrayDocument(column)
		itemAlias := quoteIdentifier("single_item")
		itemType := qualifiedJSONColumn("single_item", "type")
		itemValue := qualifiedJSONColumn("single_item", "value")
		if raw == nil {
			return fmt.Sprintf("EXISTS (SELECT 1 FROM OPENJSON(%s) AS %s WHERE %s = 0)", document, itemAlias, itemType), nil
		}
		if text, ok := raw.(string); ok {
			placeholder := params.bind(text)
			container := fmt.Sprintf("JSON_VALUE(CASE WHEN ISJSON(%s) = 1 THEN %s ELSE 'null' END, '$')", column, column)
			stringOperand := container
			stringArgument := placeholder
			arrayOperand := itemValue
			arrayArgument := placeholder
			if caseInsensitive {
				stringOperand = "LOWER(" + stringOperand + ")"
				stringArgument = "LOWER(" + stringArgument + ")"
				arrayOperand = "LOWER(" + arrayOperand + ")"
				arrayArgument = "LOWER(" + arrayArgument + ")"
			} else {
				stringOperand = binaryCollation(stringOperand)
				stringArgument = binaryCollation(stringArgument)
				arrayOperand = binaryCollation(arrayOperand)
				arrayArgument = binaryCollation(arrayArgument)
			}
			stringMatch := fmt.Sprintf("CHARINDEX(%s, %s) > 0", stringArgument, stringOperand)
			arrayMatch := fmt.Sprintf("EXISTS (SELECT 1 FROM OPENJSON(%s) AS %s WHERE %s = 1 AND %s = %s)", document, itemAlias, itemType, arrayOperand, arrayArgument)
			return fmt.Sprintf("(%s OR %s)", stringMatch, arrayMatch), nil
		}
		if numeric, ok := jsonNumericValue(raw); ok {
			placeholder := params.bind(numeric)
			return fmt.Sprintf("EXISTS (SELECT 1 FROM OPENJSON(%s) AS %s WHERE %s = 2 AND TRY_CONVERT(float, %s) = %s)", document, itemAlias, itemType, itemValue, placeholder), nil
		}
		if boolean, ok := raw.(bool); ok {
			placeholder := params.bind(strings.ToLower(fmt.Sprint(boolean)))
			return fmt.Sprintf("EXISTS (SELECT 1 FROM OPENJSON(%s) AS %s WHERE %s = 3 AND LOWER(%s) = %s)", document, itemAlias, itemType, itemValue, placeholder), nil
		}
		placeholder := params.bind(encoded)
		return fmt.Sprintf("EXISTS (SELECT 1 FROM OPENJSON(%s) AS %s WHERE %s IN (4, 5) AND %s = %s)", document, itemAlias, itemType, binaryCollation(itemValue), binaryCollation(placeholder)), nil
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
			operand = binaryCollation(operand)
			argument = binaryCollation(argument)
		}
		return fmt.Sprintf("CHARINDEX(%s, %s) > 0", argument, operand), nil
	}
}

func jsonArrayDocument(column string) string {
	return fmt.Sprintf("CASE WHEN ISJSON(%s) = 1 AND LEFT(LTRIM(%s), 1) = '[' THEN %s ELSE '[]' END", column, column, column)
}

func qualifiedJSONColumn(alias, column string) string {
	return quoteIdentifier(alias) + "." + quoteIdentifier(column)
}

func jsonNumericValue(value any) (any, bool) {
	switch typed := value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		normalized, err := normalizeNumberForDriver(typed)
		return normalized, err == nil
	default:
		return nil, false
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
			placeholder = binaryCollation(placeholder)
		}
		values = append(values, placeholder)
	}
	operand := column
	if caseInsensitive {
		operand = "LOWER(" + column + ")"
	} else if caseSensitive {
		operand = binaryCollation(column)
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
			return "1 = 0", nil
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
		return "1 = 1", nil
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
