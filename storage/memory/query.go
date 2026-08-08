package memory

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

func matches(record storage.Record, where []storage.Where) (bool, error) {
	if len(where) == 0 {
		return true, nil
	}
	result, err := evaluate(record, where[0])
	if err != nil {
		return false, err
	}
	// reference implementation evaluates the flat predicate list from left to right. The
	// first clause is intentionally visited again; combining a value with itself
	// is harmless and preserves its exact implementation semantics.
	for _, clause := range where {
		clauseResult, err := evaluate(record, clause)
		if err != nil {
			return false, err
		}
		if clause.Connector == storage.Or {
			result = result || clauseResult
		} else {
			result = result && clauseResult
		}
	}
	return result, nil
}

func evaluate(record storage.Record, clause storage.Where) (bool, error) {
	actual, exists := record[clause.Field]
	expected := clause.Value
	insensitive := clause.Mode == storage.Insensitive && isStringOperand(expected)

	switch clause.Operator {
	case storage.OpEq:
		// reference implementation's memory adapter treats absent and null as equivalent only
		// for eq null, matching SQL IS NULL and Mongo missing-or-null behavior.
		if expected == nil {
			return !exists || actual == nil, nil
		}
		return equalValues(actual, expected, insensitive), nil
	case storage.OpNe:
		if expected == nil {
			return exists && actual != nil, nil
		}
		return !equalValues(actual, expected, insensitive), nil
	case storage.OpIn, storage.OpNotIn:
		items, err := sliceValues(expected)
		if err != nil {
			return false, err
		}
		contained := false
		for _, item := range items {
			if equalValues(actual, item, insensitive) {
				contained = true
				break
			}
		}
		if clause.Operator == storage.OpNotIn {
			return !contained, nil
		}
		return contained, nil
	case storage.OpContains:
		return contains(actual, expected, insensitive), nil
	case storage.OpStartsWith:
		actualString, actualOK := actual.(string)
		expectedString, expectedOK := expected.(string)
		if !actualOK || !expectedOK {
			return false, nil
		}
		if insensitive {
			actualString, expectedString = strings.ToLower(actualString), strings.ToLower(expectedString)
		}
		return strings.HasPrefix(actualString, expectedString), nil
	case storage.OpEndsWith:
		actualString, actualOK := actual.(string)
		expectedString, expectedOK := expected.(string)
		if !actualOK || !expectedOK {
			return false, nil
		}
		if insensitive {
			actualString, expectedString = strings.ToLower(actualString), strings.ToLower(expectedString)
		}
		return strings.HasSuffix(actualString, expectedString), nil
	case storage.OpLt, storage.OpLTE, storage.OpGt, storage.OpGTE:
		comparison, comparable := compareValues(actual, expected)
		if !comparable {
			return false, nil
		}
		switch clause.Operator {
		case storage.OpLt:
			return comparison < 0, nil
		case storage.OpLTE:
			return comparison <= 0, nil
		case storage.OpGt:
			return comparison > 0, nil
		default:
			return comparison >= 0, nil
		}
	default:
		return false, fmt.Errorf("%w: unsupported operator %q", storage.ErrInvalidQuery, clause.Operator)
	}
}

func filterRows(rows []storage.Record, where []storage.Where) ([]int, error) {
	indexes := make([]int, 0, len(rows))
	for index, row := range rows {
		matched, err := matches(row, where)
		if err != nil {
			return nil, err
		}
		if matched {
			indexes = append(indexes, index)
		}
	}
	return indexes, nil
}

func sortRows(rows []storage.Record, sortBy *storage.Sort) {
	if sortBy == nil {
		return
	}
	sort.SliceStable(rows, func(left, right int) bool {
		comparison := sortComparison(rows[left][sortBy.Field], rows[right][sortBy.Field])
		if sortBy.Direction == storage.Descending {
			return comparison > 0
		}
		return comparison < 0
	})
}

func sortComparison(left, right any) int {
	if left == nil && right == nil {
		return 0
	}
	if left == nil {
		return -1
	}
	if right == nil {
		return 1
	}
	if comparison, ok := compareValues(left, right); ok {
		return comparison
	}
	return strings.Compare(fmt.Sprint(left), fmt.Sprint(right))
}

func equalValues(left, right any, insensitive bool) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	if insensitive {
		leftString, leftOK := left.(string)
		rightString, rightOK := right.(string)
		if leftOK && rightOK {
			return strings.EqualFold(leftString, rightString)
		}
	}
	if leftTime, ok := left.(time.Time); ok {
		if rightTime, ok := right.(time.Time); ok {
			return leftTime.Equal(rightTime)
		}
	}
	if leftNumber, ok := numericValue(left); ok {
		if rightNumber, ok := numericValue(right); ok {
			return leftNumber == rightNumber
		}
		if rightString, ok := right.(string); ok {
			rightNumber, err := strconv.ParseFloat(rightString, 64)
			return err == nil && leftNumber == rightNumber
		}
	}
	if rightNumber, ok := numericValue(right); ok {
		if leftString, ok := left.(string); ok {
			leftNumber, err := strconv.ParseFloat(leftString, 64)
			return err == nil && leftNumber == rightNumber
		}
	}
	return reflect.DeepEqual(left, right)
}

func compareValues(left, right any) (int, bool) {
	if left == nil || right == nil {
		return 0, false
	}
	if leftTime, ok := left.(time.Time); ok {
		if rightTime, ok := right.(time.Time); ok {
			switch {
			case leftTime.Before(rightTime):
				return -1, true
			case leftTime.After(rightTime):
				return 1, true
			default:
				return 0, true
			}
		}
	}
	if leftNumber, ok := numericValue(left); ok {
		if rightNumber, ok := numericValue(right); ok {
			switch {
			case leftNumber < rightNumber:
				return -1, true
			case leftNumber > rightNumber:
				return 1, true
			default:
				return 0, true
			}
		}
	}
	leftString, leftOK := left.(string)
	rightString, rightOK := right.(string)
	if leftOK && rightOK {
		return strings.Compare(leftString, rightString), true
	}
	leftBool, leftOK := left.(bool)
	rightBool, rightOK := right.(bool)
	if leftOK && rightOK {
		switch {
		case leftBool == rightBool:
			return 0, true
		case !leftBool && rightBool:
			return -1, true
		default:
			return 1, true
		}
	}
	return 0, false
}

func numericValue(value any) (float64, bool) {
	switch number := value.(type) {
	case int:
		return float64(number), true
	case int8:
		return float64(number), true
	case int16:
		return float64(number), true
	case int32:
		return float64(number), true
	case int64:
		return float64(number), true
	case uint:
		return float64(number), true
	case uint8:
		return float64(number), true
	case uint16:
		return float64(number), true
	case uint32:
		return float64(number), true
	case uint64:
		return float64(number), true
	case float32:
		return float64(number), true
	case float64:
		return number, true
	default:
		return 0, false
	}
}

func contains(container, expected any, insensitive bool) bool {
	if actualString, ok := container.(string); ok {
		expectedString, ok := expected.(string)
		if !ok {
			return false
		}
		if insensitive {
			actualString, expectedString = strings.ToLower(actualString), strings.ToLower(expectedString)
		}
		return strings.Contains(actualString, expectedString)
	}
	items, err := sliceValues(container)
	if err != nil {
		return false
	}
	for _, item := range items {
		if equalValues(item, expected, insensitive) {
			return true
		}
	}
	return false
}

func isStringOperand(value any) bool {
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
