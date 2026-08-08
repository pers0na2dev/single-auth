package mysql

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

func (a *Adapter) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error) {
	return a.recordTransaction(ctx, "update", func(transaction *executor) (storage.Record, error) {
		return transaction.Update(ctx, params)
	})
}

// Update locks the first matching row before updating. This preserves the row
// to return even when the mutation changes a predicate field, while the UPDATE
// itself intentionally affects every match like reference implementation's adapter contract.
func (e *executor) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	model, err := resolveModel(e.config, params.Model)
	if err != nil {
		return nil, err
	}
	if len(params.Where) == 0 {
		return nil, nil
	}
	target, err := e.lockFirst(ctx, model, params.Where, modelFields(model)[:1], "lock update "+model.canonical)
	if err != nil || target == nil {
		return nil, err
	}
	mutation, err := encodeUpdate(e.config, model, params.Update)
	if err != nil {
		return nil, err
	}
	if len(mutation.values) == 0 {
		row, selectErr := e.selectByID(ctx, model, target.raw["id"], modelFields(model), false, "read update "+model.canonical)
		if selectErr != nil || row == nil {
			return nil, selectErr
		}
		return row.decoded, nil
	}
	assignments, args, err := mutationAssignments(e.config, model, mutation, 1)
	if err != nil {
		return nil, err
	}
	where, whereArgs, err := buildWhere(e.config, model, params.Where, len(args)+1)
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf("UPDATE %s SET %s WHERE %s", quoteIdentifier(model.physical), strings.Join(assignments, ", "), where)
	args = append(args, whereArgs...)
	_, err = e.runner.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, normalizeError(ctx, "update "+model.canonical, err)
	}
	// MySQL drivers commonly expose VARCHAR columns as []byte. Re-encoding that
	// raw value with fmt.Sprint would turn "u1" into "[117 49]", so all public
	// ID round-trips must start from the canonical decoded value.
	returnID := target.decoded["id"]
	if updatedID, exists := mutation.values["id"]; exists {
		returnID = updatedID
	}
	row, err := e.selectByID(ctx, model, returnID, modelFields(model), false, "read update "+model.canonical)
	if err != nil || row == nil {
		return nil, err
	}
	return row.decoded, nil
}

func (e *executor) UpdateMany(ctx context.Context, params storage.UpdateManyParams) (int64, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	model, err := resolveModel(e.config, params.Model)
	if err != nil {
		return 0, err
	}
	mutation, err := encodeUpdate(e.config, model, params.Update)
	if err != nil {
		return 0, err
	}
	if len(mutation.values) == 0 {
		return e.Count(ctx, storage.CountParams{Model: params.Model, Where: params.Where})
	}
	assignments, args, err := mutationAssignments(e.config, model, mutation, 1)
	if err != nil {
		return 0, err
	}
	where, whereArgs, err := buildWhere(e.config, model, params.Where, len(args)+1)
	if err != nil {
		return 0, err
	}
	query := fmt.Sprintf("UPDATE %s SET %s", quoteIdentifier(model.physical), strings.Join(assignments, ", "))
	if where != "" {
		query += " WHERE " + where
	}
	args = append(args, whereArgs...)
	result, err := e.runner.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, normalizeError(ctx, "update many "+model.canonical, err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, normalizeError(ctx, "update many rows affected", err)
	}
	return count, nil
}

func mutationAssignments(configuration *config, model resolvedModel, mutation encodedMutation, start int) ([]string, []any, error) {
	assignments := make([]string, 0, len(mutation.values)*2)
	params := newParameters(start)
	for _, physical := range sortedKeys(mutation.values) {
		field, err := resolvePhysicalField(model, physical)
		if err != nil {
			return nil, nil, err
		}
		assignments = append(assignments, quoteIdentifier(physical)+" = "+bindFieldValue(configuration, field, params, mutation.values[physical]))
		if field.canonical != "id" && mutation.present[physical] {
			assignments = append(assignments, quoteIdentifier(presenceColumn(field))+" = TRUE")
		}
	}
	return assignments, params.args, nil
}

func (e *executor) Delete(ctx context.Context, params storage.DeleteParams) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	model, err := resolveModel(e.config, params.Model)
	if err != nil {
		return err
	}
	where, args, err := buildWhere(e.config, model, params.Where, 1)
	if err != nil {
		return err
	}
	if where == "" {
		return nil
	}
	_, err = e.runner.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE %s", quoteIdentifier(model.physical), where), args...)
	return normalizeError(ctx, "delete "+model.canonical, err)
}

func (e *executor) DeleteMany(ctx context.Context, params storage.DeleteManyParams) (int64, error) {
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
	query := "DELETE FROM " + quoteIdentifier(model.physical)
	if where != "" {
		query += " WHERE " + where
	}
	result, err := e.runner.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, normalizeError(ctx, "delete many "+model.canonical, err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, normalizeError(ctx, "delete many rows affected", err)
	}
	return count, nil
}

func (a *Adapter) ConsumeOne(ctx context.Context, params storage.ConsumeOneParams) (storage.Record, error) {
	return a.recordTransaction(ctx, "consume", func(transaction *executor) (storage.Record, error) {
		return transaction.ConsumeOne(ctx, params)
	})
}

func (e *executor) ConsumeOne(ctx context.Context, params storage.ConsumeOneParams) (storage.Record, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	model, err := resolveModel(e.config, params.Model)
	if err != nil {
		return nil, err
	}
	fields := modelFields(model)
	target, err := e.lockFirst(ctx, model, params.Where, fields, "lock consume "+model.canonical)
	if err != nil || target == nil {
		return nil, err
	}
	idField := fields[0]
	predicate, args := buildRawEqualityWithConfig(e.config, idField, target.raw["id"], 1)
	result, err := e.runner.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE %s", quoteIdentifier(model.physical), predicate), args...)
	if err != nil {
		return nil, normalizeError(ctx, "consume "+model.canonical, err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return nil, normalizeError(ctx, "consume rows affected", err)
	}
	if deleted == 0 {
		return nil, nil
	}
	return target.decoded, nil
}

func (a *Adapter) IncrementOne(ctx context.Context, params storage.IncrementOneParams) (storage.Record, error) {
	return a.recordTransaction(ctx, "increment", func(transaction *executor) (storage.Record, error) {
		return transaction.IncrementOne(ctx, params)
	})
}

func (e *executor) IncrementOne(ctx context.Context, params storage.IncrementOneParams) (storage.Record, error) {
	if len(params.Increment) == 0 && len(params.Set) == 0 {
		return nil, fmt.Errorf("%w: increment and set are both empty", storage.ErrInvalidIncrement)
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	model, err := resolveModel(e.config, params.Model)
	if err != nil {
		return nil, err
	}
	setMutation := encodedMutation{values: map[string]any{}, present: map[string]bool{}}
	if len(params.Set) > 0 {
		setMutation, err = encodeUpdate(e.config, model, params.Set)
		if err != nil {
			return nil, err
		}
	}
	target, err := e.lockFirst(ctx, model, params.Where, modelFields(model)[:1], "lock increment "+model.canonical)
	if err != nil || target == nil {
		return nil, err
	}

	assignments := make([]string, 0, len(params.Increment)*2+len(setMutation.values)*2)
	bind := newParameters(1)
	for _, name := range sortedKeys(params.Increment) {
		field, fieldErr := resolveField(e.config, model, name)
		if fieldErr != nil {
			return nil, fieldErr
		}
		if field.attribute.Type != storage.FieldNumber {
			return nil, fmt.Errorf("%w: %s.%s is not numeric", storage.ErrInvalidIncrement, model.canonical, field.canonical)
		}
		if _, overridden := setMutation.values[field.physical]; overridden {
			continue
		}
		delta := params.Increment[name]
		if math.IsNaN(delta) || math.IsInf(delta, 0) || delta != math.Trunc(delta) {
			return nil, fmt.Errorf("%w: %s.%s INTEGER delta must be integral", storage.ErrInvalidIncrement, model.canonical, field.canonical)
		}
		if field.attribute.BigInt {
			if delta < math.MinInt64 || delta >= float64(math.MaxInt64) {
				return nil, fmt.Errorf("%w: %s.%s BIGINT delta is out of range", storage.ErrInvalidIncrement, model.canonical, field.canonical)
			}
		} else if delta < math.MinInt32 || delta > math.MaxInt32 {
			return nil, fmt.Errorf("%w: %s.%s INTEGER delta is out of range", storage.ErrInvalidIncrement, model.canonical, field.canonical)
		}
		argument := int64(delta)
		placeholder := bind.bind(argument)
		column := quoteIdentifier(field.physical)
		assignments = append(assignments, fmt.Sprintf("%s = COALESCE(%s, 0) + %s", column, column, placeholder))
		assignments = append(assignments, quoteIdentifier(presenceColumn(field))+" = TRUE")
	}
	setAssignments, setArgs, err := mutationAssignments(e.config, model, setMutation, bind.next)
	if err != nil {
		return nil, err
	}
	assignments = append(assignments, setAssignments...)
	bind.args = append(bind.args, setArgs...)
	bind.next += len(setArgs)
	if len(assignments) == 0 {
		return nil, fmt.Errorf("%w: all assignments transformed away", storage.ErrInvalidIncrement)
	}

	idField := modelFields(model)[0]
	encodedID, err := encodeValue(e.config, idField, target.decoded["id"])
	if err != nil {
		return nil, err
	}
	predicate, idArgs := buildRawEqualityWithConfig(e.config, idField, encodedID, bind.next)
	query := fmt.Sprintf("UPDATE %s SET %s WHERE %s", quoteIdentifier(model.physical), strings.Join(assignments, ", "), predicate)
	bind.args = append(bind.args, idArgs...)
	_, err = e.runner.ExecContext(ctx, query, bind.args...)
	if err != nil {
		return nil, normalizeError(ctx, "increment "+model.canonical, err)
	}
	returnID := target.decoded["id"]
	if updatedID, exists := setMutation.values["id"]; exists {
		returnID = updatedID
	}
	record, err := e.selectByID(ctx, model, returnID, modelFields(model), false, "read increment "+model.canonical)
	if err != nil || record == nil {
		return nil, err
	}
	return record.decoded, nil
}

func (e *executor) lockFirst(ctx context.Context, model resolvedModel, whereClauses []storage.Where, fields []resolvedField, operation string) (*scannedRecord, error) {
	where, args, err := buildWhere(e.config, model, whereClauses, 1)
	if err != nil {
		return nil, err
	}
	query := fmt.Sprintf("SELECT %s FROM %s", projection(fields), quoteIdentifier(model.physical))
	if where != "" {
		query += " WHERE " + where
	}
	query += " LIMIT 1 FOR UPDATE"
	record, err := scanRecord(e.config, e.runner.QueryRowContext(ctx, query, args...), fields)
	if noRow(err) {
		return nil, nil
	}
	if err != nil {
		return nil, normalizeError(ctx, operation, err)
	}
	return &record, nil
}
