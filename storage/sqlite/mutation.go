package sqlite

import (
	"context"
	"fmt"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

func (e *executor) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	model, err := resolveModel(e.config, params.Model)
	if err != nil {
		return nil, err
	}
	where, args, err := buildWhere(e.config, model, params.Where)
	if err != nil {
		return nil, err
	}
	if where == "" {
		return nil, nil
	}
	mutation, err := encodeUpdate(e.config, model, params.Update)
	if err != nil {
		return nil, err
	}
	if len(mutation.values) == 0 {
		return e.FindOne(ctx, storage.FindOneParams{Model: params.Model, Where: params.Where})
	}
	assignments, updateArgs, err := mutationAssignments(e.config, model, mutation)
	if err != nil {
		return nil, err
	}
	fields := modelFields(model)
	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s RETURNING %s",
		quoteIdentifier(model.physical),
		strings.Join(assignments, ", "),
		where,
		projection(fields),
	)
	updateArgs = append(updateArgs, args...)
	records, err := e.queryRecords(ctx, query, updateArgs, fields, "update "+model.canonical)
	if err != nil {
		return nil, err
	}
	return firstRecord(records), nil
}

func (e *executor) UpdateMany(ctx context.Context, params storage.UpdateManyParams) (int64, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	model, err := resolveModel(e.config, params.Model)
	if err != nil {
		return 0, err
	}
	where, whereArgs, err := buildWhere(e.config, model, params.Where)
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
	assignments, args, err := mutationAssignments(e.config, model, mutation)
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

func mutationAssignments(configuration *config, model resolvedModel, mutation encodedMutation) ([]string, []any, error) {
	assignments := make([]string, 0, len(mutation.values)*2)
	args := make([]any, 0, len(mutation.values))
	for _, physical := range sortedKeys(mutation.values) {
		field, err := resolvePhysicalField(model, physical)
		if err != nil {
			return nil, nil, err
		}
		assignments = append(assignments, quoteIdentifier(physical)+" = ?")
		args = append(args, mutation.values[physical])
		if field.canonical != "id" && mutation.present[physical] {
			assignments = append(assignments, quoteIdentifier(presenceColumn(field))+" = 1")
		}
	}
	return assignments, args, nil
}

func (e *executor) Delete(ctx context.Context, params storage.DeleteParams) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	model, err := resolveModel(e.config, params.Model)
	if err != nil {
		return err
	}
	where, args, err := buildWhere(e.config, model, params.Where)
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
	where, args, err := buildWhere(e.config, model, params.Where)
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

func (e *executor) ConsumeOne(ctx context.Context, params storage.ConsumeOneParams) (storage.Record, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	model, err := resolveModel(e.config, params.Model)
	if err != nil {
		return nil, err
	}
	where, args, err := buildWhere(e.config, model, params.Where)
	if err != nil {
		return nil, err
	}
	subquery := fmt.Sprintf("SELECT %s FROM %s", quoteIdentifier("id"), quoteIdentifier(model.physical))
	if where != "" {
		subquery += " WHERE " + where
	}
	subquery += " LIMIT 1"
	fields := modelFields(model)
	query := fmt.Sprintf(
		"DELETE FROM %s WHERE %s = (%s) RETURNING %s",
		quoteIdentifier(model.physical),
		quoteIdentifier("id"),
		subquery,
		projection(fields),
	)
	record, err := scanRecord(e.config, e.runner.QueryRowContext(ctx, query, args...), fields)
	if noRow(err) {
		return nil, nil
	}
	if err != nil {
		return nil, normalizeError(ctx, "consume "+model.canonical, err)
	}
	return record.decoded, nil
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
	where, whereArgs, err := buildWhere(e.config, model, params.Where)
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
	assignments := make([]string, 0, len(params.Increment)*2+len(setMutation.values)*2)
	args := make([]any, 0, len(params.Increment)+len(setMutation.values)+len(whereArgs))
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
		assignments = append(assignments, fmt.Sprintf("%s = COALESCE(%s, 0) + ?", quoteIdentifier(field.physical), quoteIdentifier(field.physical)))
		args = append(args, params.Increment[name])
		assignments = append(assignments, quoteIdentifier(presenceColumn(field))+" = 1")
	}
	setAssignments, setArgs, err := mutationAssignments(e.config, model, setMutation)
	if err != nil {
		return nil, err
	}
	assignments = append(assignments, setAssignments...)
	args = append(args, setArgs...)
	if len(assignments) == 0 {
		return nil, fmt.Errorf("%w: all assignments transformed away", storage.ErrInvalidIncrement)
	}

	subquery := fmt.Sprintf("SELECT %s FROM %s", quoteIdentifier("id"), quoteIdentifier(model.physical))
	if where != "" {
		subquery += " WHERE " + where
	}
	subquery += " LIMIT 1"
	fields := modelFields(model)
	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE %s = (%s) RETURNING %s",
		quoteIdentifier(model.physical),
		strings.Join(assignments, ", "),
		quoteIdentifier("id"),
		subquery,
		projection(fields),
	)
	args = append(args, whereArgs...)
	record, err := scanRecord(e.config, e.runner.QueryRowContext(ctx, query, args...), fields)
	if noRow(err) {
		return nil, nil
	}
	if err != nil {
		return nil, normalizeError(ctx, "increment "+model.canonical, err)
	}
	return record.decoded, nil
}
