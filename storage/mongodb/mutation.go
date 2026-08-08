package mongodb

import (
	"context"
	"fmt"
	"math"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/pers0na2dev/single-auth/storage"
)

func (executor *executor) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error) {
	ctx, err := executor.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	model, err := resolveModel(executor.config, params.Model)
	if err != nil {
		return nil, err
	}
	if len(params.Where) == 0 {
		return nil, nil
	}
	mutation, err := encodeUpdate(executor.config, model, params.Update)
	if err != nil {
		return nil, err
	}
	if len(mutation.values) == 0 {
		return executor.FindOne(ctx, storage.FindOneParams{Model: params.Model, Where: params.Where})
	}
	filter, err := buildWhere(executor.config, model, params.Where)
	if err != nil {
		return nil, err
	}
	document, err := executor.database.Collection(model.physical).FindOneAndUpdate(
		ctx, filter, bson.D{{Key: "$set", Value: mutation.values}},
	)
	if noDocument(err) {
		return nil, nil
	}
	if err != nil {
		return nil, normalizeError(ctx, "update "+model.canonical, err)
	}
	return decodeDocument(executor.config, model, document, nil)
}

func (executor *executor) UpdateMany(ctx context.Context, params storage.UpdateManyParams) (int64, error) {
	ctx, err := executor.operationContext(ctx)
	if err != nil {
		return 0, err
	}
	model, err := resolveModel(executor.config, params.Model)
	if err != nil {
		return 0, err
	}
	mutation, err := encodeUpdate(executor.config, model, params.Update)
	if err != nil {
		return 0, err
	}
	if len(mutation.values) == 0 {
		return executor.Count(ctx, storage.CountParams{Model: params.Model, Where: params.Where})
	}
	filter, err := buildWhere(executor.config, model, params.Where)
	if err != nil {
		return 0, err
	}
	counts, err := executor.database.Collection(model.physical).UpdateMany(
		ctx, filter, bson.D{{Key: "$set", Value: mutation.values}},
	)
	if err != nil {
		return 0, normalizeError(ctx, "update many "+model.canonical, err)
	}
	// SQL adapters report rows matched by the update. MatchedCount also remains
	// stable when a value was already equal to its assignment.
	return counts.matched, nil
}

func (executor *executor) Delete(ctx context.Context, params storage.DeleteParams) error {
	ctx, err := executor.operationContext(ctx)
	if err != nil {
		return err
	}
	model, err := resolveModel(executor.config, params.Model)
	if err != nil {
		return err
	}
	if len(params.Where) == 0 {
		return nil
	}
	filter, err := buildWhere(executor.config, model, params.Where)
	if err != nil {
		return err
	}
	_, err = executor.database.Collection(model.physical).DeleteOne(ctx, filter)
	return normalizeError(ctx, "delete "+model.canonical, err)
}

func (executor *executor) DeleteMany(ctx context.Context, params storage.DeleteManyParams) (int64, error) {
	ctx, err := executor.operationContext(ctx)
	if err != nil {
		return 0, err
	}
	model, err := resolveModel(executor.config, params.Model)
	if err != nil {
		return 0, err
	}
	filter, err := buildWhere(executor.config, model, params.Where)
	if err != nil {
		return 0, err
	}
	count, err := executor.database.Collection(model.physical).DeleteMany(ctx, filter)
	if err != nil {
		return 0, normalizeError(ctx, "delete many "+model.canonical, err)
	}
	return count, nil
}

func (executor *executor) ConsumeOne(ctx context.Context, params storage.ConsumeOneParams) (storage.Record, error) {
	ctx, err := executor.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	model, err := resolveModel(executor.config, params.Model)
	if err != nil {
		return nil, err
	}
	filter, err := buildWhere(executor.config, model, params.Where)
	if err != nil {
		return nil, err
	}
	document, err := executor.database.Collection(model.physical).FindOneAndDelete(ctx, filter)
	if noDocument(err) {
		return nil, nil
	}
	if err != nil {
		return nil, normalizeError(ctx, "consume "+model.canonical, err)
	}
	return decodeDocument(executor.config, model, document, nil)
}

func (executor *executor) IncrementOne(ctx context.Context, params storage.IncrementOneParams) (storage.Record, error) {
	if len(params.Increment) == 0 && len(params.Set) == 0 {
		return nil, fmt.Errorf("%w: increment and set are both empty", storage.ErrInvalidIncrement)
	}
	ctx, err := executor.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	model, err := resolveModel(executor.config, params.Model)
	if err != nil {
		return nil, err
	}
	setMutation := encodedMutation{values: bson.M{}}
	if len(params.Set) > 0 {
		setMutation, err = encodeUpdate(executor.config, model, params.Set)
		if err != nil {
			return nil, err
		}
	}

	increments := make(bson.M, len(params.Increment))
	for _, name := range sortedKeys(params.Increment) {
		field, err := resolveField(executor.config, model, name)
		if err != nil {
			return nil, err
		}
		if field.attribute.Type != storage.FieldNumber {
			return nil, fmt.Errorf("%w: %s.%s is not numeric", storage.ErrInvalidIncrement, model.canonical, field.canonical)
		}
		if _, overridden := setMutation.values[field.physical]; overridden {
			continue
		}
		delta := params.Increment[name]
		if math.IsNaN(delta) || math.IsInf(delta, 0) {
			return nil, fmt.Errorf("%w: %s.%s delta is not finite", storage.ErrInvalidIncrement, model.canonical, field.canonical)
		}
		if delta == math.Trunc(delta) && delta >= math.MinInt64 && delta < float64(math.MaxInt64) {
			increments[field.physical] = int64(delta)
		} else {
			increments[field.physical] = delta
		}
	}
	if len(increments) == 0 && len(setMutation.values) == 0 {
		return nil, fmt.Errorf("%w: all assignments transformed away", storage.ErrInvalidIncrement)
	}
	filter, err := buildWhere(executor.config, model, params.Where)
	if err != nil {
		return nil, err
	}
	update := make(bson.D, 0, 2)
	if len(increments) > 0 {
		update = append(update, bson.E{Key: "$inc", Value: increments})
	}
	if len(setMutation.values) > 0 {
		update = append(update, bson.E{Key: "$set", Value: setMutation.values})
	}
	document, err := executor.database.Collection(model.physical).FindOneAndUpdate(ctx, filter, update)
	if noDocument(err) {
		return nil, nil
	}
	if err != nil {
		return nil, normalizeError(ctx, "increment "+model.canonical, err)
	}
	return decodeDocument(executor.config, model, document, nil)
}
