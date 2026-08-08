package mongodb

import (
	"context"
	"fmt"
	"sort"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/pers0na2dev/single-auth/storage"
)

type joinPlan struct {
	model  resolvedModel
	config storage.JoinConfig
}

func (executor *executor) prepareJoins(base resolvedModel, requested map[string]storage.JoinOption, selectFields *[]string) ([]joinPlan, error) {
	if len(requested) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(requested))
	for name := range requested {
		names = append(names, name)
	}
	sort.Strings(names)
	plans := make([]joinPlan, 0, len(names))
	for _, name := range names {
		joined, err := resolveModel(executor.config, name)
		if err != nil {
			return nil, err
		}
		plan, required, err := executor.deriveJoin(base, joined, requested[name])
		if err != nil {
			return nil, err
		}
		if len(*selectFields) > 0 && !containsString(*selectFields, required) {
			*selectFields = append(*selectFields, required)
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

func (executor *executor) deriveJoin(base, joined resolvedModel, option storage.JoinOption) (joinPlan, string, error) {
	type foreignKey struct {
		canonical string
		attribute storage.FieldAttribute
	}
	forward := make([]foreignKey, 0, 1)
	for canonical, attribute := range joined.schema.Fields {
		if attribute.References == nil {
			continue
		}
		_, target, err := executor.config.schema.ResolveModel(attribute.References.Model)
		if err != nil {
			return joinPlan{}, "", err
		}
		if target == base.canonical {
			forward = append(forward, foreignKey{canonical: canonical, attribute: attribute})
		}
	}
	if len(forward) > 1 {
		return joinPlan{}, "", fmt.Errorf("%w: multiple foreign keys between %q and %q", storage.ErrInvalidQuery, base.canonical, joined.canonical)
	}
	isForward := len(forward) == 1
	keys := forward
	if !isForward {
		for canonical, attribute := range base.schema.Fields {
			if attribute.References == nil {
				continue
			}
			_, target, err := executor.config.schema.ResolveModel(attribute.References.Model)
			if err != nil {
				return joinPlan{}, "", err
			}
			if target == joined.canonical {
				keys = append(keys, foreignKey{canonical: canonical, attribute: attribute})
			}
		}
	}
	if len(keys) == 0 {
		return joinPlan{}, "", fmt.Errorf("%w: no foreign key between %q and %q", storage.ErrInvalidQuery, base.canonical, joined.canonical)
	}
	if len(keys) > 1 {
		return joinPlan{}, "", fmt.Errorf("%w: multiple foreign keys between %q and %q", storage.ErrInvalidQuery, base.canonical, joined.canonical)
	}

	key := keys[0]
	var fromField, toField resolvedField
	var required string
	var err error
	if isForward {
		required = key.attribute.References.Field
		fromField, err = resolveField(executor.config, base, required)
		if err == nil {
			toField, err = resolveField(executor.config, joined, key.canonical)
		}
	} else {
		required = key.canonical
		fromField, err = resolveField(executor.config, base, key.canonical)
		if err == nil {
			toField, err = resolveField(executor.config, joined, key.attribute.References.Field)
		}
	}
	if err != nil {
		return joinPlan{}, "", err
	}
	unique := toField.canonical == "id" || key.attribute.Unique
	limit := executor.config.defaultLimit
	relation := storage.OneToMany
	if unique {
		limit = 1
		relation = storage.OneToOne
	} else if option.Limit != nil {
		if *option.Limit < 0 {
			return joinPlan{}, "", fmt.Errorf("%w: join limit must be non-negative", storage.ErrInvalidQuery)
		}
		limit = *option.Limit
	}
	return joinPlan{model: joined, config: storage.JoinConfig{
		From: fromField.physical, To: toField.physical, Limit: limit, Relation: relation,
	}}, required, nil
}

func (executor *executor) joinDocument(ctx context.Context, base bson.M, plan joinPlan) (any, error) {
	if plan.config.Relation != storage.OneToOne && plan.config.Limit == 0 {
		return []storage.Record{}, nil
	}
	value, exists := base[plan.config.From]
	if !exists {
		if plan.config.Relation == storage.OneToOne {
			return nil, nil
		}
		return []storage.Record{}, nil
	}
	filter := bson.D{{Key: plan.config.To, Value: value}}
	documents, err := executor.database.Collection(plan.model.physical).Find(ctx, filter, findOptions{
		hasLimit: true,
		limit:    int64(plan.config.Limit),
	})
	if err != nil {
		return nil, normalizeError(ctx, "join "+plan.model.canonical, err)
	}
	if plan.config.Relation == storage.OneToOne {
		if len(documents) == 0 {
			return nil, nil
		}
		return decodeDocument(executor.config, plan.model, documents[0], nil)
	}
	result := make([]storage.Record, 0, len(documents))
	for _, document := range documents {
		decoded, err := decodeDocument(executor.config, plan.model, document, nil)
		if err != nil {
			return nil, err
		}
		result = append(result, decoded)
	}
	return result, nil
}
