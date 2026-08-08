package mysql

import (
	"context"
	"fmt"
	"sort"

	"github.com/pers0na2dev/single-auth/storage"
)

type joinPlan struct {
	model  resolvedModel
	config storage.JoinConfig
}

func (e *executor) prepareJoins(base resolvedModel, requested map[string]storage.JoinOption, selectFields *[]string) ([]joinPlan, error) {
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
		joined, err := resolveModel(e.config, name)
		if err != nil {
			return nil, err
		}
		plan, required, err := e.deriveJoin(base, joined, requested[name])
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

func (e *executor) deriveJoin(base, joined resolvedModel, option storage.JoinOption) (joinPlan, string, error) {
	type foreignKey struct {
		canonical string
		attribute storage.FieldAttribute
	}
	forward := make([]foreignKey, 0, 1)
	for canonical, attribute := range joined.schema.Fields {
		if attribute.References == nil {
			continue
		}
		_, target, err := e.config.schema.ResolveModel(attribute.References.Model)
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
			_, target, err := e.config.schema.ResolveModel(attribute.References.Model)
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
		fromField, err = resolveField(e.config, base, required)
		if err == nil {
			toField, err = resolveField(e.config, joined, key.canonical)
		}
	} else {
		required = key.canonical
		fromField, err = resolveField(e.config, base, key.canonical)
		if err == nil {
			toField, err = resolveField(e.config, joined, key.attribute.References.Field)
		}
	}
	if err != nil {
		return joinPlan{}, "", err
	}
	unique := toField.canonical == "id" || key.attribute.Unique
	limit := e.config.defaultLimit
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

func (e *executor) joinRecord(ctx context.Context, base map[string]any, plan joinPlan) (any, error) {
	if plan.config.Relation != storage.OneToOne && plan.config.Limit == 0 {
		return []storage.Record{}, nil
	}
	toField, err := resolvePhysicalField(plan.model, plan.config.To)
	if err != nil {
		return nil, err
	}
	predicate, args := buildRawEqualityWithConfig(e.config, toField, base[plan.config.From], 1)
	fields := modelFields(plan.model)
	query := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s LIMIT ?",
		projection(fields), quoteIdentifier(plan.model.physical), predicate,
	)
	args = append(args, plan.config.Limit)
	rows, err := e.queryRecords(ctx, query, args, fields, "join "+plan.model.canonical)
	if err != nil {
		return nil, err
	}
	if plan.config.Relation == storage.OneToOne {
		if len(rows) == 0 {
			return nil, nil
		}
		return rows[0].decoded, nil
	}
	result := make([]storage.Record, 0, len(rows))
	for _, row := range rows {
		result = append(result, row.decoded)
	}
	return result, nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
