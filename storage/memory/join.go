package memory

import (
	"fmt"

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
	plans := make([]joinPlan, 0, len(requested))
	for joinedName, option := range requested {
		joined, err := e.resolveModel(joinedName)
		if err != nil {
			return nil, err
		}
		plan, requiredSelect, err := e.deriveJoin(base, joined, option)
		if err != nil {
			return nil, err
		}
		if len(*selectFields) > 0 && !containsString(*selectFields, requiredSelect) {
			*selectFields = append(*selectFields, requiredSelect)
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
	var requiredSelect string
	var err error
	if isForward {
		requiredSelect = key.attribute.References.Field
		fromField, err = e.resolveField(base, requiredSelect)
		if err != nil {
			return joinPlan{}, "", err
		}
		toField, err = e.resolveField(joined, key.canonical)
		if err != nil {
			return joinPlan{}, "", err
		}
	} else {
		requiredSelect = key.canonical
		fromField, err = e.resolveField(base, key.canonical)
		if err != nil {
			return joinPlan{}, "", err
		}
		toField, err = e.resolveField(joined, key.attribute.References.Field)
		if err != nil {
			return joinPlan{}, "", err
		}
	}

	unique := toField.canonical == "id" || key.attribute.Unique
	limit := e.config.defaultLimit
	if unique {
		limit = 1
	} else if option.Limit != nil {
		if *option.Limit < 0 {
			return joinPlan{}, "", fmt.Errorf("%w: join limit must be non-negative", storage.ErrInvalidQuery)
		}
		limit = *option.Limit
	}
	relation := storage.OneToMany
	if unique {
		relation = storage.OneToOne
	}
	return joinPlan{
		model: joined,
		config: storage.JoinConfig{
			From:     fromField.physical,
			To:       toField.physical,
			Limit:    limit,
			Relation: relation,
		},
	}, requiredSelect, nil
}

func (e *executor) joinRecords(snapshot map[string][]storage.Record, base storage.Record, plan joinPlan) (any, error) {
	rows, exists := snapshot[plan.model.physical]
	if !exists {
		return nil, fmt.Errorf("%w: %q", storage.ErrModelNotFound, plan.model.physical)
	}
	matching := make([]storage.Record, 0)
	if plan.config.Relation != storage.OneToOne && plan.config.Limit == 0 {
		return matching, nil
	}
	for _, row := range rows {
		if equalValues(row[plan.config.To], base[plan.config.From], false) {
			decoded, err := e.decodeRecord(plan.model, row, nil)
			if err != nil {
				return nil, err
			}
			matching = append(matching, decoded)
			if len(matching) >= plan.config.Limit {
				break
			}
		}
	}
	if plan.config.Relation == storage.OneToOne {
		if len(matching) == 0 {
			return nil, nil
		}
		return matching[0], nil
	}
	return matching, nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
