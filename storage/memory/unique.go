package memory

import (
	"fmt"
	"reflect"

	"github.com/pers0na2dev/single-auth/storage"
)

func validateUniqueTables(schema storage.Schema, tables map[string][]storage.Record) error {
	for canonical, table := range schema.Models {
		physical := table.ModelName
		if physical == "" {
			physical = canonical
		}
		if schema.UsePlural {
			physical += "s"
		}
		model := resolvedModel{canonical: canonical, physical: physical, schema: table}
		if err := validateUniqueRows(model, tables[physical]); err != nil {
			return err
		}
	}
	return nil
}

func validateUniqueRows(model resolvedModel, rows []storage.Record) error {
	fields := map[string]struct{}{"id": {}}
	for canonical, attribute := range model.schema.Fields {
		if !attribute.Unique {
			continue
		}
		physical := attribute.FieldName
		if physical == "" {
			physical = canonical
		}
		fields[physical] = struct{}{}
	}
	for field := range fields {
		for left := 0; left < len(rows); left++ {
			leftValue, exists := rows[left][field]
			if !exists || leftValue == nil {
				continue
			}
			for right := left + 1; right < len(rows); right++ {
				rightValue, exists := rows[right][field]
				if !exists || rightValue == nil {
					continue
				}
				if reflect.DeepEqual(leftValue, rightValue) {
					return fmt.Errorf(
						"%w: %s.%s=%v",
						storage.ErrUniqueConstraint,
						model.canonical,
						field,
						leftValue,
					)
				}
			}
		}
	}
	return nil
}
