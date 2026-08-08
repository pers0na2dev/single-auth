package sqlite

import (
	"context"
	"fmt"
	"sort"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/migration"
)

func (a *Adapter) reconciliationPlan(ctx context.Context) (SchemaPlan, error) {
	catalog, err := migration.Inspect(ctx, a.db, migration.SQLite)
	if err != nil {
		return SchemaPlan{}, err
	}
	diff, err := migration.Build(a.config.schema, catalog, migration.Options{Dialect: migration.SQLite})
	if err != nil {
		return SchemaPlan{}, err
	}

	missingTables := migrationTableSet(diff.ToBeCreated)
	missingFields := migrationFieldSet(diff.ToBeAdded)
	existing := migrationSQLiteTables(catalog)
	createSchema := a.config.schema.Clone()
	hasCreates := false
	for canonical, raw := range createSchema.Models {
		model, err := resolveModel(a.config, canonical)
		if err != nil {
			return SchemaPlan{}, err
		}
		if !missingTables[model.physical] {
			raw.DisableMigrations = true
		} else {
			hasCreates = true
		}
		createSchema.Models[canonical] = raw
	}

	columnStatements := make([]string, 0)
	postStatements := make([]string, 0)
	for _, canonical := range sortedSchemaModelNames(a.config.schema) {
		raw := a.config.schema.Models[canonical]
		if raw.DisableMigrations {
			continue
		}
		model, err := resolveModel(a.config, canonical)
		if err != nil {
			return SchemaPlan{}, err
		}
		if missingTables[model.physical] {
			continue
		}
		columns := existing[model.physical]
		for _, field := range modelFields(model)[1:] {
			dataMissing := missingFields[model.physical][field.canonical]
			_, presenceExists := columns[presenceColumn(field)]
			if dataMissing {
				definition, err := columnDefinition(a.config, model, field)
				if err != nil {
					return SchemaPlan{}, err
				}
				columnStatements = append(columnStatements, fmt.Sprintf(
					"ALTER TABLE %s ADD COLUMN %s",
					quoteIdentifier(model.physical),
					definition,
				))
			}
			if !presenceExists {
				presence := quoteIdentifier(presenceColumn(field))
				columnStatements = append(columnStatements, fmt.Sprintf(
					"ALTER TABLE %s ADD COLUMN %s INTEGER NOT NULL DEFAULT 0 CHECK (%s IN (0, 1))",
					quoteIdentifier(model.physical),
					presence,
					presence,
				))
			}
			if dataMissing && (field.attribute.Index || field.attribute.Unique) {
				kind := "INDEX"
				if field.attribute.Unique {
					kind = "UNIQUE INDEX"
				}
				postStatements = append(postStatements, fmt.Sprintf(
					"CREATE %s IF NOT EXISTS %s ON %s (%s)",
					kind,
					quoteIdentifier("single_"+model.physical+"_"+field.physical),
					quoteIdentifier(model.physical),
					quoteIdentifier(field.physical),
				))
			}
		}
	}

	statements := append([]string(nil), columnStatements...)
	if hasCreates {
		createPlan, err := PlanSchema(createSchema)
		if err != nil {
			return SchemaPlan{}, err
		}
		statements = append(statements, createPlan.Statements...)
	}
	statements = append(statements, postStatements...)
	return SchemaPlan{Statements: statements}, nil
}

func migrationSQLiteTables(catalog migration.Catalog) map[string]map[string]struct{} {
	tables := make(map[string]map[string]struct{}, len(catalog.Tables))
	for _, table := range catalog.Tables {
		columns := make(map[string]struct{}, len(table.Columns))
		for _, column := range table.Columns {
			columns[column.Name] = struct{}{}
		}
		tables[table.Name] = columns
	}
	return tables
}

func migrationTableSet(changes []migration.TableChange) map[string]bool {
	set := make(map[string]bool, len(changes))
	for _, change := range changes {
		set[change.Table] = true
	}
	return set
}

func migrationFieldSet(changes []migration.TableChange) map[string]map[string]bool {
	set := make(map[string]map[string]bool, len(changes))
	for _, change := range changes {
		fields := make(map[string]bool, len(change.Fields))
		for name := range change.Fields {
			fields[name] = true
		}
		set[change.Table] = fields
	}
	return set
}

func sortedSchemaModelNames(schema storage.Schema) []string {
	names := make([]string, 0, len(schema.Models))
	for name := range schema.Models {
		names = append(names, name)
	}
	// Model order is irrelevant for additive columns, but lexical order keeps
	// the emitted plan deterministic.
	sort.Strings(names)
	return names
}
