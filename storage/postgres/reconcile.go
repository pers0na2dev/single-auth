package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/migration"
)

func (a *Adapter) reconciliationPlan(ctx context.Context) (SchemaPlan, error) {
	type inspectedModel struct {
		model   resolvedModel
		columns map[string]struct{}
	}

	modelsBySchema := make(map[string][]string)
	resolved := make(map[string]resolvedModel, len(a.config.schema.Models))
	for canonical, raw := range a.config.schema.Models {
		if raw.DisableMigrations {
			continue
		}
		model, err := resolveModel(a.config, canonical)
		if err != nil {
			return SchemaPlan{}, err
		}
		resolved[canonical] = model
		modelsBySchema[model.databaseSchema] = append(modelsBySchema[model.databaseSchema], canonical)
	}

	schemas := make([]string, 0, len(modelsBySchema))
	for schema := range modelsBySchema {
		schemas = append(schemas, schema)
	}
	sort.Strings(schemas)

	missingModels := make(map[string]bool)
	missingFields := make(map[string]map[string]bool)
	inspected := make(map[string]inspectedModel)
	existingIndexes := make(map[string]struct{})
	existingForeignKeys := make(map[string]struct{})
	for _, databaseSchema := range schemas {
		catalog, err := migration.InspectPostgresSchema(ctx, a.db, databaseSchema)
		if err != nil {
			return SchemaPlan{}, err
		}
		if len(catalog.Tables) > 0 {
			indexes, foreignKeys, metadataErr := inspectPostgresMigrationMetadata(
				ctx,
				a.db,
				catalog.Database,
				databaseSchema,
			)
			if metadataErr != nil {
				return SchemaPlan{}, metadataErr
			}
			for key := range indexes {
				existingIndexes[key] = struct{}{}
			}
			for key := range foreignKeys {
				existingForeignKeys[key] = struct{}{}
			}
		}
		catalogTables := make(map[string]migration.Table, len(catalog.Tables))
		for _, table := range catalog.Tables {
			catalogTables[table.Name] = table
		}

		groupSchema := a.config.schema.Clone()
		groupSchema.UsePlural = false
		physicalToCanonical := make(map[string]string)
		for canonical, raw := range groupSchema.Models {
			model, err := resolveModel(a.config, canonical)
			if err != nil {
				return SchemaPlan{}, err
			}
			raw.ModelName = model.physical
			if model.databaseSchema != databaseSchema {
				raw.DisableMigrations = true
			}
			groupSchema.Models[canonical] = raw
			if model.databaseSchema == databaseSchema && !raw.DisableMigrations {
				physicalToCanonical[model.physical] = canonical
			}
		}

		diff, err := migration.Build(groupSchema, catalog, migration.Options{
			Dialect: migration.Postgres,
			IDMode:  postgresMigrationIDMode(a.config.idType),
		})
		if err != nil {
			return SchemaPlan{}, err
		}
		for _, change := range diff.ToBeCreated {
			canonical := physicalToCanonical[change.Table]
			if canonical == "" {
				return SchemaPlan{}, fmt.Errorf("postgres: migration cannot resolve missing table %q", change.Table)
			}
			missingModels[canonical] = true
		}
		for _, change := range diff.ToBeAdded {
			canonical := physicalToCanonical[change.Table]
			if canonical == "" {
				return SchemaPlan{}, fmt.Errorf("postgres: migration cannot resolve changed table %q", change.Table)
			}
			fields := make(map[string]bool, len(change.Fields))
			for field := range change.Fields {
				fields[field] = true
			}
			missingFields[canonical] = fields
		}
		for canonical, model := range resolved {
			if model.databaseSchema != databaseSchema || missingModels[canonical] {
				continue
			}
			table := catalogTables[model.physical]
			columns := make(map[string]struct{}, len(table.Columns))
			for _, column := range table.Columns {
				columns[column.Name] = struct{}{}
			}
			inspected[canonical] = inspectedModel{model: model, columns: columns}
		}
	}

	columnStatements := make([]string, 0)
	postStatements := make([]string, 0)
	canonicalNames := sortedPostgresMigrationModels(a.config.schema)
	for _, canonical := range canonicalNames {
		entry, exists := inspected[canonical]
		if !exists || missingModels[canonical] {
			continue
		}
		for _, field := range modelFields(entry.model)[1:] {
			dataMissing := missingFields[canonical][field.canonical]
			_, presenceExists := entry.columns[presenceColumn(field)]
			if dataMissing {
				definition, err := columnDefinition(field, a.config.idType)
				if err != nil {
					return SchemaPlan{}, err
				}
				columnStatements = append(columnStatements, fmt.Sprintf(
					"ALTER TABLE %s ADD COLUMN %s",
					qualifiedTable(a.config, entry.model),
					definition,
				))
			}
			if !presenceExists {
				columnStatements = append(columnStatements, fmt.Sprintf(
					"ALTER TABLE %s ADD COLUMN %s BOOLEAN NOT NULL DEFAULT FALSE",
					qualifiedTable(a.config, entry.model),
					quoteIdentifier(presenceColumn(field)),
				))
			}
			if field.attribute.Index || field.attribute.Unique {
				kind := "INDEX"
				if field.attribute.Unique {
					kind = "UNIQUE INDEX"
				}
				name := postgresObjectName("idx", entry.model.physical, field.physical)
				if _, exists := existingIndexes[postgresMigrationIndexKey(entry.model.databaseSchema, name)]; !exists {
					postStatements = append(postStatements, fmt.Sprintf(
						"CREATE %s IF NOT EXISTS %s ON %s (%s)",
						kind,
						quoteIdentifier(name),
						qualifiedTable(a.config, entry.model),
						quoteIdentifier(field.physical),
					))
				}
			}
			if field.attribute.References != nil {
				target, err := resolveModel(a.config, field.attribute.References.Model)
				if err != nil {
					return SchemaPlan{}, err
				}
				to, err := resolveField(a.config, target, field.attribute.References.Field)
				if err != nil {
					return SchemaPlan{}, err
				}
				key := postgresMigrationForeignKeyKey(
					entry.model.databaseSchema,
					entry.model.physical,
					field.physical,
					target.databaseSchema,
					target.physical,
					to.physical,
				)
				if _, exists := existingForeignKeys[key]; !exists {
					statement, statementErr := postgresMigrationForeignKeyStatement(a.config, entry.model, field)
					if statementErr != nil {
						return SchemaPlan{}, statementErr
					}
					postStatements = append(postStatements, statement)
				}
			}
		}
	}

	statements := append([]string(nil), columnStatements...)
	if len(missingModels) > 0 {
		createSchema := a.config.schema.Clone()
		for canonical, raw := range createSchema.Models {
			if !missingModels[canonical] {
				raw.DisableMigrations = true
			}
			createSchema.Models[canonical] = raw
		}
		createPlan, err := PlanSchemaWithDatabaseSchema(createSchema, a.config.idType, a.config.databaseSchema)
		if err != nil {
			return SchemaPlan{}, err
		}
		statements = append(statements, createPlan.Statements...)
	}
	statements = append(statements, postStatements...)
	return SchemaPlan{Statements: statements}, nil
}

func postgresMigrationForeignKeyStatement(configuration *config, model resolvedModel, field resolvedField) (string, error) {
	target, err := resolveModel(configuration, field.attribute.References.Model)
	if err != nil {
		return "", err
	}
	to, err := resolveField(configuration, target, field.attribute.References.Field)
	if err != nil {
		return "", err
	}
	constraint := postgresObjectName("fk", model.physical, field.physical)
	return fmt.Sprintf(
		"DO $single$\nBEGIN\n  IF NOT EXISTS (\n    SELECT 1 FROM pg_constraint\n    WHERE conname = %s AND conrelid = to_regclass(%s)\n  ) THEN\n    ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE %s;\n  END IF;\nEXCEPTION\n  WHEN duplicate_object THEN NULL;\nEND\n$single$",
		quoteLiteral(constraint), quoteLiteral(qualifiedTable(configuration, model)),
		qualifiedTable(configuration, model), quoteIdentifier(constraint), quoteIdentifier(field.physical),
		qualifiedTable(configuration, target), quoteIdentifier(to.physical), onDeleteSQL(field.attribute.References.OnDelete),
	), nil
}

func postgresMigrationIDMode(idType IDType) migration.IDMode {
	switch idType {
	case UUIDID:
		return migration.UUIDID
	case SerialID:
		return migration.SerialID
	default:
		return migration.TextID
	}
}

func sortedPostgresMigrationModels(schema storage.Schema) []string {
	names := make([]string, 0, len(schema.Models))
	for name := range schema.Models {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

const postgresMigrationIndexesQuery = `SELECT schemaname, tablename, indexname
FROM pg_indexes
WHERE schemaname = $1
ORDER BY tablename, indexname`

const postgresMigrationForeignKeysQuery = `SELECT
  tc.table_schema,
  tc.table_name,
  kcu.column_name,
  ccu.table_schema,
  ccu.table_name,
  ccu.column_name
FROM information_schema.table_constraints AS tc
JOIN information_schema.key_column_usage AS kcu
  ON kcu.constraint_catalog = tc.constraint_catalog
 AND kcu.constraint_schema = tc.constraint_schema
 AND kcu.constraint_name = tc.constraint_name
JOIN information_schema.constraint_column_usage AS ccu
  ON ccu.constraint_catalog = tc.constraint_catalog
 AND ccu.constraint_schema = tc.constraint_schema
 AND ccu.constraint_name = tc.constraint_name
WHERE tc.constraint_type = 'FOREIGN KEY'
  AND tc.constraint_catalog = $1
  AND tc.constraint_schema = $2
ORDER BY tc.table_name, kcu.ordinal_position`

func inspectPostgresMigrationMetadata(
	ctx context.Context,
	database interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	},
	databaseName string,
	databaseSchema string,
) (map[string]struct{}, map[string]struct{}, error) {
	indexes := make(map[string]struct{})
	rows, err := database.QueryContext(ctx, postgresMigrationIndexesQuery, databaseSchema)
	if err != nil {
		return nil, nil, fmt.Errorf("postgres: inspect migration indexes in schema %q: %w", databaseSchema, err)
	}
	for rows.Next() {
		var schemaName, tableName, indexName string
		if err := rows.Scan(&schemaName, &tableName, &indexName); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("postgres: inspect migration indexes: %w", err)
		}
		indexes[postgresMigrationIndexKey(schemaName, indexName)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, fmt.Errorf("postgres: inspect migration indexes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, fmt.Errorf("postgres: inspect migration indexes: %w", err)
	}

	foreignKeys := make(map[string]struct{})
	rows, err = database.QueryContext(ctx, postgresMigrationForeignKeysQuery, databaseName, databaseSchema)
	if err != nil {
		return nil, nil, fmt.Errorf("postgres: inspect migration foreign keys in schema %q: %w", databaseSchema, err)
	}
	defer rows.Close()
	for rows.Next() {
		var schemaName, tableName, columnName, targetSchema, targetTable, targetColumn string
		if err := rows.Scan(&schemaName, &tableName, &columnName, &targetSchema, &targetTable, &targetColumn); err != nil {
			return nil, nil, fmt.Errorf("postgres: inspect migration foreign keys: %w", err)
		}
		foreignKeys[postgresMigrationForeignKeyKey(
			schemaName,
			tableName,
			columnName,
			targetSchema,
			targetTable,
			targetColumn,
		)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("postgres: inspect migration foreign keys: %w", err)
	}
	return indexes, foreignKeys, nil
}

func postgresMigrationIndexKey(schemaName, indexName string) string {
	return schemaName + "\x00" + indexName
}

func postgresMigrationForeignKeyKey(
	schemaName,
	tableName,
	columnName,
	targetSchema,
	targetTable,
	targetColumn string,
) string {
	return schemaName + "\x00" + tableName + "\x00" + columnName + "\x00" +
		targetSchema + "\x00" + targetTable + "\x00" + targetColumn
}
