package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/migration"
)

// reconciliationPlan combines shared catalog inspection with the adapter's
// native presence columns and idempotent SQL Server index/FK guards. Missing
// tables keep using PlanSchema so initial installations are unchanged.
func (a *Adapter) reconciliationPlan(ctx context.Context) (SchemaPlan, error) {
	catalog, err := migration.Inspect(ctx, a.db, migration.MSSQL)
	if err != nil {
		return SchemaPlan{}, err
	}
	diff, err := migration.Build(a.config.schema, catalog, migration.Options{
		Dialect: migration.MSSQL,
		IDMode:  mssqlMigrationIDMode(a.config.idType),
	})
	if err != nil {
		return SchemaPlan{}, err
	}
	existingIndexes := make(map[string]struct{})
	existingForeignKeys := make(map[string]struct{})
	if len(catalog.Tables) > 0 {
		existingIndexes, existingForeignKeys, err = inspectMSSQLMigrationMetadata(ctx, a.db, catalog.Schema)
		if err != nil {
			return SchemaPlan{}, err
		}
	}

	missingTables := mssqlMigrationTableSet(diff.ToBeCreated)
	missingFields := mssqlMigrationFieldSet(diff.ToBeAdded)
	existing := mssqlMigrationTables(catalog)
	createSchema := a.config.schema.Clone()
	hasCreates := false
	for canonical, raw := range createSchema.Models {
		model, resolveErr := resolveModel(a.config, canonical)
		if resolveErr != nil {
			return SchemaPlan{}, resolveErr
		}
		if !missingTables[model.physical] {
			raw.DisableMigrations = true
		} else if !raw.DisableMigrations {
			hasCreates = true
		}
		createSchema.Models[canonical] = raw
	}

	columnStatements := make([]string, 0)
	postStatements := make([]string, 0)
	for _, canonical := range sortedMSSQLMigrationModels(a.config.schema) {
		raw := a.config.schema.Models[canonical]
		if raw.DisableMigrations {
			continue
		}
		model, resolveErr := resolveModel(a.config, canonical)
		if resolveErr != nil {
			return SchemaPlan{}, resolveErr
		}
		if missingTables[model.physical] {
			continue
		}
		columns := existing[model.physical]
		for _, field := range modelFields(model)[1:] {
			dataMissing := missingFields[model.physical][field.canonical]
			_, presenceExists := columns[presenceColumn(field)]
			if dataMissing {
				definition, definitionErr := columnDefinition(field, a.config.idType)
				if definitionErr != nil {
					return SchemaPlan{}, definitionErr
				}
				columnStatements = append(columnStatements, fmt.Sprintf(
					"ALTER TABLE %s ADD %s",
					quoteIdentifier(model.physical),
					definition,
				))
			}
			if !presenceExists {
				columnStatements = append(columnStatements, fmt.Sprintf(
					"ALTER TABLE %s ADD %s SMALLINT NOT NULL DEFAULT 0",
					quoteIdentifier(model.physical),
					quoteIdentifier(presenceColumn(field)),
				))
			}
			if field.attribute.Index || field.attribute.Unique {
				name := mssqlObjectName("idx", model.physical, field.physical)
				if _, exists := existingIndexes[mssqlMigrationIndexKey(model.physical, name)]; !exists {
					postStatements = append(postStatements, mssqlMigrationIndexStatement(model, field))
				}
			}
			if field.attribute.References != nil {
				target, targetErr := resolveModel(a.config, field.attribute.References.Model)
				if targetErr != nil {
					return SchemaPlan{}, targetErr
				}
				to, targetFieldErr := resolveField(a.config, target, field.attribute.References.Field)
				if targetFieldErr != nil {
					return SchemaPlan{}, targetFieldErr
				}
				key := mssqlMigrationForeignKeyKey(model.physical, field.physical, target.physical, to.physical)
				if _, exists := existingForeignKeys[key]; !exists {
					statement, statementErr := mssqlMigrationForeignKeyStatement(a.config, model, field)
					if statementErr != nil {
						return SchemaPlan{}, statementErr
					}
					postStatements = append(postStatements, statement)
				}
			}
		}
	}

	statements := append([]string(nil), columnStatements...)
	if hasCreates {
		createPlan, createErr := PlanSchemaWithIDType(createSchema, a.config.idType)
		if createErr != nil {
			return SchemaPlan{}, createErr
		}
		statements = append(statements, createPlan.Statements...)
	}
	statements = append(statements, postStatements...)
	return SchemaPlan{Statements: statements}, nil
}

func mssqlMigrationIndexStatement(model resolvedModel, field resolvedField) string {
	kind := "INDEX"
	if field.attribute.Unique {
		kind = "UNIQUE INDEX"
	}
	name := mssqlObjectName("idx", model.physical, field.physical)
	return fmt.Sprintf(
		"IF NOT EXISTS (\n  SELECT 1 FROM sys.indexes\n  WHERE [name] = %s AND [object_id] = OBJECT_ID(%s)\n)\nBEGIN\n  CREATE %s %s ON %s (%s)\nEND",
		quoteLiteral(name),
		quoteLiteral(quoteIdentifier(model.physical)),
		kind,
		quoteIdentifier(name),
		quoteIdentifier(model.physical),
		quoteIdentifier(field.physical),
	)
}

func mssqlMigrationForeignKeyStatement(configuration *config, model resolvedModel, field resolvedField) (string, error) {
	target, err := resolveModel(configuration, field.attribute.References.Model)
	if err != nil {
		return "", err
	}
	to, err := resolveField(configuration, target, field.attribute.References.Field)
	if err != nil {
		return "", err
	}
	constraint := mssqlObjectName("fk", model.physical, field.physical)
	return fmt.Sprintf(
		"IF NOT EXISTS (\n  SELECT 1 FROM sys.foreign_keys\n  WHERE [name] = %s AND [parent_object_id] = OBJECT_ID(%s)\n)\nBEGIN\n  ALTER TABLE %s WITH CHECK ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE %s\nEND",
		quoteLiteral(constraint),
		quoteLiteral(quoteIdentifier(model.physical)),
		quoteIdentifier(model.physical),
		quoteIdentifier(constraint),
		quoteIdentifier(field.physical),
		quoteIdentifier(target.physical),
		quoteIdentifier(to.physical),
		onDeleteSQL(field.attribute.References.OnDelete),
	), nil
}

func mssqlMigrationIDMode(idType IDType) migration.IDMode {
	switch idType {
	case UUIDID:
		return migration.UUIDID
	case SerialID:
		return migration.SerialID
	default:
		return migration.TextID
	}
}

func mssqlMigrationTables(catalog migration.Catalog) map[string]map[string]struct{} {
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

func mssqlMigrationTableSet(changes []migration.TableChange) map[string]bool {
	set := make(map[string]bool, len(changes))
	for _, change := range changes {
		set[change.Table] = true
	}
	return set
}

func mssqlMigrationFieldSet(changes []migration.TableChange) map[string]map[string]bool {
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

func sortedMSSQLMigrationModels(schema storage.Schema) []string {
	names := make([]string, 0, len(schema.Models))
	for name := range schema.Models {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

const mssqlMigrationIndexesQuery = `SELECT s.name, t.name, i.name
FROM sys.indexes AS i
JOIN sys.tables AS t ON t.object_id = i.object_id
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
WHERE s.name = @p1
  AND i.name IS NOT NULL
ORDER BY t.name, i.name`

const mssqlMigrationForeignKeysQuery = `SELECT
  pt.name,
  pc.name,
  rt.name,
  rc.name
FROM sys.foreign_key_columns AS fkc
JOIN sys.tables AS pt ON pt.object_id = fkc.parent_object_id
JOIN sys.schemas AS ps ON ps.schema_id = pt.schema_id
JOIN sys.columns AS pc
  ON pc.object_id = fkc.parent_object_id
 AND pc.column_id = fkc.parent_column_id
JOIN sys.tables AS rt ON rt.object_id = fkc.referenced_object_id
JOIN sys.columns AS rc
  ON rc.object_id = fkc.referenced_object_id
 AND rc.column_id = fkc.referenced_column_id
WHERE ps.name = @p1
ORDER BY pt.name, fkc.constraint_column_id`

func inspectMSSQLMigrationMetadata(
	ctx context.Context,
	database interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	},
	databaseSchema string,
) (map[string]struct{}, map[string]struct{}, error) {
	indexes := make(map[string]struct{})
	rows, err := database.QueryContext(ctx, mssqlMigrationIndexesQuery, databaseSchema)
	if err != nil {
		return nil, nil, fmt.Errorf("mssql: inspect migration indexes in schema %q: %w", databaseSchema, err)
	}
	for rows.Next() {
		var schemaName, tableName, indexName string
		if err := rows.Scan(&schemaName, &tableName, &indexName); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("mssql: inspect migration indexes: %w", err)
		}
		indexes[mssqlMigrationIndexKey(tableName, indexName)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, fmt.Errorf("mssql: inspect migration indexes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, fmt.Errorf("mssql: inspect migration indexes: %w", err)
	}

	foreignKeys := make(map[string]struct{})
	rows, err = database.QueryContext(ctx, mssqlMigrationForeignKeysQuery, databaseSchema)
	if err != nil {
		return nil, nil, fmt.Errorf("mssql: inspect migration foreign keys in schema %q: %w", databaseSchema, err)
	}
	defer rows.Close()
	for rows.Next() {
		var tableName, columnName, targetTable, targetColumn string
		if err := rows.Scan(&tableName, &columnName, &targetTable, &targetColumn); err != nil {
			return nil, nil, fmt.Errorf("mssql: inspect migration foreign keys: %w", err)
		}
		foreignKeys[mssqlMigrationForeignKeyKey(tableName, columnName, targetTable, targetColumn)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("mssql: inspect migration foreign keys: %w", err)
	}
	return indexes, foreignKeys, nil
}

func mssqlMigrationIndexKey(tableName, indexName string) string {
	return tableName + "\x00" + indexName
}

func mssqlMigrationForeignKeyKey(tableName, columnName, targetTable, targetColumn string) string {
	return tableName + "\x00" + columnName + "\x00" + targetTable + "\x00" + targetColumn
}
