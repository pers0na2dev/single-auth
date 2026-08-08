package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/migration"
)

// reconciliationPlan keeps the adapter's private presence-column encoding
// while using the shared migration inspector as the source of truth for the
// actual relational catalog. Missing tables still go through PlanSchema so an
// initial installation retains the exact native MySQL layout.
func (a *Adapter) reconciliationPlan(ctx context.Context) (SchemaPlan, error) {
	catalog, err := migration.Inspect(ctx, a.db, migration.MySQL)
	if err != nil {
		return SchemaPlan{}, err
	}
	diff, err := migration.Build(a.config.schema, catalog, migration.Options{
		Dialect: migration.MySQL,
		IDMode:  mysqlMigrationIDMode(a.config.idType),
	})
	if err != nil {
		return SchemaPlan{}, err
	}
	existingIndexes := make(map[string]struct{})
	existingForeignKeys := make(map[string]struct{})
	if len(catalog.Tables) > 0 {
		existingIndexes, existingForeignKeys, err = inspectMySQLMigrationMetadata(ctx, a.db, catalog.Database)
		if err != nil {
			return SchemaPlan{}, err
		}
	}

	missingTables := mysqlMigrationTableSet(diff.ToBeCreated)
	missingFields := mysqlMigrationFieldSet(diff.ToBeAdded)
	existing := mysqlMigrationTables(catalog)
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
	for _, canonical := range sortedMySQLMigrationModels(a.config.schema) {
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
					"ALTER TABLE %s ADD COLUMN %s",
					quoteIdentifier(model.physical),
					definition,
				))
			}
			if !presenceExists {
				columnStatements = append(columnStatements, fmt.Sprintf(
					"ALTER TABLE %s ADD COLUMN %s BOOLEAN NOT NULL DEFAULT FALSE",
					quoteIdentifier(model.physical),
					quoteIdentifier(presenceColumn(field)),
				))
			}
			if field.attribute.Index || field.attribute.Unique {
				kind := "INDEX"
				if field.attribute.Unique {
					kind = "UNIQUE INDEX"
				}
				name := mysqlObjectName("idx", model.physical, field.physical)
				if _, exists := existingIndexes[mysqlMigrationIndexKey(model.physical, name)]; !exists {
					postStatements = append(postStatements, fmt.Sprintf(
						"CREATE %s %s ON %s (%s)",
						kind,
						quoteIdentifier(name),
						quoteIdentifier(model.physical),
						quoteIdentifier(field.physical),
					))
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
				key := mysqlMigrationForeignKeyKey(model.physical, field.physical, target.physical, to.physical)
				if _, exists := existingForeignKeys[key]; !exists {
					statement, statementErr := mysqlMigrationForeignKeyStatement(a.config, model, field)
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

func mysqlMigrationForeignKeyStatement(configuration *config, model resolvedModel, field resolvedField) (string, error) {
	target, err := resolveModel(configuration, field.attribute.References.Model)
	if err != nil {
		return "", err
	}
	to, err := resolveField(configuration, target, field.attribute.References.Field)
	if err != nil {
		return "", err
	}
	action, err := mysqlOnDeleteSQL(field.attribute)
	if err != nil {
		return "", err
	}
	constraint := mysqlObjectName("fk", model.physical, field.physical)
	return fmt.Sprintf(
		"ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE %s",
		quoteIdentifier(model.physical),
		quoteIdentifier(constraint),
		quoteIdentifier(field.physical),
		quoteIdentifier(target.physical),
		quoteIdentifier(to.physical),
		action,
	), nil
}

func mysqlMigrationIDMode(idType IDType) migration.IDMode {
	switch idType {
	case UUIDID:
		return migration.UUIDID
	case SerialID:
		return migration.SerialID
	default:
		return migration.TextID
	}
}

func mysqlMigrationTables(catalog migration.Catalog) map[string]map[string]struct{} {
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

func mysqlMigrationTableSet(changes []migration.TableChange) map[string]bool {
	set := make(map[string]bool, len(changes))
	for _, change := range changes {
		set[change.Table] = true
	}
	return set
}

func mysqlMigrationFieldSet(changes []migration.TableChange) map[string]map[string]bool {
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

func sortedMySQLMigrationModels(schema storage.Schema) []string {
	names := make([]string, 0, len(schema.Models))
	for name := range schema.Models {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

const mysqlMigrationIndexesQuery = `SELECT table_name, index_name
FROM information_schema.statistics
WHERE table_schema = ?
GROUP BY table_name, index_name
ORDER BY table_name, index_name`

const mysqlMigrationForeignKeysQuery = `SELECT table_name, column_name, referenced_table_name, referenced_column_name
FROM information_schema.key_column_usage
WHERE constraint_schema = ?
  AND referenced_table_name IS NOT NULL
ORDER BY table_name, ordinal_position`

func inspectMySQLMigrationMetadata(
	ctx context.Context,
	database interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	},
	databaseName string,
) (map[string]struct{}, map[string]struct{}, error) {
	indexes := make(map[string]struct{})
	rows, err := database.QueryContext(ctx, mysqlMigrationIndexesQuery, databaseName)
	if err != nil {
		return nil, nil, fmt.Errorf("mysql: inspect migration indexes in database %q: %w", databaseName, err)
	}
	for rows.Next() {
		var tableName, indexName string
		if err := rows.Scan(&tableName, &indexName); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("mysql: inspect migration indexes: %w", err)
		}
		indexes[mysqlMigrationIndexKey(tableName, indexName)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, fmt.Errorf("mysql: inspect migration indexes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, fmt.Errorf("mysql: inspect migration indexes: %w", err)
	}

	foreignKeys := make(map[string]struct{})
	rows, err = database.QueryContext(ctx, mysqlMigrationForeignKeysQuery, databaseName)
	if err != nil {
		return nil, nil, fmt.Errorf("mysql: inspect migration foreign keys in database %q: %w", databaseName, err)
	}
	defer rows.Close()
	for rows.Next() {
		var tableName, columnName, targetTable, targetColumn string
		if err := rows.Scan(&tableName, &columnName, &targetTable, &targetColumn); err != nil {
			return nil, nil, fmt.Errorf("mysql: inspect migration foreign keys: %w", err)
		}
		foreignKeys[mysqlMigrationForeignKeyKey(tableName, columnName, targetTable, targetColumn)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("mysql: inspect migration foreign keys: %w", err)
	}
	return indexes, foreignKeys, nil
}

func mysqlMigrationIndexKey(tableName, indexName string) string {
	return tableName + "\x00" + indexName
}

func mysqlMigrationForeignKeyKey(tableName, columnName, targetTable, targetColumn string) string {
	return tableName + "\x00" + columnName + "\x00" + targetTable + "\x00" + targetColumn
}
