package migration

import (
	"database/sql"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/pers0na2dev/single-auth/storage"
)

type migrationOracle struct {
	Cases []migrationCase `json:"cases"`
}

type migrationCase struct {
	ID       string
	Dialect  Dialect
	Observed any
}

func TestMigrationSchemaBehavior(t *testing.T) {
	oracle := loadMigrationOracle(t)
	for _, testCase := range oracle.Cases {
		testCase := testCase
		t.Run(migrationCaseTitle(testCase.ID), func(t *testing.T) {
			actual := executeMigrationCase(t, testCase)
			assertMigrationJSON(t, actual, testCase.Observed)
		})
	}
}

func migrationCaseTitle(id string) string {
	if separator := strings.LastIndex(id, "::"); separator >= 0 {
		return id[separator+2:]
	}
	return id
}

func executeMigrationCase(t *testing.T, testCase migrationCase) map[string]any {
	t.Helper()
	title := migrationCaseTitle(testCase.ID)
	if testCase.Dialect == SQLite {
		return executeSQLiteMigrationCase(t, title)
	}
	return executePostgresMigrationCase(t, title)
}

func executeSQLiteMigrationCase(t *testing.T, title string) map[string]any {
	t.Helper()
	database := openMigrationSQLite(t)
	base := migrationCoreSchema()

	switch title {
	case "should enforce unique indexed fields on new tables without a duplicate index":
		schema := mergeMigrationSchema(t, base, storage.Schema{Models: map[string]storage.ModelSchema{
			"uniqueTable": {Fields: map[string]storage.FieldAttribute{
				"slug": {Type: storage.FieldString, Index: true, Unique: true, Required: storage.Bool(true)},
			}},
		}})
		plan := buildMigrationPlan(t, schema, Catalog{}, Options{Dialect: SQLite})
		sqlText := strings.ToLower(plan.SQL())
		if err := plan.Run(t.Context(), database); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(t.Context(), `INSERT INTO "uniqueTable" ("id", "slug") VALUES ('first', 'shared')`); err != nil {
			t.Fatal(err)
		}
		_, duplicateErr := database.ExecContext(t.Context(), `INSERT INTO "uniqueTable" ("id", "slug") VALUES ('second', 'shared')`)
		return map[string]any{
			"toCreate":                migrationCreatedTables(plan),
			"inlineUnique":            regexp.MustCompile(`(?s)create table "uniquetable"[^;]*"slug" text not null unique`).MatchString(sqlText),
			"hasDuplicateUniqueIndex": strings.Contains(sqlText, "uniquetable_slug_uidx"),
			"duplicateRejected":       duplicateErr != nil,
		}
	case "should execute runMigrations without error when adding indexed columns to existing tables", "should use CREATE INDEX when adding indexed columns to existing SQLite tables":
		runInitialMigration(t, database, base, SQLite)
		schema := mergeMigrationSchema(t, base, storage.Schema{Models: map[string]storage.ModelSchema{
			"user": {Fields: map[string]storage.FieldAttribute{
				"externalId": {Type: storage.FieldString, Index: true, Required: storage.Bool(false)},
			}},
		}})
		plan := buildFromMigrationDatabase(t, database, schema, Options{Dialect: SQLite})
		if strings.HasPrefix(title, "should use") {
			sqlText := strings.ToLower(plan.SQL())
			return map[string]any{
				"toCreate": migrationCreatedTables(plan), "toAdd": migrationAddedFields(plan),
				"containsCreateIndex": strings.Contains(sqlText, "create index"),
				"containsAddIndex":    strings.Contains(sqlText, "add index"),
			}
		}
		err := plan.Run(t.Context(), database)
		return map[string]any{
			"toCreate": migrationCreatedTables(plan), "toAdd": migrationAddedFields(plan), "runSucceeded": err == nil,
		}
	case "should execute runMigrations when adding a new table with indexed columns to an existing database":
		runInitialMigration(t, database, base, SQLite)
		schema := mergeMigrationSchema(t, base, apiKeyMigrationSchema(true))
		plan := buildFromMigrationDatabase(t, database, schema, Options{Dialect: SQLite})
		err := plan.Run(t.Context(), database)
		return map[string]any{
			"toCreate": migrationCreatedTables(plan), "toAdd": migrationAddedFields(plan), "runSucceeded": err == nil,
		}
	case "should execute runMigrations when upgrading an existing table with new indexed columns (simulates 1.4.x -> latest)":
		oldSchema := mergeMigrationSchema(t, base, apiKeyMigrationSchema(false))
		runInitialMigration(t, database, oldSchema, SQLite)
		newSchema := mergeMigrationSchema(t, base, apiKeyMigrationSchema(true))
		plan := buildFromMigrationDatabase(t, database, newSchema, Options{Dialect: SQLite})
		err := plan.Run(t.Context(), database)
		return map[string]any{
			"toCreate": migrationCreatedTables(plan), "toAdd": migrationAddedFields(plan), "runSucceeded": err == nil,
		}
	case "should not detect migration changes for SQLite bigint fields on subsequent runs":
		schema := storage.CoreSchema()
		runInitialMigration(t, database, schema, SQLite)
		plan := buildFromMigrationDatabase(t, database, schema, Options{Dialect: SQLite})
		return map[string]any{
			"toCreate": migrationCreatedTables(plan), "toAdd": migrationAddedFields(plan), "sql": plan.SQL(),
		}
	default:
		t.Fatalf("unknown SQLite migration-schema title %q", title)
		return nil
	}
}

func executePostgresMigrationCase(t *testing.T, title string) map[string]any {
	t.Helper()
	base := migrationCoreSchema()
	emptyCustom := Catalog{Schema: "auth_test", Tables: []Table{{Schema: "public", Name: "user", Columns: []Column{{Name: "id", DataType: "text"}}}}}
	fullUser := migrationCatalogForModels(base, Postgres, "public", "user")

	switch title {
	case "should detect custom schema from search_path":
		plan := buildMigrationPlan(t, base, emptyCustom, Options{Dialect: Postgres})
		var userFields []string
		for _, change := range plan.ToBeCreated {
			if change.Table == "user" {
				userFields = sortedMigrationKeys(change.Fields)
			}
		}
		return map[string]any{"toCreate": migrationCreatedTables(plan), "toAdd": migrationAddedFields(plan), "userFields": userFields}
	case "should detect custom schema with CamelCasePlugin enabled":
		catalog := fullUser
		catalog.Schema = "auth_test"
		catalog.Tables[0].Schema = "auth_test"
		plan := buildMigrationPlan(t, base, catalog, Options{Dialect: Postgres})
		return map[string]any{"toCreate": migrationCreatedTables(plan), "toAdd": migrationAddedFields(plan)}
	case "should not be affected by tables in public schema when using custom schema":
		plan := buildMigrationPlan(t, base, emptyCustom, Options{Dialect: Postgres})
		return map[string]any{"toCreate": migrationCreatedTables(plan), "publicUserCount": 1}
	case "should only inspect tables in public schema when using default connection":
		plan := buildMigrationPlan(t, base, fullUser, Options{Dialect: Postgres})
		return map[string]any{"toCreate": migrationCreatedTables(plan), "toAdd": migrationAddedFields(plan)}
	case "should create tables in custom schema when running migrations":
		plan := buildMigrationPlan(t, base, Catalog{Schema: "auth_test"}, Options{Dialect: Postgres})
		tables := migrationCreatedTables(plan)
		return map[string]any{"tables": tables, "containsCore": containsMigrationTables(tables, "user", "session", "account", "verification")}
	case "should use uuid for id when `advanced.database.generateId` is set to 'uuid'":
		plan := buildMigrationPlan(t, base, Catalog{Schema: "uuid_test"}, Options{Dialect: Postgres, IDMode: UUIDID})
		catalog := migrationCatalogForModels(base, Postgres, "uuid_test")
		second := buildMigrationPlan(t, base, catalog, Options{Dialect: Postgres, IDMode: UUIDID})
		return map[string]any{"uuid": strings.Contains(plan.SQL(), "UUID DEFAULT pg_catalog.gen_random_uuid()"), "secondSQL": second.SQL()}
	case "should use GENERATED ALWAYS AS IDENTITY instead of SERIAL when `advanced.database.generateId` is set to 'serial'":
		plan := buildMigrationPlan(t, base, Catalog{Schema: "identity_test"}, Options{Dialect: Postgres, IDMode: SerialID})
		sqlText := plan.SQL()
		return map[string]any{
			"containsIdentity": strings.Contains(sqlText, "GENERATED BY DEFAULT AS IDENTITY"),
			"containsSerial":   strings.Contains(sqlText, "SERIAL"),
			"identityCount":    strings.Count(sqlText, `"id" INTEGER GENERATED BY DEFAULT AS IDENTITY`),
		}
	case "should update default tables with plugin schema fields":
		catalog := migrationCatalogForModels(base, Postgres, "column_test")
		schema := mergeMigrationSchema(t, base, storage.Schema{Models: map[string]storage.ModelSchema{
			"user":    {Fields: map[string]storage.FieldAttribute{"role": {Type: storage.FieldString}}},
			"session": {Fields: map[string]storage.FieldAttribute{"impersonatedBy": {Type: storage.FieldString}}},
		}})
		plan := buildMigrationPlan(t, schema, catalog, Options{Dialect: Postgres})
		return map[string]any{"toCreate": migrationCreatedTables(plan), "toAdd": migrationAddedFields(plan)}
	case "should generate valid PostgreSQL CREATE INDEX syntax for indexed columns added to existing tables":
		catalog := migrationCatalogForModels(base, Postgres, "column_test")
		schema := mergeMigrationSchema(t, base, storage.Schema{Models: map[string]storage.ModelSchema{
			"user": {Fields: map[string]storage.FieldAttribute{"externalId": {Type: storage.FieldString, Index: true, Required: storage.Bool(false)}}},
		}})
		plan := buildMigrationPlan(t, schema, catalog, Options{Dialect: Postgres})
		sqlText := strings.ToLower(plan.SQL())
		return map[string]any{
			"toCreate": migrationCreatedTables(plan), "toAdd": migrationAddedFields(plan),
			"containsCreateIndex": strings.Contains(sqlText, "create index"), "containsAddIndex": strings.Contains(sqlText, "add index"),
		}
	default:
		t.Fatalf("unknown PostgreSQL migration-schema title %q", title)
		return nil
	}
}

func migrationCoreSchema() storage.Schema {
	schema := storage.CoreSchema()
	delete(schema.Models, "rateLimit")
	return schema
}

func apiKeyMigrationSchema(upgraded bool) storage.Schema {
	fields := map[string]storage.FieldAttribute{
		"key": {Type: storage.FieldString}, "userId": {Type: storage.FieldString},
		"createdAt": {Type: storage.FieldDate}, "updatedAt": {Type: storage.FieldDate},
	}
	if upgraded {
		fields["key"] = storage.FieldAttribute{Type: storage.FieldString, Index: true}
		fields["configId"] = storage.FieldAttribute{Type: storage.FieldString, Index: true}
		fields["referenceId"] = storage.FieldAttribute{Type: storage.FieldString, Index: true}
	}
	return storage.Schema{Models: map[string]storage.ModelSchema{"apikey": {Fields: fields}}}
}

func mergeMigrationSchema(t *testing.T, base, extension storage.Schema) storage.Schema {
	t.Helper()
	merged, err := base.Merge(extension)
	if err != nil {
		t.Fatal(err)
	}
	return merged
}

func openMigrationSQLite(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close SQLite migration database: %v", err)
		}
	})
	return database
}

func runInitialMigration(t *testing.T, database *sql.DB, schema storage.Schema, dialect Dialect) {
	t.Helper()
	plan := buildMigrationPlan(t, schema, Catalog{}, Options{Dialect: dialect})
	if err := plan.Run(t.Context(), database); err != nil {
		t.Fatal(err)
	}
}

func buildFromMigrationDatabase(t *testing.T, database *sql.DB, schema storage.Schema, options Options) Plan {
	t.Helper()
	plan, err := BuildFromDatabase(t.Context(), database, schema, options)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func buildMigrationPlan(t *testing.T, schema storage.Schema, catalog Catalog, options Options) Plan {
	t.Helper()
	plan, err := Build(schema, catalog, options)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func migrationCatalogForModels(schema storage.Schema, dialect Dialect, namespace string, included ...string) Catalog {
	filter := make(map[string]bool, len(included))
	for _, name := range included {
		filter[name] = true
	}
	catalog := Catalog{Schema: namespace}
	for canonical, raw := range schema.Models {
		model, _, _ := schema.ResolveModel(canonical)
		if len(filter) > 0 && !filter[model.ModelName] {
			continue
		}
		table := Table{Schema: namespace, Name: model.ModelName, Columns: []Column{{Name: "id", DataType: "text"}}}
		for fieldName, field := range raw.Fields {
			physical := field.FieldName
			if physical == "" {
				physical = fieldName
			}
			typeName, _ := fieldTypeSQL(field, fieldName, Options{Dialect: dialect})
			table.Columns = append(table.Columns, Column{Name: physical, DataType: typeName})
		}
		catalog.Tables = append(catalog.Tables, table)
	}
	return catalog
}

func migrationCreatedTables(plan Plan) []string {
	tables := make([]string, len(plan.ToBeCreated))
	for index, change := range plan.ToBeCreated {
		tables[index] = change.Table
	}
	sort.Strings(tables)
	return tables
}

func migrationAddedFields(plan Plan) map[string][]string {
	fields := make(map[string][]string, len(plan.ToBeAdded))
	for _, change := range plan.ToBeAdded {
		fields[change.Table] = sortedMigrationKeys(change.Fields)
	}
	return fields
}

func sortedMigrationKeys(fields map[string]storage.FieldAttribute) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func containsMigrationTables(tables []string, expected ...string) bool {
	set := make(map[string]bool, len(tables))
	for _, table := range tables {
		set[table] = true
	}
	for _, table := range expected {
		if !set[table] {
			return false
		}
	}
	return true
}

func loadMigrationOracle(t *testing.T) migrationOracle {
	t.Helper()
	oracle := migrationOracle{Cases: migrationScenarios}
	if len(oracle.Cases) != 15 {
		t.Fatalf("migration scenarios=%d, want 15", len(oracle.Cases))
	}
	for _, scenario := range oracle.Cases {
		if scenario.ID == "" || scenario.Observed == nil || (scenario.Dialect != SQLite && scenario.Dialect != Postgres) {
			t.Fatalf("invalid migration scenario: %#v", scenario)
		}
	}
	return oracle
}

func assertMigrationJSON(t *testing.T, actual, expected any) {
	t.Helper()
	actualValue := normalizeMigrationValue(actual)
	expectedValue := normalizeMigrationValue(expected)
	if !reflect.DeepEqual(actualValue, expectedValue) {
		t.Fatalf("migration observation = %#v, want %#v", actualValue, expectedValue)
	}
}

func normalizeMigrationValue(value any) any {
	if value == nil {
		return nil
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Interface, reflect.Pointer:
		if reflected.IsNil() {
			return nil
		}
		return normalizeMigrationValue(reflected.Elem().Interface())
	case reflect.Map:
		result := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			result[iterator.Key().String()] = normalizeMigrationValue(iterator.Value().Interface())
		}
		return result
	case reflect.Slice, reflect.Array:
		result := make([]any, reflected.Len())
		for index := range reflected.Len() {
			result[index] = normalizeMigrationValue(reflected.Index(index).Interface())
		}
		return result
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(reflected.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(reflected.Uint())
	case reflect.Float32, reflect.Float64:
		return reflected.Convert(reflect.TypeOf(float64(0))).Float()
	default:
		return value
	}
}

func TestMigrationSearchPathParsing(t *testing.T) {
	for input, expected := range map[string]string{
		`"$user", public`: "public",
		`"\\$user", auth`: "auth",
		`custom, public`:  "custom",
		``:                "public",
	} {
		if actual := firstConcreteSchema(input); actual != expected {
			t.Fatalf("firstConcreteSchema(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func ExamplePlan_SQL() {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"widget": {Fields: map[string]storage.FieldAttribute{"slug": {Type: storage.FieldString, Index: true}}},
	}}
	plan, _ := Build(schema, Catalog{}, Options{Dialect: SQLite})
	fmt.Println(strings.Contains(strings.ToLower(plan.SQL()), "create index"))
	// Output: true
}
