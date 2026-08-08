package mysql

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestPlanSchemaMatchesGolden(t *testing.T) {
	schema := schemaGoldenInput()
	plan, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan, repeated) {
		t.Fatal("schema plan is not deterministic")
	}
	want, err := os.ReadFile("testdata/schema.golden.sql")
	if err != nil {
		t.Fatal(err)
	}
	if plan.SQL() != string(want) {
		t.Fatalf("schema SQL:\n%s\nwant:\n%s", plan.SQL(), want)
	}
}

func TestPlanSchemaIDTypesPropagateToReferences(t *testing.T) {
	checks := []struct {
		idType IDType
		idDDL  string
		fkDDL  string
	}{
		{TextID, "`id` VARCHAR(36) NOT NULL PRIMARY KEY", "`parentId` VARCHAR(36) NOT NULL"},
		{UUIDID, "`id` VARCHAR(36) NOT NULL PRIMARY KEY", "`parentId` VARCHAR(36) NOT NULL"},
		{SerialID, "`id` INTEGER AUTO_INCREMENT NOT NULL PRIMARY KEY", "`parentId` INTEGER NOT NULL"},
	}
	for _, check := range checks {
		plan, err := PlanSchemaWithIDType(relationSchema(), check.idType)
		if err != nil {
			t.Fatal(err)
		}
		code := plan.SQL()
		if !strings.Contains(code, check.idDDL) || !strings.Contains(code, check.fkDDL) {
			t.Fatalf("%s ID schema:\n%s", check.idType, code)
		}
		if check.idType == UUIDID && strings.Contains(code, "UUID()") {
			t.Fatalf("UUID mode must be client generated:\n%s", code)
		}
	}
}

func TestPlanSchemaSupportsCyclicReferences(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"left": {Fields: map[string]storage.FieldAttribute{
			"rightId": {Type: storage.FieldString, References: &storage.Reference{Model: "right", Field: "id"}},
		}},
		"right": {Fields: map[string]storage.FieldAttribute{
			"leftId": {Type: storage.FieldString, References: &storage.Reference{Model: "left", Field: "id"}},
		}},
	}}
	plan, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	code := plan.SQL()
	if strings.Count(code, "CREATE TABLE") != 2 || strings.Count(code, "FOREIGN KEY") != 2 ||
		!strings.HasPrefix(code, "SET FOREIGN_KEY_CHECKS = 0;") || !strings.HasSuffix(code, "SET FOREIGN_KEY_CHECKS = 1;\n") {
		t.Fatalf("cyclic plan:\n%s", code)
	}
}

func TestPlanSchemaRejectsUnsupportedDeleteActions(t *testing.T) {
	checks := []struct {
		name     string
		required *bool
		action   storage.DeleteAction
		wantErr  bool
	}{
		{"set-default", storage.Bool(false), storage.SetDefault, true},
		{"required-set-null", nil, storage.SetNull, true},
		{"optional-set-null", storage.Bool(false), storage.SetNull, false},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			schema := storage.Schema{Models: map[string]storage.ModelSchema{
				"parent": {Fields: map[string]storage.FieldAttribute{}},
				"child": {Fields: map[string]storage.FieldAttribute{
					"parentId": {Type: storage.FieldString, Required: check.required, References: &storage.Reference{Model: "parent", Field: "id", OnDelete: check.action}},
				}},
			}}
			plan, err := PlanSchema(schema)
			if check.wantErr && !errors.Is(err, storage.ErrInvalidQuery) {
				t.Fatalf("error = %v", err)
			}
			if !check.wantErr && (err != nil || !strings.Contains(plan.SQL(), "ON DELETE SET NULL")) {
				t.Fatalf("plan=%s error=%v", plan.SQL(), err)
			}
		})
	}
}

func TestMySQLObjectNamesAndIdentifiersRespectLimits(t *testing.T) {
	name := mysqlObjectName("idx", strings.Repeat("table", 12), strings.Repeat("field", 12))
	if len(name) > 64 || name != mysqlObjectName("idx", strings.Repeat("table", 12), strings.Repeat("field", 12)) {
		t.Fatalf("object name = %q (%d bytes)", name, len(name))
	}
	tooLong := strings.Repeat("m", 65)
	_, err := PlanSchema(storage.Schema{Models: map[string]storage.ModelSchema{tooLong: {Fields: map[string]storage.FieldAttribute{}}}})
	if !errors.Is(err, storage.ErrInvalidQuery) {
		t.Fatalf("long identifier error = %v", err)
	}
}

func TestEnsureSchemaUsesPinnedConnectionAndRestoresChecks(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{"empty": {Fields: map[string]storage.FieldAttribute{}}}}
	db, mock := newMockDB(t)
	adapter, err := New(db, Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	expectEmptyMySQLCatalog(mock, "auth")
	for _, statement := range plan.Statements {
		mock.ExpectExec(statement).WillReturnResult(sqlmock.NewResult(0, 0))
	}
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	artifact, err := adapter.CreateSchema(t.Context(), schema, "schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Code != plan.SQL() || artifact.Path != "schema.sql" || !artifact.Append || artifact.Overwrite {
		t.Fatalf("artifact = %#v", artifact)
	}
	assertExpectations(t, mock)
}

func TestEnsureSchemaRestoresForeignKeyChecksAfterDDLFailure(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{"empty": {Fields: map[string]storage.FieldAttribute{}}}}
	db, mock := newMockDB(t)
	adapter, err := New(db, Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	expectEmptyMySQLCatalog(mock, "auth")
	mock.ExpectExec(plan.Statements[0]).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(plan.Statements[1]).WillReturnError(errors.New("ddl failed"))
	mock.ExpectExec("SET FOREIGN_KEY_CHECKS = 1").WillReturnResult(sqlmock.NewResult(0, 0))
	if err := adapter.EnsureSchema(t.Context()); err == nil {
		t.Fatal("schema creation unexpectedly succeeded")
	}
	assertExpectations(t, mock)
}

func TestEnsureSchemaReconcilesAdditiveFieldThenNoops(t *testing.T) {
	schema := mysqlAdditiveMigrationSchema()
	db, mock := newMockDB(t)
	adapter, err := New(db, Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}

	expectMySQLCatalog(mock, "auth", []mysqlCatalogColumn{
		{table: "child", column: "id", dataType: "varchar(36)"},
		{table: "parent", column: "id", dataType: "varchar(36)"},
	})
	expectMySQLMigrationMetadata(mock, "auth", false)
	child, err := resolveModel(adapter.config, "child")
	if err != nil {
		t.Fatal(err)
	}
	parentID, err := resolveField(adapter.config, child, "parentId")
	if err != nil {
		t.Fatal(err)
	}
	foreignKey, err := mysqlMigrationForeignKeyStatement(adapter.config, child, parentID)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec("ALTER TABLE `child` ADD COLUMN `parentId` VARCHAR(36)").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ALTER TABLE `child` ADD COLUMN `__single_present__parentId` BOOLEAN NOT NULL DEFAULT FALSE").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE INDEX `single_child_parentId_idx` ON `child` (`parentId`)").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(foreignKey).WillReturnResult(sqlmock.NewResult(0, 0))
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}

	expectMySQLCatalog(mock, "auth", []mysqlCatalogColumn{
		{table: "child", column: "id", dataType: "varchar(36)"},
		{table: "child", column: "parentId", dataType: "varchar(36)"},
		{table: "child", column: "__single_present__parentId", dataType: "tinyint(1)"},
		{table: "parent", column: "id", dataType: "varchar(36)"},
	})
	expectMySQLMigrationMetadata(mock, "auth", true)
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertExpectations(t, mock)
}

func TestEnsureSchemaReplansAfterPartiallyAppliedAdditiveDDL(t *testing.T) {
	schema := mysqlAdditiveMigrationSchema()
	db, mock := newMockDB(t)
	adapter, err := New(db, Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	child, err := resolveModel(adapter.config, "child")
	if err != nil {
		t.Fatal(err)
	}
	parentID, err := resolveField(adapter.config, child, "parentId")
	if err != nil {
		t.Fatal(err)
	}
	foreignKey, err := mysqlMigrationForeignKeyStatement(adapter.config, child, parentID)
	if err != nil {
		t.Fatal(err)
	}

	expectMySQLCatalog(mock, "auth", []mysqlCatalogColumn{
		{table: "child", column: "id", dataType: "varchar(36)"},
		{table: "parent", column: "id", dataType: "varchar(36)"},
	})
	expectMySQLMigrationMetadata(mock, "auth", false)
	mock.ExpectExec("ALTER TABLE `child` ADD COLUMN `parentId` VARCHAR(36)").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ALTER TABLE `child` ADD COLUMN `__single_present__parentId` BOOLEAN NOT NULL DEFAULT FALSE").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE INDEX `single_child_parentId_idx` ON `child` (`parentId`)").WillReturnError(errors.New("index failed"))
	if err := adapter.EnsureSchema(t.Context()); err == nil {
		t.Fatal("partially applied additive migration unexpectedly succeeded")
	}

	// MySQL retained both ALTER TABLE statements. The retry must inspect that
	// partial state and emit only the missing index and foreign key.
	expectMySQLCatalog(mock, "auth", []mysqlCatalogColumn{
		{table: "child", column: "id", dataType: "varchar(36)"},
		{table: "child", column: "parentId", dataType: "varchar(36)"},
		{table: "child", column: "__single_present__parentId", dataType: "tinyint(1)"},
		{table: "parent", column: "id", dataType: "varchar(36)"},
	})
	expectMySQLMigrationMetadata(mock, "auth", false)
	mock.ExpectExec("CREATE INDEX `single_child_parentId_idx` ON `child` (`parentId`)").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(foreignKey).WillReturnResult(sqlmock.NewResult(0, 0))
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertExpectations(t, mock)
}

func mysqlAdditiveMigrationSchema() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"child": {Fields: map[string]storage.FieldAttribute{
			"parentId": {
				Type:       storage.FieldString,
				Required:   storage.Bool(false),
				Index:      true,
				References: &storage.Reference{Model: "parent", Field: "id", OnDelete: storage.Cascade},
			},
		}},
		"parent": {Fields: map[string]storage.FieldAttribute{}},
	}}
}

type mysqlCatalogColumn struct {
	table    string
	column   string
	dataType string
}

func expectMySQLCatalog(mock sqlmock.Sqlmock, database string, columns []mysqlCatalogColumn) {
	mock.ExpectQuery(`SELECT DATABASE()`).
		WillReturnRows(sqlmock.NewRows([]string{"database"}).AddRow(database))
	rows := sqlmock.NewRows([]string{"table_schema", "table_name", "column_name", "column_type"})
	for _, column := range columns {
		rows.AddRow(database, column.table, column.column, column.dataType)
	}
	mock.ExpectQuery(`SELECT table_schema, table_name, column_name, column_type
FROM information_schema.columns
WHERE table_schema = ?
ORDER BY table_name, ordinal_position`).
		WithArgs(database).
		WillReturnRows(rows)
}

func expectMySQLMigrationMetadata(mock sqlmock.Sqlmock, database string, present bool) {
	indexes := sqlmock.NewRows([]string{"table_name", "index_name"})
	foreignKeys := sqlmock.NewRows([]string{"table_name", "column_name", "target_table", "target_column"})
	if present {
		indexes.AddRow("child", "single_child_parentId_idx")
		foreignKeys.AddRow("child", "parentId", "parent", "id")
	}
	mock.ExpectQuery(mysqlMigrationIndexesQuery).
		WithArgs(database).
		WillReturnRows(indexes)
	mock.ExpectQuery(mysqlMigrationForeignKeysQuery).
		WithArgs(database).
		WillReturnRows(foreignKeys)
}

func expectEmptyMySQLCatalog(mock sqlmock.Sqlmock, database string) {
	expectMySQLCatalog(mock, database, nil)
}

func TestDefaultUUIDGeneratorProducesRFC4122Version4(t *testing.T) {
	configuration, err := normalizeOptions(Options{Schema: storage.Schema{Models: map[string]storage.ModelSchema{
		"empty": {Fields: map[string]storage.FieldAttribute{}},
	}}, IDType: UUIDID})
	if err != nil {
		t.Fatal(err)
	}
	generated, err := configuration.idGenerator("empty")
	if err != nil {
		t.Fatal(err)
	}
	identifier, ok := generated.(string)
	if !ok || !uuidPattern.MatchString(identifier) || identifier[14] != '4' {
		t.Fatalf("generated UUID = %#v", generated)
	}
}

func schemaGoldenInput() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"parent": {Order: 1, Fields: map[string]storage.FieldAttribute{
			"created": {Type: storage.FieldDate, DefaultValue: storage.StaticValue(nil)},
			"email":   {Type: storage.FieldString, Unique: true},
		}},
		"child": {Order: 2, Fields: map[string]storage.FieldAttribute{
			"metadata": {Type: storage.FieldJSON, Required: storage.Bool(false)},
			"parentId": {Type: storage.FieldString, Index: true, References: &storage.Reference{Model: "parent", Field: "id", OnDelete: storage.Cascade}},
		}},
	}}
}
