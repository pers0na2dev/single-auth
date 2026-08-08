package mssql

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"

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
	code := plan.SQL()
	if firstForeignKey, lastTable, lastIndex := strings.Index(code, "ALTER TABLE"), strings.LastIndex(code, "CREATE TABLE"), strings.LastIndex(code, "CREATE INDEX"); firstForeignKey < lastTable || firstForeignKey < lastIndex {
		t.Fatalf("foreign keys were not deferred:\n%s", code)
	}
}

func TestPlanSchemaIDTypesAndScalarMapping(t *testing.T) {
	checks := []struct {
		idType IDType
		idDDL  string
		fkDDL  string
	}{
		{TextID, "[id] VARCHAR(36) NOT NULL PRIMARY KEY", "[parentId] VARCHAR(36) NOT NULL"},
		{UUIDID, "[id] VARCHAR(36) NOT NULL PRIMARY KEY", "[parentId] VARCHAR(36) NOT NULL"},
		{SerialID, "[id] INTEGER IDENTITY(1,1) NOT NULL PRIMARY KEY", "[parentId] INTEGER NOT NULL"},
	}
	for _, check := range checks {
		plan, err := PlanSchemaWithIDType(relationSchema(), check.idType)
		if err != nil {
			t.Fatal(err)
		}
		if code := plan.SQL(); !strings.Contains(code, check.idDDL) || !strings.Contains(code, check.fkDDL) {
			t.Fatalf("%s ID schema:\n%s", check.idType, code)
		}
	}

	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"scalar": {Fields: map[string]storage.FieldAttribute{
			"active":   {Type: storage.FieldBoolean},
			"amount":   {Type: storage.FieldNumber},
			"big":      {Type: storage.FieldNumber, BigInt: true},
			"created":  {Type: storage.FieldDate, DefaultValue: storage.StaticValue(nil)},
			"indexed":  {Type: storage.FieldString, Index: true},
			"labels":   {Type: storage.FieldStringArray, Required: storage.Bool(false)},
			"metadata": {Type: storage.FieldJSON, Required: storage.Bool(false)},
			"name":     {Type: storage.FieldString},
			"role":     {Type: storage.FieldEnum, Enum: []string{"member", "o'wner"}},
			"scores":   {Type: storage.FieldNumberArray, Required: storage.Bool(false)},
		}},
	}}
	plan, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	code := plan.SQL()
	for _, expected := range []string{
		"[active] SMALLINT NOT NULL",
		"[amount] INTEGER NOT NULL",
		"[big] BIGINT NOT NULL",
		"[created] DATETIME2(3) NOT NULL DEFAULT CURRENT_TIMESTAMP",
		"[indexed] VARCHAR(255) NOT NULL",
		"[labels] VARCHAR(8000)",
		"[metadata] VARCHAR(8000)",
		"[name] VARCHAR(8000) NOT NULL",
		"[role] VARCHAR(255) NOT NULL CHECK ([role] IN (N'member', N'o''wner'))",
		"[scores] VARCHAR(8000)",
	} {
		if !strings.Contains(code, expected) {
			t.Fatalf("schema is missing %q:\n%s", expected, code)
		}
	}
}

func TestPlanSchemaSupportsCyclesActionsAliasesAndDisabledModels(t *testing.T) {
	schema := storage.Schema{UsePlural: true, Models: map[string]storage.ModelSchema{
		"left": {ModelName: "left_table", Fields: map[string]storage.FieldAttribute{
			"rightId": {Type: storage.FieldString, FieldName: "right_id", References: &storage.Reference{Model: "right", Field: "id", OnDelete: storage.Restrict}},
		}},
		"right": {ModelName: "right_table", Fields: map[string]storage.FieldAttribute{
			"leftId": {Type: storage.FieldString, References: &storage.Reference{Model: "left", Field: "id"}},
		}},
		"ignored": {DisableMigrations: true, Fields: map[string]storage.FieldAttribute{}},
	}}
	plan, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	code := plan.SQL()
	if strings.Count(code, "CREATE TABLE") != 2 || strings.Count(code, "FOREIGN KEY") != 2 || strings.Contains(code, "ignored") {
		t.Fatalf("cyclic/disabled plan:\n%s", code)
	}
	for _, expected := range []string{
		"CREATE TABLE [left_tables]",
		"[right_id] VARCHAR(36) NOT NULL",
		"REFERENCES [right_tables] ([id]) ON DELETE NO ACTION",
		"REFERENCES [left_tables] ([id]) ON DELETE CASCADE",
	} {
		if !strings.Contains(code, expected) {
			t.Fatalf("schema is missing %q:\n%s", expected, code)
		}
	}
}

func TestMSSQLObjectNamesAndIdentifiersRespectUTF16Limit(t *testing.T) {
	name := mssqlObjectName("idx", strings.Repeat("table", 40), strings.Repeat("field", 40))
	if utf16Length(name) > 128 || name != mssqlObjectName("idx", strings.Repeat("table", 40), strings.Repeat("field", 40)) {
		t.Fatalf("object name = %q (%d UTF-16 units)", name, utf16Length(name))
	}
	unicodeName := mssqlObjectName("idx", strings.Repeat("😀", 80), strings.Repeat("f", 100))
	if len(utf16.Encode([]rune(unicodeName))) > 128 {
		t.Fatalf("unicode object name exceeds sysname: %q", unicodeName)
	}
	tooLong := strings.Repeat("m", 129)
	_, err := PlanSchema(storage.Schema{Models: map[string]storage.ModelSchema{tooLong: {Fields: map[string]storage.FieldAttribute{}}}})
	if !errors.Is(err, storage.ErrInvalidQuery) {
		t.Fatalf("long identifier error = %v", err)
	}
}

func TestEnsureSchemaExecutesPlanTransactionally(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{"empty": {Fields: map[string]storage.FieldAttribute{}}}}
	adapter, mock := newMockAdapter(t, schema)
	plan, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	expectEmptyMSSQLCatalog(mock, "auth", "dbo")
	mock.ExpectBegin()
	for _, statement := range plan.Statements {
		mock.ExpectExec(statement).WillReturnResult(sqlmock.NewResult(0, 0))
	}
	mock.ExpectCommit()
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

func TestEnsureSchemaRollsBackOnDDLFailure(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{"empty": {Fields: map[string]storage.FieldAttribute{}}}}
	adapter, mock := newMockAdapter(t, schema)
	plan, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	expectEmptyMSSQLCatalog(mock, "auth", "dbo")
	mock.ExpectBegin()
	mock.ExpectExec(plan.Statements[0]).WillReturnError(errors.New("ddl failed"))
	mock.ExpectRollback()
	if err := adapter.EnsureSchema(t.Context()); err == nil {
		t.Fatal("schema creation unexpectedly succeeded")
	}
	assertExpectations(t, mock)
}

func TestEnsureSchemaReconcilesAdditiveFieldThenNoops(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
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
	adapter, mock := newMockAdapter(t, schema)

	expectMSSQLCatalog(mock, "auth", "dbo", []mssqlCatalogColumn{
		{table: "child", column: "id", dataType: "varchar"},
		{table: "parent", column: "id", dataType: "varchar"},
	})
	expectMSSQLMigrationMetadata(mock, "dbo", false)
	child, err := resolveModel(adapter.config, "child")
	if err != nil {
		t.Fatal(err)
	}
	parentID, err := resolveField(adapter.config, child, "parentId")
	if err != nil {
		t.Fatal(err)
	}
	foreignKey, err := mssqlMigrationForeignKeyStatement(adapter.config, child, parentID)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectExec("ALTER TABLE [child] ADD [parentId] VARCHAR(36)").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ALTER TABLE [child] ADD [__single_present__parentId] SMALLINT NOT NULL DEFAULT 0").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(mssqlMigrationIndexStatement(child, parentID)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(foreignKey).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}

	expectMSSQLCatalog(mock, "auth", "dbo", []mssqlCatalogColumn{
		{table: "child", column: "id", dataType: "varchar"},
		{table: "child", column: "parentId", dataType: "varchar"},
		{table: "child", column: "__single_present__parentId", dataType: "smallint"},
		{table: "parent", column: "id", dataType: "varchar"},
	})
	expectMSSQLMigrationMetadata(mock, "dbo", true)
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertExpectations(t, mock)
}

type mssqlCatalogColumn struct {
	table    string
	column   string
	dataType string
}

func expectMSSQLCatalog(mock sqlmock.Sqlmock, database, schema string, columns []mssqlCatalogColumn) {
	mock.ExpectQuery(`SELECT DB_NAME(), SCHEMA_NAME()`).
		WillReturnRows(sqlmock.NewRows([]string{"database", "schema"}).AddRow(database, schema))
	rows := sqlmock.NewRows([]string{"database", "schema", "table", "column", "type"})
	for _, column := range columns {
		rows.AddRow(database, schema, column.table, column.column, column.dataType)
	}
	mock.ExpectQuery(`SELECT DB_NAME(), s.name, t.name, c.name, ty.name
FROM sys.tables AS t
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
JOIN sys.columns AS c ON c.object_id = t.object_id
JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
WHERE s.name = @p1
ORDER BY t.name, c.column_id`).
		WithArgs(schema).
		WillReturnRows(rows)
}

func expectMSSQLMigrationMetadata(mock sqlmock.Sqlmock, schema string, present bool) {
	indexes := sqlmock.NewRows([]string{"schema", "table", "index"})
	foreignKeys := sqlmock.NewRows([]string{"table", "column", "target_table", "target_column"})
	if present {
		indexes.AddRow(schema, "child", "single_child_parentId_idx")
		foreignKeys.AddRow("child", "parentId", "parent", "id")
	}
	mock.ExpectQuery(mssqlMigrationIndexesQuery).
		WithArgs(schema).
		WillReturnRows(indexes)
	mock.ExpectQuery(mssqlMigrationForeignKeysQuery).
		WithArgs(schema).
		WillReturnRows(foreignKeys)
}

func expectEmptyMSSQLCatalog(mock sqlmock.Sqlmock, database, schema string) {
	expectMSSQLCatalog(mock, database, schema, nil)
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
	if !ok || !uuidPattern.MatchString(identifier) || identifier[14] != '4' || (identifier[19] != '8' && identifier[19] != '9' && identifier[19] != 'a' && identifier[19] != 'b') {
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
