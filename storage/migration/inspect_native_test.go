package migration

import (
	"database/sql"
	"reflect"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestInspectPostgresUsesEffectiveNamespace(t *testing.T) {
	database, mock := newMigrationMockDatabase(t)
	mock.ExpectQuery(postgresNamespaceQuery).
		WillReturnRows(sqlmock.NewRows([]string{"database", "schema"}).AddRow("auth", "tenant"))
	mock.ExpectQuery(postgresColumnsQuery).
		WithArgs("auth", "tenant").
		WillReturnRows(sqlmock.NewRows([]string{"table_catalog", "table_schema", "table_name", "column_name", "data_type"}).
			AddRow("auth", "tenant", "session", "id", "text").
			AddRow("auth", "tenant", "session", "expiresAt", "timestamp with time zone").
			AddRow("auth", "public", "session", "ignored_schema", "text").
			AddRow("other", "tenant", "session", "ignored_database", "text"))

	actual, err := Inspect(t.Context(), database, Postgres)
	if err != nil {
		t.Fatal(err)
	}
	expected := Catalog{
		Database: "auth",
		Schema:   "tenant",
		Tables: []Table{{
			Database: "auth",
			Schema:   "tenant",
			Name:     "session",
			Columns: []Column{
				{Name: "id", DataType: "text"},
				{Name: "expiresAt", DataType: "timestamp with time zone"},
			},
		}},
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("catalog = %#v, want %#v", actual, expected)
	}
	assertMigrationMockExpectations(t, mock)
}

func TestInspectMySQLCurrentDatabase(t *testing.T) {
	database, mock := newMigrationMockDatabase(t)
	mock.ExpectQuery(mysqlDatabaseQuery).
		WillReturnRows(sqlmock.NewRows([]string{"database"}).AddRow("auth"))
	mock.ExpectQuery(mysqlColumnsQuery).
		WithArgs("auth").
		WillReturnRows(sqlmock.NewRows([]string{"table_schema", "table_name", "column_name", "column_type"}).
			AddRow("auth", "session", "id", "varchar(36)").
			AddRow("auth", "session", "expiresAt", "timestamp(3)").
			AddRow("other", "session", "ignored", "text"))

	actual, err := Inspect(t.Context(), database, MySQL)
	if err != nil {
		t.Fatal(err)
	}
	expected := Catalog{
		Database: "auth",
		Tables: []Table{{
			Database: "auth",
			Name:     "session",
			Columns: []Column{
				{Name: "id", DataType: "varchar(36)"},
				{Name: "expiresAt", DataType: "timestamp(3)"},
			},
		}},
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("catalog = %#v, want %#v", actual, expected)
	}
	assertMigrationMockExpectations(t, mock)
}

func TestInspectMSSQLCurrentNamespace(t *testing.T) {
	tests := []struct {
		name           string
		databaseSchema any
		expectedSchema string
	}{
		{name: "configured default schema", databaseSchema: "tenant", expectedSchema: "tenant"},
		{name: "dbo fallback", databaseSchema: nil, expectedSchema: "dbo"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, mock := newMigrationMockDatabase(t)
			mock.ExpectQuery(mssqlNamespaceQuery).
				WillReturnRows(sqlmock.NewRows([]string{"database", "schema"}).AddRow("auth", test.databaseSchema))
			mock.ExpectQuery(mssqlColumnsQuery).
				WithArgs(test.expectedSchema).
				WillReturnRows(sqlmock.NewRows([]string{"database_name", "schema_name", "table_name", "column_name", "data_type"}).
					AddRow("auth", test.expectedSchema, "session", "id", "varchar").
					AddRow("auth", test.expectedSchema, "session", "expiresAt", "datetime2").
					AddRow("auth", "another_schema", "session", "ignored_schema", "varchar").
					AddRow("other", test.expectedSchema, "session", "ignored_database", "varchar"))

			actual, err := Inspect(t.Context(), database, MSSQL)
			if err != nil {
				t.Fatal(err)
			}
			expected := Catalog{
				Database: "auth",
				Schema:   test.expectedSchema,
				Tables: []Table{{
					Database: "auth",
					Schema:   test.expectedSchema,
					Name:     "session",
					Columns: []Column{
						{Name: "id", DataType: "varchar"},
						{Name: "expiresAt", DataType: "datetime2"},
					},
				}},
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("catalog = %#v, want %#v", actual, expected)
			}
			assertMigrationMockExpectations(t, mock)
		})
	}
}

func newMigrationMockDatabase(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	database, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database, mock
}

func assertMigrationMockExpectations(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
