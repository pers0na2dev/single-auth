package migration

import (
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestNativeDialectBuildSQL(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"widget": {
			Fields: map[string]storage.FieldAttribute{
				"createdAt": {Type: storage.FieldDate, DefaultValue: storage.StaticValue("now")},
				"payload":   {Type: storage.FieldJSON, Required: storage.Bool(false)},
				"slug":      {Type: storage.FieldString, Index: true},
			},
		},
	}}

	tests := []struct {
		name     string
		options  Options
		expected string
	}{
		{
			name:    "mysql",
			options: Options{Dialect: MySQL},
			expected: "CREATE TABLE `widget` (\n" +
				"  `id` VARCHAR(36) NOT NULL PRIMARY KEY,\n" +
				"  `createdAt` TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),\n" +
				"  `payload` JSON,\n" +
				"  `slug` VARCHAR(255) NOT NULL\n" +
				");\n\n" +
				"CREATE INDEX `single_widget_slug_idx` ON `widget` (`slug`);",
		},
		{
			name:    "mssql",
			options: Options{Dialect: MSSQL, IDMode: SerialID},
			expected: "CREATE TABLE [widget] (\n" +
				"  [id] INTEGER IDENTITY(1,1) NOT NULL PRIMARY KEY,\n" +
				"  [createdAt] DATETIME2(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,\n" +
				"  [payload] VARCHAR(8000),\n" +
				"  [slug] VARCHAR(255) NOT NULL\n" +
				");\n\n" +
				"CREATE INDEX [single_widget_slug_idx] ON [widget] ([slug]);",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := Build(schema, Catalog{}, test.options)
			if err != nil {
				t.Fatal(err)
			}
			if actual := plan.SQL(); actual != test.expected {
				t.Fatalf("SQL mismatch:\nactual:\n%s\nexpected:\n%s", actual, test.expected)
			}
		})
	}
}

func TestNativeDialectAddColumnSQL(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"widget": {Fields: map[string]storage.FieldAttribute{
			"slug": {Type: storage.FieldString, Index: true},
		}},
	}}

	tests := []struct {
		name     string
		dialect  Dialect
		catalog  Catalog
		expected string
	}{
		{
			name:    "mysql",
			dialect: MySQL,
			catalog: Catalog{Database: "auth", Tables: []Table{{
				Database: "auth",
				Name:     "widget",
				Columns:  []Column{{Name: "id", DataType: "varchar(36)"}},
			}}},
			expected: "ALTER TABLE `widget` ADD COLUMN `slug` VARCHAR(255) NOT NULL;\n\n" +
				"CREATE INDEX `single_widget_slug_idx` ON `widget` (`slug`);",
		},
		{
			name:    "mssql",
			dialect: MSSQL,
			catalog: Catalog{Database: "auth", Schema: "dbo", Tables: []Table{{
				Database: "auth",
				Schema:   "dbo",
				Name:     "widget",
				Columns:  []Column{{Name: "id", DataType: "varchar"}},
			}}},
			expected: "ALTER TABLE [widget] ADD [slug] VARCHAR(255) NOT NULL;\n\n" +
				"CREATE INDEX [single_widget_slug_idx] ON [widget] ([slug]);",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := Build(schema, test.catalog, Options{Dialect: test.dialect})
			if err != nil {
				t.Fatal(err)
			}
			if actual := plan.SQL(); actual != test.expected {
				t.Fatalf("SQL mismatch:\nactual:\n%s\nexpected:\n%s", actual, test.expected)
			}
		})
	}
}

func TestNativeDialectFieldSQL(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {},
		"membership": {
			Fields: map[string]storage.FieldAttribute{
				"userId": {
					Type:      storage.FieldString,
					FieldName: "user_id",
					References: &storage.Reference{
						Model:    "user",
						Field:    "id",
						OnDelete: storage.Restrict,
					},
				},
			},
		},
	}}
	field := schema.Models["membership"].Fields["userId"]

	tests := []struct {
		name          string
		dialect       Dialect
		referenceSQL  string
		foreignKeySQL string
		enumSQL       string
		identifier    string
		quoted        string
		indexSQL      string
	}{
		{
			name:         "mysql",
			dialect:      MySQL,
			referenceSQL: "`user_id` VARCHAR(36) NOT NULL",
			foreignKeySQL: "ALTER TABLE `membership` ADD CONSTRAINT `single_membership_user_id_fk` " +
				"FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE RESTRICT",
			enumSQL:    "`role` VARCHAR(255) NOT NULL CHECK (`role` IN ('member', 'owner''s'))",
			identifier: "odd`name",
			quoted:     "`odd``name`",
			indexSQL:   "CREATE UNIQUE INDEX `single_membership_user_id_idx` ON `membership` (`user_id`)",
		},
		{
			name:         "mssql",
			dialect:      MSSQL,
			referenceSQL: "[user_id] VARCHAR(36) NOT NULL",
			foreignKeySQL: "ALTER TABLE [membership] WITH CHECK ADD CONSTRAINT [single_membership_user_id_fk] " +
				"FOREIGN KEY ([user_id]) REFERENCES [user] ([id]) ON DELETE NO ACTION",
			enumSQL:    "[role] VARCHAR(255) NOT NULL CHECK ([role] IN (N'member', N'owner''s'))",
			identifier: "odd]name",
			quoted:     "[odd]]name]",
			indexSQL:   "CREATE UNIQUE INDEX [single_membership_user_id_idx] ON [membership] ([user_id])",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			referenceSQL, err := columnSQL(schema, "membership", "userId", field, Options{Dialect: test.dialect})
			if err != nil {
				t.Fatal(err)
			}
			if referenceSQL != test.referenceSQL {
				t.Fatalf("reference SQL = %q, want %q", referenceSQL, test.referenceSQL)
			}
			actualForeignKeySQL, err := foreignKeySQL(schema, "membership", "userId", field, Options{Dialect: test.dialect})
			if err != nil {
				t.Fatal(err)
			}
			if actualForeignKeySQL != test.foreignKeySQL {
				t.Fatalf("foreign-key SQL = %q, want %q", actualForeignKeySQL, test.foreignKeySQL)
			}

			enumSQL, err := columnSQL(schema, "membership", "role", storage.FieldAttribute{
				Type: storage.FieldEnum,
				Enum: []string{"member", "owner's"},
			}, Options{Dialect: test.dialect})
			if err != nil {
				t.Fatal(err)
			}
			if enumSQL != test.enumSQL {
				t.Fatalf("enum SQL = %q, want %q", enumSQL, test.enumSQL)
			}
			if actual := quoteIdentifier(test.identifier, test.dialect); actual != test.quoted {
				t.Fatalf("quoted identifier = %q, want %q", actual, test.quoted)
			}
			if actual := createIndexSQL("membership", "user_id", true, test.dialect); actual != test.indexSQL {
				t.Fatalf("index SQL = %q, want %q", actual, test.indexSQL)
			}
		})
	}
}

func TestNativeDialectDefersForeignKeysUntilAllTablesExist(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"earlyReference": {
			Order: 0,
			Fields: map[string]storage.FieldAttribute{
				"userId": {
					Type: storage.FieldString,
					References: &storage.Reference{
						Model:    "user",
						Field:    "id",
						OnDelete: storage.Cascade,
					},
				},
			},
		},
		"user": {Order: 1},
	}}

	tests := []struct {
		name       string
		dialect    Dialect
		foreignKey string
	}{
		{
			name:    "postgres",
			dialect: Postgres,
			foreignKey: "ALTER TABLE \"earlyReference\" ADD CONSTRAINT \"single_earlyReference_userId_fk\" " +
				"FOREIGN KEY (\"userId\") REFERENCES \"user\" (\"id\") ON DELETE CASCADE",
		},
		{
			name:    "mysql",
			dialect: MySQL,
			foreignKey: "ALTER TABLE `earlyReference` ADD CONSTRAINT `single_earlyReference_userId_fk` " +
				"FOREIGN KEY (`userId`) REFERENCES `user` (`id`) ON DELETE CASCADE",
		},
		{
			name:    "mssql",
			dialect: MSSQL,
			foreignKey: "ALTER TABLE [earlyReference] WITH CHECK ADD CONSTRAINT [single_earlyReference_userId_fk] " +
				"FOREIGN KEY ([userId]) REFERENCES [user] ([id]) ON DELETE CASCADE",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := Build(schema, Catalog{}, Options{Dialect: test.dialect})
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Statements) != 3 {
				t.Fatalf("statement count = %d, want 3: %#v", len(plan.Statements), plan.Statements)
			}
			if strings.Contains(plan.Statements[0], "REFERENCES") || !strings.Contains(plan.Statements[1], "CREATE TABLE") {
				t.Fatalf("foreign key was not deferred until both tables existed: %#v", plan.Statements)
			}
			if plan.Statements[2] != test.foreignKey {
				t.Fatalf("deferred foreign-key SQL = %q, want %q", plan.Statements[2], test.foreignKey)
			}
		})
	}
}

func TestNativeDialectDateDefaultsAndRollbackPolicy(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"event": {Fields: map[string]storage.FieldAttribute{
			"createdAt": {
				Type:         storage.FieldDate,
				DefaultValue: storage.StaticValue("now"),
			},
		}},
	}}

	for _, dialect := range []Dialect{SQLite, Postgres, MySQL, MSSQL} {
		t.Run(string(dialect), func(t *testing.T) {
			plan, err := Build(schema, Catalog{}, Options{Dialect: dialect})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(plan.SQL(), "DEFAULT CURRENT_TIMESTAMP") {
				t.Fatalf("date default missing from %s plan: %s", dialect, plan.SQL())
			}

			policy, err := RollbackPolicyForDialect(dialect)
			if err != nil {
				t.Fatal(err)
			}
			want := RollbackAtomic
			if dialect == MySQL {
				want = RollbackMayPartiallyApply
			}
			if policy != want {
				t.Fatalf("rollback policy = %q, want %q", policy, want)
			}
		})
	}

	if _, err := RollbackPolicyForDialect(Dialect("unknown")); err == nil {
		t.Fatal("unsupported dialect did not return a rollback-policy error")
	}
}

func TestNativeDialectKeepsNonIDStringReferenceTypesCompatible(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"oauthAccessToken": {
			Order: 0,
			Fields: map[string]storage.FieldAttribute{
				"clientId": {
					Type:  storage.FieldString,
					Index: true,
					References: &storage.Reference{
						Model:    "oauthApplication",
						Field:    "clientId",
						OnDelete: storage.Cascade,
					},
				},
			},
		},
		"oauthApplication": {
			Order: 1,
			Fields: map[string]storage.FieldAttribute{
				"clientId": {Type: storage.FieldString, Unique: true},
			},
		},
	}}

	for _, dialect := range []Dialect{MySQL, MSSQL} {
		t.Run(string(dialect), func(t *testing.T) {
			plan, err := Build(schema, Catalog{}, Options{Dialect: dialect, IDMode: SerialID})
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Statements) != 4 {
				t.Fatalf("statement count = %d, want 4: %#v", len(plan.Statements), plan.Statements)
			}
			for _, tableStatement := range plan.Statements[:2] {
				if !strings.Contains(tableStatement, "clientId") || !strings.Contains(tableStatement, "VARCHAR(255)") {
					t.Fatalf("non-ID reference types are incompatible: %#v", plan.Statements)
				}
			}
			if !strings.Contains(plan.Statements[3], "REFERENCES") || !strings.Contains(plan.Statements[3], "clientId") {
				t.Fatalf("non-ID foreign key was not deferred: %#v", plan.Statements)
			}
		})
	}
}

func TestNativeDialectObjectNamesRespectLimits(t *testing.T) {
	tests := []struct {
		name      string
		dialect   Dialect
		table     string
		field     string
		length    func(string) int
		maxLength int
	}{
		{
			name: "postgres UTF-8 bytes", dialect: Postgres,
			table: strings.Repeat("таблица", 12), field: strings.Repeat("поле", 12),
			length: func(value string) int { return len(value) }, maxLength: 63,
		},
		{
			name: "mysql UTF-8 bytes", dialect: MySQL,
			table: strings.Repeat("таблица", 12), field: strings.Repeat("поле", 12),
			length: func(value string) int { return len(value) }, maxLength: 64,
		},
		{
			name: "mssql UTF-16 units", dialect: MSSQL,
			table: strings.Repeat("table💾", 20), field: strings.Repeat("field💾", 20),
			length: utf16ObjectNameLength, maxLength: 128,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			foreignKey := databaseObjectName(test.dialect, "fk", test.table, test.field)
			if actual := test.length(foreignKey); actual > test.maxLength {
				t.Fatalf("foreign-key name length = %d, max %d: %q", actual, test.maxLength, foreignKey)
			}
			if second := databaseObjectName(test.dialect, "fk", test.table, test.field); second != foreignKey {
				t.Fatalf("foreign-key name is not deterministic: %q then %q", foreignKey, second)
			}
			other := databaseObjectName(test.dialect, "fk", test.table, test.field+"x")
			if other == foreignKey {
				t.Fatalf("different identifiers collided at %q", foreignKey)
			}
			index := indexObjectName(test.table, test.field, "idx", test.dialect)
			if actual := test.length(index); actual > test.maxLength {
				t.Fatalf("index name length = %d, max %d: %q", actual, test.maxLength, index)
			}
		})
	}
}

func TestNativeDialectFieldTypes(t *testing.T) {
	tests := []struct {
		name      string
		dialect   Dialect
		idMode    IDMode
		canonical string
		field     storage.FieldAttribute
		expected  string
	}{
		{name: "mysql text id", dialect: MySQL, canonical: "id", expected: "VARCHAR(36)"},
		{name: "mysql serial id", dialect: MySQL, idMode: SerialID, canonical: "id", expected: "INTEGER AUTO_INCREMENT"},
		{name: "mysql indexed string", dialect: MySQL, canonical: "slug", field: storage.FieldAttribute{Type: storage.FieldString, Index: true}, expected: "VARCHAR(255)"},
		{name: "mysql plain string", dialect: MySQL, canonical: "bio", field: storage.FieldAttribute{Type: storage.FieldString}, expected: "TEXT"},
		{name: "mysql date", dialect: MySQL, canonical: "createdAt", field: storage.FieldAttribute{Type: storage.FieldDate}, expected: "TIMESTAMP(3)"},
		{name: "mysql json", dialect: MySQL, canonical: "payload", field: storage.FieldAttribute{Type: storage.FieldJSON}, expected: "JSON"},
		{name: "mysql serial id reference", dialect: MySQL, idMode: SerialID, canonical: "userId", field: storage.FieldAttribute{Type: storage.FieldString, References: &storage.Reference{Model: "user", Field: "id"}}, expected: "INTEGER"},
		{name: "mysql serial non-id string reference", dialect: MySQL, idMode: SerialID, canonical: "clientId", field: storage.FieldAttribute{Type: storage.FieldString, Index: true, References: &storage.Reference{Model: "oauthApplication", Field: "clientId"}}, expected: "VARCHAR(255)"},
		{name: "mssql uuid id", dialect: MSSQL, idMode: UUIDID, canonical: "id", expected: "VARCHAR(36)"},
		{name: "mssql serial id", dialect: MSSQL, idMode: SerialID, canonical: "id", expected: "INTEGER IDENTITY(1,1)"},
		{name: "mssql sortable string", dialect: MSSQL, canonical: "slug", field: storage.FieldAttribute{Type: storage.FieldString, Sortable: true}, expected: "VARCHAR(255)"},
		{name: "mssql plain string", dialect: MSSQL, canonical: "bio", field: storage.FieldAttribute{Type: storage.FieldString}, expected: "VARCHAR(8000)"},
		{name: "mssql boolean", dialect: MSSQL, canonical: "enabled", field: storage.FieldAttribute{Type: storage.FieldBoolean}, expected: "SMALLINT"},
		{name: "mssql date", dialect: MSSQL, canonical: "createdAt", field: storage.FieldAttribute{Type: storage.FieldDate}, expected: "DATETIME2(3)"},
		{name: "mssql serial id reference", dialect: MSSQL, idMode: SerialID, canonical: "userId", field: storage.FieldAttribute{Type: storage.FieldString, References: &storage.Reference{Model: "user", Field: "id"}}, expected: "INTEGER"},
		{name: "mssql serial non-id string reference", dialect: MSSQL, idMode: SerialID, canonical: "clientId", field: storage.FieldAttribute{Type: storage.FieldString, Index: true, References: &storage.Reference{Model: "oauthApplication", Field: "clientId"}}, expected: "VARCHAR(255)"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := fieldTypeSQL(test.field, test.canonical, Options{Dialect: test.dialect, IDMode: test.idMode})
			if err != nil {
				t.Fatal(err)
			}
			if actual != test.expected {
				t.Fatalf("field type = %q, want %q", actual, test.expected)
			}
		})
	}
}

func TestNativeDialectMatchType(t *testing.T) {
	tests := []struct {
		name     string
		dialect  Dialect
		column   string
		field    storage.FieldType
		expected bool
	}{
		{name: "mysql varchar string", dialect: MySQL, column: "varchar(255)", field: storage.FieldString, expected: true},
		{name: "mysql tinyint boolean", dialect: MySQL, column: "tinyint(1)", field: storage.FieldBoolean, expected: true},
		{name: "mysql unsigned bigint number", dialect: MySQL, column: "BIGINT UNSIGNED", field: storage.FieldNumber, expected: true},
		{name: "mysql timestamp date", dialect: MySQL, column: "timestamp(3)", field: storage.FieldDate, expected: true},
		{name: "mysql json array", dialect: MySQL, column: "json", field: storage.FieldStringArray, expected: true},
		{name: "mysql text is not json", dialect: MySQL, column: "longtext", field: storage.FieldJSON, expected: false},
		{name: "mssql varchar string", dialect: MSSQL, column: "varchar(8000)", field: storage.FieldString, expected: true},
		{name: "mssql smallint boolean", dialect: MSSQL, column: "smallint", field: storage.FieldBoolean, expected: true},
		{name: "mssql datetime2 date", dialect: MSSQL, column: "datetime2(3)", field: storage.FieldDate, expected: true},
		{name: "mssql varchar json", dialect: MSSQL, column: "varchar(8000)", field: storage.FieldJSON, expected: true},
		{name: "mssql datetime is not number", dialect: MSSQL, column: "datetime2", field: storage.FieldNumber, expected: false},
		{name: "sqlite compatibility", dialect: SQLite, column: "TEXT", field: storage.FieldStringArray, expected: true},
		{name: "postgres compatibility", dialect: Postgres, column: "timestamp with time zone", field: storage.FieldDate, expected: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := MatchType(test.column, test.field, test.dialect); actual != test.expected {
				t.Fatalf("MatchType(%q, %q, %q) = %t, want %t", test.column, test.field, test.dialect, actual, test.expected)
			}
		})
	}
}

func TestNativeDialectCatalogFiltering(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"widget": {Fields: map[string]storage.FieldAttribute{"name": {Type: storage.FieldString}}},
	}}

	tests := []struct {
		name       string
		dialect    Dialect
		catalog    Catalog
		wantCreate bool
	}{
		{
			name:       "postgres ignores another database",
			dialect:    Postgres,
			catalog:    Catalog{Database: "auth", Schema: "public", Tables: []Table{{Database: "other", Schema: "public", Name: "widget", Columns: nativeCatalogColumns("text")}}},
			wantCreate: true,
		},
		{
			name:    "postgres accepts current namespace",
			dialect: Postgres,
			catalog: Catalog{Database: "auth", Schema: "tenant", Tables: []Table{{Database: "auth", Schema: "tenant", Name: "widget", Columns: nativeCatalogColumns("text")}}},
		},
		{
			name:       "mysql ignores another database",
			dialect:    MySQL,
			catalog:    Catalog{Database: "auth", Tables: []Table{{Database: "other", Name: "widget", Columns: nativeCatalogColumns("text")}}},
			wantCreate: true,
		},
		{
			name:    "mysql accepts current database",
			dialect: MySQL,
			catalog: Catalog{Database: "auth", Tables: []Table{{Database: "auth", Name: "widget", Columns: nativeCatalogColumns("text")}}},
		},
		{
			name:       "mssql ignores another database",
			dialect:    MSSQL,
			catalog:    Catalog{Database: "auth", Schema: "dbo", Tables: []Table{{Database: "other", Schema: "dbo", Name: "widget", Columns: nativeCatalogColumns("varchar")}}},
			wantCreate: true,
		},
		{
			name:       "mssql ignores another schema",
			dialect:    MSSQL,
			catalog:    Catalog{Database: "auth", Schema: "tenant", Tables: []Table{{Database: "auth", Schema: "dbo", Name: "widget", Columns: nativeCatalogColumns("varchar")}}},
			wantCreate: true,
		},
		{
			name:    "mssql accepts current namespace",
			dialect: MSSQL,
			catalog: Catalog{Database: "auth", Schema: "tenant", Tables: []Table{{Database: "auth", Schema: "tenant", Name: "widget", Columns: nativeCatalogColumns("varchar")}}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := Build(schema, test.catalog, Options{Dialect: test.dialect})
			if err != nil {
				t.Fatal(err)
			}
			created := len(plan.ToBeCreated) == 1 && plan.ToBeCreated[0].Table == "widget"
			if created != test.wantCreate {
				t.Fatalf("created widget = %t, want %t; SQL = %s", created, test.wantCreate, plan.SQL())
			}
			if !test.wantCreate && (len(plan.ToBeAdded) != 0 || plan.SQL() != ";") {
				t.Fatalf("matching catalog produced migration: %#v", plan)
			}
		})
	}
}

func TestMySQLRejectsUnsupportedReferenceActions(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"parent": {},
		"child": {
			Fields: map[string]storage.FieldAttribute{
				"parentId": {
					Type: storage.FieldString,
					References: &storage.Reference{
						Model:    "parent",
						Field:    "id",
						OnDelete: storage.SetDefault,
					},
				},
			},
		},
	}}

	_, err := Build(schema, Catalog{}, Options{Dialect: MySQL})
	if err == nil || !strings.Contains(err.Error(), "does not support ON DELETE SET DEFAULT") {
		t.Fatalf("Build error = %v", err)
	}
}

func nativeCatalogColumns(stringType string) []Column {
	return []Column{{Name: "id", DataType: stringType}, {Name: "name", DataType: stringType}}
}
