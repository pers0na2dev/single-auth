package migration

var migrationScenarios = []migrationCase{
	{ID: "should generate valid PostgreSQL CREATE INDEX syntax for indexed columns added to existing tables", Dialect: Postgres, Observed: map[string]any{"toCreate": []any{}, "toAdd": map[string]any{"user": []any{"externalId"}}, "containsCreateIndex": true, "containsAddIndex": false}},
	{ID: "should update default tables with plugin schema fields", Dialect: Postgres, Observed: map[string]any{"toCreate": []any{}, "toAdd": map[string]any{"session": []any{"impersonatedBy"}, "user": []any{"role"}}}},
	{ID: "should use GENERATED ALWAYS AS IDENTITY instead of SERIAL when `advanced.database.generateId` is set to 'serial'", Dialect: Postgres, Observed: map[string]any{"containsIdentity": true, "containsSerial": false, "identityCount": float64(4)}},
	{ID: "should create tables in custom schema when running migrations", Dialect: Postgres, Observed: map[string]any{"tables": []any{"account", "session", "user", "verification"}, "containsCore": true}},
	{ID: "should detect custom schema from search_path", Dialect: Postgres, Observed: map[string]any{"toCreate": []any{"account", "session", "user", "verification"}, "toAdd": map[string]any{}, "userFields": []any{"createdAt", "email", "emailVerified", "image", "name", "updatedAt"}}},
	{ID: "should detect custom schema with CamelCasePlugin enabled", Dialect: Postgres, Observed: map[string]any{"toCreate": []any{"account", "session", "verification"}, "toAdd": map[string]any{}}},
	{ID: "should not be affected by tables in public schema when using custom schema", Dialect: Postgres, Observed: map[string]any{"toCreate": []any{"account", "session", "user", "verification"}, "publicUserCount": float64(1)}},
	{ID: "should only inspect tables in public schema when using default connection", Dialect: Postgres, Observed: map[string]any{"toCreate": []any{"account", "session", "verification"}, "toAdd": map[string]any{}}},
	{ID: "should use uuid for id when `advanced.database.generateId` is set to 'uuid'", Dialect: Postgres, Observed: map[string]any{"uuid": true, "secondSQL": ";"}},
	{ID: "should enforce unique indexed fields on new tables without a duplicate index", Dialect: SQLite, Observed: map[string]any{"toCreate": []any{"account", "session", "uniqueTable", "user", "verification"}, "inlineUnique": true, "hasDuplicateUniqueIndex": false, "duplicateRejected": true}},
	{ID: "should execute runMigrations when adding a new table with indexed columns to an existing database", Dialect: SQLite, Observed: map[string]any{"toCreate": []any{"apikey"}, "toAdd": map[string]any{}, "runSucceeded": true}},
	{ID: "should execute runMigrations when upgrading an existing table with new indexed columns (simulates 1.4.x -> latest)", Dialect: SQLite, Observed: map[string]any{"toCreate": []any{}, "toAdd": map[string]any{"apikey": []any{"configId", "referenceId"}}, "runSucceeded": true}},
	{ID: "should execute runMigrations without error when adding indexed columns to existing tables", Dialect: SQLite, Observed: map[string]any{"toCreate": []any{}, "toAdd": map[string]any{"user": []any{"externalId"}}, "runSucceeded": true}},
	{ID: "should not detect migration changes for SQLite bigint fields on subsequent runs", Dialect: SQLite, Observed: map[string]any{"toCreate": []any{}, "toAdd": map[string]any{}, "sql": ";"}},
	{ID: "should use CREATE INDEX when adding indexed columns to existing SQLite tables", Dialect: SQLite, Observed: map[string]any{"toCreate": []any{}, "toAdd": map[string]any{"user": []any{"externalId"}}, "containsCreateIndex": true, "containsAddIndex": false}},
}
