package sqlite_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"sync"
	"testing"

	modernsqlite "modernc.org/sqlite"
)

type sqliteTraceStatement struct {
	SQL           string
	ArgumentCount int
}

type sqliteTraceLog struct {
	mu         sync.Mutex
	statements []sqliteTraceStatement
}

func (log *sqliteTraceLog) Add(query string, argumentCount int) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.statements = append(log.statements, sqliteTraceStatement{
		SQL:           query,
		ArgumentCount: argumentCount,
	})
}

func (log *sqliteTraceLog) Reset() {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.statements = nil
}

func (log *sqliteTraceLog) Snapshot() []sqliteTraceStatement {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]sqliteTraceStatement(nil), log.statements...)
}

type sqliteTraceDriver struct {
	inner driver.Driver
	log   *sqliteTraceLog
}

func (traceDriver *sqliteTraceDriver) Open(name string) (driver.Conn, error) {
	connection, err := traceDriver.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &sqliteTraceConnection{Conn: connection, log: traceDriver.log}, nil
}

type sqliteTraceConnector struct {
	driver *sqliteTraceDriver
	dsn    string
}

func (connector *sqliteTraceConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return connector.driver.Open(connector.dsn)
}

func (connector *sqliteTraceConnector) Driver() driver.Driver { return connector.driver }

type sqliteTraceConnection struct {
	driver.Conn
	log *sqliteTraceLog
}

func (connection *sqliteTraceConnection) ExecContext(
	ctx context.Context,
	query string,
	args []driver.NamedValue,
) (driver.Result, error) {
	connection.log.Add(query, len(args))
	execer, ok := connection.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return execer.ExecContext(ctx, query, args)
}

func (connection *sqliteTraceConnection) QueryContext(
	ctx context.Context,
	query string,
	args []driver.NamedValue,
) (driver.Rows, error) {
	connection.log.Add(query, len(args))
	queryer, ok := connection.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return queryer.QueryContext(ctx, query, args)
}

func (connection *sqliteTraceConnection) PrepareContext(
	ctx context.Context,
	query string,
) (driver.Stmt, error) {
	if preparer, ok := connection.Conn.(driver.ConnPrepareContext); ok {
		return preparer.PrepareContext(ctx, query)
	}
	return connection.Conn.Prepare(query)
}

func (connection *sqliteTraceConnection) BeginTx(
	ctx context.Context,
	options driver.TxOptions,
) (driver.Tx, error) {
	if beginner, ok := connection.Conn.(driver.ConnBeginTx); ok {
		return beginner.BeginTx(ctx, options)
	}
	return connection.Conn.Begin()
}

func (connection *sqliteTraceConnection) Ping(ctx context.Context) error {
	if pinger, ok := connection.Conn.(driver.Pinger); ok {
		return pinger.Ping(ctx)
	}
	return nil
}

func (connection *sqliteTraceConnection) ResetSession(ctx context.Context) error {
	if resetter, ok := connection.Conn.(driver.SessionResetter); ok {
		return resetter.ResetSession(ctx)
	}
	return nil
}

func (connection *sqliteTraceConnection) IsValid() bool {
	if validator, ok := connection.Conn.(driver.Validator); ok {
		return validator.IsValid()
	}
	return true
}

func openTracedSQLiteDatabase(t *testing.T) (*sql.DB, *sqliteTraceLog) {
	t.Helper()
	statements := &sqliteTraceLog{}
	traceDriver := &sqliteTraceDriver{inner: &modernsqlite.Driver{}, log: statements}
	database := sql.OpenDB(&sqliteTraceConnector{driver: traceDriver, dsn: ":memory:"})
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close traced SQLite database: %v", err)
		}
	})
	if err := database.PingContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	return database, statements
}

var _ driver.Driver = (*sqliteTraceDriver)(nil)
var _ driver.Connector = (*sqliteTraceConnector)(nil)
var _ driver.ExecerContext = (*sqliteTraceConnection)(nil)
var _ driver.QueryerContext = (*sqliteTraceConnection)(nil)
var _ driver.ConnPrepareContext = (*sqliteTraceConnection)(nil)
var _ driver.ConnBeginTx = (*sqliteTraceConnection)(nil)
var _ driver.Pinger = (*sqliteTraceConnection)(nil)
var _ driver.SessionResetter = (*sqliteTraceConnection)(nil)
var _ driver.Validator = (*sqliteTraceConnection)(nil)
