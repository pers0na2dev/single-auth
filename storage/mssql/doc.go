// Package mssql implements the single-auth storage contract on top of an
// already opened SQL Server database/sql handle.
//
// The package is driver-neutral: callers select and configure a SQL Server
// driver, open the *sql.DB, and retain ownership of its lifetime. Generated
// statements use SQL Server's @pN parameter syntax and require SQL Server 2016
// or newer (database compatibility level 130 or newer) for OPENJSON queries.
//
// reference implementation's MSSQL scalar contract stores JSON and arrays in VARCHAR,
// booleans in SMALLINT, and dates in DATETIME2(3). Dates are encoded as UTC ISO
// strings and zone-less DATETIME2 values returned by a driver are interpreted
// as UTC.
//
// Create, single-row update, ConsumeOne, and IncrementOne use OUTPUT to return
// the affected row in one statement. SQL Server tables with enabled triggers
// for those DML actions are not supported because SQL Server rejects OUTPUT
// without OUTPUT INTO on such a target.
package mssql
