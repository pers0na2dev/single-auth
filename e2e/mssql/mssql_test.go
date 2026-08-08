package mssql_e2e_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"testing"

	_ "github.com/microsoft/go-mssqldb"
	"github.com/testcontainers/testcontainers-go"
	tcmssql "github.com/testcontainers/testcontainers-go/modules/mssql"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/adaptertest"
	mssqlstore "github.com/pers0na2dev/single-auth/storage/mssql"
)

const mssqlImage = "mcr.microsoft.com/mssql/server:2022-latest@sha256:ba4c8329f48fb8f02e1416be6a930ebfd71268caee78aa985f3af4315e457c89"

func TestMSSQLAdapterContractAgainstRealServer(t *testing.T) {
	ctx := t.Context()
	container, err := tcmssql.Run(
		ctx,
		mssqlImage,
		tcmssql.WithAcceptEULA(),
		tcmssql.WithPassword("Strong@Passw0rd"),
	)
	if err != nil {
		if os.Getenv("SINGLE_AUTH_E2E_REQUIRED") == "1" {
			t.Fatalf("start required SQL Server container: %v", err)
		}
		t.Skipf("Docker cannot run the local SQL Server E2E image: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, logErr := container.Logs(context.Background())
			if logErr == nil {
				defer logs.Close()
				if output, readErr := io.ReadAll(logs); readErr == nil {
					t.Logf("SQL Server container logs:\n%s", output)
				}
			}
		}
		if terminateErr := testcontainers.TerminateContainer(container); terminateErr != nil {
			t.Errorf("terminate SQL Server container: %v", terminateErr)
		}
	})

	adminDSN, err := container.ConnectionString(ctx, "database=master", "encrypt=false", "TrustServerCertificate=true")
	if err != nil {
		t.Fatal(err)
	}
	adminDB, err := sql.Open("sqlserver", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := adminDB.Close(); closeErr != nil {
			t.Errorf("close SQL Server admin handle: %v", closeErr)
		}
	})
	if err := adminDB.PingContext(ctx); err != nil {
		t.Fatalf("ping SQL Server: %v", err)
	}

	var sequence atomic.Uint64
	adaptertest.Run(t, func(t *testing.T, schema storage.Schema) (storage.Adapter, error) {
		name := fmt.Sprintf("contract_%d", sequence.Add(1))
		if _, err := adminDB.ExecContext(t.Context(), "CREATE DATABASE ["+name+"]"); err != nil {
			return nil, fmt.Errorf("create isolated database %s: %w", name, err)
		}
		dsn, err := container.ConnectionString(t.Context(), "database="+name, "encrypt=false", "TrustServerCertificate=true")
		if err != nil {
			return nil, err
		}
		db, err := sql.Open("sqlserver", dsn)
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("close SQL Server contract handle: %v", closeErr)
			}
		})
		if err := db.PingContext(t.Context()); err != nil {
			return nil, err
		}
		adapter, err := mssqlstore.New(db, mssqlstore.Options{Schema: schema})
		if err != nil {
			return nil, err
		}
		if err := adapter.EnsureSchema(t.Context()); err != nil {
			return nil, err
		}
		return adapter, nil
	})
}
