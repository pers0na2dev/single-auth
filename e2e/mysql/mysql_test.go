package mysql_e2e_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	gomysql "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/adaptertest"
	mysqlstore "github.com/pers0na2dev/single-auth/storage/mysql"
)

const mysqlImage = "mysql:8.4.4@sha256:23818b7d7de427096ab1427b2e3d9d5e14a5b933f9a4431a482d6414bc879091"

func TestMySQLAdapterContractAgainstRealServer(t *testing.T) {
	ctx := t.Context()
	container, err := testcontainers.Run(
		ctx,
		mysqlImage,
		testcontainers.WithEnv(map[string]string{
			"MYSQL_DATABASE":      "single_auth",
			"MYSQL_ROOT_PASSWORD": "single_auth_e2e",
		}),
		testcontainers.WithExposedPorts("3306/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("port: 3306  MySQL Community Server - GPL.").
				WithOccurrence(1).
				WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		if os.Getenv("SINGLE_AUTH_E2E_REQUIRED") == "1" {
			t.Fatalf("start required MySQL container: %v", err)
		}
		t.Skipf("Docker is unavailable for local MySQL E2E: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, logErr := container.Logs(context.Background())
			if logErr == nil {
				defer logs.Close()
				if output, readErr := io.ReadAll(logs); readErr == nil {
					t.Logf("MySQL container logs:\n%s", output)
				}
			}
		}
		if terminateErr := testcontainers.TerminateContainer(container); terminateErr != nil {
			t.Errorf("terminate MySQL container: %v", terminateErr)
		}
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, "3306/tcp")
	if err != nil {
		t.Fatal(err)
	}
	baseConfig := gomysql.Config{
		User:                 "root",
		Passwd:               "single_auth_e2e",
		Net:                  "tcp",
		Addr:                 net.JoinHostPort(host, port.Port()),
		DBName:               "single_auth",
		AllowNativePasswords: true,
		ParseTime:            true,
		Loc:                  time.UTC,
		InterpolateParams:    true,
	}
	adminDB, err := sql.Open("mysql", baseConfig.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := adminDB.Close(); closeErr != nil {
			t.Errorf("close MySQL admin handle: %v", closeErr)
		}
	})
	if err := adminDB.PingContext(ctx); err != nil {
		t.Fatalf("ping MySQL: %v", err)
	}

	var sequence atomic.Uint64
	adaptertest.Run(t, func(t *testing.T, schema storage.Schema) (storage.Adapter, error) {
		name := fmt.Sprintf("contract_%d", sequence.Add(1))
		if _, err := adminDB.ExecContext(t.Context(), "CREATE DATABASE `"+name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"); err != nil {
			return nil, fmt.Errorf("create isolated database %s: %w", name, err)
		}
		config := baseConfig
		config.DBName = name
		db, err := sql.Open("mysql", config.FormatDSN())
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("close MySQL contract handle: %v", closeErr)
			}
		})
		if err := db.PingContext(t.Context()); err != nil {
			return nil, err
		}
		adapter, err := mysqlstore.New(db, mysqlstore.Options{Schema: schema})
		if err != nil {
			return nil, err
		}
		if err := adapter.EnsureSchema(t.Context()); err != nil {
			return nil, err
		}
		return adapter, nil
	})
}
