# single-auth E2E

This nested Go module owns integration-only dependencies and runs adapter
contracts against real services. It is intentionally excluded from the root
`go test ./...` package graph.

Docker must be available. Run the real-service profiles with:

```sh
go test ./redis ./postgres ./mysql ./mongodb ./mssql -count=1
```

CI must set `SINGLE_AUTH_E2E_REQUIRED=1`. When that variable is absent, a local
machine without a healthy Docker daemon may skip the suite explicitly.

Container images are pinned per frozen Better Auth baseline. A version change
must be reviewed as a separate storage-matrix change.

| Profile | Real service | Contract focus |
| --- | --- | --- |
| `redis` | Redis 7.4.2 | TTL, key listing/clear, atomic consume and increment |
| `postgres` | PostgreSQL 17.4 | Full adapter contract and transactions |
| `mysql` | MySQL 8.4.4 | Full adapter contract and transactions |
| `mongodb` | MongoDB 7.0.16 replica set | Full adapter contract and transactions |
| `mssql` | SQL Server 2022 | Full adapter contract and transactions |

The GitHub Actions storage matrix runs one backend per job with required mode
enabled. Container startup failures therefore fail CI instead of becoming
successful skips. Failed tests attach the corresponding service log to the Go
test output; credentials are never printed by the harness.
