package postgres_e2e_test

import (
	"context"
	"database/sql"
	"io"
	"net"
	"net/url"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/plugins/bearer"
	"github.com/pers0na2dev/single-auth/storage"
	postgresstore "github.com/pers0na2dev/single-auth/storage/postgres"
)

type dbBehaviorOracle struct {
	Tests []dbBehaviorOracleTest
}

type dbBehaviorOracleTest struct {
	Suite       string
	Title       string
	Observation dbBehaviorObservation
}

type dbBehaviorObservation struct {
	Image               string `json:"image"`
	Callback            bool   `json:"callback"`
	ResultIDMatches     bool   `json:"resultIDMatches"`
	StoredIDMatches     bool   `json:"storedIDMatches"`
	StoredEmailMatches  bool   `json:"storedEmailMatches"`
	UserDeleteBefore    int    `json:"userDeleteBefore"`
	UserDeleteAfter     int    `json:"userDeleteAfter"`
	SessionDeleteBefore int    `json:"sessionDeleteBefore"`
	SessionDeleteAfter  int    `json:"sessionDeleteAfter"`
	BeforeUserMatches   bool   `json:"beforeUserMatches"`
	AfterUserMatches    bool   `json:"afterUserMatches"`
	BeforeContextObject bool   `json:"beforeContextObject"`
	AfterContextObject  bool   `json:"afterContextObject"`
	Rejected            bool   `json:"rejected"`
	Email               string `json:"email"`
	ResponseDataDefined bool   `json:"responseDataDefined"`
	Users               int    `json:"users"`
	Sessions            int    `json:"sessions"`
	Accounts            int    `json:"accounts"`
}

func TestDatabaseRuntimeBehavior(t *testing.T) {
	oracle := loadDBBehaviorOracle(t)
	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			var actual dbBehaviorObservation
			switch vector.Title {
			case "db hooks":
				actual = runDBHooksBehavior(t)
			case "db hooks should preserve a forced UUID on postgres when generateId is uuid":
				actual = runForcedUUIDBehavior(t, postgresImage)
			case "delete hooks":
				actual = runDeleteHooksBehavior(t, false)
			case "delete hooks abort":
				actual = runDeleteHooksBehavior(t, true)
			case "should work with custom field names":
				actual = runCustomFieldNamesBehavior(t)
			case "should work with custom model names":
				actual = runCustomModelNamesBehavior(t)
			default:
				t.Fatalf("unknown database scenario %q", vector.Title)
			}
			if !reflect.DeepEqual(actual, vector.Observation) {
				t.Fatalf("database observation = %#v, want %#v", actual, vector.Observation)
			}
		})
	}
}

func runDBHooksBehavior(t *testing.T) dbBehaviorObservation {
	t.Helper()
	var callback atomic.Bool
	auth := newDBBehaviorAuth(t, singleauth.Options{
		DatabaseHooks: singleauth.DatabaseHooks{
			"user": {Create: singleauth.DatabaseOperationHooks{
				Before: func(user storage.Record, _ singleauth.DatabaseHookContext) (singleauth.DatabaseHookResult, error) {
					return singleauth.DatabaseHookResult{Data: storage.Record{"image": "test-image"}}, nil
				},
				After: func(any, singleauth.DatabaseHookContext) error {
					callback.Store(true)
					return nil
				},
			}},
		},
	})
	created := dbBehaviorSignUp(t, auth, "test@email.com", "test")
	session, err := auth.API().GetSession(t.Context(), singleauth.GetSessionInput{
		Headers: dbBehaviorBearerHeaders(t, created),
	})
	if err != nil || session == nil {
		t.Fatalf("get hook session = %#v, %v", session, err)
	}
	return dbBehaviorObservation{
		Image:    session.User.Image.Or(""),
		Callback: callback.Load(),
	}
}

func runCustomFieldNamesBehavior(t *testing.T) dbBehaviorObservation {
	t.Helper()
	auth := newDBBehaviorAuth(t, singleauth.Options{
		Schema: storage.Schema{Models: map[string]storage.ModelSchema{
			"user": {Fields: map[string]storage.FieldAttribute{
				"email": {
					Type: storage.FieldString, FieldName: "email_address",
					Unique: true, Sortable: true,
				},
			}},
		}},
	})
	created := dbBehaviorSignUp(t, auth, "test@email.com", "Test User")
	session, err := auth.API().GetSession(t.Context(), singleauth.GetSessionInput{
		Headers: dbBehaviorBearerHeaders(t, created),
	})
	if err != nil || session == nil {
		t.Fatalf("get custom-field session = %#v, %v", session, err)
	}
	return dbBehaviorObservation{Email: session.User.Email}
}

func runCustomModelNamesBehavior(t *testing.T) dbBehaviorObservation {
	t.Helper()
	auth := newDBBehaviorAuth(t, singleauth.Options{
		Schema: storage.Schema{Models: map[string]storage.ModelSchema{
			"user":    {ModelName: "users"},
			"session": {ModelName: "sessions"},
			"account": {ModelName: "accounts"},
		}},
	})
	dbBehaviorSignUp(t, auth, "test@test.com", "test user")
	created, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Email: "test@email2.com", Password: "password", Name: "Test User",
	})
	if err != nil {
		t.Fatalf("custom-model sign-up: %v", err)
	}
	counts := make(map[string]int, 3)
	for _, modelName := range []string{"user", "session", "account"} {
		rows, findErr := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: modelName})
		if findErr != nil {
			t.Fatalf("find custom model %s: %v", modelName, findErr)
		}
		counts[modelName] = len(rows)
	}
	return dbBehaviorObservation{
		ResponseDataDefined: created.User.ID != "",
		Users:               counts["user"], Sessions: counts["session"], Accounts: counts["account"],
	}
}

func runDeleteHooksBehavior(t *testing.T, abort bool) dbBehaviorObservation {
	t.Helper()
	var userDeleteBefore atomic.Int64
	var userDeleteAfter atomic.Int64
	var sessionDeleteBefore atomic.Int64
	var sessionDeleteAfter atomic.Int64
	var beforeUserMatches atomic.Bool
	var afterUserMatches atomic.Bool
	var beforeContextObject atomic.Bool
	var afterContextObject atomic.Bool

	email := "delete-test@email.com"
	name := "Delete Test User"
	if abort {
		email = "abort-delete-test@email.com"
		name = "Abort Delete Test User"
	}
	var userID string
	auth := newDBBehaviorAuth(t, singleauth.Options{
		User:    singleauth.UserOptions{DeleteUser: singleauth.DeleteUserOptions{Enabled: true}},
		Session: singleauth.SessionOptions{StoreSessionInDatabase: !abort},
		DatabaseHooks: singleauth.DatabaseHooks{
			"user": {Delete: singleauth.DatabaseOperationHooks{
				Before: func(user storage.Record, context singleauth.DatabaseHookContext) (singleauth.DatabaseHookResult, error) {
					userDeleteBefore.Add(1)
					beforeUserMatches.Store(
						dbBehaviorRecordString(user, "id") == userID &&
							dbBehaviorRecordString(user, "email") == email &&
							dbBehaviorRecordString(user, "name") == name,
					)
					beforeContextObject.Store(context.Context != nil && context.Endpoint != nil)
					return singleauth.DatabaseHookResult{Cancel: abort}, nil
				},
				After: func(value any, context singleauth.DatabaseHookContext) error {
					userDeleteAfter.Add(1)
					user, _ := value.(storage.Record)
					afterUserMatches.Store(
						dbBehaviorRecordString(user, "id") == userID &&
							dbBehaviorRecordString(user, "email") == email &&
							dbBehaviorRecordString(user, "name") == name,
					)
					afterContextObject.Store(context.Context != nil && context.Endpoint != nil)
					return nil
				},
			}},
			"session": {Delete: singleauth.DatabaseOperationHooks{
				Before: func(storage.Record, singleauth.DatabaseHookContext) (singleauth.DatabaseHookResult, error) {
					sessionDeleteBefore.Add(1)
					return singleauth.DatabaseHookResult{}, nil
				},
				After: func(any, singleauth.DatabaseHookContext) error {
					sessionDeleteAfter.Add(1)
					return nil
				},
			}},
		},
	})
	created := dbBehaviorSignUp(t, auth, email, name)
	userID = created.User.ID
	_, err := auth.API().DeleteUser(t.Context(), singleauth.DeleteUserInput{
		Headers: dbBehaviorBearerHeaders(t, created),
	})
	observation := dbBehaviorObservation{
		UserDeleteBefore:    int(userDeleteBefore.Load()),
		UserDeleteAfter:     int(userDeleteAfter.Load()),
		BeforeUserMatches:   beforeUserMatches.Load(),
		BeforeContextObject: beforeContextObject.Load(),
		Rejected:            err != nil,
	}
	if !abort {
		observation.SessionDeleteBefore = int(sessionDeleteBefore.Load())
		observation.SessionDeleteAfter = int(sessionDeleteAfter.Load())
		observation.AfterUserMatches = afterUserMatches.Load()
		observation.AfterContextObject = afterContextObject.Load()
	}
	return observation
}

func runForcedUUIDBehavior(t *testing.T, image string) dbBehaviorObservation {
	t.Helper()
	adapter := startDBBehaviorPostgres(t, image)
	const existingID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
	const email = "forced-id-runtime@test.com"
	auth := newDBBehaviorAuth(t, singleauth.Options{
		Database: adapter,
		GenerateID: func(model string, _ int) (string, bool, error) {
			switch model {
			case "user":
				return "11111111-1111-4111-8111-111111111111", true, nil
			case "account":
				return "22222222-2222-4222-8222-222222222222", true, nil
			case "session":
				return "33333333-3333-4333-8333-333333333333", true, nil
			default:
				return "44444444-4444-4444-8444-444444444444", true, nil
			}
		},
		DatabaseHooks: singleauth.DatabaseHooks{
			"user": {Create: singleauth.DatabaseOperationHooks{
				Before: func(storage.Record, singleauth.DatabaseHookContext) (singleauth.DatabaseHookResult, error) {
					return singleauth.DatabaseHookResult{Data: storage.Record{"id": existingID}}, nil
				},
			}},
		},
	})
	created, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Email: email, Name: "forced-id-user", Password: "password",
	})
	if err != nil {
		t.Fatalf("forced UUID sign-up: %v", err)
	}
	stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: existingID}},
	})
	if err != nil {
		t.Fatalf("find forced UUID user: %v", err)
	}
	return dbBehaviorObservation{
		ResultIDMatches:    created.User.ID == existingID,
		StoredIDMatches:    dbBehaviorRecordString(stored, "id") == existingID,
		StoredEmailMatches: dbBehaviorRecordString(stored, "email") == email,
	}
}

func newDBBehaviorAuth(t *testing.T, options singleauth.Options) *singleauth.Auth {
	t.Helper()
	options.BaseURL = "http://localhost:3000"
	options.Secret = "single-auth-db-behavior-secret-01234567890123456789"
	options.EmailAndPassword.Enabled = true
	options.EmailAndPassword.Password = singleauth.PasswordOptions{
		Hash:   func(password string) (string, error) { return password, nil },
		Verify: func(hash, password string) bool { return hash == password },
	}
	options.PluginFactories = append(options.PluginFactories, bearer.NewFactory(bearer.Options{}))
	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func dbBehaviorSignUp(t *testing.T, auth *singleauth.Auth, email, name string) singleauth.SignUpEmailResult {
	t.Helper()
	result, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Email: email, Name: name, Password: "password",
	})
	if err != nil || result.Token == nil {
		t.Fatalf("sign-up %s = %#v, %v", email, result, err)
	}
	return result
}

func dbBehaviorBearerHeaders(t *testing.T, result singleauth.SignUpEmailResult) contract.Headers {
	t.Helper()
	if result.Token == nil {
		t.Fatal("sign-up returned no bearer token")
	}
	return contract.NewHeaders(contract.HeaderField{
		Name: "Authorization", Value: "Bearer " + *result.Token,
	})
}

func dbBehaviorRecordString(record storage.Record, field string) string {
	if record == nil {
		return ""
	}
	value, _ := record[field].(string)
	return value
}

func startDBBehaviorPostgres(t *testing.T, image string) *postgresstore.Adapter {
	t.Helper()
	ctx := t.Context()
	container, err := testcontainers.Run(
		ctx,
		image,
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_DB":       "single_auth",
			"POSTGRES_USER":     "user",
			"POSTGRES_PASSWORD": "password",
		}),
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		if os.Getenv("SINGLE_AUTH_E2E_REQUIRED") == "1" {
			t.Fatalf("start required PostgreSQL container: %v", err)
		}
		t.Skipf("Docker is unavailable for reference implementation database behavior: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, logErr := container.Logs(context.Background())
			if logErr == nil {
				defer logs.Close()
				if output, readErr := io.ReadAll(logs); readErr == nil {
					t.Logf("PostgreSQL container logs:\n%s", output)
				}
			}
		}
		if terminateErr := testcontainers.TerminateContainer(container); terminateErr != nil {
			t.Errorf("terminate PostgreSQL database behavior container: %v", terminateErr)
		}
	})
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatal(err)
	}
	dsn := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword("user", "password"),
		Host:   net.JoinHostPort(host, port.Port()),
		Path:   "/single_auth",
	}
	query := dsn.Query()
	query.Set("sslmode", "disable")
	dsn.RawQuery = query.Encode()
	database, err := sql.Open("pgx", dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Errorf("close PostgreSQL database behavior handle: %v", closeErr)
		}
	})
	if err := database.PingContext(ctx); err != nil {
		t.Fatalf("ping PostgreSQL database behavior server: %v", err)
	}
	schema := storage.CoreSchema()
	delete(schema.Models, "rateLimit")
	adapter, err := postgresstore.New(database, postgresstore.Options{
		Schema: schema, IDType: postgresstore.UUIDID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure PostgreSQL database behavior schema: %v", err)
	}
	return adapter
}

func loadDBBehaviorOracle(t *testing.T) dbBehaviorOracle {
	t.Helper()
	oracle := dbBehaviorOracle{Tests: dbBehaviorScenarios}
	if len(oracle.Tests) != 6 {
		t.Fatalf("database scenarios=%d, want 6", len(oracle.Tests))
	}
	seen := make(map[string]struct{}, len(oracle.Tests))
	for _, vector := range oracle.Tests {
		if vector.Suite == "" || vector.Title == "" {
			t.Fatalf("invalid database scenario: %#v", vector)
		}
		key := vector.Suite + "::" + vector.Title
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("duplicate database scenario %q", key)
		}
		seen[key] = struct{}{}
	}
	return oracle
}
