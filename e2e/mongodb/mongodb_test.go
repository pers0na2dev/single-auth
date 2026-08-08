package mongodb_e2e_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcmongodb "github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/adaptertest"
	mongostore "github.com/pers0na2dev/single-auth/storage/mongodb"
)

const mongoImage = "mongo:7.0.16@sha256:c630c59342c1493d50345136df2af14a76b9e827dd5316bfabee07a0880a5f3a"

func TestMongoDBAdapterContractAgainstRealReplicaSet(t *testing.T) {
	ctx := t.Context()
	container, err := tcmongodb.Run(
		ctx,
		mongoImage,
		tcmongodb.WithReplicaSet("single-rs"),
	)
	if err != nil {
		if os.Getenv("SINGLE_AUTH_E2E_REQUIRED") == "1" {
			t.Fatalf("start required MongoDB replica set: %v", err)
		}
		t.Skipf("Docker is unavailable for local MongoDB E2E: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, logErr := container.Logs(context.Background())
			if logErr == nil {
				defer logs.Close()
				if output, readErr := io.ReadAll(logs); readErr == nil {
					t.Logf("MongoDB container logs:\n%s", output)
				}
			}
		}
		if terminateErr := testcontainers.TerminateContainer(container); terminateErr != nil {
			t.Errorf("terminate MongoDB container: %v", terminateErr)
		}
	})

	connectionString, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client, err := mongo.Connect(options.Client().ApplyURI(connectionString).SetServerSelectionTimeout(15 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if disconnectErr := client.Disconnect(context.Background()); disconnectErr != nil {
			t.Errorf("disconnect MongoDB client: %v", disconnectErr)
		}
	})
	if err := client.Ping(ctx, nil); err != nil {
		t.Fatalf("ping MongoDB replica set: %v", err)
	}

	var sequence atomic.Uint64
	adaptertest.Run(t, func(t *testing.T, schema storage.Schema) (storage.Adapter, error) {
		name := fmt.Sprintf("contract_%d", sequence.Add(1))
		adapter, err := mongostore.New(client.Database(name), mongostore.Options{
			Schema: schema,
			IDType: mongostore.TextID,
		})
		if err != nil {
			return nil, err
		}
		if err := adapter.EnsureSchema(t.Context()); err != nil {
			return nil, err
		}
		return adapter, nil
	})
}
