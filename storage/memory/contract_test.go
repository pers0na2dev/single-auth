package memory_test

import (
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/adaptertest"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

func TestAdapterContract(t *testing.T) {
	fixed := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	adaptertest.Run(t, func(t *testing.T, schema storage.Schema) (storage.Adapter, error) {
		t.Helper()
		return memory.New(memory.WithSchema(schema), memory.WithClock(func() time.Time { return fixed }))
	})
}
