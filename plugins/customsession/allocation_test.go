package customsession

import (
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func TestPluginInstancesStayBelowFrozenFiveKiBAllocationBudget(t *testing.T) {
	result := testing.Benchmark(func(benchmark *testing.B) {
		for index := 0; index < benchmark.N; index++ {
			iteration := index
			descriptor, err := New(Options{
				Enrich: func(SessionData, *engine.Context) (any, error) {
					return map[string]any{"iteration": iteration}, nil
				},
				Runtime: Runtime{GetSession: func(*engine.Context) (contract.Response, error) {
					return contract.JSONResponse(200, nil)
				}},
			})
			if err != nil || descriptor.ID != "custom-session" {
				benchmark.Fatalf("descriptor=%#v err=%v", descriptor, err)
			}
		}
	})
	if bytes := result.AllocedBytesPerOp(); bytes >= 5*1024 {
		t.Fatalf("custom-session allocation = %d bytes/instance, want < 5120", bytes)
	}
}
