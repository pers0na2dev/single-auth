package memory_test

import (
	"strings"
	"testing"
)

func TestMemoryAdapterBehavior(t *testing.T) {
	oracle := loadMemoryAdapterOracle(t)
	executed := make(map[string]struct{}, len(oracle.UpstreamTests))
	for _, vector := range oracle.UpstreamTests {
		vector := vector
		// Pass the frozen upstream title itself to testing.T.Run. The testing
		// package may sanitize it for terminal display, but the vector-to-subtest
		// The binding retains the exact ANSI-bearing scenario title and stable ID.
		t.Run(vector.Title, func(t *testing.T) {
			if _, duplicate := executed[vector.ID]; duplicate {
				t.Fatalf("vector executed more than once: %s", vector.ID)
			}
			executed[vector.ID] = struct{}{}
			runMemoryAdapterVector(t, vector)
		})
	}
	if len(executed) != 455 {
		t.Fatalf("executed vectors=%d, want 455", len(executed))
	}
}

func runMemoryAdapterVector(t *testing.T, vector memoryAdapterVector) {
	t.Helper()
	if vector.Scenario == "suite-banner" {
		harness := newMemoryBehaviorHarness(t, vector)
		if harness.adapter.ID() != "memory" || !harness.adapter.Capabilities().AtomicIncrement ||
			!harness.adapter.Capabilities().Joins {
			t.Fatalf("suite initialization failed: id=%q capabilities=%#v", harness.adapter.ID(), harness.adapter.Capabilities())
		}
		return
	}
	if vector.Profile == "auth-flow" {
		runMemoryAuthFlowScenario(t, vector)
		return
	}
	if vector.Profile == "transactions" {
		runMemoryTransactionScenario(t, vector)
		return
	}

	harness := newMemoryBehaviorHarness(t, vector)
	operation, description, ok := strings.Cut(vector.Scenario, " ─ ")
	if !ok {
		t.Fatalf("invalid operation scenario %q", vector.Scenario)
	}
	switch operation {
	case "init":
		runMemoryInitScenario(t, harness, vector, description)
	case "create":
		runMemoryCreateScenario(t, harness, vector, description)
	case "findOne":
		runMemoryFindOneScenario(t, harness, vector, description)
	case "findMany":
		runMemoryFindManyScenario(t, harness, vector, description)
	case "count":
		runMemoryCountScenario(t, harness, description)
	case "update":
		runMemoryUpdateScenario(t, harness, description)
	case "updateMany":
		runMemoryUpdateManyScenario(t, harness, description)
	case "incrementOne":
		runMemoryIncrementOneScenario(t, harness, description)
	case "delete":
		runMemoryDeleteScenario(t, harness, description)
	case "deleteMany":
		runMemoryDeleteManyScenario(t, harness, description)
	default:
		t.Fatalf("unsupported operation %q for %q", operation, vector.ID)
	}
}

func supportsMemoryAdapterScenario(vector memoryAdapterVector) bool {
	if vector.Scenario == "suite-banner" {
		return true
	}
	if vector.Profile == "auth-flow" {
		return supportsMemoryAuthFlowScenario(vector.Scenario)
	}
	if vector.Profile == "transactions" {
		return vector.Scenario == "transaction ─ should rollback failing transaction"
	}
	operation, description, ok := strings.Cut(vector.Scenario, " ─ ")
	if !ok {
		return false
	}
	switch operation {
	case "init":
		return description == "tests"
	case "create":
		return supportsMemoryCreateScenario(description)
	case "findOne":
		return supportsMemoryFindOneScenario(description)
	case "findMany":
		return supportsMemoryFindManyScenario(description)
	case "count":
		return supportsMemoryCountScenario(description)
	case "update":
		return supportsMemoryUpdateScenario(description)
	case "updateMany":
		return supportsMemoryUpdateManyScenario(description)
	case "incrementOne":
		return description == "guarded set transition returns the row on a matching guard and null on a guard miss"
	case "delete":
		return supportsMemoryDeleteScenario(description)
	case "deleteMany":
		return supportsMemoryDeleteManyScenario(description)
	default:
		return false
	}
}
