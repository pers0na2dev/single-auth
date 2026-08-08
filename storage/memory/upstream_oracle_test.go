package memory_test

import "testing"

type frozenMemoryAdapterOracle struct {
	UpstreamTests []memoryAdapterVector `json:"upstreamTests"`
}

type memoryAdapterVector struct {
	ID         string `json:"id"`
	Suite      string `json:"suite"`
	Title      string `json:"title"`
	CleanTitle string `json:"cleanTitle"`
	State      string `json:"state"`
	Profile    string `json:"profile"`
	Scenario   string `json:"scenario"`
}

func loadMemoryAdapterOracle(t *testing.T) frozenMemoryAdapterOracle {
	t.Helper()
	oracle := frozenMemoryAdapterOracle{UpstreamTests: memoryAdapterScenarios}
	if len(oracle.UpstreamTests) != 455 {
		t.Fatalf("memory adapter scenarios=%d, want 455", len(oracle.UpstreamTests))
	}
	return oracle
}

func TestMemoryAdapterScenarioTable(t *testing.T) {
	oracle := loadMemoryAdapterOracle(t)
	seenIDs := make(map[string]struct{}, len(oracle.UpstreamTests))
	for index, vector := range oracle.UpstreamTests {
		if vector.ID == "" || vector.Suite != "memory adapter" || vector.Title == "" ||
			vector.CleanTitle == "" || vector.Profile == "" || vector.Scenario == "" {
			t.Fatalf("incomplete vector %d: %#v", index, vector)
		}
		if _, duplicate := seenIDs[vector.ID]; duplicate {
			t.Fatalf("duplicate scenario %q", vector.ID)
		}
		seenIDs[vector.ID] = struct{}{}
		if vector.State != "run" && vector.State != "skip" {
			t.Fatalf("unsupported scenario state %q for %q", vector.State, vector.ID)
		}
		if !supportsMemoryAdapterScenario(vector) {
			t.Fatalf("no executable Go scenario for %q (%s / %s)", vector.ID, vector.Profile, vector.Scenario)
		}
	}
	if len(seenIDs) != 455 {
		t.Fatalf("scenario count=%d, want 455", len(seenIDs))
	}
}
