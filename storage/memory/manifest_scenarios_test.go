package memory_test

var memoryManifestScenarios = []memoryManifestCase{
	{Suite: "memory adapter incrementOne", Title: "applies a negative delta to decrement", Observation: map[string]any{"remaining": float64(1)}},
	{Suite: "memory adapter incrementOne", Title: "applies a positive delta and returns the updated row", Observation: map[string]any{"updatedCount": float64(8), "storedCount": float64(8)}},
	{Suite: "memory adapter incrementOne", Title: "applies absolute set assignments alongside increments", Observation: map[string]any{"count": float64(2), "tag": "touched"}},
	{Suite: "memory adapter incrementOne", Title: "mutates only the single guarded row matching the where clause", Observation: map[string]any{"byId": map[string]any{"1": float64(10), "2": float64(0)}}},
	{Suite: "memory adapter incrementOne", Title: "participates in copy-on-write so a failed transaction discards the increment", Observation: map[string]any{"isError": true, "errorMessage": "Simulated failure", "count": float64(5)}},
	{Suite: "memory adapter incrementOne", Title: "treats a missing counter field as zero before applying the delta", Observation: map[string]any{"count": float64(4)}},
	{Suite: "memory adapter incrementOne", Title: "when the guard matches no row, returns null and mutates nothing", Observation: map[string]any{"updated": nil, "remaining": float64(0)}},
	{Suite: "memory adapter singular mutation with empty predicate", Title: "singular delete with an empty where is a no-op and removes no rows", Observation: map[string]any{"resultType": "undefined", "ids": []any{"1", "2"}}},
	{Suite: "memory adapter singular mutation with empty predicate", Title: "singular update with an empty where is a no-op and leaves every row untouched", Observation: map[string]any{"result": nil, "names": []any{"alice", "bob"}}},
	{Suite: "memory adapter transaction isolation", Title: "a committed transaction mutates the original db object in place", Observation: map[string]any{"dbIds": []any{"committed"}}},
	{Suite: "memory adapter transaction isolation", Title: "a committing transaction must not erase a write made by a concurrent in-flight operation", Observation: map[string]any{"result": "committed", "ids": []any{"outside", "tx"}}},
	{Suite: "memory adapter transaction isolation", Title: "a committing transaction's delete is applied while a concurrent insert survives", Observation: map[string]any{"ids": []any{"fresh"}}},
	{Suite: "memory adapter transaction isolation", Title: "a committing transaction's update to one row does not clobber a concurrent update to a different row", Observation: map[string]any{"byId": map[string]any{"a": "a-from-tx", "b": "b-from-outside"}}},
	{Suite: "memory adapter transaction isolation", Title: "a failing transaction must not erase a write made by a concurrent in-flight operation", Observation: map[string]any{"isError": true, "errorMessage": "Simulated failure", "ids": []any{"outside"}}},
	{Suite: "memory adapter transaction isolation", Title: "uncommitted transaction writes are invisible to operations outside the transaction", Observation: map[string]any{"observedDuringTransaction": float64(0), "result": "committed", "ids": []any{"tx"}}},
	{Suite: "memory adapter updateMany return shape", Title: "returns the number of affected rows, not a record", Observation: map[string]any{"affected": float64(0), "matched": float64(2), "all": float64(3), "returnTypes": []any{"number", "number", "number"}}},
}
