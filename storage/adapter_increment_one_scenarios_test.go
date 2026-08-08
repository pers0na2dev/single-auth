package storage

var adapterIncrementOneScenarios = []adapterIncrementOneScenario{
	{Title: "applies a guarded transition via `set` with an empty increment", Expected: map[string]any{"wonLastRequest": float64(200), "lostNull": true, "storedLastRequest": float64(200)}},
	{Title: "applies a negative delta to decrement", Expected: map[string]any{"resultCount": float64(3), "storedCount": float64(3)}},
	{Title: "applies a positive delta and returns the updated row", Expected: map[string]any{"resultCount": float64(1), "storedCount": float64(1)}},
	{Title: "assigns absolute values via `set` in the same call", Expected: map[string]any{"resultCount": float64(1), "resultLastRequest": float64(999), "storedLastRequest": float64(999)}},
	{Title: "returns null and does not mutate when the guard matches no row", Expected: map[string]any{"resultNull": true, "storedCount": float64(0)}},
	{Title: "throws when both `increment` and `set` are empty", Expected: map[string]any{"threw": true}},
	{Title: "yields a single winner under contention and never goes negative", Expected: map[string]any{"winners": float64(1), "storedCount": float64(0)}},
	{Title: "delegates to a native incrementOne when implemented", Expected: map[string]any{"nativeCalls": float64(1), "resultCount": float64(15), "storedCount": float64(15)}},
	{Title: "throws when `set` resolves to empty after input transform", Expected: map[string]any{"threw": true, "nativeCalls": float64(0)}},
}
