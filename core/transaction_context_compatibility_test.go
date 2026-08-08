package core

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

type transactionBehaviorCase struct {
	title            string
	transactionCalls int
	adapterMatches   []bool
	hookRunsInside   *int
	hookRunsAfter    *int
}

type transactionCountingAdapter struct {
	storage.Adapter
	mutex sync.Mutex
	calls int
}

func (adapter *transactionCountingAdapter) Transaction(ctx context.Context, callback func(storage.TransactionAdapter) error) error {
	adapter.mutex.Lock()
	adapter.calls++
	adapter.mutex.Unlock()
	return adapter.Adapter.Transaction(ctx, callback)
}

func (adapter *transactionCountingAdapter) callCount() int {
	adapter.mutex.Lock()
	defer adapter.mutex.Unlock()
	return adapter.calls
}

func TestTransactionContextScenarios(t *testing.T) {
	for _, vector := range transactionBehaviorCases() {
		vector := vector
		t.Run(vector.title, func(t *testing.T) {
			auth, adapter := newTransactionBehaviorAuth(t)
			var actualMatches []bool
			var hookRuns, hookRunsInside int

			switch vector.title {
			case "reuses the active transaction for nested calls":
				var active storage.TransactionAdapter
				err := auth.RunInTransaction(t.Context(), func(ctx context.Context) error {
					active = auth.AdapterForContext(ctx)
					actualMatches = append(actualMatches, active != nil && active != auth.Adapter())
					return auth.RunInTransaction(ctx, func(nested context.Context) error {
						actualMatches = append(actualMatches, auth.AdapterForContext(nested) == active)
						return nil
					})
				})
				if err != nil {
					t.Fatal(err)
				}

			case "still opens a transaction from a plain adapter context":
				err := auth.RunWithAdapter(t.Context(), func(adapterContext context.Context) error {
					if auth.AdapterForContext(adapterContext) != auth.Adapter() {
						t.Fatal("plain adapter context did not bind the root adapter")
					}
					return auth.RunInTransaction(adapterContext, func(transactionContext context.Context) error {
						active := auth.AdapterForContext(transactionContext)
						actualMatches = append(actualMatches, active != nil && active != auth.Adapter())
						return nil
					})
				})
				if err != nil {
					t.Fatal(err)
				}

			case "runs hooks queued by nested calls after the outer transaction finishes":
				err := auth.RunInTransaction(t.Context(), func(ctx context.Context) error {
					if err := auth.RunInTransaction(ctx, func(nested context.Context) error {
						return QueueAfterTransactionHook(nested, func() error {
							hookRuns++
							return nil
						})
					}); err != nil {
						return err
					}
					hookRunsInside = hookRuns
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}

			default:
				t.Fatalf("unknown transaction scenario %q", vector.title)
			}

			if adapter.callCount() != vector.transactionCalls || !reflect.DeepEqual(actualMatches, vector.adapterMatches) {
				t.Fatalf("calls=%d matches=%v, want calls=%d matches=%v", adapter.callCount(), actualMatches, vector.transactionCalls, vector.adapterMatches)
			}
			if vector.hookRunsInside != nil && hookRunsInside != *vector.hookRunsInside {
				t.Fatalf("hook runs inside=%d, want %d", hookRunsInside, *vector.hookRunsInside)
			}
			if vector.hookRunsAfter != nil && hookRuns != *vector.hookRunsAfter {
				t.Fatalf("hook runs after=%d, want %d", hookRuns, *vector.hookRunsAfter)
			}
		})
	}
}

func TestTransactionContextScenarioDefinitions(t *testing.T) {
	cases := transactionBehaviorCases()
	if len(cases) != 3 {
		t.Fatalf("transaction scenarios=%d, want 3", len(cases))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, vector := range cases {
		if vector.title == "" {
			t.Fatal("transaction scenario has no name")
		}
		if _, exists := seen[vector.title]; exists {
			t.Fatalf("duplicate transaction scenario %q", vector.title)
		}
		seen[vector.title] = struct{}{}
	}
}

func transactionBehaviorCases() []transactionBehaviorCase {
	zero, one := 0, 1
	return []transactionBehaviorCase{
		{title: "reuses the active transaction for nested calls", transactionCalls: 1, adapterMatches: []bool{true, true}},
		{title: "runs hooks queued by nested calls after the outer transaction finishes", transactionCalls: 1, hookRunsInside: &zero, hookRunsAfter: &one},
		{title: "still opens a transaction from a plain adapter context", transactionCalls: 1, adapterMatches: []bool{true}},
	}
}

func newTransactionBehaviorAuth(t *testing.T) (*Auth, *transactionCountingAdapter) {
	t.Helper()
	base, err := memory.New()
	if err != nil {
		t.Fatal(err)
	}
	adapter := &transactionCountingAdapter{Adapter: base}
	auth := MustNew(Options{
		Secret:   "0123456789abcdef0123456789abcdef",
		Database: adapter,
	})
	return auth, adapter
}
