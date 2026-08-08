package requeststate

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var requestStateCases = []string{
	"initialization race::shares state across concurrent first callers",
	"getCurrentRequestState::returns the current store when in context",
	"getCurrentRequestState::returns an error outside request state context",
	"hasRequestState::returns false outside request state context",
	"hasRequestState::returns true in request state context",
	"runWithRequestState::executes a function within request state context",
	"runWithRequestState::isolates concurrent request states",
	"runWithRequestState::supports nested operations",
}

func TestRequestStateBehavior(t *testing.T) {
	for _, name := range requestStateCases {
		name := name
		t.Run(name, func(t *testing.T) {
			switch {
			case strings.HasSuffix(name, "::executes a function within request state context"):
				var expected struct {
					Has    bool   `json:"has"`
					Result string `json:"result"`
				}
				expected.Has, expected.Result = true, "success"
				actual, err := Run(t.Context(), NewStore(), func(ctx context.Context) (string, error) {
					if Has(ctx) != expected.Has {
						t.Fatalf("Has=%v, want %v", Has(ctx), expected.Has)
					}
					return "success", nil
				})
				if err != nil || actual != expected.Result {
					t.Fatalf("Run=(%q,%v), want (%q,nil)", actual, err, expected.Result)
				}

			case strings.HasSuffix(name, "::isolates concurrent request states"):
				var expected struct {
					Results []string `json:"results"`
				}
				expected.Results = []string{"store1", "store2"}
				state := DefineValue(func() string { return "initial" })
				results := make([]string, 2)
				var wait sync.WaitGroup
				for index, value := range []string{"store1", "store2"} {
					index, value := index, value
					wait.Add(1)
					go func() {
						defer wait.Done()
						result, err := Run(context.Background(), NewStore(), func(ctx context.Context) (string, error) {
							if err := state.Set(ctx, value); err != nil {
								return "", err
							}
							return state.Get(ctx)
						})
						if err != nil {
							t.Errorf("request %d: %v", index, err)
						}
						results[index] = result
					}()
				}
				wait.Wait()
				if !reflect.DeepEqual(results, expected.Results) {
					t.Fatalf("results=%q, want %q", results, expected.Results)
				}

			case strings.HasSuffix(name, "::supports nested operations"):
				var expected struct {
					NestedValue  int `json:"nestedValue"`
					CurrentValue int `json:"currentValue"`
				}
				expected.NestedValue, expected.CurrentValue = 2, 2
				state := DefineValue(func() int { return 1 })
				actual, err := Run(t.Context(), NewStore(), func(ctx context.Context) ([2]int, error) {
					current, err := state.Get(ctx)
					if err != nil {
						return [2]int{}, err
					}
					if err := state.Set(ctx, current+1); err != nil {
						return [2]int{}, err
					}
					nested, err := state.Get(ctx)
					if err != nil {
						return [2]int{}, err
					}
					currentAgain, err := state.Get(ctx)
					return [2]int{nested, currentAgain}, err
				})
				if err != nil || actual != [2]int{expected.NestedValue, expected.CurrentValue} {
					t.Fatalf("nested=%v err=%v", actual, err)
				}

			case strings.Contains(name, "hasRequestState::returns false"):
				var expected struct {
					Has bool `json:"has"`
				}
				if actual := Has(t.Context()); actual != expected.Has {
					t.Fatalf("Has=%v, want %v", actual, expected.Has)
				}

			case strings.Contains(name, "hasRequestState::returns true"):
				var expected struct {
					Has bool `json:"has"`
				}
				expected.Has = true
				err := RunWithRequestState(t.Context(), NewStore(), func(ctx context.Context) error {
					if actual := Has(ctx); actual != expected.Has {
						t.Fatalf("Has=%v, want %v", actual, expected.Has)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}

			case strings.Contains(name, "getCurrentRequestState::returns an error"):
				var expected struct {
					Message string `json:"message"`
				}
				expected.Message = "No request state found. Please make sure you are calling this function within a `runWithRequestState` callback."
				_, err := Current(t.Context())
				if !errors.Is(err, ErrNoRequestState) || err.Error() != expected.Message {
					t.Fatalf("Current error=%v, want %q", err, expected.Message)
				}

			case strings.Contains(name, "getCurrentRequestState::returns the current store"):
				var expected struct {
					Same bool `json:"same"`
				}
				expected.Same = true
				store := NewStore()
				err := RunWithRequestState(t.Context(), store, func(ctx context.Context) error {
					current, err := Current(ctx)
					if err != nil || (current == store) != expected.Same {
						t.Fatalf("Current=(%p,%v), store=%p", current, err, store)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}

			case strings.Contains(name, "initialization race"):
				var expected struct {
					Count        int  `json:"count"`
					AllSucceeded bool `json:"allSucceeded"`
				}
				expected.Count, expected.AllSucceeded = 32, true
				outcomes := make(chan bool, expected.Count)
				var wait sync.WaitGroup
				for range expected.Count {
					wait.Add(1)
					go func() {
						defer wait.Done()
						err := RunWithRequestState(context.Background(), NewStore(), func(ctx context.Context) error {
							_, err := Current(ctx)
							return err
						})
						outcomes <- err == nil
					}()
				}
				wait.Wait()
				close(outcomes)
				allSucceeded := true
				count := 0
				for outcome := range outcomes {
					count++
					allSucceeded = allSucceeded && outcome
				}
				if count != expected.Count || allSucceeded != expected.AllSucceeded {
					t.Fatalf("cold-start outcomes=%d/%v, want %d/%v", count, allSucceeded, expected.Count, expected.AllSucceeded)
				}

			default:
				t.Fatalf("unknown request-state case %q", name)
			}
		})
	}
}
