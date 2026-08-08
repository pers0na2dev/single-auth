package asyncutil_test

import (
	"context"
	"errors"
	"math"
	"reflect"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/internal/asyncutil"
)

type observedOutcome struct {
	State   string `json:"state"`
	Message string `json:"message"`
}

type mapResult[T any] struct {
	values []T
	err    error
}

func TestAsyncBehavior(t *testing.T) {
	handlers := map[string]func(*testing.T){
		"aborts at the next iteration boundary when signal fires mid-run": testAbortAtNextBoundary,
		"accepts sync mappers (Awaitable)":                                testAcceptsSyncMapper,
		"caps simultaneous in-flight mappers at concurrency":              testCapsInflight,
		"clamps concurrency to items.length when larger":                  testClampsToItemsLength,
		"clamps sub-1 concurrency to 1 (zero, negative, NaN, 0 < x < 1)":  testClampsSubOne,
		"fails fast on the first mapper rejection":                        testFailsFast,
		"floors non-integer concurrency (2.5 runs at most 2 in flight)":   testFloorsConcurrency,
		"passes (item, index) to the mapper":                              testPassesItemAndIndex,
		"preserves input order regardless of completion order":            testPreservesOrder,
		"rejects immediately when the signal is already aborted":          testAlreadyCancelled,
		"returns [] for an empty input without invoking the mapper":       testEmptyInput,
		"stops scheduling new mappers after the first rejection":          testStopsScheduling,
	}
	names := make([]string, 0, len(handlers))
	for name := range handlers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, handlers[name])
	}
}

func testAbortAtNextBoundary(t *testing.T) {
	expectedOutcome := observedOutcome{State: "rejected", Message: "cancel"}
	expectedProcessed := []int{0, 1}

	ctx, cancel := context.WithCancelCause(context.Background())
	cancelCause := errors.New(expectedOutcome.Message)
	releaseInflight := make(chan struct{})
	firstWaveStarted := make(chan struct{})
	var startedOnce sync.Once
	var processedMu sync.Mutex
	processed := make([]int, 0, 2)
	finished := make(chan mapResult[int], 1)
	go func() {
		values, err := asyncutil.MapConcurrent(
			ctx,
			makeSequence(20),
			func(_ context.Context, item, _ int) (int, error) {
				processedMu.Lock()
				processed = append(processed, item)
				if len(processed) == 2 {
					startedOnce.Do(func() { close(firstWaveStarted) })
				}
				processedMu.Unlock()
				<-releaseInflight
				return item, nil
			},
			asyncutil.Options{Concurrency: 2},
		)
		finished <- mapResult[int]{values: values, err: err}
	}()

	waitSignal(t, firstWaveStarted, "first mapper wave")
	cancel(cancelCause)
	close(releaseInflight)
	result := waitMapResult(t, finished, "mid-run cancellation")
	if result.err != cancelCause {
		t.Fatalf("error = %v, want exact cancellation cause %v", result.err, cancelCause)
	}
	if result.values != nil {
		t.Fatalf("values = %v, want nil on cancellation", result.values)
	}

	processedMu.Lock()
	gotProcessed := slices.Clone(processed)
	processedMu.Unlock()
	sort.Ints(gotProcessed)
	if !slices.Equal(gotProcessed, expectedProcessed) {
		t.Fatalf("processed = %v, want %v", gotProcessed, expectedProcessed)
	}
	if len(gotProcessed) >= 20 {
		t.Fatalf("processedLessThanInput mismatch for %v", gotProcessed)
	}
	assertRejectedOutcome(t, result.err, expectedOutcome)
}

func testAcceptsSyncMapper(t *testing.T) {
	expected := []int{2, 4, 6}
	result, err := asyncutil.MapConcurrent(
		context.Background(),
		[]int{1, 2, 3},
		func(_ context.Context, item, _ int) (int, error) { return item * 2, nil },
		asyncutil.Options{Concurrency: 2},
	)
	if err != nil {
		t.Fatalf("MapConcurrent: %v", err)
	}
	if !slices.Equal(result, expected) {
		t.Fatalf("result = %v, want %v", result, expected)
	}
}

func testCapsInflight(t *testing.T) {
	peak, resultLength := measurePeak(t, 20, 4, 4)
	if peak != 4 || resultLength != 20 {
		t.Fatalf(
			"peak/resultLength = %d/%d, want %d/%d",
			peak,
			resultLength,
			4,
			20,
		)
	}
}

func testClampsToItemsLength(t *testing.T) {
	peak, resultLength := measurePeak(t, 3, 100, 3)
	if peak != 3 || resultLength != 3 {
		t.Fatalf(
			"peak/resultLength = %d/%d, want %d/%d",
			peak,
			resultLength,
			3,
			3,
		)
	}
}

func testClampsSubOne(t *testing.T) {
	expectedCases := []struct {
		Input  string
		Peak   int
		Result []int
	}{
		{Input: "0", Peak: 1, Result: []int{2, 4, 6}},
		{Input: "-1", Peak: 1, Result: []int{2, 4, 6}},
		{Input: "-10", Peak: 1, Result: []int{2, 4, 6}},
		{Input: "NaN", Peak: 1, Result: []int{2, 4, 6}},
		{Input: "0.4", Peak: 1, Result: []int{2, 4, 6}},
	}
	inputs := map[string]float64{
		"0":   0,
		"-1":  -1,
		"-10": -10,
		"NaN": math.NaN(),
		"0.4": 0.4,
	}
	if len(expectedCases) != len(inputs) {
		t.Fatalf("cases = %d, want %d", len(expectedCases), len(inputs))
	}
	for _, expectedCase := range expectedCases {
		expectedCase := expectedCase
		t.Run(expectedCase.Input, func(t *testing.T) {
			concurrency, ok := inputs[expectedCase.Input]
			if !ok {
				t.Fatalf("unexpected case input %q", expectedCase.Input)
			}
			peak, _ := measurePeak(t, 3, concurrency, 1)
			result, err := asyncutil.MapConcurrent(
				context.Background(),
				[]int{1, 2, 3},
				func(_ context.Context, item, _ int) (int, error) { return item * 2, nil },
				asyncutil.Options{Concurrency: concurrency},
			)
			if err != nil {
				t.Fatalf("MapConcurrent: %v", err)
			}
			if peak != expectedCase.Peak || !slices.Equal(result, expectedCase.Result) {
				t.Fatalf(
					"peak/result = %d/%v, want %d/%v",
					peak,
					result,
					expectedCase.Peak,
					expectedCase.Result,
				)
			}
		})
	}
}

func testFailsFast(t *testing.T) {
	expectedOutcome := observedOutcome{State: "rejected", Message: "boom"}

	releaseInflight := make(chan struct{})
	firstStarted := make(chan struct{})
	firstFinished := make(chan struct{})
	rejection := errors.New(expectedOutcome.Message)
	var callsMu sync.Mutex
	calls := make([]int, 0, 2)
	finished := make(chan mapResult[int], 1)
	go func() {
		values, err := asyncutil.MapConcurrent(
			context.Background(),
			[]int{1, 2, 3, 4, 5},
			func(_ context.Context, item, _ int) (int, error) {
				callsMu.Lock()
				calls = append(calls, item)
				callsMu.Unlock()
				switch item {
				case 1:
					close(firstStarted)
					<-releaseInflight
					close(firstFinished)
				case 2:
					<-firstStarted
					return 0, rejection
				}
				return item, nil
			},
			asyncutil.Options{Concurrency: 2},
		)
		finished <- mapResult[int]{values: values, err: err}
	}()

	result := waitMapResult(t, finished, "fail-fast mapper rejection")
	returnedBeforeInflightFinished := channelOpen(firstFinished)
	callsMu.Lock()
	callsIncludeRejectedItem := slices.Contains(calls, 2)
	callsMu.Unlock()
	close(releaseInflight)
	waitSignal(t, firstFinished, "in-flight mapper cleanup")

	if result.err != rejection {
		t.Fatalf("error = %v, want exact first mapper error %v", result.err, rejection)
	}
	if result.values != nil {
		t.Fatalf("values = %v, want nil after rejection", result.values)
	}
	if !callsIncludeRejectedItem {
		t.Fatal("rejected item was not called")
	}
	if !returnedBeforeInflightFinished {
		t.Fatalf(
			"returnedBeforeInflightFinished = %v, want true",
			returnedBeforeInflightFinished,
		)
	}
	assertRejectedOutcome(t, result.err, expectedOutcome)
}

func testFloorsConcurrency(t *testing.T) {
	peak, resultLength := measurePeak(t, 10, 2.5, 2)
	if peak != 2 || resultLength != 10 {
		t.Fatalf(
			"peak/resultLength = %d/%d, want %d/%d",
			peak,
			resultLength,
			2,
			10,
		)
	}
}

func testPassesItemAndIndex(t *testing.T) {
	expected := [][]any{{"a", float64(0)}, {"b", float64(1)}, {"c", float64(2)}}
	type seenCall struct {
		item  string
		index int
	}
	var seenMu sync.Mutex
	seen := make([]seenCall, 0, 3)
	_, err := asyncutil.MapConcurrent(
		context.Background(),
		[]string{"a", "b", "c"},
		func(_ context.Context, item string, index int) (string, error) {
			seenMu.Lock()
			seen = append(seen, seenCall{item: item, index: index})
			seenMu.Unlock()
			return item, nil
		},
		asyncutil.Options{Concurrency: 2},
	)
	if err != nil {
		t.Fatalf("MapConcurrent: %v", err)
	}
	sort.Slice(seen, func(left, right int) bool { return seen[left].index < seen[right].index })
	got := make([][]any, len(seen))
	for index, call := range seen {
		got[index] = []any{call.item, float64(call.index)}
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("seen = %#v, want %#v", got, expected)
	}
}

func testPreservesOrder(t *testing.T) {
	expected := []int{10, 20, 30, 40, 50}
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	var thirdCompleted atomic.Bool
	var firstObservedThirdCompletion atomic.Bool
	result, err := asyncutil.MapConcurrent(
		context.Background(),
		[]int{1, 2, 3, 4, 5},
		func(_ context.Context, item, _ int) (int, error) {
			if item == 1 {
				<-releaseFirst
				firstObservedThirdCompletion.Store(thirdCompleted.Load())
			}
			if item == 3 {
				thirdCompleted.Store(true)
				releaseOnce.Do(func() { close(releaseFirst) })
			}
			return item * 10, nil
		},
		asyncutil.Options{Concurrency: 3},
	)
	if err != nil {
		t.Fatalf("MapConcurrent: %v", err)
	}
	if !slices.Equal(result, expected) {
		t.Fatalf("result = %v, want %v", result, expected)
	}
	if !firstObservedThirdCompletion.Load() {
		t.Fatal("first mapper did not observe the third mapper complete")
	}
}

func testAlreadyCancelled(t *testing.T) {
	expectedOutcome := observedOutcome{State: "rejected", Message: "pre-aborted"}
	cause := errors.New(expectedOutcome.Message)
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	var calls atomic.Int64
	result, err := asyncutil.MapConcurrent(
		ctx,
		[]int{1, 2, 3},
		func(_ context.Context, item, _ int) (int, error) {
			calls.Add(1)
			return item, nil
		},
		asyncutil.Options{Concurrency: 2},
	)
	if err != cause {
		t.Fatalf("error = %v, want exact cancellation cause %v", err, cause)
	}
	if result != nil {
		t.Fatalf("result = %v, want nil", result)
	}
	if gotCalls := int(calls.Load()); gotCalls != 0 {
		t.Fatalf("mapper calls = %d, want 0", gotCalls)
	}
	assertRejectedOutcome(t, err, expectedOutcome)
}

func testEmptyInput(t *testing.T) {
	var calls atomic.Int64
	result, err := asyncutil.MapConcurrent(
		context.Background(),
		[]int{},
		func(_ context.Context, item, _ int) (int, error) {
			calls.Add(1)
			return item, nil
		},
		asyncutil.Options{Concurrency: 4},
	)
	if err != nil {
		t.Fatalf("MapConcurrent: %v", err)
	}
	if result == nil || len(result) != 0 {
		t.Fatalf("result = %#v, want a non-nil empty slice", result)
	}
	if gotCalls := int(calls.Load()); gotCalls != 0 {
		t.Fatalf("mapper calls = %d, want 0", gotCalls)
	}
}

func testStopsScheduling(t *testing.T) {
	expectedOutcome := observedOutcome{State: "rejected", Message: "boom"}
	rejection := errors.New(expectedOutcome.Message)
	releaseInflight := make(chan struct{})
	mapperFinished := make(chan struct{}, 50)
	var scheduled atomic.Int64
	finished := make(chan mapResult[int], 1)
	go func() {
		values, err := asyncutil.MapConcurrent(
			context.Background(),
			makeSequence(50),
			func(_ context.Context, item, _ int) (int, error) {
				scheduled.Add(1)
				if item == 2 {
					return 0, rejection
				}
				<-releaseInflight
				mapperFinished <- struct{}{}
				return item, nil
			},
			asyncutil.Options{Concurrency: 4},
		)
		finished <- mapResult[int]{values: values, err: err}
	}()

	result := waitMapResult(t, finished, "scheduling-stop rejection")
	scheduledAtReturn := int(scheduled.Load())
	if result.err != rejection {
		t.Fatalf("error = %v, want exact first mapper error %v", result.err, rejection)
	}
	if result.values != nil {
		t.Fatalf("values = %v, want nil after rejection", result.values)
	}
	if scheduledAtReturn >= 50 {
		t.Fatalf(
			"scheduledLessThanInput = %v (%d calls), want true",
			scheduledAtReturn < 50,
			scheduledAtReturn,
		)
	}

	close(releaseInflight)
	for range scheduledAtReturn - 1 {
		waitSignal(t, mapperFinished, "in-flight mapper cleanup")
	}
	if got := int(scheduled.Load()); got != scheduledAtReturn {
		t.Fatalf("scheduled %d mapper(s) after rejection; before cleanup=%d after=%d", got-scheduledAtReturn, scheduledAtReturn, got)
	}
	assertRejectedOutcome(t, result.err, expectedOutcome)
}

func measurePeak(t *testing.T, itemCount int, concurrency float64, expectedFirstWave int) (int, int) {
	t.Helper()
	releaseInflight := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseInflight) }) }
	t.Cleanup(release)
	firstWaveStarted := make(chan struct{})
	var firstWaveOnce sync.Once
	var inflight atomic.Int64
	var peak atomic.Int64
	var started atomic.Int64
	finished := make(chan mapResult[int], 1)
	go func() {
		values, err := asyncutil.MapConcurrent(
			context.Background(),
			makeSequence(itemCount),
			func(_ context.Context, item, _ int) (int, error) {
				current := inflight.Add(1)
				for {
					previousPeak := peak.Load()
					if current <= previousPeak || peak.CompareAndSwap(previousPeak, current) {
						break
					}
				}
				if started.Add(1) == int64(expectedFirstWave) {
					firstWaveOnce.Do(func() { close(firstWaveStarted) })
				}
				<-releaseInflight
				inflight.Add(-1)
				return item, nil
			},
			asyncutil.Options{Concurrency: concurrency},
		)
		finished <- mapResult[int]{values: values, err: err}
	}()

	select {
	case <-firstWaveStarted:
		release()
	case early := <-finished:
		t.Fatalf("mapping ended before first wave: values=%v err=%v", early.values, early.err)
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %d concurrent mapper(s)", expectedFirstWave)
	}
	result := waitMapResult(t, finished, "bounded mapping completion")
	if result.err != nil {
		t.Fatalf("MapConcurrent: %v", result.err)
	}
	return int(peak.Load()), len(result.values)
}

func assertRejectedOutcome(t *testing.T, err error, expected observedOutcome) {
	t.Helper()
	if expected.State != "rejected" {
		t.Fatalf("outcome state = %q, want rejected", expected.State)
	}
	if err == nil || err.Error() != expected.Message {
		t.Fatalf("error = %v, want message %q", err, expected.Message)
	}
}

func waitMapResult[T any](t *testing.T, result <-chan mapResult[T], label string) mapResult[T] {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
		return mapResult[T]{}
	}
}

func waitSignal(t *testing.T, signal <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func channelOpen(signal <-chan struct{}) bool {
	select {
	case <-signal:
		return false
	default:
		return true
	}
}

func makeSequence(length int) []int {
	items := make([]int, length)
	for index := range items {
		items[index] = index
	}
	return items
}
