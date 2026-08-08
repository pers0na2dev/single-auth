package customsession

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func listDispatcher(t *testing.T, options Options) *engine.Dispatcher {
	t.Helper()
	plugin, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	core := engine.Endpoint{
		Name: "listDeviceSessions", Path: "/multi-session/list-device-sessions", Methods: []string{http.MethodGet},
		Handler: func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(http.StatusOK, []any{
				map[string]any{"user": map[string]any{"id": "user-1"}, "session": map[string]any{"token": "token-1"}},
				map[string]any{"user": map[string]any{"id": "user-2"}, "session": map[string]any{"token": "token-2"}},
			})
		},
	}
	registry, err := engine.NewRegistry([]engine.Endpoint{coreGetSessionEndpoint(), core}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher
}

func callList(t *testing.T, dispatcher *engine.Dispatcher) (contract.Response, error) {
	t.Helper()
	request := contract.NewRequest(http.MethodGet, "/api/auth/multi-session/list-device-sessions", contract.RequestOptions{})
	return dispatcher.Dispatch(request)
}

func TestListDeviceSessionsMutationDefaultAndEnabled(t *testing.T) {
	base := Options{
		Runtime: Runtime{GetSession: func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(http.StatusOK, nil)
		}},
		Enrich: func(data SessionData, _ *engine.Context) (any, error) {
			return map[string]any{"id": data.User["id"], "token": data.Session["token"]}, nil
		},
	}

	disabled, err := callList(t, listDispatcher(t, base))
	if err != nil {
		t.Fatal(err)
	}
	disabledItems := decodeResponse(t, disabled).([]any)
	if _, hasUser := disabledItems[0].(map[string]any)["user"]; !hasUser {
		t.Fatalf("default unexpectedly mutated list: %#v", disabledItems)
	}

	base.ShouldMutateListDeviceSessionsEndpoint = true
	enabled, err := callList(t, listDispatcher(t, base))
	if err != nil {
		t.Fatal(err)
	}
	want := []any{
		map[string]any{"id": "user-1", "token": "token-1"},
		map[string]any{"id": "user-2", "token": "token-2"},
	}
	if got := decodeResponse(t, enabled); !reflect.DeepEqual(got, want) {
		t.Fatalf("mutated list = %#v, want %#v", got, want)
	}
}

func TestListDeviceSessionsMapsConcurrentlyAndPreservesOrder(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var active atomic.Int64
	var maximum atomic.Int64
	options := Options{
		ShouldMutateListDeviceSessionsEndpoint: true,
		Runtime: Runtime{GetSession: func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(http.StatusOK, nil)
		}},
		Enrich: func(data SessionData, _ *engine.Context) (any, error) {
			current := active.Add(1)
			defer active.Add(-1)
			for {
				previous := maximum.Load()
				if current <= previous || maximum.CompareAndSwap(previous, current) {
					break
				}
			}
			started <- struct{}{}
			<-release
			return data.User["id"], nil
		},
	}
	dispatcher := listDispatcher(t, options)
	type outcome struct {
		response contract.Response
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		response, err := callList(t, dispatcher)
		done <- outcome{response: response, err: err}
	}()
	for index := 0; index < 2; index++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("list projection was not concurrent")
		}
	}
	close(release)
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	if maximum.Load() != 2 || !reflect.DeepEqual(decodeResponse(t, result.response), []any{"user-1", "user-2"}) {
		t.Fatalf("maximum=%d response=%s", maximum.Load(), result.response.Body())
	}
}

func TestListDeviceSessionsCallbackErrorPropagates(t *testing.T) {
	sentinel := errors.New("list projection failed")
	var calls atomic.Int64
	dispatcher := listDispatcher(t, Options{
		ShouldMutateListDeviceSessionsEndpoint: true,
		Runtime: Runtime{GetSession: func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(http.StatusOK, nil)
		}},
		Enrich: func(SessionData, *engine.Context) (any, error) {
			calls.Add(1)
			return nil, sentinel
		},
	})
	response, err := callList(t, dispatcher)
	if !errors.Is(err, sentinel) || response.Status() != http.StatusInternalServerError || calls.Load() != 2 {
		t.Fatalf("status=%d body=%s calls=%d err=%v", response.Status(), response.Body(), calls.Load(), err)
	}
}

func TestListDeviceSessionsConcurrentCallbackContextIsSafe(t *testing.T) {
	var mu sync.Mutex
	paths := make([]string, 0, 2)
	dispatcher := listDispatcher(t, Options{
		ShouldMutateListDeviceSessionsEndpoint: true,
		Runtime: Runtime{GetSession: func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(http.StatusOK, nil)
		}},
		Enrich: func(data SessionData, ctx *engine.Context) (any, error) {
			mu.Lock()
			paths = append(paths, ctx.Path())
			mu.Unlock()
			return fmt.Sprint(data.User["id"]), nil
		},
	})
	if _, err := callList(t, dispatcher); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 || paths[0] != "/multi-session/list-device-sessions" || paths[1] != paths[0] {
		t.Fatalf("callback paths = %#v", paths)
	}
}
