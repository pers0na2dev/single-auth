package customsession

import (
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func TestConcurrentGetSessionProjectionIsIsolated(t *testing.T) {
	options := Options{
		Runtime: Runtime{GetSession: func(ctx *engine.Context) (contract.Response, error) {
			id, _ := ctx.Request().Headers().Get("X-Request-ID")
			return testSessionResponse("user-"+id, "token-"+id, contract.NewHeaders()), nil
		}},
		Enrich: func(data SessionData, _ *engine.Context) (any, error) {
			return map[string]any{"user": data.User["id"], "token": data.Session["token"]}, nil
		},
	}
	_, dispatcher := newTestPlugin(t, func(target *Options) { *target = options })

	const requests = 64
	var wait sync.WaitGroup
	errors := make(chan error, requests)
	for index := 0; index < requests; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			id := fmt.Sprintf("%02d", index)
			headers := contract.NewHeaders(contract.HeaderField{Name: "X-Request-ID", Value: id})
			request := contract.NewRequest(http.MethodGet, "/api/auth/get-session", contract.RequestOptions{Headers: headers})
			response, err := dispatcher.Dispatch(request)
			if err != nil {
				errors <- err
				return
			}
			result := responseMap(t, response)
			if result["user"] != "user-"+id || result["token"] != "token-"+id {
				errors <- fmt.Errorf("request %s received %#v", id, result)
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}
