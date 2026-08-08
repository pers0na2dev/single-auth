package customsession

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func (p *plugin) getSession(ctx *engine.Context) (contract.Response, error) {
	inner, err := p.options.Runtime.GetSession(ctx)
	if err != nil || inner.Status() != http.StatusOK {
		return contract.JSONResponse(http.StatusOK, nil)
	}
	value, decoded := decodeJSON(inner.Body())
	if !decoded || !truthyJSON(value) {
		return contract.JSONResponse(http.StatusOK, nil)
	}
	data, ok := sessionData(value)
	if !ok {
		return contract.Response{}, fmt.Errorf("customsession: core get-session returned an invalid payload")
	}
	result, err := p.options.Enrich(cloneSessionData(data), ctx)
	if err != nil {
		return contract.Response{}, err
	}

	// Upstream invokes the callback before forwarding any inner headers.
	transferSessionHeaders(ctx, inner)
	return contract.JSONResponse(http.StatusOK, result)
}

func (p *plugin) matchesListDeviceSessions(ctx *engine.Context) (bool, error) {
	return p.options.ShouldMutateListDeviceSessionsEndpoint &&
		ctx.Path() == "/multi-session/list-device-sessions", nil
}

func (p *plugin) mutateListDeviceSessions(
	ctx *engine.Context,
	response contract.Response,
) (*contract.Response, error) {
	if response.Status() != http.StatusOK {
		return nil, nil
	}
	value, decoded := decodeJSON(response.Body())
	if !decoded || !truthyJSON(value) {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("customsession: list-device-sessions returned a non-array payload")
	}

	results := make([]any, len(items))
	type projection struct {
		index int
		value any
		err   error
	}
	completed := make(chan projection, len(items))
	var wait sync.WaitGroup
	wait.Add(len(items))
	for index := range items {
		index := index
		go func() {
			defer wait.Done()
			data, valid := sessionData(items[index])
			if !valid {
				completed <- projection{index: index, err: fmt.Errorf(
					"customsession: list-device-sessions item %d is invalid", index,
				)}
				return
			}
			value, err := p.options.Enrich(cloneSessionData(data), ctx)
			completed <- projection{index: index, value: value, err: err}
		}()
	}
	go func() {
		wait.Wait()
		close(completed)
	}()
	var firstError error
	for result := range completed {
		results[result.index] = result.value
		if firstError == nil && result.err != nil {
			firstError = result.err
		}
	}
	if firstError != nil {
		return nil, firstError
	}
	replacement, err := contract.JSONResponse(http.StatusOK, results)
	if err != nil {
		return nil, err
	}
	return &replacement, nil
}
