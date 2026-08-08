package haveibeenpwned

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func TestConcurrentPasswordChecks(t *testing.T) {
	const count = 96
	ranges := make(map[string][]string)
	passwords := make([]string, count)
	for index := range passwords {
		passwords[index] = fmt.Sprintf("concurrent-password-%03d", index)
		if index%2 == 0 {
			digest := passwordDigest(passwords[index])
			ranges[digest[:5]] = append(ranges[digest[:5]], digest[5:]+":7")
		}
	}

	var fetchCalls atomic.Int64
	doer := doerFunc(func(request *http.Request) (*http.Response, error) {
		fetchCalls.Add(1)
		prefix := strings.TrimPrefix(request.URL.Path, "/range/")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(strings.Join(ranges[prefix], "\n"))),
		}, nil
	})
	var hashCalls atomic.Int64
	var hash PasswordHashFunc = func(_ *engine.Context, password string) (string, error) {
		hashCalls.Add(1)
		return "hashed:" + password, nil
	}
	descriptor, err := New(Options{
		HTTPClient: doer,
		Runtime: Runtime{WrapPasswordHash: func(wrapper PasswordHashWrapper) error {
			hash = wrapper(hash)
			return nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := engine.Endpoint{
		Name: "concurrentHash", Path: "/sign-up/email", Methods: []string{http.MethodPost},
		Handler: func(ctx *engine.Context) (contract.Response, error) {
			value, _ := ctx.Value("password")
			password, _ := value.(string)
			hashed, hashErr := hash(ctx, password)
			if hashErr != nil {
				return contract.Response{}, hashErr
			}
			return contract.TextResponse(contract.StatusOK, hashed), nil
		},
	}
	registry, err := engine.NewRegistry([]engine.Endpoint{endpoint}, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}

	results := make(chan error, count)
	var wait sync.WaitGroup
	for index, password := range passwords {
		wait.Add(1)
		go func(index int, password string) {
			defer wait.Done()
			response, invokeErr := dispatcher.Invoke("concurrentHash", engine.DirectInput{
				Values: map[string]any{"password": password},
			})
			if index%2 == 0 {
				apiError, ok := contract.AsAPIError(invokeErr)
				if !ok || apiError.Code != ErrorPasswordCompromised {
					results <- fmt.Errorf("index %d error = %#v", index, invokeErr)
				}
				return
			}
			if invokeErr != nil || string(response.Body()) != "hashed:"+password {
				results <- fmt.Errorf("index %d response=%q error=%v", index, response.Body(), invokeErr)
			}
		}(index, password)
	}
	wait.Wait()
	close(results)
	for result := range results {
		t.Error(result)
	}
	if actual := fetchCalls.Load(); actual != count {
		t.Errorf("fetch calls = %d, want %d", actual, count)
	}
	if actual := hashCalls.Load(); actual != count/2 {
		t.Errorf("hash calls = %d, want %d", actual, count/2)
	}
}
