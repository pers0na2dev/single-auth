package username

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestConcurrentAvailabilityAndSignInAreRequestLocal(t *testing.T) {
	auth := newTestAuth(t, Options{}, singleauth.EmailVerificationOptions{}, false)
	status, _, result := usernameExchange(t, auth, "POST", "/sign-up/email", "", map[string]any{
		"name": "Race", "email": "race@example.com", "password": "password123", "username": "Race.User",
	})
	if status != 200 {
		t.Fatalf("seed sign-up status=%d body=%#v", status, result)
	}

	const workers = 32
	start := make(chan struct{})
	errors := make(chan error, workers*2)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			response, err := concurrentDispatch(auth, "/is-username-available", map[string]any{"username": "RACE.USER"})
			if err != nil || response.Status() != 200 {
				errors <- fmt.Errorf("availability status=%d err=%v body=%s", response.Status(), err, response.Body())
				return
			}
			var value map[string]any
			if err := json.Unmarshal(response.Body(), &value); err != nil || value["available"] != false {
				errors <- fmt.Errorf("availability body=%s err=%v", response.Body(), err)
			}
		}()
		go func() {
			defer wait.Done()
			<-start
			response, err := concurrentDispatch(auth, "/sign-in/username", map[string]any{
				"username": "Race.User", "password": "password123",
			})
			if err != nil || response.Status() != 200 || len(response.Headers().Values("Set-Cookie")) == 0 {
				errors <- fmt.Errorf("sign-in status=%d err=%v body=%s cookies=%v", response.Status(), err, response.Body(), response.Headers().Values("Set-Cookie"))
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

func TestUnknownUsernameUsesFinalContextAwareHashChain(t *testing.T) {
	probe := &hashContextProbe{}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://auth.example.test/api/auth", Secret: integrationSecret,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return "hash:" + password, nil },
				Verify: func(hash, password string) bool { return hash == "hash:"+password },
			},
		},
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{}), probe},
	})
	if err != nil {
		t.Fatal(err)
	}
	response, invokeErr := concurrentDispatch(auth, "/sign-in/username", map[string]any{
		"username": "missing.user", "password": "password123",
	})
	apiError, ok := contract.AsAPIError(invokeErr)
	if !ok || apiError.Code != CodeInvalidUsernameOrPassword || response.Status() != 401 {
		t.Fatalf("response status=%d body=%s err=%v", response.Status(), response.Body(), invokeErr)
	}
	probe.mu.Lock()
	paths := append([]string(nil), probe.paths...)
	probe.mu.Unlock()
	if len(paths) != 1 || paths[0] != "/sign-in/username" {
		t.Fatalf("hash wrapper paths=%#v", paths)
	}
}

func concurrentDispatch(auth *singleauth.Auth, path string, body map[string]any) (contract.Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return contract.Response{}, err
	}
	request := contract.NewRequest("POST", "/api/auth"+path, contract.RequestOptions{
		Scheme: "http", Host: "auth.example.test", Body: raw,
		Headers: contract.NewHeaders(
			contract.HeaderField{Name: "Content-Type", Value: "application/json"},
			contract.HeaderField{Name: "Origin", Value: "http://auth.example.test"},
		),
	})
	return auth.Dispatch(request)
}

type hashContextProbe struct {
	mu    sync.Mutex
	paths []string
}

func (*hashContextProbe) PluginID() string { return "username-hash-probe" }

func (*hashContextProbe) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (probe *hashContextProbe) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	err := host.WrapPasswordHash(func(next singleauth.PluginPasswordHash) singleauth.PluginPasswordHash {
		return func(ctx *engine.Context, password string) (string, error) {
			path := ""
			if ctx != nil {
				path = ctx.Path()
			}
			probe.mu.Lock()
			probe.paths = append(probe.paths, path)
			probe.mu.Unlock()
			return next(ctx, password)
		}
	})
	return engine.Plugin{ID: probe.PluginID(), Version: "test"}, err
}
