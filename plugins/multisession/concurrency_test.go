package multisession_test

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/core/engine"
)

func TestConcurrentDirectListAndSetActive(t *testing.T) {
	auth := newAuth(t, nil, nil)
	_, cookie, token := signUp(t, auth, "", "concurrent@example.test")

	const workers = 48
	start := make(chan struct{})
	errors := make(chan string, workers*2)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			response, err := auth.Invoke("listDeviceSessions", engine.DirectInput{
				Request: directRequest(http.MethodGet, "/multi-session/list-device-sessions", cookie, nil),
			})
			if err != nil || response.Status() != http.StatusOK {
				errors <- "list failed"
				return
			}
			var sessions []map[string]any
			if json.Unmarshal(response.Body(), &sessions) != nil || len(sessions) != 1 {
				errors <- "list response mismatch"
			}
		}()
		go func() {
			defer wait.Done()
			<-start
			response, err := auth.Invoke("setActiveSession", engine.DirectInput{
				Request: directRequest(http.MethodPost, "/multi-session/set-active", cookie, map[string]any{
					"sessionToken": token,
				}),
			})
			if err != nil || response.Status() != http.StatusOK ||
				len(response.Headers().Values("Set-Cookie")) == 0 {
				errors <- "set-active failed"
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	for message := range errors {
		t.Error(message)
	}
}
