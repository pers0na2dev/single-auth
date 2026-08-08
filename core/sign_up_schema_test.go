package core

import (
	"net/http"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestSignUpRejectsInputFalseFieldsBeforeExistingUserLookup(t *testing.T) {
	optional := storage.Bool(false)
	notInput := storage.Bool(false)
	auth := MustNew(Options{
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		Schema: storage.Schema{Models: map[string]storage.ModelSchema{
			"user": {Fields: map[string]storage.FieldAttribute{
				"authority": {Type: storage.FieldString, Required: optional, Input: notInput},
			}},
		}},
	})

	_, _, _ = createSessionTestUser(t, auth, "input-false-signup@example.com")
	status, _, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Attacker", "email": "input-false-signup@example.com", "password": "password123",
		"authority": "admin",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d value=%#v", status, value)
	}
	errorBody, ok := value.(map[string]any)
	if !ok || errorBody["code"] != string(ErrorFieldNotAllowed) ||
		errorBody["message"] != "authority is not allowed to be set" {
		t.Fatalf("error=%#v", value)
	}

	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Allowed", "email": "falsey-input@example.com", "password": "password123",
		"authority": "",
	})
	if status != http.StatusOK {
		t.Fatalf("falsey input status=%d value=%#v", status, value)
	}
	stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: "falsey-input@example.com"}},
	})
	if err != nil || stored == nil {
		t.Fatalf("stored user=%#v err=%v", stored, err)
	}
	if _, exists := stored["authority"]; exists {
		t.Fatalf("falsey input:false field persisted: %#v", stored)
	}
}
