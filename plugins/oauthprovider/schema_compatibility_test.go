package oauthprovider

import (
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

type oauthProviderSchemaCase struct {
	Title        string
	Observations []oauthProviderSchemaObservation
}

type oauthProviderSchemaObservation struct {
	Model             string `json:"model"`
	Field             string `json:"field"`
	Index             bool   `json:"index"`
	ReferencesDefined bool   `json:"referencesDefined"`
	References        struct {
		Model    string `json:"model"`
		Field    string `json:"field"`
		OnDelete string `json:"onDelete"`
	} `json:"references"`
}

func TestOAuthProviderSchemaRuntime(t *testing.T) {
	vector := oauthProviderSchemaCases[0]
	t.Run(vector.Title, func(t *testing.T) {
		schema := OAuthProviderSchema()
		if _, err := storage.CoreSchema().Merge(schema); err != nil {
			t.Fatal(err)
		}
		for _, observation := range vector.Observations {
			model, modelExists := schema.Models[observation.Model]
			field, fieldExists := model.Fields[observation.Field]
			if !modelExists || !fieldExists {
				t.Fatalf("missing OAuth schema field %s.%s", observation.Model, observation.Field)
			}
			if field.Index != observation.Index || (field.References != nil) != observation.ReferencesDefined {
				t.Fatalf("OAuth schema field %s.%s = %#v, want %#v", observation.Model, observation.Field, field, observation)
			}
			if field.References == nil || field.References.Model != observation.References.Model ||
				field.References.Field != observation.References.Field ||
				string(field.References.OnDelete) != observation.References.OnDelete {
				t.Fatalf("OAuth schema reference %s.%s = %#v, want %#v", observation.Model, observation.Field, field.References, observation.References)
			}
		}
	})
}

func TestOAuthProviderSchemaReturnsIndependentCopies(t *testing.T) {
	left := OAuthProviderSchema()
	right := OAuthProviderSchema()
	delete(left.Models["oauthClient"].Fields, "userId")
	if _, exists := right.Models["oauthClient"].Fields["userId"]; !exists {
		t.Fatal("OAuthProviderSchema returned shared field maps")
	}
}
