package additionalfields

import (
	"fmt"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestProcessorIsConcurrentAndReturnsIndependentValues(t *testing.T) {
	optional := storage.Bool(false)
	processor, err := Compile(Options{
		User: Fields{{
			Name: "metadata", Attribute: storage.FieldAttribute{Type: storage.FieldJSON, Required: optional},
		}},
		Session: Fields{{
			Name: "theme", Attribute: storage.FieldAttribute{Type: storage.FieldString, DefaultValue: storage.StaticValue("light")},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	const workers = 64
	var wait sync.WaitGroup
	errors := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			input := storage.Record{"metadata": map[string]any{"worker": index}}
			parsed, parseErr := processor.ParseUserInput(input, ActionCreate)
			if parseErr != nil {
				errors <- parseErr
				return
			}
			parsedMetadata := parsed["metadata"].(map[string]any)
			parsedMetadata["worker"] = -1
			if input["metadata"].(map[string]any)["worker"] != index {
				errors <- fmt.Errorf("worker %d input was aliased", index)
				return
			}
			defaults, defaultErr := processor.SessionDefaults()
			if defaultErr != nil || defaults["theme"] != "light" {
				errors <- fmt.Errorf("worker %d defaults=%#v err=%v", index, defaults, defaultErr)
				return
			}
			schema := processor.Schema()
			schema.Models["user"].Fields["metadata"] = storage.FieldAttribute{Type: storage.FieldNumber}
			if processor.Schema().Models["user"].Fields["metadata"].Type != storage.FieldJSON {
				errors <- fmt.Errorf("worker %d mutated schema", index)
			}
		}(worker)
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}
