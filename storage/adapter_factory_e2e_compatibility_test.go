package storage_test

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

type adapterFactoryE2ETest struct {
	Suite string
	Title string
}

type adapterFactoryE2EOracle struct {
	Tests []adapterFactoryE2ETest
}

func TestE2EAdapterFactoryBehavior(t *testing.T) {
	oracle := loadAdapterFactoryE2EOracle(t)
	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Suite+"::"+normalizeAdapterFactoryTitle(vector.Title), func(t *testing.T) {
			runAdapterFactoryE2EVector(t, vector)
		})
	}
}

func TestAdapterFactoryDisabledRecordTransformsKeepQueryAndIDGuards(t *testing.T) {
	var createCall storage.CreateParams
	var findCall storage.FindOneParams
	var incrementCall storage.IncrementOneParams
	adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, schema *storage.Schema, driver *storage.CustomAdapter) {
		config.DisableTransformInput = true
		config.DisableTransformOutput = true
		config.MapKeysTransformInput = map[string]string{
			"email":  "email_override",
			"visits": "visits_override",
		}
		config.TransformInput = func(input storage.AdapterTransformContext) (any, error) {
			if value, ok := input.Data.(string); ok {
				return strings.ToUpper(value), nil
			}
			return input.Data, nil
		}
		user := schema.Models["user"]
		user.ModelName = "user_table"
		user.Fields["visits"] = storage.FieldAttribute{Type: storage.FieldNumber, FieldName: "visit_count"}
		schema.Models["user"] = user
		driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
			createCall = params
			return cloneAdapterFactoryRecord(params.Data), nil
		}
		driver.FindOne = func(_ context.Context, params storage.FindOneParams) (storage.Record, error) {
			findCall = params
			return storage.Record{"id": "raw-id", "email_override": "STORED"}, nil
		}
		driver.IncrementOne = func(_ context.Context, params storage.IncrementOneParams) (storage.Record, error) {
			incrementCall = params
			return storage.Record{"id": "raw-id", "visit_count": float64(3)}, nil
		}
	})

	created := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{
		"id": "caller-id", "email": "raw@example.com",
	}, nil, false)
	if createCall.Model != "user_table" || createCall.Data["email"] != "raw@example.com" ||
		created["email"] != "raw@example.com" {
		t.Fatalf("disabled create transforms call=%#v result=%#v", createCall, created)
	}
	if _, exists := createCall.Data["id"]; exists {
		t.Fatalf("disableTransformInput bypassed create ID guard: %#v", createCall.Data)
	}

	found, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: "find@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findCall.Where) != 1 || findCall.Where[0].Field != "email_override" ||
		findCall.Where[0].Value != "FIND@EXAMPLE.COM" ||
		!reflect.DeepEqual(found, storage.Record{"id": "raw-id", "email_override": "STORED"}) {
		t.Fatalf("disabled record transforms changed where/output semantics call=%#v result=%#v", findCall, found)
	}

	incremented, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model:     "user",
		Where:     []storage.Where{{Field: "email", Value: "increment@example.com"}},
		Increment: map[string]float64{"visits": 1},
		Set:       storage.Record{"email": "raw-set@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(incrementCall.Where) != 1 || incrementCall.Where[0].Field != "email_override" ||
		incrementCall.Where[0].Value != "INCREMENT@EXAMPLE.COM" ||
		incrementCall.Increment["visits_override"] != 1 ||
		incrementCall.Set["email"] != "raw-set@example.com" ||
		!reflect.DeepEqual(incremented, storage.Record{"id": "raw-id", "visit_count": float64(3)}) {
		t.Fatalf("disabled increment transforms call=%#v result=%#v", incrementCall, incremented)
	}
}

func loadAdapterFactoryE2EOracle(t *testing.T) adapterFactoryE2EOracle {
	t.Helper()
	oracle := adapterFactoryE2EOracle{Tests: adapterFactoryE2EScenarios}
	if len(oracle.Tests) != 50 {
		t.Fatalf("adapter-factory scenarios=%d, want 50", len(oracle.Tests))
	}
	seen := make(map[string]struct{}, len(oracle.Tests))
	for _, vector := range oracle.Tests {
		if vector.Suite == "" || vector.Title == "" {
			t.Fatalf("invalid adapter-factory scenario: %#v", vector)
		}
		key := vector.Suite + "::" + vector.Title
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("duplicate adapter-factory scenario %q", key)
		}
		seen[key] = struct{}{}
	}
	return oracle
}

type adapterFactoryE2ESetup func(
	*storage.AdapterFactoryConfig,
	*storage.Schema,
	*storage.CustomAdapter,
)

func newAdapterFactoryE2EAdapter(t *testing.T, setups ...adapterFactoryE2ESetup) storage.Adapter {
	t.Helper()
	schema := storage.CoreSchema()
	capabilities := storage.Capabilities{
		NumericIDs: true,
		JSON:       true,
		Dates:      true,
		Booleans:   true,
		Arrays:     false,
	}
	config := storage.AdapterFactoryConfig{
		AdapterID: "test-id", AdapterName: "Test Adapter", Schema: schema,
		Capabilities: &capabilities,
	}
	driver := adapterFactoryE2EDriver()
	for _, setup := range setups {
		setup(&config, &schema, &driver)
	}
	config.Schema = schema
	adapter, err := storage.NewAdapterFactory(config, driver)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func adapterFactoryE2EDriver() storage.CustomAdapter {
	return storage.CustomAdapter{
		Create: func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
			return cloneAdapterFactoryRecord(params.Data), nil
		},
		Update: func(_ context.Context, params storage.UpdateParams) (storage.Record, error) {
			return cloneAdapterFactoryRecord(params.Update), nil
		},
		UpdateMany: func(context.Context, storage.UpdateManyParams) (int64, error) { return 0, nil },
		FindOne:    func(context.Context, storage.FindOneParams) (storage.Record, error) { return nil, nil },
		FindMany: func(context.Context, storage.FindManyParams) ([]storage.Record, error) {
			return []storage.Record{}, nil
		},
		Count:      func(context.Context, storage.CountParams) (int64, error) { return 0, nil },
		Delete:     func(context.Context, storage.DeleteParams) error { return nil },
		DeleteMany: func(context.Context, storage.DeleteManyParams) (any, error) { return 0, nil },
	}
}

func cloneAdapterFactoryRecord(record storage.Record) storage.Record {
	if record == nil {
		return nil
	}
	clone := make(storage.Record, len(record))
	for key, value := range record {
		clone[key] = value
	}
	return clone
}

func runAdapterFactoryE2EVector(t *testing.T, vector adapterFactoryE2ETest) {
	t.Helper()
	title := normalizeAdapterFactoryTitle(vector.Title)
	switch {
	case vector.Suite == "Create Adapter Helper":
		runAdapterFactoryRootVector(t, title)
	case strings.HasSuffix(vector.Suite, " > create"):
		runAdapterFactoryCreateVector(t, title)
	case strings.HasSuffix(vector.Suite, " > update"):
		runAdapterFactoryUpdateVector(t, title)
	case strings.HasSuffix(vector.Suite, " > find"):
		runAdapterFactoryFindVector(t, title)
	case strings.HasPrefix(vector.Suite, "Fallback JoinOption System"):
		runAdapterFactoryJoinVector(t, vector.Suite, title)
	default:
		t.Fatalf("unhandled adapter-factory suite %q", vector.Suite)
	}
}

func normalizeAdapterFactoryTitle(title string) string {
	const prefix = "Should use the id generator if passed into the "
	if strings.HasPrefix(title, prefix) && strings.HasSuffix(title, " config") {
		return prefix + "adapter config"
	}
	return title
}

func runAdapterFactoryRootVector(t *testing.T, title string) {
	t.Helper()
	switch title {
	case "Should have the correct adapter id":
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, _ *storage.CustomAdapter) {
			config.AdapterID = "test-adapter-id"
		})
		if adapter.ID() != "test-adapter-id" {
			t.Fatalf("adapter ID=%q", adapter.ID())
		}
	case "Should use the id generator if passed into the adapter config":
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, _ *storage.CustomAdapter) {
			config.GenerateID = func(string) (any, error) { return "HARD-CODED-ID", nil }
		})
		result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"name": "test-name"}, nil, false)
		if result["id"] != "HARD-CODED-ID" {
			t.Fatalf("generated id=%#v", result["id"])
		}
	case "Should not generate an id if `advanced.database.generateId` is not defined or false":
		var call storage.CreateParams
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			config.IDGeneration = storage.IDGenerationNone
			driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
				call = params
				return cloneAdapterFactoryRecord(params.Data), nil
			}
		})
		result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"name": "test-name"}, nil, false)
		if _, exists := call.Data["id"]; exists || result["id"] != nil {
			t.Fatalf("unexpected generated id call=%#v result=%#v", call.Data, result)
		}
	case "Should generate UUIDs when `advanced.database.generateId` is set to 'uuid'":
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, _ *storage.CustomAdapter) {
			config.IDGeneration = storage.IDGenerationUUID
		})
		pattern := regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
		ids := map[string]struct{}{}
		for index := 0; index < 11; index++ {
			result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"name": fmt.Sprintf("test-name-%d", index)}, nil, false)
			id, ok := result["id"].(string)
			if !ok || !pattern.MatchString(id) {
				t.Fatalf("invalid UUID %#v", result["id"])
			}
			if _, duplicate := ids[id]; duplicate {
				t.Fatalf("duplicate UUID %q", id)
			}
			ids[id] = struct{}{}
		}
	case "Should preserve a forced UUID when the adapter supports native UUIDs":
		const existingID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
		var call storage.CreateParams
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			config.IDGeneration = storage.IDGenerationUUID
			config.Capabilities.UUIDs = true
			driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
				call = params
				return cloneAdapterFactoryRecord(params.Data), nil
			}
		})
		result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"id": existingID, "name": "test-name"}, nil, true)
		if call.Data["id"] != existingID || result["id"] != existingID {
			t.Fatalf("forced UUID call=%#v result=%#v", call.Data, result)
		}
	default:
		t.Fatalf("unhandled root adapter-factory test %q", title)
	}
}

func mustAdapterFactoryCreate(
	t *testing.T,
	adapter storage.Adapter,
	model string,
	data storage.Record,
	selectFields []string,
	forceAllowID bool,
) storage.Record {
	t.Helper()
	result, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: model, Data: data, Select: selectFields, ForceAllowID: forceAllowID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustAdapterFactoryUpdate(
	t *testing.T,
	adapter storage.Adapter,
	update storage.Record,
) storage.Record {
	t.Helper()
	result, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "user-id"}}, Update: update,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertAdapterFactoryFields(t *testing.T, record storage.Record, fields ...string) {
	t.Helper()
	for _, field := range fields {
		if _, exists := record[field]; !exists {
			t.Fatalf("record %#v has no field %q", record, field)
		}
	}
}

func adapterFactorySchemaWithField(name string, attribute storage.FieldAttribute) adapterFactoryE2ESetup {
	return func(_ *storage.AdapterFactoryConfig, schema *storage.Schema, _ *storage.CustomAdapter) {
		user := schema.Models["user"]
		user.Fields[name] = attribute
		schema.Models["user"] = user
	}
}

func adapterFactoryCapabilities(update func(*storage.Capabilities)) adapterFactoryE2ESetup {
	return func(config *storage.AdapterFactoryConfig, _ *storage.Schema, _ *storage.CustomAdapter) {
		update(config.Capabilities)
	}
}

func runAdapterFactoryCreateVector(t *testing.T, title string) {
	t.Helper()
	switch title {
	case "Should fill in the missing fields in the result":
		adapter := newAdapterFactoryE2EAdapter(t)
		result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"name": "test-name"}, nil, false)
		assertAdapterFactoryFields(t, result, "id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt")
		if result["name"] != "test-name" || result["email"] != nil || result["image"] != nil || result["emailVerified"] != false {
			t.Fatalf("unexpected schema-complete create result %#v", result)
		}
		if _, ok := result["createdAt"].(time.Time); !ok {
			t.Fatalf("createdAt=%T", result["createdAt"])
		}
		if _, ok := result["updatedAt"].(time.Time); !ok {
			t.Fatalf("updatedAt=%T", result["updatedAt"])
		}
	case "should not return string for nullable foreign keys":
		for _, mode := range []storage.IDGenerationMode{storage.IDGenerationDefault, storage.IDGenerationSerial} {
			adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, schema *storage.Schema, _ *storage.CustomAdapter) {
				config.IDGeneration = mode
				schema.Models["testModel"] = storage.ModelSchema{ModelName: "testModel", Fields: map[string]storage.FieldAttribute{
					"nullableReference": {
						Type: storage.FieldString, Required: storage.Bool(false),
						References: &storage.Reference{Model: "user", Field: "id"},
					},
				}}
			})
			result := mustAdapterFactoryCreate(t, adapter, "testModel", storage.Record{"nullableReference": nil}, nil, false)
			if value, exists := result["nullableReference"]; !exists || value != nil {
				t.Fatalf("nullable reference mode=%q result=%#v", mode, result)
			}
		}
	case "Should include an \"id\" in the result in all cases, unless \"select\" is used to exclude it":
		adapter := newAdapterFactoryE2EAdapter(t)
		result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"name": "test-name"}, nil, false)
		if id, ok := result["id"].(string); !ok || id == "" {
			t.Fatalf("generated id=%#v", result["id"])
		}
		withoutGeneration := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, _ *storage.CustomAdapter) {
			config.DisableIDGeneration = true
		})
		result = mustAdapterFactoryCreate(t, withoutGeneration, "user", storage.Record{"name": "test-name"}, nil, false)
		if value, exists := result["id"]; !exists || value != nil {
			t.Fatalf("disabled ID result=%#v", result)
		}
		selected := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"name": "test-name"}, []string{"name"}, false)
		if selected["name"] != "test-name" {
			t.Fatalf("selected result=%#v", selected)
		}
		if _, exists := selected["id"]; exists {
			t.Fatalf("select unexpectedly returned id: %#v", selected)
		}
	case "Should receive a generated id during the call, unless \"disableIdGeneration\" is set to true":
		var withID, withoutID storage.CreateParams
		adapter := newAdapterFactoryE2EAdapter(t, func(_ *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
				withID = params
				return cloneAdapterFactoryRecord(params.Data), nil
			}
		})
		mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"name": "test-name"}, nil, false)
		if id, ok := withID.Data["id"].(string); !ok || id == "" {
			t.Fatalf("driver did not receive generated id: %#v", withID.Data)
		}
		adapter = newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			config.DisableIDGeneration = true
			driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
				withoutID = params
				return cloneAdapterFactoryRecord(params.Data), nil
			}
		})
		mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"name": "test-name"}, nil, false)
		if _, exists := withoutID.Data["id"]; exists {
			t.Fatalf("driver received disabled id: %#v", withoutID.Data)
		}
	case "Should not modify result null to string for id or fields referencing id":
		adapter := newAdapterFactoryE2EAdapter(t, func(_ *storage.AdapterFactoryConfig, schema *storage.Schema, _ *storage.CustomAdapter) {
			schema.Models["testPluginTable"] = storage.ModelSchema{ModelName: "testPluginTable", Fields: map[string]storage.FieldAttribute{
				"testPluginField": {
					Type: storage.FieldString, Required: storage.Bool(false),
					References: &storage.Reference{Model: "user", Field: "id"},
				},
			}}
		})
		result := mustAdapterFactoryCreate(t, adapter, "testPluginTable", storage.Record{"testPluginField": nil}, nil, false)
		if id, ok := result["id"].(string); !ok || id == "" || result["testPluginField"] != nil {
			t.Fatalf("nullable ID reference result=%#v", result)
		}
	case "Should modify boolean type to 1 or 0 if the DB doesn't support it. And expect the result to be transformed back to boolean":
		for _, value := range []bool{true, false} {
			var call storage.CreateParams
			adapter := newAdapterFactoryE2EAdapter(t,
				adapterFactoryCapabilities(func(capabilities *storage.Capabilities) { capabilities.Booleans = false }),
				func(_ *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
					driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
						call = params
						return cloneAdapterFactoryRecord(params.Data), nil
					}
				},
			)
			result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"emailVerified": value}, nil, false)
			want := int64(0)
			if value {
				want = 1
			}
			if call.Data["emailVerified"] != want || result["emailVerified"] != value {
				t.Fatalf("boolean=%v call=%#v result=%#v", value, call.Data, result)
			}
		}
	case "Should modify string[] type to TEXT if the DB doesn't support it. And expect the result to be transformed back to string[]":
		assertAdapterFactoryCreateCollectionTransform(t, storage.FieldStringArray, []string{"medium", "large"}, `["medium","large"]`, []string{"medium", "large"})
	case "Should modify number[] type to TEXT if the DB doesn't support it. And expect the result to be transformed back to number[]":
		assertAdapterFactoryCreateCollectionTransform(t, storage.FieldNumberArray, []int{6, 7}, `[6,7]`, []float64{6, 7})
	case "Should modify JSON type to TEXT if the DB doesn't support it. And expect the result to be transformed back to JSON":
		value := map[string]any{"color": "blue", "size": "large"}
		assertAdapterFactoryCreateCollectionTransform(t, storage.FieldJSON, value, `{"color":"blue","size":"large"}`, value)
	case "Should modify date type to TEXT if the DB doesn't support it. And expect the result to be transformed back to date":
		date := time.Date(2026, time.August, 9, 7, 6, 5, 123456000, time.UTC)
		var call storage.CreateParams
		adapter := newAdapterFactoryE2EAdapter(t,
			adapterFactoryCapabilities(func(capabilities *storage.Capabilities) { capabilities.Dates = false }),
			func(_ *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
				driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
					call = params
					return cloneAdapterFactoryRecord(params.Data), nil
				}
			},
		)
		result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"createdAt": date}, nil, false)
		if call.Data["createdAt"] != date.Format(time.RFC3339Nano) || !result["createdAt"].(time.Time).Equal(date) {
			t.Fatalf("date call=%#v result=%#v", call.Data, result)
		}
	case "Should allow custom transform input":
		assertAdapterFactoryCreateTransform(t, true, false)
	case "Should allow custom transform output":
		assertAdapterFactoryCreateTransform(t, false, true)
	case "Should allow custom transform input and output":
		assertAdapterFactoryCreateTransform(t, true, true)
	case "Should allow custom map input key transformation":
		var call storage.CreateParams
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			config.MapKeysTransformInput = map[string]string{"email": "email_address"}
			driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
				call = params
				return cloneAdapterFactoryRecord(params.Data), nil
			}
		})
		result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"email": "test@test.com"}, nil, false)
		if call.Data["email_address"] != "test@test.com" || result["email"] != nil {
			t.Fatalf("input map call=%#v result=%#v", call.Data, result)
		}
		if _, exists := result["email_address"]; exists {
			t.Fatalf("input-only map escaped into output %#v", result)
		}
	case "Should allow custom transform input to transform the where clause":
		var call storage.FindOneParams
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			config.MapKeysTransformInput = map[string]string{"id": "_id"}
			driver.FindOne = func(_ context.Context, params storage.FindOneParams) (storage.Record, error) {
				call = params
				return storage.Record{}, nil
			}
		})
		if _, err := adapter.FindOne(t.Context(), storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: "123"}}}); err != nil {
			t.Fatal(err)
		}
		if len(call.Where) != 1 || call.Where[0].Field != "_id" {
			t.Fatalf("where map call=%#v", call)
		}
	case "Should allow custom map output key transformation":
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, _ *storage.CustomAdapter) {
			config.MapKeysTransformOutput = map[string]string{"email": "wrong_email_key"}
		})
		result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"email": "test@test.com"}, nil, false)
		if result["wrong_email_key"] != "test@test.com" {
			t.Fatalf("output map result=%#v", result)
		}
		if _, exists := result["email"]; exists {
			t.Fatalf("canonical key survived output map %#v", result)
		}
	case "Should allow custom map input and output key transformation":
		assertAdapterFactoryCreateBothMaps(t)
	case "Should expect the fields to be transformed into the correct field names if customized":
		var call storage.CreateParams
		adapter := newAdapterFactoryE2EAdapter(t, adapterFactoryEmailAlias(&call, nil))
		result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"email": "test@test.com"}, nil, false)
		if call.Data["email_address"] != "test@test.com" || result["email"] != "test@test.com" {
			t.Fatalf("field alias call=%#v result=%#v", call.Data, result)
		}
		if _, exists := result["email_address"]; exists {
			t.Fatalf("physical field escaped %#v", result)
		}
	case "Should expect the model to be transformed into the correct model name if customized":
		var call storage.CreateParams
		adapter := newAdapterFactoryE2EAdapter(t, func(_ *storage.AdapterFactoryConfig, schema *storage.Schema, driver *storage.CustomAdapter) {
			user := schema.Models["user"]
			user.ModelName = "user_table"
			schema.Models["user"] = user
			driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
				call = params
				return cloneAdapterFactoryRecord(params.Data), nil
			}
		})
		result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"email": "test@test.com"}, nil, false)
		if call.Model != "user_table" || result["id"] == nil || result["email"] != "test@test.com" {
			t.Fatalf("model alias call=%#v result=%#v", call, result)
		}
	case "Should expect the result to follow the schema":
		var call storage.CreateParams
		adapter := newAdapterFactoryE2EAdapter(t, adapterFactoryEmailAlias(&call, nil))
		result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"email": "test@test.com"}, nil, false)
		assertAdapterFactoryFields(t, result, "email", "id", "createdAt", "updatedAt", "name", "emailVerified", "image")
		if call.Data["email_address"] != "test@test.com" {
			t.Fatalf("schema alias call=%#v", call.Data)
		}
		if _, exists := result["email_address"]; exists {
			t.Fatalf("schema result exposed physical field %#v", result)
		}
	case "Should expect the result to respect the select fields":
		adapter := newAdapterFactoryE2EAdapter(t, adapterFactoryEmailAlias(nil, nil))
		result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{
			"email": "test@test.com", "name": "test-name", "emailVerified": false, "image": "test-image",
		}, []string{"email"}, false)
		if !reflect.DeepEqual(result, storage.Record{"email": "test@test.com"}) {
			t.Fatalf("selected result=%#v", result)
		}
	default:
		t.Fatalf("unhandled create adapter-factory test %q", title)
	}
}

func assertAdapterFactoryCreateCollectionTransform(
	t *testing.T,
	fieldType storage.FieldType,
	input any,
	wantRaw string,
	wantOutput any,
) {
	t.Helper()
	var call storage.CreateParams
	adapter := newAdapterFactoryE2EAdapter(t,
		adapterFactorySchemaWithField("preferences", storage.FieldAttribute{Type: fieldType}),
		func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			if fieldType == storage.FieldJSON {
				config.Capabilities.JSON = false
			} else {
				config.Capabilities.Arrays = false
			}
			driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
				call = params
				return cloneAdapterFactoryRecord(params.Data), nil
			}
		},
	)
	result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"preferences": input}, nil, false)
	if call.Data["preferences"] != wantRaw || !reflect.DeepEqual(result["preferences"], wantOutput) {
		t.Fatalf("collection transform call=%#v result=%#v", call.Data, result)
	}
}

func assertAdapterFactoryCreateTransform(t *testing.T, inputTransform, outputTransform bool) {
	t.Helper()
	var call storage.CreateParams
	adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
		if inputTransform {
			config.TransformInput = func(value storage.AdapterTransformContext) (any, error) {
				if value.Field == "name" {
					return strings.ToUpper(value.Data.(string)), nil
				}
				return value.Data, nil
			}
		}
		if outputTransform {
			config.TransformOutput = func(value storage.AdapterOutputTransformContext) (any, error) {
				if value.Field == "name" {
					return strings.ToLower(value.Data.(string)), nil
				}
				return value.Data, nil
			}
		}
		driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
			call = params
			return cloneAdapterFactoryRecord(params.Data), nil
		}
	})
	inputName := "TEST-NAME"
	if inputTransform && !outputTransform {
		inputName = "test-name"
	}
	result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"name": inputName}, nil, false)
	wantRaw := inputName
	if inputTransform {
		wantRaw = strings.ToUpper(inputName)
	}
	wantOutput := wantRaw
	if outputTransform {
		wantOutput = strings.ToLower(wantRaw)
	}
	if call.Data["name"] != wantRaw || result["name"] != wantOutput {
		t.Fatalf("custom transforms call=%#v result=%#v", call.Data, result)
	}
}

func assertAdapterFactoryCreateBothMaps(t *testing.T) {
	t.Helper()
	var call storage.CreateParams
	adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
		config.MapKeysTransformInput = map[string]string{"email": "email_address"}
		config.MapKeysTransformOutput = map[string]string{"email_address": "email"}
		driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
			call = params
			return cloneAdapterFactoryRecord(params.Data), nil
		}
	})
	result := mustAdapterFactoryCreate(t, adapter, "user", storage.Record{"email": "test@test.com"}, nil, false)
	if call.Data["email_address"] != "test@test.com" || result["email"] != "test@test.com" {
		t.Fatalf("input/output maps call=%#v result=%#v", call.Data, result)
	}
	if _, exists := call.Data["email"]; exists {
		t.Fatalf("canonical input key reached driver %#v", call.Data)
	}
	if _, exists := result["email_address"]; exists {
		t.Fatalf("physical output key escaped %#v", result)
	}
}

func adapterFactoryEmailAlias(createCall *storage.CreateParams, updateCall *storage.UpdateParams) adapterFactoryE2ESetup {
	return func(_ *storage.AdapterFactoryConfig, schema *storage.Schema, driver *storage.CustomAdapter) {
		user := schema.Models["user"]
		email := user.Fields["email"]
		email.FieldName = "email_address"
		user.Fields["email"] = email
		schema.Models["user"] = user
		if createCall != nil {
			driver.Create = func(_ context.Context, params storage.CreateParams) (storage.Record, error) {
				*createCall = params
				return cloneAdapterFactoryRecord(params.Data), nil
			}
		}
		if updateCall != nil {
			driver.Update = func(_ context.Context, params storage.UpdateParams) (storage.Record, error) {
				*updateCall = params
				return cloneAdapterFactoryRecord(params.Update), nil
			}
		}
	}
}

func runAdapterFactoryUpdateVector(t *testing.T, title string) {
	t.Helper()
	switch title {
	case "Should fill in the missing fields in the result":
		adapter := newAdapterFactoryE2EAdapter(t)
		result := mustAdapterFactoryUpdate(t, adapter, storage.Record{"name": "test-name-2"})
		assertAdapterFactoryFields(t, result, "id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt")
		if result["name"] != "test-name-2" {
			t.Fatalf("update result=%#v", result)
		}
	case "Should include an \"id\" in the result in all cases":
		result := mustAdapterFactoryUpdate(t, newAdapterFactoryE2EAdapter(t), storage.Record{"name": "test-name-2"})
		if _, exists := result["id"]; !exists {
			t.Fatalf("update result has no id: %#v", result)
		}
	case "Should modify boolean type to 1 or 0 if the DB doesn't support it. And expect the result to be transformed back to boolean":
		for _, value := range []bool{true, false} {
			var call storage.UpdateParams
			adapter := newAdapterFactoryE2EAdapter(t,
				adapterFactoryCapabilities(func(capabilities *storage.Capabilities) { capabilities.Booleans = false }),
				func(_ *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
					driver.Update = func(_ context.Context, params storage.UpdateParams) (storage.Record, error) {
						call = params
						return cloneAdapterFactoryRecord(params.Update), nil
					}
				},
			)
			result := mustAdapterFactoryUpdate(t, adapter, storage.Record{"emailVerified": value})
			want := int64(0)
			if value {
				want = 1
			}
			if call.Update["emailVerified"] != want || result["emailVerified"] != value {
				t.Fatalf("boolean=%v call=%#v result=%#v", value, call.Update, result)
			}
		}
	case "Should modify JSON type to TEXT if the DB doesn't support it. And expect the result to be transformed back to JSON":
		value := map[string]any{"color": "blue", "size": "large"}
		var call storage.UpdateParams
		adapter := newAdapterFactoryE2EAdapter(t,
			adapterFactorySchemaWithField("preferences", storage.FieldAttribute{Type: storage.FieldJSON}),
			adapterFactoryCapabilities(func(capabilities *storage.Capabilities) { capabilities.JSON = false }),
			func(_ *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
				driver.Update = func(_ context.Context, params storage.UpdateParams) (storage.Record, error) {
					call = params
					return cloneAdapterFactoryRecord(params.Update), nil
				}
			},
		)
		result := mustAdapterFactoryUpdate(t, adapter, storage.Record{"preferences": value})
		if call.Update["preferences"] != `{"color":"blue","size":"large"}` || !reflect.DeepEqual(result["preferences"], value) {
			t.Fatalf("JSON update call=%#v result=%#v", call.Update, result)
		}
	case "Should modify date type to TEXT if the DB doesn't support it. And expect the result to be transformed back to date":
		date := time.Date(2026, time.August, 9, 7, 6, 5, 123456000, time.UTC)
		var call storage.UpdateParams
		adapter := newAdapterFactoryE2EAdapter(t,
			adapterFactoryCapabilities(func(capabilities *storage.Capabilities) { capabilities.Dates = false }),
			func(_ *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
				driver.Update = func(_ context.Context, params storage.UpdateParams) (storage.Record, error) {
					call = params
					return cloneAdapterFactoryRecord(params.Update), nil
				}
			},
		)
		result := mustAdapterFactoryUpdate(t, adapter, storage.Record{"createdAt": date})
		if call.Update["createdAt"] != date.Format(time.RFC3339Nano) || !result["createdAt"].(time.Time).Equal(date) {
			t.Fatalf("date update call=%#v result=%#v", call.Update, result)
		}
	case "Should allow custom transform input":
		assertAdapterFactoryUpdateTransform(t, true, false)
	case "Should allow custom transform output":
		assertAdapterFactoryUpdateTransform(t, false, true)
	case "Should allow custom transform input and output":
		assertAdapterFactoryUpdateTransform(t, true, true)
	case "Should allow custom map input key transformation":
		var call storage.UpdateParams
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			config.MapKeysTransformInput = map[string]string{"email": "email_address"}
			driver.Update = func(_ context.Context, params storage.UpdateParams) (storage.Record, error) {
				call = params
				return cloneAdapterFactoryRecord(params.Update), nil
			}
		})
		result := mustAdapterFactoryUpdate(t, adapter, storage.Record{"email": "test2@test.com"})
		if call.Update["email_address"] != "test2@test.com" || result["email"] != nil {
			t.Fatalf("input map update call=%#v result=%#v", call.Update, result)
		}
		if _, exists := result["email_address"]; exists {
			t.Fatalf("input-only update key escaped %#v", result)
		}
	case "Should allow custom map output key transformation":
		var call storage.UpdateParams
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			config.MapKeysTransformOutput = map[string]string{"email": "email_address"}
			driver.Update = func(_ context.Context, params storage.UpdateParams) (storage.Record, error) {
				call = params
				return cloneAdapterFactoryRecord(params.Update), nil
			}
		})
		result := mustAdapterFactoryUpdate(t, adapter, storage.Record{"email": "test2@test.com"})
		if call.Update["email"] != "test2@test.com" || result["email_address"] != "test2@test.com" {
			t.Fatalf("output map update call=%#v result=%#v", call.Update, result)
		}
		if _, exists := result["email"]; exists {
			t.Fatalf("canonical update key survived output map %#v", result)
		}
	case "Should allow custom map input and output key transformation":
		var call storage.UpdateParams
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			config.MapKeysTransformInput = map[string]string{"email": "email_address"}
			config.MapKeysTransformOutput = map[string]string{"email_address": "email"}
			driver.Update = func(_ context.Context, params storage.UpdateParams) (storage.Record, error) {
				call = params
				return cloneAdapterFactoryRecord(params.Update), nil
			}
		})
		result := mustAdapterFactoryUpdate(t, adapter, storage.Record{"email": "test2@test.com"})
		if call.Update["email_address"] != "test2@test.com" || result["email"] != "test2@test.com" {
			t.Fatalf("both maps update call=%#v result=%#v", call.Update, result)
		}
	case "Should expect the fields to be transformed into the correct field names if customized":
		var call storage.UpdateParams
		adapter := newAdapterFactoryE2EAdapter(t, adapterFactoryEmailAlias(nil, &call))
		result := mustAdapterFactoryUpdate(t, adapter, storage.Record{"email": "test2@test.com"})
		if call.Update["email_address"] != "test2@test.com" || result["email"] != "test2@test.com" {
			t.Fatalf("field alias update call=%#v result=%#v", call.Update, result)
		}
	case "Should expect not to receive an id even if disableIdGeneration is false in an update call":
		var call storage.UpdateParams
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			config.DisableIDGeneration = true
			driver.Update = func(_ context.Context, params storage.UpdateParams) (storage.Record, error) {
				call = params
				return cloneAdapterFactoryRecord(params.Update), nil
			}
		})
		mustAdapterFactoryUpdate(t, adapter, storage.Record{"email": "test2@test.com"})
		if _, exists := call.Update["id"]; exists {
			t.Fatalf("update received generated id %#v", call.Update)
		}
	default:
		t.Fatalf("unhandled update adapter-factory test %q", title)
	}
}

func assertAdapterFactoryUpdateTransform(t *testing.T, inputTransform, outputTransform bool) {
	t.Helper()
	var call storage.UpdateParams
	adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
		if inputTransform {
			config.TransformInput = func(value storage.AdapterTransformContext) (any, error) {
				if value.Field == "name" {
					return strings.ToUpper(value.Data.(string)), nil
				}
				return value.Data, nil
			}
		}
		if outputTransform {
			config.TransformOutput = func(value storage.AdapterOutputTransformContext) (any, error) {
				if value.Field == "name" {
					return strings.ToLower(value.Data.(string)), nil
				}
				return value.Data, nil
			}
		}
		driver.Update = func(_ context.Context, params storage.UpdateParams) (storage.Record, error) {
			call = params
			return cloneAdapterFactoryRecord(params.Update), nil
		}
	})
	result := mustAdapterFactoryUpdate(t, adapter, storage.Record{"name": "test-name-2"})
	wantRaw := "test-name-2"
	if inputTransform {
		wantRaw = "TEST-NAME-2"
	}
	wantOutput := wantRaw
	if outputTransform {
		wantOutput = strings.ToLower(wantRaw)
	}
	if call.Update["name"] != wantRaw || result["name"] != wantOutput {
		t.Fatalf("custom update transforms call=%#v result=%#v", call.Update, result)
	}
}

func runAdapterFactoryFindVector(t *testing.T, title string) {
	t.Helper()
	switch title {
	case "findOne: Should transform the where clause according to the schema":
		var call storage.FindOneParams
		adapter := newAdapterFactoryE2EAdapter(t, func(_ *storage.AdapterFactoryConfig, schema *storage.Schema, driver *storage.CustomAdapter) {
			setAdapterFactoryEmailAlias(schema)
			driver.FindOne = func(_ context.Context, params storage.FindOneParams) (storage.Record, error) {
				call = params
				return adapterFactoryRawUser("random-id-oudwduwbdouwbdu123b", "email_address", "test@test.com"), nil
			}
		})
		result, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "email", Value: "test@test.com"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(call.Where) != 1 || call.Where[0].Field != "email_address" || result["email"] != "test@test.com" {
			t.Fatalf("findOne alias call=%#v result=%#v", call, result)
		}
		if _, exists := result["email_address"]; exists {
			t.Fatalf("physical findOne field escaped %#v", result)
		}
	case "findMany: Should transform the where clause according to the schema":
		var call storage.FindManyParams
		adapter := newAdapterFactoryE2EAdapter(t, func(_ *storage.AdapterFactoryConfig, schema *storage.Schema, driver *storage.CustomAdapter) {
			setAdapterFactoryEmailAlias(schema)
			driver.FindMany = func(_ context.Context, params storage.FindManyParams) ([]storage.Record, error) {
				call = params
				return []storage.Record{adapterFactoryRawUser("random-id-eio1d1u12h33123ed", "email_address", "test@test.com")}, nil
			}
		})
		result, err := adapter.FindMany(t.Context(), storage.FindManyParams{
			Model: "user", Where: []storage.Where{{Field: "email", Value: "test@test.com"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(call.Where) != 1 || call.Where[0].Field != "email_address" || len(result) != 1 || result[0]["email"] != "test@test.com" {
			t.Fatalf("findMany alias call=%#v result=%#v", call, result)
		}
	case "findOne: Should receive an integer id in where clause if the user has enabled `serial`":
		var call storage.FindOneParams
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			config.IDGeneration = storage.IDGenerationSerial
			driver.FindOne = func(_ context.Context, params storage.FindOneParams) (storage.Record, error) {
				call = params
				return adapterFactoryRawUser(int64(1), "email", "test@test.com"), nil
			}
		})
		result, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: "1"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(call.Where) != 1 || !adapterFactoryNumberEquals(call.Where[0].Value, 1) || result["id"] != "1" {
			t.Fatalf("serial findOne call=%#v result=%#v", call, result)
		}
	case "findMany: Should receive an integer id in where clause if the user has enabled `serial`":
		var call storage.FindManyParams
		adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
			config.IDGeneration = storage.IDGenerationSerial
			driver.FindMany = func(_ context.Context, params storage.FindManyParams) ([]storage.Record, error) {
				call = params
				return []storage.Record{adapterFactoryRawUser(int64(1), "email", "test@test.com")}, nil
			}
		})
		result, err := adapter.FindMany(t.Context(), storage.FindManyParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: "1"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(call.Where) != 1 || !adapterFactoryNumberEquals(call.Where[0].Value, 1) || len(result) != 1 || result[0]["id"] != "1" {
			t.Fatalf("serial findMany call=%#v result=%#v", call, result)
		}
	default:
		t.Fatalf("unhandled find adapter-factory test %q", title)
	}
}

func setAdapterFactoryEmailAlias(schema *storage.Schema) {
	user := schema.Models["user"]
	email := user.Fields["email"]
	email.FieldName = "email_address"
	user.Fields["email"] = email
	schema.Models["user"] = user
}

func adapterFactoryRawUser(id any, emailField string, email string) storage.Record {
	return storage.Record{
		"id": id, emailField: email, "emailVerified": false,
		"createdAt": time.Date(2026, time.August, 9, 1, 2, 3, 0, time.UTC),
		"updatedAt": time.Date(2026, time.August, 9, 1, 2, 4, 0, time.UTC),
		"name":      "test-name",
	}
}

func adapterFactoryNumberEquals(value any, want float64) bool {
	switch number := value.(type) {
	case int:
		return float64(number) == want
	case int64:
		return float64(number) == want
	case float64:
		return number == want
	default:
		return false
	}
}

type adapterFactoryJoinCall struct {
	Method string
	One    storage.FindOneParams
	Many   storage.FindManyParams
}

func runAdapterFactoryJoinVector(t *testing.T, suite, title string) {
	t.Helper()
	native := strings.Contains(suite, "supportsJoin: true")
	defaultMode := strings.Contains(suite, "Default behavior")
	calls := make([]adapterFactoryJoinCall, 0, 3)
	adapter := newAdapterFactoryE2EAdapter(t, func(config *storage.AdapterFactoryConfig, _ *storage.Schema, driver *storage.CustomAdapter) {
		if native {
			config.Capabilities.Joins = true
		}
		if defaultMode {
			config.Capabilities = nil
		}
		driver.FindOne = func(_ context.Context, params storage.FindOneParams) (storage.Record, error) {
			calls = append(calls, adapterFactoryJoinCall{Method: "findOne", One: params})
			if params.Model == "user" {
				return adapterFactoryRawUser("user-123", "email", "test@test.com"), nil
			}
			return nil, nil
		}
		driver.FindMany = func(_ context.Context, params storage.FindManyParams) ([]storage.Record, error) {
			calls = append(calls, adapterFactoryJoinCall{Method: "findMany", Many: params})
			switch params.Model {
			case "user":
				return []storage.Record{
					adapterFactoryRawUser("user-1", "email", "test1@test.com"),
					adapterFactoryRawUser("user-2", "email", "test2@test.com"),
				}, nil
			case "session":
				if len(params.Where) == 1 && params.Where[0].Operator == storage.OpEq && params.Where[0].Value == "user-123" {
					return []storage.Record{adapterFactoryRawSession("session-1", "user-123")}, nil
				}
				return []storage.Record{
					adapterFactoryRawSession("session-1", "user-1"),
					adapterFactoryRawSession("session-2", "user-2"),
				}, nil
			default:
				return []storage.Record{}, nil
			}
		}
	})

	join := map[string]storage.JoinOption{"session": {}}
	switch title {
	case "findOne: Should handle forward joins (joined model has FK to base model) by making separate queries":
		result, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: "user-123"}}, Join: join,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !adapterFactoryHasCall(calls, "findOne", "user") || !adapterFactoryHasCall(calls, "findMany", "session") {
			t.Fatalf("fallback join calls=%#v", calls)
		}
		sessions, ok := result["session"].([]storage.Record)
		if !ok || len(sessions) != 1 || sessions[0]["userId"] != "user-123" {
			t.Fatalf("fallback findOne result=%#v", result)
		}
	case "findMany: Should handle forward joins efficiently using IN operator":
		result, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "user", Where: []storage.Where{}, Join: join})
		if err != nil {
			t.Fatal(err)
		}
		var sessionCall *storage.FindManyParams
		for index := range calls {
			if calls[index].Method == "findMany" && calls[index].Many.Model == "session" {
				sessionCall = &calls[index].Many
			}
		}
		if sessionCall == nil || len(sessionCall.Where) != 1 || sessionCall.Where[0].Operator != storage.OpIn {
			t.Fatalf("batched fallback calls=%#v", calls)
		}
		if len(result) != 2 {
			t.Fatalf("fallback findMany result=%#v", result)
		}
		for _, row := range result {
			sessions, ok := row["session"].([]storage.Record)
			if !ok || len(sessions) != 1 {
				t.Fatalf("joined row=%#v", row)
			}
		}
	case "findOne: Should not pass join to adapter when supportsJoin is false":
		if _, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: "user-123"}}, Join: join,
		}); err != nil {
			t.Fatal(err)
		}
		base := adapterFactoryFindOneCall(calls, "user")
		if base == nil || base.Join != nil {
			t.Fatalf("fallback findOne received join %#v", base)
		}
	case "findMany: Should not pass join to adapter when supportsJoin is false":
		if _, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "user", Where: []storage.Where{}, Join: join}); err != nil {
			t.Fatal(err)
		}
		base := adapterFactoryFindManyCall(calls, "user")
		if base == nil || base.Join != nil {
			t.Fatalf("fallback findMany received join %#v", base)
		}
	case "findOne: Should pass join to adapter when supportsJoin is true":
		if _, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: "user-123"}}, Join: join,
		}); err != nil {
			t.Fatal(err)
		}
		base := adapterFactoryFindOneCall(calls, "user")
		if base == nil {
			t.Fatalf("missing native findOne call %#v", calls)
		}
		assertAdapterFactoryNativeJoin(t, base.Join)
	case "findMany: Should pass join to adapter when supportsJoin is true":
		if _, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "user", Where: []storage.Where{}, Join: join}); err != nil {
			t.Fatal(err)
		}
		base := adapterFactoryFindManyCall(calls, "user")
		if base == nil {
			t.Fatalf("missing native findMany call %#v", calls)
		}
		assertAdapterFactoryNativeJoin(t, base.Join)
	case "Should default to supportsJoin: false and use fallback join system":
		if _, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: "user-123"}}, Join: join,
		}); err != nil {
			t.Fatal(err)
		}
		base := adapterFactoryFindOneCall(calls, "user")
		if base == nil || base.Join != nil || adapter.Capabilities().Joins {
			t.Fatalf("default join mode call=%#v capabilities=%#v", base, adapter.Capabilities())
		}
	default:
		t.Fatalf("unhandled join adapter-factory test %q", title)
	}
}

func adapterFactoryRawSession(id, userID string) storage.Record {
	return storage.Record{
		"id": id, "userId": userID,
		"expiresAt": time.Date(2026, time.August, 10, 1, 2, 3, 0, time.UTC),
		"createdAt": time.Date(2026, time.August, 9, 1, 2, 3, 0, time.UTC),
		"updatedAt": time.Date(2026, time.August, 9, 1, 2, 4, 0, time.UTC),
		"token":     "token-" + id,
	}
}

func adapterFactoryHasCall(calls []adapterFactoryJoinCall, method, model string) bool {
	if method == "findOne" {
		return adapterFactoryFindOneCall(calls, model) != nil
	}
	return adapterFactoryFindManyCall(calls, model) != nil
}

func adapterFactoryFindOneCall(calls []adapterFactoryJoinCall, model string) *storage.FindOneParams {
	for index := range calls {
		if calls[index].Method == "findOne" && calls[index].One.Model == model {
			return &calls[index].One
		}
	}
	return nil
}

func adapterFactoryFindManyCall(calls []adapterFactoryJoinCall, model string) *storage.FindManyParams {
	for index := range calls {
		if calls[index].Method == "findMany" && calls[index].Many.Model == model {
			return &calls[index].Many
		}
	}
	return nil
}

func assertAdapterFactoryNativeJoin(t *testing.T, join map[string]storage.JoinOption) {
	t.Helper()
	option, exists := join["session"]
	if !exists || option.On == nil || option.On.From != "id" || option.On.To != "userId" ||
		option.Relation != storage.OneToMany || option.Limit == nil || *option.Limit != 100 {
		t.Fatalf("native join=%#v", join)
	}
}
