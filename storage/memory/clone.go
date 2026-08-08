package memory

import (
	"reflect"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

func cloneRecord(record storage.Record) storage.Record {
	if record == nil {
		return nil
	}
	clone := make(storage.Record, len(record))
	for key, value := range record {
		clone[key] = cloneValue(value)
	}
	return clone
}

func cloneRows(rows []storage.Record) []storage.Record {
	if rows == nil {
		return nil
	}
	clone := make([]storage.Record, len(rows))
	for index, row := range rows {
		clone[index] = cloneRecord(row)
	}
	return clone
}

func cloneTables(tables map[string][]storage.Record) map[string][]storage.Record {
	clone := make(map[string][]storage.Record, len(tables))
	for model, rows := range tables {
		clone[model] = cloneRows(rows)
	}
	return clone
}

func cloneValue(value any) any {
	if value == nil {
		return nil
	}
	return cloneReflect(reflect.ValueOf(value)).Interface()
}

func cloneReflect(value reflect.Value) reflect.Value {
	if !value.IsValid() {
		return reflect.Value{}
	}
	if value.Type() == reflect.TypeOf(time.Time{}) {
		return value
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		cloned := cloneReflect(value.Elem())
		wrapped := reflect.New(value.Type()).Elem()
		wrapped.Set(cloned)
		return wrapped
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		clone := reflect.New(value.Type().Elem())
		clone.Elem().Set(cloneReflect(value.Elem()))
		return clone
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		clone := reflect.MakeMapWithSize(value.Type(), value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			clone.SetMapIndex(iterator.Key(), cloneReflect(iterator.Value()))
		}
		return clone
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}
		clone := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for index := 0; index < value.Len(); index++ {
			clone.Index(index).Set(cloneReflect(value.Index(index)))
		}
		return clone
	case reflect.Array:
		clone := reflect.New(value.Type()).Elem()
		for index := 0; index < value.Len(); index++ {
			clone.Index(index).Set(cloneReflect(value.Index(index)))
		}
		return clone
	default:
		return value
	}
}
