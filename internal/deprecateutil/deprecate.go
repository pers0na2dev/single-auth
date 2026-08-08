// Package deprecateutil wraps deprecated functions with a one-time warning.
package deprecateutil

import (
	"log"
	"os"
	"reflect"
	"sync"
)

// Logger is the warning subset required by Deprecate.
type Logger interface {
	Warn(message string)
}

// WarnFunc adapts a function to Logger.
type WarnFunc func(message string)

// Warn calls fn with message.
func (fn WarnFunc) Warn(message string) {
	fn(message)
}

var fallbackLogger = log.New(os.Stderr, "", 0)

// Deprecate returns a function of the exact same type as fn. The wrapper emits
// "[Deprecation] <message>" once and forwards every argument, result, and
// bound method receiver unchanged. When logger is omitted or nil, stderr is
// used as the console.warn equivalent.
func Deprecate[T any](fn T, message string, loggers ...Logger) T {
	if len(loggers) > 1 {
		panic("deprecateutil: expected at most one logger")
	}

	original := reflect.ValueOf(fn)
	if !original.IsValid() || original.Kind() != reflect.Func {
		panic("deprecateutil: fn must be a function")
	}

	var logger Logger
	if len(loggers) == 1 && !isNilLogger(loggers[0]) {
		logger = loggers[0]
	}

	var mutex sync.Mutex
	warned := false
	warnOnce := func() {
		mutex.Lock()
		defer mutex.Unlock()
		if warned {
			return
		}
		warning := "[Deprecation] " + message
		if logger != nil {
			logger.Warn(warning)
		} else {
			fallbackLogger.Print(warning)
		}
		warned = true
	}

	wrapper := reflect.MakeFunc(original.Type(), func(arguments []reflect.Value) []reflect.Value {
		warnOnce()
		if original.Type().IsVariadic() {
			return original.CallSlice(arguments)
		}
		return original.Call(arguments)
	})
	return wrapper.Interface().(T)
}

func isNilLogger(logger Logger) bool {
	if logger == nil {
		return true
	}
	value := reflect.ValueOf(logger)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
