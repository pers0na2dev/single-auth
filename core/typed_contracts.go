package core

import (
	"errors"

	"github.com/pers0na2dev/single-auth/core/engine"
)

// NoAdditionalFields is the explicit Go representation of a upstream implementation model
// with no configured or plugin-contributed fields. Go cannot intersect object
// types, so TypedUser and TypedSession retain additional fields in a generic
// slot whose empty form is this zero-sized type.
type NoAdditionalFields struct{}

// TypedSessionInference is the static session/user pair exposed by Better
// Auth's $Infer.Session contract. The two generic arguments allow plugins to
// contribute user and session fields independently without erasing either
// model's base fields.
type TypedSessionInference[UserAdditional, SessionAdditional any] struct {
	Session TypedSession[SessionAdditional]
	User    TypedUser[UserAdditional]
}

// TypedRequestContext retains body and query as independent type parameters.
// In particular, choosing any for Body cannot widen Query to any, mirroring
// upstream implementation's InferCtx any-poisoning guard.
type TypedRequestContext[Body, Query any] struct {
	Body   Body
	Query  Query
	Method string
	Path   string
	Params map[string]string
}

// RequiredKeysResult is the closed result set for RequiredKeysOf.
type RequiredKeysResult interface {
	requiredKeysResult()
	Bool() bool
}

// RequiredKeysPresent and RequiredKeysAbsent are distinct compile-time result
// types. upstream implementation computes this distinction structurally; Go callers use an
// explicit shape wrapper because the language has no optional object keys.
type RequiredKeysPresent struct{}
type RequiredKeysAbsent struct{}

func (RequiredKeysPresent) requiredKeysResult() {}
func (RequiredKeysAbsent) requiredKeysResult()  {}
func (RequiredKeysPresent) Bool() bool          { return true }
func (RequiredKeysAbsent) Bool() bool           { return false }

// AnyKeyShape represents an unconstrained any-shaped object. It deliberately
// reports no statically known required keys.
type AnyKeyShape struct{}

func (AnyKeyShape) RequiredKeysResult() RequiredKeysAbsent { return RequiredKeysAbsent{} }

// RequiredKeyShape and OptionalKeyShape retain the caller's field shape while
// explicitly recording whether its keys are required or optional.
type RequiredKeyShape[Fields any] struct{ Fields Fields }
type OptionalKeyShape[Fields any] struct{ Fields Fields }

func (RequiredKeyShape[Fields]) RequiredKeysResult() RequiredKeysPresent {
	return RequiredKeysPresent{}
}

func (OptionalKeyShape[Fields]) RequiredKeysResult() RequiredKeysAbsent {
	return RequiredKeysAbsent{}
}

// RequiredKeysOf returns a compile-time marker without reflection. Result is
// inferred from the shape's method signature on current Go toolchains.
func RequiredKeysOf[
	Result RequiredKeysResult,
	Shape interface{ RequiredKeysResult() Result },
](shape Shape) Result {
	return shape.RequiredKeysResult()
}

// KnownPluginPresence is the true literal marker returned for a plugin whose
// position and type are known at compile time. Dynamic plugin IDs continue to
// return an ordinary bool through TypedPluginContext2.HasPlugin.
type KnownPluginPresence struct{}

func (KnownPluginPresence) Bool() bool { return true }

// TypedPluginContext2 binds two concrete plugin values to the runtime plugin
// registry. Go has no string-literal indexed return types, so known plugins are
// retrieved by stable typed positions while arbitrary IDs use HasPlugin.
type TypedPluginContext2[First, Second any] struct {
	auth     *Auth
	firstID  string
	secondID string
	first    First
	second   Second
}

// NewTypedPluginContext2 creates a typed view over two configured plugins.
func NewTypedPluginContext2[First, Second any](
	auth *Auth,
	firstID string,
	first First,
	secondID string,
	second Second,
) (TypedPluginContext2[First, Second], error) {
	if auth == nil {
		return TypedPluginContext2[First, Second]{}, errors.New("single-auth: typed plugin context requires an initialized Auth")
	}
	if firstID == "" || secondID == "" {
		return TypedPluginContext2[First, Second]{}, errors.New("single-auth: typed plugin IDs must not be empty")
	}
	return TypedPluginContext2[First, Second]{
		auth: auth, firstID: firstID, secondID: secondID, first: first, second: second,
	}, nil
}

func (context TypedPluginContext2[First, Second]) First() First   { return context.first }
func (context TypedPluginContext2[First, Second]) Second() Second { return context.second }

func (TypedPluginContext2[First, Second]) HasFirst() KnownPluginPresence {
	return KnownPluginPresence{}
}

func (TypedPluginContext2[First, Second]) HasSecond() KnownPluginPresence {
	return KnownPluginPresence{}
}

// HasPlugin performs the dynamic counterpart of upstream implementation context.hasPlugin.
func (context TypedPluginContext2[First, Second]) HasPlugin(id string) bool {
	if id == context.firstID || id == context.secondID {
		return true
	}
	if context.auth == nil {
		return false
	}
	for _, plugin := range context.auth.options.Plugins {
		if plugin.ID == id {
			return true
		}
	}
	return false
}

// Plugin returns the immutable runtime descriptor for a dynamic plugin ID.
func (context TypedPluginContext2[First, Second]) Plugin(id string) (engine.Plugin, bool) {
	if context.auth == nil {
		return engine.Plugin{}, false
	}
	for _, plugin := range context.auth.options.Plugins {
		if plugin.ID == id {
			return plugin, true
		}
	}
	return engine.Plugin{}, false
}

// TypedContext preserves fields contributed by plugin init hooks. Extension is
// explicit because Go cannot synthesize fields onto AuthContext at compile
// time; Runtime still provides the initialized production context.
type TypedContext[Extension any] struct {
	Runtime   *AuthContext
	extension Extension
}

// NewTypedContext binds a caller-defined init extension to an Auth context.
func NewTypedContext[Extension any](auth *Auth, extension Extension) (TypedContext[Extension], error) {
	if auth == nil {
		return TypedContext[Extension]{}, errors.New("single-auth: typed context requires an initialized Auth")
	}
	runtime, err := auth.Context()
	if err != nil {
		return TypedContext[Extension]{}, err
	}
	return TypedContext[Extension]{Runtime: runtime, extension: extension}, nil
}

// Extension returns the concrete init-hook context contribution.
func (context TypedContext[Extension]) Extension() Extension { return context.extension }

// PluginAPIs2 composes differently shaped plugin APIs without losing either
// concrete type. TypeScript flattens plugin endpoints into one object; Go keeps
// each collision-free API in an explicit slot.
type PluginAPIs2[First, Second any] struct {
	First  First
	Second Second
}

func ComposePluginAPIs2[First, Second any](first First, second Second) PluginAPIs2[First, Second] {
	return PluginAPIs2[First, Second]{First: first, Second: second}
}

// BaseErrorCodes is the statically typed core error-code subset used by type
// contracts. Values retain the public ErrorCode type instead of widening to
// string or any.
type BaseErrorCodes struct {
	SessionExpired ErrorCode
}

// TypedErrorCodes composes core and plugin-specific code sets.
type TypedErrorCodes[PluginCodes any] struct {
	Base   BaseErrorCodes
	Plugin PluginCodes
}

func NewTypedErrorCodes[PluginCodes any](plugin PluginCodes) TypedErrorCodes[PluginCodes] {
	return TypedErrorCodes[PluginCodes]{
		Base:   BaseErrorCodes{SessionExpired: ErrorSessionExpired},
		Plugin: plugin,
	}
}

// PreserveInferenceWithUntypedPlugins deliberately keeps the inferred static
// session type when an integration also supplies dynamically typed plugins.
func PreserveInferenceWithUntypedPlugins[Inference any](
	inference Inference,
	_ ...any,
) Inference {
	return inference
}

// PreserveErrorCodesWithUntypedPlugins is the error-code counterpart of
// PreserveInferenceWithUntypedPlugins.
func PreserveErrorCodesWithUntypedPlugins[PluginCodes any](
	codes TypedErrorCodes[PluginCodes],
	_ ...any,
) TypedErrorCodes[PluginCodes] {
	return codes
}
