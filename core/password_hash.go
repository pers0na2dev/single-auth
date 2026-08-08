package core

import (
	"fmt"
	"sync"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

// PluginPasswordHash is the request-aware password hash function exposed to
// plugin factories. Context is nil for non-endpoint use; wrappers must then
// behave as if no route path were active.
type PluginPasswordHash func(*engine.Context, string) (string, error)

// PluginPasswordHashWrapper decorates the hash function installed by prior
// factories. Factories are applied in declaration order, so the latest wrapper
// becomes the outermost one, matching upstream implementation init context composition.
type PluginPasswordHashWrapper func(PluginPasswordHash) PluginPasswordHash

type passwordHashChain struct {
	mu     sync.RWMutex
	hash   PluginPasswordHash
	frozen bool
}

func newPasswordHashChain(base func(string) (string, error)) *passwordHashChain {
	return &passwordHashChain{hash: func(_ *engine.Context, password string) (string, error) {
		return base(password)
	}}
}

func (chain *passwordHashChain) wrap(wrapper PluginPasswordHashWrapper) error {
	if wrapper == nil {
		return fmt.Errorf("single-auth: password hash wrapper is nil")
	}
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if chain.frozen {
		return fmt.Errorf("single-auth: password hash wrappers are already initialized")
	}
	next := wrapper(chain.hash)
	if next == nil {
		return fmt.Errorf("single-auth: password hash wrapper returned nil")
	}
	chain.hash = next
	return nil
}

func (chain *passwordHashChain) freeze() {
	chain.mu.Lock()
	chain.frozen = true
	chain.mu.Unlock()
}

func (chain *passwordHashChain) run(ctx *engine.Context, password string) (string, error) {
	chain.mu.RLock()
	hash := chain.hash
	chain.mu.RUnlock()
	if hash == nil {
		return "", fmt.Errorf("single-auth: password hash is not initialized")
	}
	return hash(ctx, password)
}

func (a *Auth) hashPassword(ctx *engine.Context, password string) (string, error) {
	if a == nil || a.passwordHash == nil {
		return "", fmt.Errorf("single-auth: password hash is not initialized")
	}
	return a.passwordHash.run(ctx, password)
}

func passwordHashError(err error, fallback *contract.APIError) *contract.APIError {
	if apiError, ok := contract.AsAPIError(err); ok {
		return apiError
	}
	if fallback == nil {
		fallback = contract.NewAPIError(
			contract.StatusInternalServerError,
			"INTERNAL_SERVER_ERROR",
			"Internal Server Error",
		)
	}
	return fallback.WithCause(err)
}
