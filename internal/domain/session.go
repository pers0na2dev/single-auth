// Package domain defines the small data structures shared by internal runtime
// services. It intentionally contains no behavior and imports no root package.
package domain

import "github.com/pers0na2dev/single-auth/storage"

// SessionPair is the authoritative session record together with its user.
type SessionPair struct {
	Session storage.Record `json:"session"`
	User    storage.Record `json:"user"`
}

// ActiveSessionEntry indexes one session token in secondary storage.
type ActiveSessionEntry struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}
