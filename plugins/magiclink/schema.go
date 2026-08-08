package magiclink

import "github.com/pers0na2dev/single-auth/storage"

// Schema is empty because magic-link 1.6.26 adds no plugin model. It consumes
// single-auth's core verification, user, account, and session models.
func Schema() storage.Schema { return storage.Schema{} }
