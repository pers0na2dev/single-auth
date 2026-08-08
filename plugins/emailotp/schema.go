package emailotp

import "github.com/pers0na2dev/single-auth/storage"

// Schema is empty because email-otp 1.6.26 adds no plugin table. It consumes
// single-auth's core verification, user, account, and session models.
func Schema() storage.Schema { return storage.Schema{} }
