package haveibeenpwned

import (
	"crypto/sha1" // #nosec G505 -- required by the range API protocol.
	"encoding/hex"
	"net/http"
	"strings"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (function doerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

func passwordSuffix(password string) string {
	digest := sha1.Sum([]byte(password)) // #nosec G401 -- required by the range API protocol.
	hash := strings.ToUpper(hex.EncodeToString(digest[:]))
	return hash[5:]
}
