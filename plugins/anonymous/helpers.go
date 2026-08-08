package anonymous

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/pers0na2dev/single-auth/storage"
)

const idAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (reader *lockedReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.r.Read(target)
}

func randomIdentifier(reader io.Reader, size int) (string, error) {
	if reader == nil {
		reader = rand.Reader
	}
	if size <= 0 {
		return "", fmt.Errorf("anonymous: random identifier length must be positive")
	}
	result := make([]byte, size)
	buffer := make([]byte, size*2)
	ceiling := 256 - 256%len(idAlphabet)
	written := 0
	for written < size {
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return "", fmt.Errorf("anonymous: generate random identifier: %w", err)
		}
		for _, value := range buffer {
			if int(value) >= ceiling {
				continue
			}
			result[written] = idAlphabet[int(value)%len(idAlphabet)]
			written++
			if written == size {
				break
			}
		}
	}
	return string(result), nil
}

func formatGeneratedEmail(id, domain string) string {
	if domain != "" {
		return "temp-" + id + "@" + domain
	}
	return "temp@" + id + ".com"
}

// validGeneratedEmail implements zod 4.3.6's practical z.email() expression,
// which is the validator used by single-auth 1.6.26's anonymous plugin.
func validGeneratedEmail(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.Contains(value, "..") || strings.Count(value, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(value, "@")
	if local == "" || domain == "" || !validEmailLocal(local) {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 || len(labels[len(labels)-1]) < 2 || !asciiLetters(labels[len(labels)-1]) {
		return false
	}
	for _, label := range labels[:len(labels)-1] {
		if label == "" || !asciiAlphaNumeric(label[0]) {
			return false
		}
		for index := 1; index < len(label); index++ {
			if !asciiAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func validEmailLocal(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if asciiAlphaNumeric(character) || strings.ContainsRune("_'+-.", rune(character)) {
			continue
		}
		return false
	}
	last := value[len(value)-1]
	return asciiAlphaNumeric(last) || strings.ContainsRune("_+-", rune(last))
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func asciiLetters(value string) bool {
	for index := 0; index < len(value); index++ {
		if character := value[index]; character < 'a' || character > 'z' {
			if character < 'A' || character > 'Z' {
				return false
			}
		}
	}
	return true
}

func recordString(record storage.Record, key string) (string, bool) {
	if record == nil {
		return "", false
	}
	value, exists := record[key]
	if !exists || value == nil {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func jsTruthy(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		return typed != ""
	case int:
		return typed != 0
	case int8:
		return typed != 0
	case int16:
		return typed != 0
	case int32:
		return typed != 0
	case int64:
		return typed != 0
	case uint:
		return typed != 0
	case uint8:
		return typed != 0
	case uint16:
		return typed != 0
	case uint32:
		return typed != 0
	case uint64:
		return typed != 0
	case float32:
		return typed != 0 && typed == typed
	case float64:
		return typed != 0 && typed == typed
	default:
		return true
	}
}

func cloneRecord(source storage.Record) storage.Record {
	if source == nil {
		return nil
	}
	result := make(storage.Record, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
