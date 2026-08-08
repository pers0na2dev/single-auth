package core

import (
	"fmt"
	"io"
)

const idAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generateIdentifier(options runtimeOptions, model string, size int) (string, bool, error) {
	if size <= 0 {
		size = 32
	}
	if options.GenerateID != nil {
		return options.GenerateID(model, size)
	}
	value, err := randomString(options.Random, size)
	return value, true, err
}

func randomString(random io.Reader, size int) (string, error) {
	return randomStringFromAlphabet(random, size, idAlphabet)
}

func randomStringFromAlphabet(random io.Reader, size int, alphabet string) (string, error) {
	if random == nil {
		return "", fmt.Errorf("single-auth: random source is nil")
	}
	if size < 0 || len(alphabet) < 2 || len(alphabet) > 256 {
		return "", fmt.Errorf("single-auth: invalid random string configuration")
	}
	result := make([]byte, size)
	buffer := make([]byte, size*2+1)
	written := 0
	// Rejection sampling avoids modulo bias.
	ceiling := 256 - (256 % len(alphabet))
	for written < size {
		if _, err := io.ReadFull(random, buffer); err != nil {
			return "", fmt.Errorf("single-auth: generate random identifier: %w", err)
		}
		for _, value := range buffer {
			if int(value) >= ceiling {
				continue
			}
			result[written] = alphabet[int(value)%len(alphabet)]
			written++
			if written == size {
				break
			}
		}
	}
	return string(result), nil
}
