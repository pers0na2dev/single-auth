package passkey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type ceremony string

const (
	registrationCeremony    ceremony = "registration"
	authenticationCeremony  ceremony = "authentication"
	maxStoredChallengeBytes          = 64 << 10
)

type storedChallenge struct {
	Type              ceremony         `json:"type,omitempty"`
	ExpectedChallenge string           `json:"expectedChallenge"`
	UserData          RegistrationUser `json:"userData"`
	Context           json.RawMessage  `json:"context,omitempty"`
}

func (value storedChallenge) flowContext() (*string, error) {
	if len(value.Context) == 0 || bytes.Equal(bytes.TrimSpace(value.Context), []byte("null")) {
		return nil, nil
	}
	var contextValue string
	if err := json.Unmarshal(value.Context, &contextValue); err != nil {
		return nil, fmt.Errorf("decode passkey context: %w", err)
	}
	return &contextValue, nil
}

func registrationContext(value *string) json.RawMessage {
	if value == nil {
		return json.RawMessage("null")
	}
	encoded, _ := json.Marshal(*value)
	return encoded
}

func (p *plugin) mintChallenge(ctx *engine.Context, value storedChallenge) error {
	cookie, err := p.challengeCookie(ctx.Request())
	if err != nil {
		return err
	}
	token, err := randomString(p.random, 32, "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_")
	if err != nil {
		return fmt.Errorf("passkey: generate verification token: %w", err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("passkey: encode challenge: %w", err)
	}
	now := p.clock().UTC()
	if create := p.options.Runtime.CreateChallenge; create != nil {
		_, err = create(ctx.GoContext(), token, string(encoded), now.Add(defaultChallengeAge))
	} else {
		_, err = p.options.Runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{
			Model: "verification",
			Data: storage.Record{
				"identifier": token,
				"value":      string(encoded),
				"expiresAt":  now.Add(defaultChallengeAge),
				"createdAt":  now,
				"updatedAt":  now,
			},
		})
	}
	if err != nil {
		return err
	}
	maxAge := int(defaultChallengeAge / time.Second)
	attributes := cookie.Attributes
	attributes.MaxAge = &maxAge
	signed := token + "." + baCrypto.MakeSignature(token, p.options.Secret)
	ctx.AddSetCookie(cookies.Serialize(cookie.Name, signed, attributes))
	return nil
}

func (p *plugin) consumeChallenge(ctx *engine.Context, expected ceremony) (storedChallenge, error) {
	token, ok := p.signedChallengeToken(ctx)
	if !ok {
		return storedChallenge{}, passkeyError(contract.StatusBadRequest, ErrorChallengeNotFound)
	}
	var consumed storage.Record
	var err error
	if consume := p.options.Runtime.ConsumeChallenge; consume != nil {
		consumed, err = consume(ctx.GoContext(), token)
		if err != nil {
			return storedChallenge{}, err
		}
	} else {
		rows, findErr := p.options.Runtime.Adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: token}},
			SortBy: &storage.Sort{Field: "createdAt", Direction: storage.Descending}, Limit: storage.Int(1),
		})
		if findErr != nil || len(rows) == 0 {
			if findErr != nil {
				return storedChallenge{}, findErr
			}
			return storedChallenge{}, passkeyError(contract.StatusBadRequest, ErrorChallengeNotFound)
		}
		id, ok := rows[0]["id"]
		if !ok || id == nil {
			return storedChallenge{}, passkeyError(contract.StatusBadRequest, ErrorChallengeNotFound)
		}
		consumed, err = p.options.Runtime.Adapter.ConsumeOne(ctx.GoContext(), storage.ConsumeOneParams{
			Model: "verification", Where: []storage.Where{{Field: "id", Value: id}},
		})
		if err != nil {
			return storedChallenge{}, err
		}
		if consumed != nil {
			if _, err := p.options.Runtime.Adapter.DeleteMany(ctx.GoContext(), storage.DeleteManyParams{
				Model: "verification", Where: []storage.Where{{Field: "identifier", Value: token}},
			}); err != nil {
				return storedChallenge{}, err
			}
		}
	}
	if consumed == nil {
		return storedChallenge{}, passkeyError(contract.StatusBadRequest, ErrorChallengeNotFound)
	}
	expiresAt, ok := recordTime(consumed, "expiresAt")
	if !ok || expiresAt.Before(p.clock()) {
		return storedChallenge{}, passkeyError(contract.StatusBadRequest, ErrorChallengeNotFound)
	}
	raw, ok := recordString(consumed, "value")
	if !ok || len(raw) > maxStoredChallengeBytes {
		return storedChallenge{}, passkeyError(contract.StatusBadRequest, ErrorChallengeNotFound)
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	var value storedChallenge
	if err := decoder.Decode(&value); err != nil {
		return storedChallenge{}, passkeyError(contract.StatusBadRequest, ErrorChallengeNotFound).WithCause(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return storedChallenge{}, passkeyError(contract.StatusBadRequest, ErrorChallengeNotFound)
	}
	// Missing type is accepted for challenges minted before single-auth 1.6.17.
	if value.Type != "" && value.Type != expected {
		return storedChallenge{}, passkeyError(contract.StatusBadRequest, ErrorChallengeNotFound)
	}
	return value, nil
}

func (p *plugin) signedChallengeToken(ctx *engine.Context) (string, bool) {
	cookie, err := p.challengeCookie(ctx.Request())
	if err != nil {
		return "", false
	}
	header := strings.Join(ctx.Request().Headers().Values("Cookie"), "; ")
	value, ok := cookies.Parse(header).Get(cookie.Name)
	if !ok {
		return "", false
	}
	separator := strings.LastIndexByte(value, '.')
	if separator < 1 {
		return "", false
	}
	token, signature := value[:separator], value[separator+1:]
	if !baCrypto.VerifySignature(token, signature, p.options.Secret) {
		return "", false
	}
	return token, true
}

func randomString(random io.Reader, size int, alphabet string) (string, error) {
	if size < 0 || len(alphabet) < 2 || len(alphabet) > 256 {
		return "", fmt.Errorf("invalid random string parameters")
	}
	limit := 256 - (256 % len(alphabet))
	result := make([]byte, 0, size)
	buffer := make([]byte, 1)
	for len(result) < size {
		if _, err := io.ReadFull(random, buffer); err != nil {
			return "", err
		}
		if int(buffer[0]) >= limit {
			continue
		}
		result = append(result, alphabet[int(buffer[0])%len(alphabet)])
	}
	return string(result), nil
}
