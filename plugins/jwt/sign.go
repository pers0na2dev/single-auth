package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type protectedHeader struct {
	Algorithm Algorithm `json:"alg"`
	KeyID     string    `json:"kid"`
}

// SignJWT signs an arbitrary claim set using the plugin's configured key.
func SignJWT(ctx *engine.Context, options Options, payload map[string]any) (string, error) {
	compiled, err := normalize(options, false)
	if err != nil {
		return "", err
	}
	return compiled.signJWT(ctx, payload)
}

// GetJWTToken builds the session-derived payload and signs it. It is the Go
// equivalent of the upstream getJwtToken export.
func GetJWTToken(ctx *engine.Context, options Options, state SessionState) (string, error) {
	compiled, err := normalize(options, false)
	if err != nil {
		return "", err
	}
	return compiled.getJWTToken(ctx, state)
}

func (plugin *compiledPlugin) signJWT(ctx *engine.Context, input map[string]any) (string, error) {
	payload := cloneMap(input)
	if payload == nil {
		payload = map[string]any{}
	}
	nowSeconds := float64(plugin.clock().Unix())
	iat, hasIAT, err := numericClaim(payload, "iat")
	if err != nil {
		return "", err
	}
	baseIAT := nowSeconds
	if hasIAT {
		baseIAT = iat
	}
	exp, hasExp, err := numericClaim(payload, "exp")
	if err != nil {
		return "", err
	}
	if !hasExp {
		expiration := plugin.options.Token.ExpirationTime
		if expiration == nil {
			expiration = "15m"
		}
		exp, err = ToExpJWT(expiration, baseIAT)
		if err != nil {
			return "", err
		}
	}
	nbf, hasNBF, err := numericClaim(payload, "nbf")
	if err != nil {
		return "", err
	}

	baseOrigin, err := plugin.baseOrigin(ctx)
	if err != nil {
		return "", err
	}
	var issuerValue any = baseOrigin
	if plugin.options.Token.Issuer != nil {
		issuerValue = *plugin.options.Token.Issuer
	}
	if value, exists := payload["iss"]; exists && value != nil {
		issuerValue = value
	}
	audience := plugin.options.Token.Audience
	if value, exists := payload["aud"]; exists && value != nil {
		audience, err = normalizeAudience(value)
		if err != nil {
			return "", err
		}
	}
	if audience == nil {
		audience = baseOrigin
	}

	if plugin.options.Token.Sign != nil {
		remotePayload := cloneMap(payload)
		if hasIAT {
			remotePayload["iat"] = iat
		} else if value, exists := payload["iat"]; exists {
			remotePayload["iat"] = value
		} else {
			delete(remotePayload, "iat")
		}
		remotePayload["exp"] = exp
		if hasNBF {
			remotePayload["nbf"] = nbf
		} else if value, exists := payload["nbf"]; exists {
			remotePayload["nbf"] = value
		} else {
			delete(remotePayload, "nbf")
		}
		remotePayload["iss"] = issuerValue
		remotePayload["aud"] = audience
		goContext := context.Background()
		if ctx != nil {
			goContext = ctx.GoContext()
		}
		return plugin.options.Token.Sign(goContext, remotePayload)
	}
	issuer, ok := issuerValue.(string)
	if !ok {
		return "", errors.New("jwt: claim \"iss\" must be a string")
	}

	key, err := plugin.signingKey(ctx)
	if err != nil {
		return "", err
	}
	privateJSON := []byte(key.PrivateKey)
	if !plugin.options.JWKS.DisablePrivateKeyEncryption {
		privateJSON, err = plugin.decryptPrivateKey(ctx, key.PrivateKey)
		if err != nil {
			return "", err
		}
	}
	privateJWK, err := parseJWK(string(privateJSON))
	if err != nil {
		return "", err
	}
	algorithm := key.Algorithm
	if algorithm == "" && plugin.options.JWKS.KeyPair != nil {
		algorithm = plugin.options.JWKS.KeyPair.Algorithm
	}
	if algorithm == "" {
		algorithm = EdDSA
	}
	privateKey, err := jwkPrivateKey(privateJWK, algorithm)
	if err != nil {
		return "", err
	}

	payload["exp"] = exp
	payload["iss"] = issuer
	payload["aud"] = audience
	if hasIAT {
		payload["iat"] = iat
	}
	if hasNBF {
		payload["nbf"] = nbf
	}
	if value, exists := payload["sub"]; exists && jsTruthy(value) {
		if _, ok := value.(string); !ok {
			return "", errors.New("jwt: claim \"sub\" must be a string")
		}
	}
	if value, exists := payload["jti"]; exists && jsTruthy(value) {
		if _, ok := value.(string); !ok {
			return "", errors.New("jwt: claim \"jti\" must be a string")
		}
	}
	headerBytes, err := json.Marshal(protectedHeader{Algorithm: algorithm, KeyID: key.ID})
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := rawURL.EncodeToString(headerBytes) + "." + rawURL.EncodeToString(payloadBytes)
	signature, err := signBytes(plugin.random, algorithm, privateKey, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + rawURL.EncodeToString(signature), nil
}

func (plugin *compiledPlugin) getJWTToken(ctx *engine.Context, state SessionState) (string, error) {
	payload := map[string]any(nil)
	var err error
	if plugin.options.Token.DefinePayload != nil {
		payload, err = plugin.options.Token.DefinePayload(ctx, cloneSessionState(state))
		if err != nil {
			return "", err
		}
	} else {
		serialized := plugin.options.Runtime.SerializeUser(cloneRecord(state.User))
		switch value := serialized.(type) {
		case map[string]any:
			payload = cloneMap(value)
		case storage.Record:
			payload = cloneMap(value)
		default:
			encoded, marshalErr := json.Marshal(value)
			if marshalErr != nil || json.Unmarshal(encoded, &payload) != nil || payload == nil {
				return "", errors.New("jwt: serialized user must be an object")
			}
		}
	}
	if payload == nil {
		payload = map[string]any{}
	}
	payload["iat"] = float64(plugin.clock().Unix())
	var subject *string
	if plugin.options.Token.GetSubject != nil {
		subject, err = plugin.options.Token.GetSubject(ctx, cloneSessionState(state))
		if err != nil {
			return "", err
		}
	}
	if subject == nil {
		value, _ := recordString(state.User, "id")
		subject = &value
	}
	payload["sub"] = *subject
	return plugin.signJWT(ctx, payload)
}

func signBytes(randomSource io.Reader, algorithm Algorithm, key crypto.PrivateKey, input []byte) ([]byte, error) {
	switch algorithm {
	case EdDSA:
		private, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("jwt: EdDSA private key type mismatch")
		}
		return ed25519.Sign(private, input), nil
	case ES256:
		digest := sha256.Sum256(input)
		return signECDSA(randomSource, key, digest[:], 32)
	case ES512:
		digest := sha512.Sum512(input)
		return signECDSA(randomSource, key, digest[:], 66)
	case PS256:
		private, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("jwt: PS256 private key type mismatch")
		}
		digest := sha256.Sum256(input)
		return rsa.SignPSS(randomSource, private, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case RS256:
		private, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("jwt: RS256 private key type mismatch")
		}
		digest := sha256.Sum256(input)
		return rsa.SignPKCS1v15(randomSource, private, crypto.SHA256, digest[:])
	default:
		return nil, fmt.Errorf("jwt: unsupported JWS algorithm %q", algorithm)
	}
}

func signECDSA(randomSource io.Reader, key crypto.PrivateKey, digest []byte, size int) ([]byte, error) {
	private, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("jwt: ECDSA private key type mismatch")
	}
	r, s, err := ecdsa.Sign(randomSource, private, digest)
	if err != nil {
		return nil, err
	}
	signature := make([]byte, size*2)
	r.FillBytes(signature[:size])
	s.FillBytes(signature[size:])
	return signature, nil
}

func numericClaim(payload map[string]any, name string) (float64, bool, error) {
	value, exists := payload[name]
	if !exists || value == nil {
		return 0, false, nil
	}
	switch number := value.(type) {
	case int:
		return float64(number), true, nil
	case int8:
		return float64(number), true, nil
	case int16:
		return float64(number), true, nil
	case int32:
		return float64(number), true, nil
	case int64:
		return float64(number), true, nil
	case uint:
		return float64(number), true, nil
	case uint8:
		return float64(number), true, nil
	case uint16:
		return float64(number), true, nil
	case uint32:
		return float64(number), true, nil
	case uint64:
		return float64(number), true, nil
	case float32:
		return float64(number), true, nil
	case float64:
		return number, true, nil
	case json.Number:
		parsed, err := number.Float64()
		return parsed, err == nil, err
	default:
		return 0, false, fmt.Errorf("jwt: claim %q must be a number", name)
	}
}

func cloneSessionState(state SessionState) SessionState {
	return SessionState{Session: cloneRecord(state.Session), User: cloneRecord(state.User)}
}

func jsTruthy(value any) bool {
	switch item := value.(type) {
	case nil:
		return false
	case bool:
		return item
	case string:
		return item != ""
	case int:
		return item != 0
	case int64:
		return item != 0
	case float64:
		return item != 0 && !math.IsNaN(item)
	case json.Number:
		value, err := item.Float64()
		return err == nil && value != 0 && !math.IsNaN(value)
	default:
		return true
	}
}
