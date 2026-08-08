package siwe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const maxBodyBytes = 4 << 20

var (
	walletInputPattern = regexp.MustCompile(`^0[xX][a-fA-F0-9]{40}$`)
	emailLocalPattern  = regexp.MustCompile(`^[A-Za-z0-9_'+.\-]*[A-Za-z0-9_+\-]$`)
	emailDomainPattern = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$`)
)

func (p *plugin) nonce(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	walletAddress, hasWalletAddress, walletAddressIsString := bodyString(body, "walletAddress")
	addressAlias, hasAddressAlias, addressAliasIsString := bodyString(body, "address")
	issues := make([]string, 0, 5)
	if hasWalletAddress {
		if !walletAddressIsString {
			issues = append(issues, typeValidationMessage("walletAddress", body["walletAddress"], "string"))
		} else if message := addressValidationMessage("walletAddress", walletAddress); message != "" {
			issues = append(issues, message)
		}
	}
	if hasAddressAlias {
		if !addressAliasIsString {
			issues = append(issues, typeValidationMessage("address", body["address"], "string"))
		} else if message := addressValidationMessage("address", addressAlias); message != "" {
			issues = append(issues, message)
		}
	}
	if walletAddress == "" && addressAlias == "" {
		issues = append(issues, "[body.walletAddress] walletAddress or address is required")
	}
	if len(issues) != 0 {
		return contract.Response{}, validation(strings.Join(issues, "; "))
	}
	address := addressAlias
	if hasWalletAddress {
		address = walletAddress
	}
	chainID, err := chainID(body)
	if err != nil {
		return contract.Response{}, err
	}
	checksum := ChecksumAddress(address)
	nonce, err := p.options.GetNonce(ctx.GoContext())
	if err != nil {
		return contract.Response{}, err
	}
	_, err = p.options.Runtime.CreateVerification(
		ctx.GoContext(), verificationIdentifier(checksum, chainID), nonce,
		p.clock().Add(nonceLifetime),
	)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{"nonce": nonce})
}

func (p *plugin) verify(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	message := optionalString(body, "message")
	signature := optionalString(body, "signature")
	address := optionalString(body, "walletAddress")
	if message == "" {
		return contract.Response{}, validation("[body.message] Too small: expected string to have >=1 characters")
	}
	if signature == "" {
		return contract.Response{}, validation("[body.signature] Too small: expected string to have >=1 characters")
	}
	if validationMessage := addressValidationMessage("walletAddress", address); validationMessage != "" {
		return contract.Response{}, validation(validationMessage)
	}
	chainID, err := chainID(body)
	if err != nil {
		return contract.Response{}, err
	}
	email, hasEmail := body["email"]
	emailString, emailIsString := email.(string)
	validationMessages := make([]string, 0, 2)
	if hasEmail && (!emailIsString || !validEmail(emailString)) {
		validationMessages = append(validationMessages, "[body.email] Invalid email address")
	}
	if !p.isAnonymous() && (!hasEmail || !emailIsString || emailString == "") {
		validationMessages = append(validationMessages, "[body.email] Email is required when the anonymous plugin option is disabled.")
	}
	if len(validationMessages) != 0 {
		return contract.Response{}, validation(strings.Join(validationMessages, "; "))
	}

	checksum := ChecksumAddress(address)
	verification, err := p.options.Runtime.ConsumeVerification(
		ctx.GoContext(), verificationIdentifier(checksum, chainID),
	)
	if err != nil {
		return contract.Response{}, wrapUnauthorized(err)
	}
	if verification == nil {
		return contract.Response{}, apiError(
			contract.StatusUnauthorized,
			"UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
			"Unauthorized: Invalid or expired nonce",
		)
	}
	nonce, _ := recordString(verification, "value")
	parsed := ParseMessage(message)
	if parsed.Nonce != nonce ||
		parsed.Address == "" || !strings.EqualFold(parsed.Address, checksum) ||
		!parsed.HasChainID || parsed.ChainID != chainID ||
		parsed.Domain == "" || NormalizeDomain(parsed.Domain) != NormalizeDomain(p.options.Domain) {
		return contract.Response{}, apiError(
			contract.StatusUnauthorized,
			"UNAUTHORIZED_SIWE_MESSAGE_MISMATCH",
			"Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID",
		)
	}
	now := p.clock()
	if parsed.ExpirationTime != "" {
		if expiresAt, ok := parseJavaScriptDate(parsed.ExpirationTime); ok && !now.Before(expiresAt) {
			return contract.Response{}, apiError(
				contract.StatusUnauthorized,
				"UNAUTHORIZED_SIWE_MESSAGE_EXPIRED",
				"Unauthorized: SIWE message has expired",
			)
		}
	}
	if parsed.NotBefore != "" {
		if notBefore, ok := parseJavaScriptDate(parsed.NotBefore); ok && now.Before(notBefore) {
			return contract.Response{}, apiError(
				contract.StatusUnauthorized,
				"UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
				"Unauthorized: SIWE message is not yet valid",
			)
		}
	}
	verified, err := p.options.VerifyMessage(ctx.GoContext(), VerifyMessageArgs{
		Message: message, Signature: signature, Address: checksum, ChainID: chainID,
		Cacao: Cacao{
			Header: CacaoHeader{Type: "caip122"},
			Payload: CacaoPayload{
				Domain: p.options.Domain, Audience: p.options.Domain, Nonce: nonce,
				Issuer: p.options.Domain, Version: "1",
			},
			Signature: CacaoSignature{Type: "eip191", Value: signature},
		},
	})
	if err != nil {
		return contract.Response{}, wrapUnauthorized(err)
	}
	if !verified {
		return contract.Response{}, apiError(
			contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized: Invalid SIWE signature",
		)
	}

	user, err := p.findWalletUser(ctx, checksum, chainID)
	if err != nil {
		return contract.Response{}, wrapUnauthorized(err)
	}
	if user == nil {
		user, err = p.createWalletUser(ctx, checksum, chainID, emailString)
		if err != nil {
			return contract.Response{}, wrapUnauthorized(err)
		}
	} else {
		existing, findErr := p.findExactWallet(ctx, checksum, chainID)
		if findErr != nil {
			return contract.Response{}, wrapUnauthorized(findErr)
		}
		if existing == nil {
			userID, _ := recordString(user, "id")
			if err := p.createWalletAndAccount(ctx, userID, checksum, chainID, false); err != nil {
				return contract.Response{}, wrapUnauthorized(err)
			}
		}
	}
	userID, _ := recordString(user, "id")
	state, err := p.options.Runtime.IssueSession(ctx, userID)
	if err != nil {
		return contract.Response{}, wrapUnauthorized(err)
	}
	if state == nil || state.Session == nil {
		return contract.Response{}, apiError(
			contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Internal Server Error",
		)
	}
	token, _ := recordString(state.Session, "token")
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"token": token, "success": true,
		"user": map[string]any{"id": userID, "walletAddress": checksum, "chainId": chainID},
	})
}

func (p *plugin) findWalletUser(ctx *engine.Context, address string, chainID int64) (storage.Record, error) {
	exact, err := p.findExactWallet(ctx, address, chainID)
	if err != nil {
		return nil, err
	}
	wallet := exact
	if wallet == nil {
		wallet, err = p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "walletAddress", Where: []storage.Where{{Field: "address", Value: address}},
		})
		if err != nil {
			return nil, err
		}
	}
	if wallet == nil {
		return nil, nil
	}
	userID, _ := recordString(wallet, "userId")
	return p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
}

func (p *plugin) findExactWallet(ctx *engine.Context, address string, chainID int64) (storage.Record, error) {
	return p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "walletAddress", Where: []storage.Where{
			{Field: "address", Value: address}, {Field: "chainId", Value: chainID},
		},
	})
}

func (p *plugin) createWalletUser(
	ctx *engine.Context, address string, chainID int64, suppliedEmail string,
) (storage.Record, error) {
	domain := p.options.EmailDomainName
	if domain == "" {
		baseURL, err := p.options.Runtime.ResolveBaseURL(ctx.Request())
		if err != nil {
			return nil, err
		}
		domain = origin(baseURL)
	}
	userEmail := address + "@" + domain
	if !p.isAnonymous() && suppliedEmail != "" {
		normalized := strings.ToLower(suppliedEmail)
		existing, err := p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{
				Field: "email", Value: normalized, Mode: storage.Insensitive,
			}},
		})
		if err != nil {
			return nil, err
		}
		if existing == nil {
			userEmail = normalized
		}
	}
	name := address
	avatar := ""
	if p.options.ENSLookup != nil {
		ens, err := p.options.ENSLookup(ctx.GoContext(), ENSLookupArgs{WalletAddress: address})
		if err != nil {
			return nil, err
		}
		if ens.Name != "" {
			name = ens.Name
		}
		if ens.Avatar != "" {
			avatar = ens.Avatar
		}
	}
	user, err := p.options.Runtime.CreateUser(ctx, storage.Record{
		"name": name, "email": userEmail, "image": avatar,
	})
	if err != nil {
		return nil, err
	}
	userID, _ := recordString(user, "id")
	if err := p.createWalletAndAccount(ctx, userID, address, chainID, true); err != nil {
		return nil, err
	}
	return user, nil
}

func (p *plugin) createWalletAndAccount(
	ctx *engine.Context, userID, address string, chainID int64, primary bool,
) error {
	now := p.clock()
	if _, err := p.options.Runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{
		Model: "walletAddress", Data: storage.Record{
			"userId": userID, "address": address, "chainId": chainID,
			"isPrimary": primary, "createdAt": now,
		},
	}); err != nil {
		return err
	}
	_, err := p.options.Runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{
		Model: "account", Data: storage.Record{
			"userId": userID, "providerId": "siwe", "accountId": fmt.Sprintf("%s:%d", address, chainID),
			"createdAt": now, "updatedAt": now,
		},
	})
	return err
}

func (p *plugin) isAnonymous() bool {
	return p.options.Anonymous == nil || *p.options.Anonymous
}

func verificationIdentifier(address string, chainID int64) string {
	return fmt.Sprintf("siwe:%s:%d", address, chainID)
}

func chainID(body map[string]any) (int64, error) {
	value, exists := body["chainId"]
	if !exists || value == nil {
		return 1, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, validation("[body.chainId] Invalid input: expected number, received " + jsonTypeName(value))
	}
	parsed, err := number.Float64()
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed != math.Trunc(parsed) {
		return 0, validation("[body.chainId] Invalid input: expected int, received number")
	}
	if parsed <= 0 {
		return 0, validation("[body.chainId] Too small: expected number to be >0")
	}
	if parsed > math.MaxInt64 {
		return 0, validation("[body.chainId] Too big: expected int to be <9223372036854775807")
	}
	return int64(parsed), nil
}

func decodeObject(ctx *engine.Context) (map[string]any, error) {
	body := ctx.Request().Body()
	if len(body) > maxBodyBytes {
		return nil, validation("Request body is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, validation("Invalid request body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, validation("Invalid request body")
	}
	return object, nil
}

func addressValidationMessage(field, value string) string {
	messages := make([]string, 0, 2)
	if !walletInputPattern.MatchString(value) {
		messages = append(messages, "[body."+field+"] Invalid string: must match pattern /^0[xX][a-fA-F0-9]{40}$/i")
	}
	if len(value) < 42 {
		messages = append(messages, "[body."+field+"] Too small: expected string to have >=42 characters")
	} else if len(value) > 42 {
		messages = append(messages, "[body."+field+"] Too big: expected string to have <=42 characters")
	}
	return strings.Join(messages, "; ")
}

func validEmail(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.Contains(value, "..") || strings.Count(value, "@") != 1 {
		return false
	}
	parts := strings.SplitN(value, "@", 2)
	return emailLocalPattern.MatchString(parts[0]) && emailDomainPattern.MatchString(parts[1])
}

func optionalString(body map[string]any, field string) string {
	value, _ := body[field].(string)
	return value
}

func bodyString(body map[string]any, field string) (string, bool, bool) {
	value, exists := body[field]
	if !exists {
		return "", false, false
	}
	text, ok := value.(string)
	return text, true, ok
}

func typeValidationMessage(field string, value any, expected string) string {
	received := jsonTypeName(value)
	return "[body." + field + "] Invalid input: expected " + expected + ", received " + received
}

func recordString(record storage.Record, field string) (string, bool) {
	value, ok := record[field].(string)
	return value, ok
}

func parseJavaScriptDate(value string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func origin(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func jsonTypeName(value any) string {
	switch value.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case nil:
		return "null"
	default:
		return "object"
	}
}

func validation(message string) *contract.APIError {
	return apiError(contract.StatusBadRequest, "VALIDATION_ERROR", message)
}

func apiError(status int, code, message string) *contract.APIError {
	return contract.NewAPIError(status, code, message)
}

func wrapUnauthorized(err error) error {
	if _, ok := contract.AsAPIError(err); ok {
		return err
	}
	return apiError(
		contract.StatusUnauthorized, "UNAUTHORIZED", "Something went wrong. Please try again later.",
	).WithCause(err)
}
