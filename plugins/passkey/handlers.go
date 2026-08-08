package passkey

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/protocol/webauthn"
)

const maxRequestBodyBytes = 4 << 20

type verifyRegistrationBody struct {
	Response json.RawMessage `json:"response"`
	Name     bodyString      `json:"name,omitempty"`
}

type verifyAuthenticationBody struct {
	Response json.RawMessage `json:"response"`
}

type resourceBody struct {
	ID bodyString `json:"id"`
}

type updateBody struct {
	ID   bodyString `json:"id"`
	Name bodyString `json:"name"`
}

// bodyString preserves the distinction zod makes between an omitted string
// and a present string while rejecting JSON null and non-string values.
type bodyString struct {
	Value   string
	Present bool
}

func (value *bodyString) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("value must be a string")
	}
	var decoded string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	value.Value = decoded
	value.Present = true
	return nil
}

func (p *plugin) generateRegistrationOptions(ctx *engine.Context) (contract.Response, error) {
	user, err := p.resolveRegistrationUser(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, validationError("Invalid query")
	}
	attachment := query.Get("authenticatorAttachment")
	if attachment != "" && attachment != "platform" && attachment != "cross-platform" {
		return contract.Response{}, validationError("Invalid authenticatorAttachment")
	}

	rows, err := p.options.Runtime.Adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "passkey", Where: []storage.Where{{Field: "userId", Value: user.ID}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	excluded := make([]webauthn.CredentialDescriptor, 0, len(rows))
	for _, row := range rows {
		credentialID, ok := recordString(row, "credentialID")
		if !ok {
			continue
		}
		excluded = append(excluded, webauthn.CredentialDescriptor{
			ID: credentialID, Transports: recordTransports(row),
		})
	}
	extensions, err := p.registrationExtensions(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	userID, err := randomString(p.random, 32, "abcdefghijklmnopqrstuvwxyz0123456789")
	if err != nil {
		return contract.Response{}, fmt.Errorf("passkey: generate user id: %w", err)
	}
	selection := p.registrationSelection(attachment)
	userName := query.Get("name")
	if userName == "" {
		userName = user.Name
	}
	if userName == "" {
		userName = user.ID
	}
	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.Name
	}
	if displayName == "" {
		displayName = user.ID
	}
	options, err := webauthn.GenerateRegistrationOptions(webauthn.GenerateRegistrationOptionsInput{
		RPName: p.rpName, RPID: p.rpID, UserID: []byte(userID), UserName: userName,
		UserDisplayName: displayName, AttestationType: "none",
		ExcludeCredentials: excluded, AuthenticatorSelection: &selection,
		Extensions: extensions, Random: p.random,
	})
	if err != nil {
		return contract.Response{}, err
	}
	var flowContext *string
	if values, exists := query["context"]; exists && len(values) > 0 {
		value := values[0]
		flowContext = &value
	}
	if err := p.mintChallenge(ctx, storedChallenge{
		Type: registrationCeremony, ExpectedChallenge: options.Challenge,
		UserData: user, Context: registrationContext(flowContext),
	}); err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, options)
}

func (p *plugin) generateAuthenticationOptions(ctx *engine.Context) (contract.Response, error) {
	session, err := p.options.Runtime.ResolveSession(ctx, SessionOptional)
	if err != nil {
		return contract.Response{}, err
	}
	var allowed []webauthn.CredentialDescriptor
	userData := RegistrationUser{}
	if id, ok := userID(session); ok {
		userData.ID = id
		rows, findErr := p.options.Runtime.Adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
			Model: "passkey", Where: []storage.Where{{Field: "userId", Value: id}},
		})
		if findErr != nil {
			return contract.Response{}, findErr
		}
		if len(rows) > 0 {
			allowed = make([]webauthn.CredentialDescriptor, 0, len(rows))
			for _, row := range rows {
				credentialID, ok := recordString(row, "credentialID")
				if !ok {
					continue
				}
				allowed = append(allowed, webauthn.CredentialDescriptor{
					ID: credentialID, Transports: recordTransports(row),
				})
			}
		}
	}
	extensions, err := p.authenticationExtensions(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	options, err := webauthn.GenerateAuthenticationOptions(webauthn.GenerateAuthenticationOptionsInput{
		RPID: p.rpID, AllowCredentials: allowed, UserVerification: "preferred",
		Extensions: extensions, Random: p.random,
	})
	if err != nil {
		return contract.Response{}, err
	}
	if err := p.mintChallenge(ctx, storedChallenge{
		Type: authenticationCeremony, ExpectedChallenge: options.Challenge, UserData: userData,
	}); err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, options)
}

func (p *plugin) verifyRegistration(ctx *engine.Context) (contract.Response, error) {
	requireSession := p.registrationRequiresSession()
	var session *SessionState
	if requireSession {
		var err error
		session, err = p.options.Runtime.ResolveSession(ctx, SessionFresh)
		if err != nil {
			return contract.Response{}, err
		}
		if id, ok := userID(session); !ok || id == "" {
			return contract.Response{}, passkeyError(contract.StatusUnauthorized, ErrorSessionRequired)
		}
	}
	var body verifyRegistrationBody
	if err := decodeBody(ctx, &body); err != nil {
		return contract.Response{}, err
	}
	if len(bytes.TrimSpace(body.Response)) == 0 {
		return contract.Response{}, validationError("Missing required parameter: response")
	}
	origins, err := p.expectedOrigins(ctx)
	if err != nil {
		return contract.Response{}, passkeyError(contract.StatusBadRequest, ErrorFailedToVerifyRegistration)
	}
	challenge, err := p.consumeChallenge(ctx, registrationCeremony)
	if err != nil {
		return contract.Response{}, err
	}
	if !requireSession {
		session, err = p.options.Runtime.ResolveSession(ctx, SessionOptional)
		if err != nil {
			return contract.Response{}, err
		}
	}
	if id, ok := userID(session); ok && challenge.UserData.ID != id {
		return contract.Response{}, passkeyError(contract.StatusUnauthorized, ErrorRegistrationNotAllowed)
	}
	var registrationResponse webauthn.RegistrationResponseJSON
	if err := json.Unmarshal(body.Response, &registrationResponse); err != nil {
		return contract.Response{}, preserveOrWrap(
			err, contract.StatusInternalServerError, ErrorFailedToVerifyRegistration,
		)
	}

	verification, verifyErr := p.verifyRegister(webauthn.VerifyRegistrationOptions{
		Response: registrationResponse, ExpectedChallenge: challenge.ExpectedChallenge,
		ExpectedOrigins: origins, ExpectedRPIDs: []string{p.rpID},
		RequireUserVerification: Bool(false), Now: p.clock,
	})
	if verifyErr != nil {
		return contract.Response{}, preserveOrWrap(
			verifyErr, contract.StatusInternalServerError, ErrorFailedToVerifyRegistration,
		)
	}
	if !verification.Verified || verification.RegistrationInfo == nil {
		return contract.Response{}, passkeyError(contract.StatusBadRequest, ErrorFailedToVerifyRegistration)
	}
	info := verification.RegistrationInfo
	resolvedUser := challenge.UserData
	if resolvedUser.Name == "" {
		resolvedUser.Name = resolvedUser.ID
	}
	targetUserID := resolvedUser.ID
	resolvedName := ""
	if body.Name.Present {
		resolvedName = strings.TrimSpace(body.Name.Value)
	}
	flowContext, contextErr := challenge.flowContext()
	if contextErr != nil {
		return contract.Response{}, preserveOrWrap(
			contextErr, contract.StatusInternalServerError, ErrorFailedToVerifyRegistration,
		)
	}
	if hook := p.options.Registration.AfterVerification; hook != nil {
		result, hookErr := hook(AfterRegistrationVerificationArgs{
			Context: ctx, Verification: verification, User: resolvedUser,
			ClientData: registrationResponse, FlowContext: flowContext,
		})
		if hookErr != nil {
			return contract.Response{}, preserveOrWrap(
				hookErr, contract.StatusInternalServerError, ErrorFailedToVerifyRegistration,
			)
		}
		if result.UserID != "" {
			if id, ok := userID(session); ok && result.UserID != id {
				return contract.Response{}, passkeyError(contract.StatusUnauthorized, ErrorRegistrationNotAllowed)
			}
			targetUserID = result.UserID
		}
		if resolvedName == "" {
			resolvedName = strings.TrimSpace(result.Name)
		}
	}
	if targetUserID == "" {
		return contract.Response{}, passkeyError(contract.StatusBadRequest, ErrorResolvedUserInvalid)
	}
	record := storage.Record{
		"userId":       targetUserID,
		"credentialID": info.Credential.ID,
		"publicKey":    base64.StdEncoding.EncodeToString(info.Credential.PublicKey),
		"counter":      info.Credential.Counter,
		"deviceType":   string(info.CredentialDeviceType),
		"transports":   strings.Join(registrationResponse.Response.Transports, ","),
		"backedUp":     info.CredentialBackedUp,
		"createdAt":    p.clock().UTC(),
		"aaguid":       info.AAGUID,
	}
	if resolvedName != "" {
		record["name"] = resolvedName
	}
	created, createErr := p.options.Runtime.Adapter.Create(ctx.GoContext(), storage.CreateParams{
		Model: "passkey", Data: record,
	})
	if createErr != nil {
		return contract.Response{}, preserveOrWrap(
			createErr, contract.StatusInternalServerError, ErrorFailedToVerifyRegistration,
		)
	}
	return contract.JSONResponse(contract.StatusOK, created)
}

func (p *plugin) verifyAuthentication(ctx *engine.Context) (contract.Response, error) {
	var envelope verifyAuthenticationBody
	if err := decodeBody(ctx, &envelope); err != nil {
		return contract.Response{}, err
	}
	trimmed := bytes.TrimSpace(envelope.Response)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || trimmed[0] != '{' {
		return contract.Response{}, validationError("response must be an object")
	}
	var response webauthn.AuthenticationResponseJSON
	if err := json.Unmarshal(envelope.Response, &response); err != nil {
		return contract.Response{}, validationError("Invalid response")
	}
	origins, err := p.expectedOrigins(ctx)
	if err != nil {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", "origin missing")
	}
	challenge, err := p.consumeChallenge(ctx, authenticationCeremony)
	if err != nil {
		return contract.Response{}, err
	}
	passkeyRecord, err := p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "passkey", Where: []storage.Where{{Field: "credentialID", Value: response.ID}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if passkeyRecord == nil {
		return contract.Response{}, passkeyError(contract.StatusUnauthorized, ErrorPasskeyNotFound)
	}
	credential, err := credentialFromRecord(passkeyRecord)
	if err != nil {
		return contract.Response{}, preserveOrWrap(
			err, contract.StatusBadRequest, ErrorAuthenticationFailed,
		)
	}
	verification, verifyErr := p.verifyAuthenticate(webauthn.VerifyAuthenticationOptions{
		Response: response, ExpectedChallenge: challenge.ExpectedChallenge,
		ExpectedOrigins: origins, ExpectedRPIDs: []string{p.rpID}, Credential: credential,
		RequireUserVerification: Bool(false),
	})
	if verifyErr != nil {
		return contract.Response{}, preserveOrWrap(
			verifyErr, contract.StatusBadRequest, ErrorAuthenticationFailed,
		)
	}
	if !verification.Verified {
		return contract.Response{}, passkeyError(contract.StatusUnauthorized, ErrorAuthenticationFailed)
	}
	if hook := p.options.Authentication.AfterVerification; hook != nil {
		if hookErr := hook(AfterAuthenticationVerificationArgs{
			Context: ctx, Verification: verification, ClientData: response,
		}); hookErr != nil {
			return contract.Response{}, preserveOrWrap(
				hookErr, contract.StatusBadRequest, ErrorAuthenticationFailed,
			)
		}
	}
	passkeyID, _ := recordString(passkeyRecord, "id")
	if _, err := p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "passkey", Where: []storage.Where{{Field: "id", Value: passkeyID}},
		Update: storage.Record{"counter": verification.AuthenticationInfo.NewCounter},
	}); err != nil {
		return contract.Response{}, preserveOrWrap(
			err, contract.StatusBadRequest, ErrorAuthenticationFailed,
		)
	}
	ownerID, _ := recordString(passkeyRecord, "userId")
	issued, issueErr := p.options.Runtime.IssueSession(ctx, ownerID)
	if issueErr != nil {
		return contract.Response{}, preserveOrWrap(
			issueErr, contract.StatusBadRequest, ErrorAuthenticationFailed,
		)
	}
	if issued == nil || issued.Session == nil {
		return contract.Response{}, passkeyError(contract.StatusInternalServerError, ErrorUnableToCreateSession)
	}
	if issued.User == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "User not found",
		)
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{
		"session": issued.Session, "user": issued.User,
	})
}

func (p *plugin) list(ctx *engine.Context) (contract.Response, error) {
	session, err := p.requireSession(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	id, _ := userID(session)
	rows, err := p.options.Runtime.Adapter.FindMany(ctx.GoContext(), storage.FindManyParams{
		Model: "passkey", Where: []storage.Where{{Field: "userId", Value: id}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, rows)
}

func (p *plugin) delete(ctx *engine.Context) (contract.Response, error) {
	var body resourceBody
	if err := decodeBody(ctx, &body); err != nil {
		return contract.Response{}, err
	}
	if !body.ID.Present {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", "Missing required parameter: id")
	}
	session, err := p.requireSession(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	record, err := p.ownedPasskey(ctx, session, body.ID.Value, false)
	if err != nil {
		return contract.Response{}, err
	}
	if err := p.options.Runtime.Adapter.Delete(ctx.GoContext(), storage.DeleteParams{
		Model: "passkey", Where: []storage.Where{{Field: "id", Value: record["id"]}},
	}); err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{"status": true})
}

func (p *plugin) update(ctx *engine.Context) (contract.Response, error) {
	var body updateBody
	if err := decodeBody(ctx, &body); err != nil {
		return contract.Response{}, err
	}
	if !body.ID.Present {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", "Missing required parameter: id")
	}
	if !body.Name.Present {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "BAD_REQUEST", "Missing required parameter: name")
	}
	name := strings.TrimSpace(body.Name.Value)
	if name == "" {
		return contract.Response{}, validationError("name must contain at least 1 character")
	}
	session, err := p.requireSession(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	if _, err := p.ownedPasskey(ctx, session, body.ID.Value, true); err != nil {
		return contract.Response{}, err
	}
	updated, err := p.options.Runtime.Adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "passkey", Where: []storage.Where{{Field: "id", Value: body.ID.Value}},
		Update: storage.Record{"name": name},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if updated == nil {
		return contract.Response{}, passkeyError(contract.StatusInternalServerError, ErrorFailedToUpdatePasskey)
	}
	return contract.JSONResponse(contract.StatusOK, map[string]any{"passkey": updated})
}

func (p *plugin) resolveRegistrationUser(ctx *engine.Context) (RegistrationUser, error) {
	if p.registrationRequiresSession() {
		session, err := p.options.Runtime.ResolveSession(ctx, SessionFresh)
		if err != nil {
			return RegistrationUser{}, err
		}
		if user, ok := registrationUserFromSession(session); ok {
			return user, nil
		}
		return RegistrationUser{}, passkeyError(contract.StatusUnauthorized, ErrorSessionRequired)
	}
	session, err := p.options.Runtime.ResolveSession(ctx, SessionOptional)
	if err != nil {
		return RegistrationUser{}, err
	}
	if user, ok := registrationUserFromSession(session); ok {
		return user, nil
	}
	if p.options.Registration.ResolveUser == nil {
		return RegistrationUser{}, passkeyError(contract.StatusBadRequest, ErrorResolveUserRequired)
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return RegistrationUser{}, validationError("Invalid query")
	}
	var flowContext *string
	if values, exists := query["context"]; exists && len(values) > 0 {
		value := values[0]
		flowContext = &value
	}
	user, err := p.options.Registration.ResolveUser(ResolveRegistrationUserArgs{
		Context: flowContext, Request: ctx,
	})
	if err != nil {
		return RegistrationUser{}, err
	}
	if user.ID == "" || user.Name == "" {
		return RegistrationUser{}, passkeyError(contract.StatusBadRequest, ErrorResolvedUserInvalid)
	}
	return user, nil
}

func (p *plugin) requireSession(ctx *engine.Context) (*SessionState, error) {
	session, err := p.options.Runtime.ResolveSession(ctx, SessionRequired)
	if err != nil {
		return nil, err
	}
	if id, ok := userID(session); !ok || id == "" {
		return nil, unauthorized()
	}
	return session, nil
}

func (p *plugin) ownedPasskey(ctx *engine.Context, session *SessionState, id string, update bool) (storage.Record, error) {
	record, err := p.options.Runtime.Adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "passkey", Where: []storage.Where{{Field: "id", Value: id}},
	})
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, passkeyError(contract.StatusNotFound, ErrorPasskeyNotFound)
	}
	owner, _ := recordString(record, "userId")
	current, _ := userID(session)
	if owner != current {
		if update {
			return nil, passkeyError(contract.StatusUnauthorized, ErrorRegistrationNotAllowed)
		}
		return nil, unauthorized()
	}
	return record, nil
}

func (p *plugin) registrationRequiresSession() bool {
	return p.options.Registration.RequireSession == nil || *p.options.Registration.RequireSession
}

func (p *plugin) registrationSelection(attachment string) webauthn.AuthenticatorSelectionCriteria {
	selection := webauthn.AuthenticatorSelectionCriteria{
		ResidentKey: "preferred", UserVerification: "preferred",
	}
	if configured := p.options.AuthenticatorSelection; configured != nil {
		if configured.AuthenticatorAttachment != "" {
			selection.AuthenticatorAttachment = configured.AuthenticatorAttachment
		}
		if configured.ResidentKey != "" {
			selection.ResidentKey = configured.ResidentKey
		}
		if configured.RequireResidentKey != nil {
			required := *configured.RequireResidentKey
			selection.RequireResidentKey = &required
		}
		if configured.UserVerification != "" {
			selection.UserVerification = configured.UserVerification
		}
	}
	if attachment != "" {
		selection.AuthenticatorAttachment = attachment
	}
	return selection
}

func (p *plugin) registrationExtensions(ctx *engine.Context) (map[string]any, error) {
	if resolver := p.options.Registration.ResolveExtensions; resolver != nil {
		return resolver(ctx)
	}
	return cloneMap(p.options.Registration.Extensions), nil
}

func (p *plugin) authenticationExtensions(ctx *engine.Context) (map[string]any, error) {
	if resolver := p.options.Authentication.ResolveExtensions; resolver != nil {
		return resolver(ctx)
	}
	return cloneMap(p.options.Authentication.Extensions), nil
}

func (p *plugin) expectedOrigins(ctx *engine.Context) ([]string, error) {
	if p.options.Origins != nil {
		return append([]string(nil), p.options.Origins...), nil
	}
	if p.options.Origin != "" {
		return []string{p.options.Origin}, nil
	}
	origin, ok := ctx.Request().Headers().Get("Origin")
	if !ok || origin == "" {
		return nil, errors.New("origin missing")
	}
	return []string{origin}, nil
}

func decodeBody(ctx *engine.Context, target any) error {
	body := ctx.Request().Body()
	if len(body) > maxRequestBodyBytes {
		return validationError("Request body is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return validationError("Invalid request body").WithCause(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return validationError("Invalid request body")
	}
	return nil
}

func preserveOrWrap(err error, status int, code string) error {
	if _, ok := contract.AsAPIError(err); ok {
		return err
	}
	return passkeyError(status, code).WithCause(err)
}

func recordTransports(record storage.Record) []string {
	value, exists := record["transports"]
	if !exists || value == nil {
		return nil
	}
	text, ok := value.(string)
	if !ok {
		return nil
	}
	return strings.Split(text, ",")
}

func decodeStandardBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}
