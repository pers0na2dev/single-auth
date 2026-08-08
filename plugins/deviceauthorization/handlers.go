package deviceauthorization

import (
	"errors"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) deviceCode(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	clientID, err := requiredString(body, "client_id")
	if err != nil {
		return contract.Response{}, err
	}
	userID, err := optionalString(body, "user_id")
	if err != nil {
		return contract.Response{}, err
	}
	scope, err := optionalString(body, "scope")
	if err != nil {
		return contract.Response{}, err
	}
	if p.options.ValidateClient != nil {
		valid, validateErr := p.options.ValidateClient(ctx.GoContext(), clientID)
		if validateErr != nil {
			return contract.Response{}, preserveInternal(validateErr)
		}
		if !valid {
			return contract.Response{}, badRequest("invalid_client", "Invalid client ID")
		}
	}
	if p.options.OnDeviceAuthRequest != nil {
		if err := p.options.OnDeviceAuthRequest(ctx.GoContext(), clientID, scope); err != nil {
			return contract.Response{}, preserveInternal(err)
		}
	}

	var deviceCode string
	if p.options.GenerateDeviceCode != nil {
		deviceCode, err = p.options.GenerateDeviceCode(ctx.GoContext())
	} else {
		deviceCode, err = p.randomString(p.options.DeviceCodeLength, deviceCodeAlphabet, false)
	}
	if err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	var userCode string
	if p.options.GenerateUserCode != nil {
		userCode, err = p.options.GenerateUserCode(ctx.GoContext())
	} else {
		userCode, err = p.randomString(p.options.UserCodeLength, userCodeAlphabet, true)
	}
	if err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	now := p.clock()
	data := storage.Record{
		"deviceCode": deviceCode, "userCode": userCode,
		"userId": nil, "expiresAt": now.Add(p.options.ExpiresIn),
		"status": "pending", "pollingInterval": p.options.Interval.Milliseconds(),
		"clientId": clientID,
	}
	if userID != nil && *userID != "" {
		data["userId"] = *userID
	}
	if scope != nil {
		data["scope"] = *scope
	}
	adapter := p.adapter(ctx.GoContext())
	if adapter == nil {
		return contract.Response{}, preserveInternal(errors.New("deviceauthorization: Runtime.Adapter is required"))
	}
	if _, err := adapter.Create(ctx.GoContext(), storage.CreateParams{Model: "deviceCode", Data: data}); err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	baseURL, err := p.resolveBaseURL(ctx)
	if err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	verificationURI, completeURI, err := buildVerificationURIs(p.options.VerificationURI, baseURL, userCode)
	if err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	response, err := jsonSuccess(contract.StatusOK, DeviceCodeResponse{
		DeviceCode: deviceCode, UserCode: userCode,
		VerificationURI: verificationURI, VerificationURIComplete: completeURI,
		ExpiresIn: floorDurationSeconds(p.options.ExpiresIn),
		Interval:  floorDurationSeconds(p.options.Interval),
	})
	return response.WithHeader("Cache-Control", "no-store"), err
}

func (p *plugin) deviceToken(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	grantType, err := requiredString(body, "grant_type")
	if err != nil {
		return contract.Response{}, err
	}
	if grantType != DeviceCodeGrantType {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid grant_type")
	}
	deviceCode, err := requiredString(body, "device_code")
	if err != nil {
		return contract.Response{}, err
	}
	clientID, err := requiredString(body, "client_id")
	if err != nil {
		return contract.Response{}, err
	}
	if p.options.ValidateClient != nil {
		valid, validateErr := p.options.ValidateClient(ctx.GoContext(), clientID)
		if validateErr != nil {
			return contract.Response{}, preserveInternal(validateErr)
		}
		if !valid {
			return contract.Response{}, badRequest("invalid_grant", "Invalid client ID")
		}
	}
	adapter := p.adapter(ctx.GoContext())
	if adapter == nil {
		return contract.Response{}, preserveInternal(errors.New("deviceauthorization: Runtime.Adapter is required"))
	}
	record, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "deviceCode", Where: []storage.Where{{Field: "deviceCode", Value: deviceCode}},
	})
	if err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	if record == nil {
		return contract.Response{}, badRequest("invalid_grant", MessageInvalidDeviceCode)
	}
	state, err := deviceCodeFromRecord(record)
	if err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	if state.ClientID != "" && state.ClientID != clientID {
		return contract.Response{}, badRequest("invalid_grant", "Client ID mismatch")
	}
	now := p.clock()
	if state.LastPolledAt != nil && state.PollingInterval != 0 && now.Sub(*state.LastPolledAt) < time.Duration(state.PollingInterval)*time.Millisecond {
		return contract.Response{}, badRequest("slow_down", MessagePollingTooFrequently)
	}
	if _, err := adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "deviceCode", Where: []storage.Where{{Field: "id", Value: state.ID}},
		Update: storage.Record{"lastPolledAt": now},
	}); err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	if state.ExpiresAt.Before(now) {
		if err := adapter.Delete(ctx.GoContext(), storage.DeleteParams{
			Model: "deviceCode", Where: []storage.Where{{Field: "id", Value: state.ID}},
		}); err != nil {
			return contract.Response{}, preserveInternal(err)
		}
		return contract.Response{}, badRequest("expired_token", MessageExpiredDeviceCode)
	}
	switch state.Status {
	case "pending":
		return contract.Response{}, badRequest("authorization_pending", MessageAuthorizationPending)
	case "denied":
		if err := adapter.Delete(ctx.GoContext(), storage.DeleteParams{
			Model: "deviceCode", Where: []storage.Where{{Field: "id", Value: state.ID}},
		}); err != nil {
			return contract.Response{}, preserveInternal(err)
		}
		return contract.Response{}, badRequest("access_denied", MessageAccessDenied)
	case "approved":
		if state.UserID == nil || *state.UserID == "" {
			return contract.Response{}, internalProtocolError(MessageInvalidDeviceCodeStatus, nil)
		}
	default:
		return contract.Response{}, internalProtocolError(MessageInvalidDeviceCodeStatus, nil)
	}
	claimed, err := adapter.ConsumeOne(ctx.GoContext(), storage.ConsumeOneParams{
		Model: "deviceCode", Where: []storage.Where{
			{Field: "deviceCode", Value: deviceCode}, {Field: "status", Value: "approved"},
		},
	})
	if err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	if claimed == nil {
		return contract.Response{}, badRequest("invalid_grant", MessageInvalidDeviceCode)
	}
	claimedState, err := deviceCodeFromRecord(claimed)
	if err != nil || claimedState.UserID == nil || *claimedState.UserID == "" {
		return contract.Response{}, badRequest("invalid_grant", MessageInvalidDeviceCode)
	}
	user, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: *claimedState.UserID}},
	})
	if err != nil {
		return contract.Response{}, internalProtocolError(MessageUserNotFound, err)
	}
	if user == nil {
		return contract.Response{}, internalProtocolError(MessageUserNotFound, nil)
	}
	if p.options.Runtime.CreateSession == nil {
		return contract.Response{}, internalProtocolError(MessageFailedToCreateSession, errors.New("deviceauthorization: Runtime.CreateSession is required"))
	}
	sessionState, err := p.options.Runtime.CreateSession(ctx, *claimedState.UserID, false)
	if err != nil {
		return contract.Response{}, internalProtocolError(MessageFailedToCreateSession, err)
	}
	if sessionState == nil || sessionState.Session == nil {
		return contract.Response{}, internalProtocolError(MessageFailedToCreateSession, nil)
	}
	if sessionState.User == nil {
		sessionState.User = user
	}
	if p.options.Runtime.SetNewSession != nil {
		p.options.Runtime.SetNewSession(ctx, sessionState)
	}
	token, ok := recordString(sessionState.Session, "token")
	if !ok || token == "" {
		return contract.Response{}, internalProtocolError(MessageFailedToCreateSession, nil)
	}
	expiresAt, ok := recordTime(sessionState.Session, "expiresAt")
	if !ok {
		return contract.Response{}, internalProtocolError(MessageFailedToCreateSession, nil)
	}
	scope := ""
	if claimedState.Scope != nil {
		scope = *claimedState.Scope
	}
	response, err := jsonSuccess(contract.StatusOK, TokenResponse{
		AccessToken: token, TokenType: "Bearer",
		ExpiresIn: int64(expiresAt.Sub(p.clock()) / time.Second), Scope: scope,
	})
	return response.WithHeader("Cache-Control", "no-store").WithHeader("Pragma", "no-cache"), err
}

func (p *plugin) deviceVerify(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query")
	}
	userCodes, exists := query["user_code"]
	if !exists || len(userCodes) == 0 {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "user_code is required")
	}
	userCode := userCodes[0]
	adapter := p.adapter(ctx.GoContext())
	if adapter == nil {
		return contract.Response{}, preserveInternal(errors.New("deviceauthorization: Runtime.Adapter is required"))
	}
	record, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "deviceCode", Where: []storage.Where{{Field: "userCode", Value: cleanUserCode(userCode)}},
	})
	if err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	if record == nil {
		return contract.Response{}, badRequest("invalid_request", MessageInvalidUserCode)
	}
	state, err := deviceCodeFromRecord(record)
	if err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	if state.ExpiresAt.Before(p.clock()) {
		return contract.Response{}, badRequest("expired_token", MessageExpiredUserCode)
	}
	var session *SessionState
	if p.options.Runtime.ResolveSession != nil {
		session, err = p.options.Runtime.ResolveSession(ctx, false)
		if err != nil {
			return contract.Response{}, preserveInternal(err)
		}
	}
	if session != nil && session.User != nil && state.UserID == nil && state.Status == "pending" {
		userID, _ := recordString(session.User, "id")
		if userID != "" {
			claimed, claimErr := adapter.IncrementOne(ctx.GoContext(), storage.IncrementOneParams{
				Model: "deviceCode",
				Where: []storage.Where{
					{Field: "id", Value: state.ID},
					{Field: "status", Value: "pending"},
					{Field: "userId", Operator: storage.OpEq, Value: nil},
				},
				Set: storage.Record{"userId": userID},
			})
			if claimErr != nil {
				return contract.Response{}, preserveInternal(claimErr)
			}
			if claimed != nil {
				state.UserID = &userID
			}
		}
	}
	return jsonSuccess(contract.StatusOK, VerifyResponse{UserCode: userCode, Status: state.Status})
}

func (p *plugin) deviceApprove(ctx *engine.Context) (contract.Response, error) {
	return p.processDecision(ctx, "approved")
}

func (p *plugin) deviceDeny(ctx *engine.Context) (contract.Response, error) {
	return p.processDecision(ctx, "denied")
}

func (p *plugin) processDecision(ctx *engine.Context, status string) (contract.Response, error) {
	if p.options.Runtime.ResolveSession == nil {
		return contract.Response{}, oauthError(contract.StatusUnauthorized, "unauthorized", MessageAuthenticationRequired)
	}
	session, err := p.options.Runtime.ResolveSession(ctx, true)
	if err != nil || session == nil || session.User == nil {
		if apiError, ok := contract.AsAPIError(err); ok && apiError.Status != contract.StatusUnauthorized {
			return contract.Response{}, err
		}
		return contract.Response{}, oauthError(contract.StatusUnauthorized, "unauthorized", MessageAuthenticationRequired)
	}
	body, err := decodeObject(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	userCode, err := requiredString(body, "userCode")
	if err != nil {
		return contract.Response{}, err
	}
	adapter := p.adapter(ctx.GoContext())
	if adapter == nil {
		return contract.Response{}, preserveInternal(errors.New("deviceauthorization: Runtime.Adapter is required"))
	}
	record, err := adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "deviceCode", Where: []storage.Where{{Field: "userCode", Value: cleanUserCode(userCode)}},
	})
	if err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	if record == nil {
		return contract.Response{}, badRequest("invalid_request", MessageInvalidUserCode)
	}
	state, err := deviceCodeFromRecord(record)
	if err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	if state.ExpiresAt.Before(p.clock()) {
		return contract.Response{}, badRequest("expired_token", MessageExpiredUserCode)
	}
	if state.Status != "pending" {
		return contract.Response{}, badRequest("invalid_request", MessageAlreadyProcessed)
	}
	if state.UserID == nil || *state.UserID == "" {
		return contract.Response{}, badRequest("invalid_request", MessageDeviceCodeNotClaimed)
	}
	currentUserID, _ := recordString(session.User, "id")
	if currentUserID == "" || *state.UserID != currentUserID {
		description := "You are not authorized to approve this device authorization"
		if status == "denied" {
			description = "You are not authorized to deny this device authorization"
		}
		return contract.Response{}, oauthError(contract.StatusForbidden, "access_denied", description)
	}
	if _, err := adapter.Update(ctx.GoContext(), storage.UpdateParams{
		Model: "deviceCode", Where: []storage.Where{{Field: "id", Value: state.ID}},
		Update: storage.Record{"status": status, "userId": currentUserID},
	}); err != nil {
		return contract.Response{}, preserveInternal(err)
	}
	return jsonSuccess(contract.StatusOK, map[string]any{"success": true})
}
