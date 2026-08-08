package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	samlSessionPrefix     = "saml-session:"
	samlSessionByIDPrefix = "saml-session-by-id:"
)

type samlSessionRecord struct {
	SessionID    string `json:"sessionId"`
	SessionToken string `json:"sessionToken"`
	ProviderID   string `json:"providerId"`
	NameID       string `json:"nameID"`
	SessionIndex string `json:"sessionIndex,omitempty"`
}

func samlSessionKey(providerID, nameID string) string {
	return samlSessionPrefix + providerID + ":" + nameID
}

func (p *plugin) storeSAMLSession(
	ctx context.Context,
	providerID, nameID, sessionIndex string,
	session storage.Record,
) error {
	if providerID == "" || nameID == "" || session == nil {
		return nil
	}
	sessionID := recordStringValue(session, "id")
	sessionToken := recordStringValue(session, "token")
	expiresAt, ok := samlRecordTime(session["expiresAt"])
	if sessionID == "" || sessionToken == "" || !ok {
		return fmt.Errorf("sso: cannot create SAML session record from incomplete session")
	}
	record := samlSessionRecord{
		SessionID: sessionID, SessionToken: sessionToken, ProviderID: providerID,
		NameID: nameID, SessionIndex: sessionIndex,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	forwardKey := samlSessionKey(providerID, nameID)
	reverseKey := samlSessionByIDPrefix + sessionID

	p.sloMu.Lock()
	defer p.sloMu.Unlock()
	oldForward, err := p.runtime.PeekVerification(ctx, forwardKey)
	if err != nil {
		return err
	}
	oldReverse, err := p.runtime.PeekVerification(ctx, reverseKey)
	if err != nil {
		return err
	}
	oldRecord, _ := decodeSAMLSessionRecord(oldForward)
	if err := p.upsertSAMLVerification(ctx, reverseKey, forwardKey, expiresAt); err != nil {
		return err
	}
	if err := p.upsertSAMLVerification(ctx, forwardKey, string(encoded), expiresAt); err != nil {
		if oldReverse == nil {
			_ = p.runtime.DeleteVerification(ctx, reverseKey)
		} else if oldExpiry, valid := samlRecordTime(oldReverse["expiresAt"]); valid {
			_ = p.runtime.UpdateVerification(ctx, reverseKey, storage.Record{
				"value": recordStringValue(oldReverse, "value"), "expiresAt": oldExpiry,
			})
		}
		return err
	}
	if oldRecord.SessionID != "" && oldRecord.SessionID != sessionID {
		_ = p.runtime.DeleteVerification(ctx, samlSessionByIDPrefix+oldRecord.SessionID)
	}
	return nil
}

func (p *plugin) upsertSAMLVerification(
	ctx context.Context,
	identifier, value string,
	expiresAt time.Time,
) error {
	existing, err := p.runtime.PeekVerification(ctx, identifier)
	if err != nil {
		return err
	}
	if existing != nil {
		return p.runtime.UpdateVerification(ctx, identifier, storage.Record{
			"value": value, "expiresAt": expiresAt.UTC(),
		})
	}
	reserved, err := p.runtime.ReserveVerification(ctx, identifier, value, expiresAt)
	if err != nil {
		return err
	}
	if reserved {
		return nil
	}
	return p.runtime.UpdateVerification(ctx, identifier, storage.Record{
		"value": value, "expiresAt": expiresAt.UTC(),
	})
}

func decodeSAMLSessionRecord(record storage.Record) (samlSessionRecord, bool) {
	if record == nil {
		return samlSessionRecord{}, false
	}
	var result samlSessionRecord
	if err := json.Unmarshal([]byte(recordStringValue(record, "value")), &result); err != nil {
		return samlSessionRecord{}, false
	}
	if result.SessionID == "" || result.SessionToken == "" || result.ProviderID == "" || result.NameID == "" {
		return samlSessionRecord{}, false
	}
	return result, true
}

func samlRecordTime(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC(), !typed.IsZero()
	case *time.Time:
		if typed == nil {
			return time.Time{}, false
		}
		return typed.UTC(), !typed.IsZero()
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		return parsed.UTC(), err == nil && !parsed.IsZero()
	case int64:
		return time.UnixMilli(typed).UTC(), typed != 0
	case float64:
		return time.UnixMilli(int64(typed)).UTC(), typed != 0
	default:
		return time.Time{}, false
	}
}

func (p *plugin) deleteSAMLSessionRecords(
	ctx context.Context,
	forwardKey string,
	record samlSessionRecord,
) error {
	if forwardKey != "" {
		if err := p.runtime.DeleteVerification(ctx, forwardKey); err != nil {
			return err
		}
	}
	if record.SessionID != "" {
		if err := p.runtime.DeleteVerification(ctx, samlSessionByIDPrefix+record.SessionID); err != nil {
			return err
		}
	}
	return nil
}

func (p *plugin) cleanupSAMLSessionOnSignOut(
	ctx *engine.Context,
) (*contract.Response, error) {
	if !p.options.SAML.EnableSingleLogout || p.runtime.ResolveSession == nil {
		return nil, nil
	}
	session, err := p.runtime.ResolveSession(ctx, singleauth.PluginSessionOptional)
	if err != nil || session == nil || session.Session == nil {
		return nil, nil
	}
	sessionID := recordStringValue(session.Session, "id")
	if sessionID == "" {
		return nil, nil
	}
	reverse, err := p.runtime.PeekVerification(ctx.GoContext(), samlSessionByIDPrefix+sessionID)
	if err != nil || reverse == nil {
		return nil, nil
	}
	forwardKey := recordStringValue(reverse, "value")
	forward, _ := p.runtime.PeekVerification(ctx.GoContext(), forwardKey)
	record, _ := decodeSAMLSessionRecord(forward)
	if record.SessionID != sessionID {
		return nil, nil
	}
	p.sloMu.Lock()
	_ = p.deleteSAMLSessionRecords(ctx.GoContext(), forwardKey, record)
	p.sloMu.Unlock()
	return nil, nil
}
