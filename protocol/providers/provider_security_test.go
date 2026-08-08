package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

func TestFacebookOpaqueTokenBinding(t *testing.T) {
	debugURL := "https://graph.facebook.com/debug_token?input_token=opaque&access_token=fb-app%7Cfb-secret"
	profileURL := "https://graph.facebook.com/me?fields=id%2Cname%2Cemail%2Cpicture"
	validFixtures := fixtureTransport{
		debugURL:   jsonFixture(map[string]any{"data": map[string]any{"is_valid": true, "app_id": "fb-app", "user_id": "user-1"}}),
		profileURL: jsonFixture(map[string]any{"id": "user-1", "name": "Facebook User", "email": "user@example.com", "picture": map[string]any{"data": map[string]any{"url": "https://img/fb"}}}),
	}
	provider, _ := Facebook(Options{ClientID: []string{"fb-app", "fb-mobile"}, ClientSecret: "fb-secret", HTTPClient: &http.Client{Transport: validFixtures}})
	valid, err := provider.VerifyIDToken(context.Background(), "opaque", "")
	if err != nil || !valid {
		t.Fatalf("bound opaque token rejected: valid=%v err=%v", valid, err)
	}
	info, err := provider.GetUserInfo(context.Background(), oauth2.Tokens{AccessToken: "opaque"})
	if err != nil || info == nil || info.User.ID != "user-1" {
		t.Fatalf("bound opaque profile rejected: info=%#v err=%v", info, err)
	}

	foreign := fixtureTransport{debugURL: jsonFixture(map[string]any{"data": map[string]any{"is_valid": true, "app_id": "foreign-app", "user_id": "user-1"}})}
	provider, _ = Facebook(Options{ClientID: []string{"fb-app", "fb-mobile"}, ClientSecret: "fb-secret", HTTPClient: &http.Client{Transport: foreign}})
	valid, _ = provider.VerifyIDToken(context.Background(), "opaque", "")
	if valid {
		t.Fatal("token issued to a foreign Facebook app was accepted")
	}

	mismatch := fixtureTransport{
		debugURL:   jsonFixture(map[string]any{"data": map[string]any{"is_valid": true, "app_id": "fb-app", "user_id": "user-1"}}),
		profileURL: jsonFixture(map[string]any{"id": "different-user", "name": "Substituted", "email": "other@example.com", "picture": map[string]any{"data": map[string]any{"url": "https://img/fb"}}}),
	}
	provider, _ = Facebook(Options{ClientID: "fb-app", ClientSecret: "fb-secret", HTTPClient: &http.Client{Transport: mismatch}})
	info, _ = provider.GetUserInfo(context.Background(), oauth2.Tokens{AccessToken: "opaque"})
	if info != nil {
		t.Fatal("Facebook profile not bound to debug_token user_id was accepted")
	}
}

func TestHostedDomainTenantAndSubjectRestrictions(t *testing.T) {
	google, _ := Google(Options{ClientID: "client", ClientSecret: "secret", HostedDomain: "example.com"})
	info, err := google.GetUserInfo(context.Background(), oauth2.Tokens{IDToken: unsignedJWT(map[string]any{"sub": "g", "email": "g@example.com", "hd": "other.com"})})
	if err != nil || info != nil {
		t.Fatalf("Google hosted-domain mismatch accepted: info=%#v err=%v", info, err)
	}

	paypalURL := "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1"
	paypal, _ := PayPal(Options{ClientID: "client", ClientSecret: "secret", HTTPClient: &http.Client{Transport: fixtureTransport{paypalURL: jsonFixture(map[string]any{"sub": "profile-sub", "user_id": "paypal-user", "name": "PayPal", "email": "p@example.com"})}}})
	info, err = paypal.GetUserInfo(context.Background(), oauth2.Tokens{AccessToken: "access", IDToken: unsignedJWT(map[string]any{"sub": "different-sub"})})
	if err != nil || info != nil {
		t.Fatalf("PayPal subject mismatch accepted: info=%#v err=%v", info, err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now().Unix()
	consumerClaims := map[string]any{"iss": "https://login.microsoftonline.com/" + microsoftConsumerTenantID + "/v2.0", "aud": "client", "iat": now, "exp": now + 3600, "tid": microsoftConsumerTenantID}
	jwksURL := "https://login.microsoftonline.com/organizations/discovery/v2.0/keys"
	microsoft, _ := Microsoft(Options{ClientID: "client", TenantID: "organizations", HTTPClient: &http.Client{Transport: fixtureTransport{jwksURL: jsonFixture(map[string]any{"keys": []any{rsaJWK(key, "kid")}})}}})
	valid, err := microsoft.VerifyIDToken(context.Background(), signRS256(t, key, "kid", consumerClaims), "")
	if err != nil || valid {
		t.Fatalf("consumer Microsoft token accepted by organizations: valid=%v err=%v", valid, err)
	}
}

func TestPlaceholderEmailOverrides(t *testing.T) {
	reddit, _ := Reddit(Options{ClientID: "client", ClientSecret: "secret", HTTPClient: &http.Client{Transport: fixtureTransport{"https://oauth.reddit.com/api/v1/me": jsonFixture(map[string]any{"id": "reddit-id", "name": "Reddit", "icon_img": nil})}}, MapProfileToUser: func(context.Context, map[string]any) (map[string]any, error) {
		return map[string]any{"email": "real@example.com"}, nil
	}})
	info, _ := reddit.GetUserInfo(context.Background(), oauth2.Tokens{AccessToken: "access"})
	if info == nil || info.User.Email == nil || *info.User.Email != "real@example.com" {
		t.Fatalf("Reddit mapped email not honored: %#v", info)
	}

	wechatURL := "https://api.weixin.qq.com/sns/userinfo?access_token=access&openid=open-id&lang=zh_CN"
	wechat, _ := WeChat(Options{ClientID: "client", ClientSecret: "secret", HTTPClient: &http.Client{Transport: fixtureTransport{wechatURL: jsonFixture(map[string]any{"openid": "open-id", "nickname": "WeChat"})}}, MapProfileToUser: func(context.Context, map[string]any) (map[string]any, error) {
		return map[string]any{"email": "real@example.com"}, nil
	}})
	info, _ = wechat.GetUserInfo(context.Background(), oauth2.Tokens{AccessToken: "access", Raw: map[string]any{"openid": "open-id"}})
	if info == nil || info.User.ID != "open-id" || info.User.Email == nil || *info.User.Email != "real@example.com" {
		t.Fatalf("WeChat fallback/map behavior mismatch: %#v", info)
	}
}
