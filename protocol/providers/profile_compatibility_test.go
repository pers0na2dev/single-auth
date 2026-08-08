package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

type fixtureResponse struct {
	status int
	body   []byte
}

type fixtureTransport map[string]fixtureResponse

func (transport fixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	fixture, ok := transport[request.URL.String()]
	if !ok {
		return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":"missing fixture"}`)), Request: request}, nil
	}
	status := fixture.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(fixture.body))), Request: request}, nil
}

func jsonFixture(value any) fixtureResponse {
	raw, _ := json.Marshal(value)
	return fixtureResponse{body: raw}
}

func unsignedJWT(claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "none"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".x"
}

func strptr(value string) *string { return &value }

func TestProfileMappingsMatchReference126(t *testing.T) {
	type vector struct {
		id        string
		options   Options
		tokens    oauth2.Tokens
		responses fixtureTransport
		callback  []AuthorizationUser
		want      oauth2.UserInfo
	}
	baseOptions := func() Options { return Options{ClientID: "client", ClientSecret: "secret"} }
	vectors := []vector{
		{id: "spotify", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://api.spotify.com/v1/me": jsonFixture(map[string]any{"id": "sp1", "display_name": "Spot", "email": "spot@example.com", "images": []any{map[string]any{"url": "https://img/sp"}}})}, want: oauth2.UserInfo{ID: "sp1", Name: "Spot", Email: strptr("spot@example.com"), Image: "https://img/sp"}},
		{id: "railway", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://backboard.railway.com/oauth/me": jsonFixture(map[string]any{"sub": "rw1", "name": "Rail", "email": "rail@example.com", "picture": "https://img/rw"})}, want: oauth2.UserInfo{ID: "rw1", Name: "Rail", Email: strptr("rail@example.com"), Image: "https://img/rw"}},
		{id: "linkedin", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://api.linkedin.com/v2/userinfo": jsonFixture(map[string]any{"sub": "li1", "name": "Linked", "email": "li@example.com", "picture": "https://img/li", "email_verified": true})}, want: oauth2.UserInfo{ID: "li1", Name: "Linked", Email: strptr("li@example.com"), Image: "https://img/li", EmailVerified: true}},
		{id: "huggingface", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://huggingface.co/oauth/userinfo": jsonFixture(map[string]any{"sub": "hf1", "preferred_username": "hugger", "email": "hf@example.com", "picture": "https://img/hf", "email_verified": true})}, want: oauth2.UserInfo{ID: "hf1", Name: "hugger", Email: strptr("hf@example.com"), Image: "https://img/hf", EmailVerified: true}},
		{id: "gitlab", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://gitlab.com/api/v4/user": jsonFixture(map[string]any{"id": 42, "username": "git", "state": "active", "email": "git@example.com", "avatar_url": "https://img/git", "email_verified": true})}, want: oauth2.UserInfo{ID: "42", Name: "git", Email: strptr("git@example.com"), Image: "https://img/git", EmailVerified: true}},
		{id: "naver", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://openapi.naver.com/v1/nid/me": jsonFixture(map[string]any{"resultcode": "00", "response": map[string]any{"id": "na1", "nickname": "Naver", "email": "na@example.com", "profile_image": "https://img/na"}})}, want: oauth2.UserInfo{ID: "na1", Name: "Naver", Email: strptr("na@example.com"), Image: "https://img/na"}},
		{id: "kakao", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://kapi.kakao.com/v2/user/me": jsonFixture(map[string]any{"id": 7, "kakao_account": map[string]any{"email": "ka@example.com", "is_email_valid": true, "is_email_verified": true, "profile": map[string]any{"nickname": "Kakao", "profile_image_url": "https://img/ka"}}})}, want: oauth2.UserInfo{ID: "7", Name: "Kakao", Email: strptr("ka@example.com"), Image: "https://img/ka", EmailVerified: true}},
		{id: "dropbox", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://api.dropboxapi.com/2/users/get_current_account": jsonFixture(map[string]any{"account_id": "db1", "name": map[string]any{"display_name": "Drop"}, "email": "db@example.com", "email_verified": true, "profile_photo_url": "https://img/db"})}, want: oauth2.UserInfo{ID: "db1", Name: "Drop", Email: strptr("db@example.com"), Image: "https://img/db", EmailVerified: true}},
		{id: "figma", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://api.figma.com/v1/me": jsonFixture(map[string]any{"id": "fi1", "handle": "Figma", "email": "fi@example.com", "img_url": "https://img/fi"})}, want: oauth2.UserInfo{ID: "fi1", Name: "Figma", Email: strptr("fi@example.com"), Image: "https://img/fi"}},
		{id: "atlassian", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://api.atlassian.com/me": jsonFixture(map[string]any{"account_id": "at1", "name": "Atlas", "email": "at@example.com", "picture": "https://img/at"})}, want: oauth2.UserInfo{ID: "at1", Name: "Atlas", Email: strptr("at@example.com"), Image: "https://img/at"}},
		{id: "salesforce", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://login.salesforce.com/services/oauth2/userinfo": jsonFixture(map[string]any{"user_id": "sf1", "name": "Sales", "email": "sf@example.com", "email_verified": true, "photos": map[string]any{"picture": "https://img/sf"}})}, want: oauth2.UserInfo{ID: "sf1", Name: "Sales", Email: strptr("sf@example.com"), Image: "https://img/sf", EmailVerified: true}},
		{id: "vercel", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://api.vercel.com/login/oauth/userinfo": jsonFixture(map[string]any{"sub": "ve1", "preferred_username": "Vercel", "email": "ve@example.com", "email_verified": true, "picture": "https://img/ve"})}, want: oauth2.UserInfo{ID: "ve1", Name: "Vercel", Email: strptr("ve@example.com"), Image: "https://img/ve", EmailVerified: true}},
		{id: "paybin", options: baseOptions(), tokens: oauth2.Tokens{IDToken: unsignedJWT(map[string]any{"sub": "pb1", "preferred_username": "Paybin", "email": "pb@example.com", "email_verified": true, "picture": "https://img/pb"})}, want: oauth2.UserInfo{ID: "pb1", Name: "Paybin", Email: strptr("pb@example.com"), Image: "https://img/pb", EmailVerified: true}},
		{id: "kick", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://api.kick.com/public/v1/users": jsonFixture(map[string]any{"data": []any{map[string]any{"user_id": "ki1", "name": "Kick", "email": "ki@example.com", "profile_picture": "https://img/ki"}}})}, want: oauth2.UserInfo{ID: "ki1", Name: "Kick", Email: strptr("ki@example.com"), Image: "https://img/ki"}},
		{id: "discord", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://discord.com/api/users/@me": jsonFixture(map[string]any{"id": "175928847299117063", "username": "discord", "global_name": "Discord", "discriminator": "0", "avatar": nil, "email": "di@example.com", "verified": true})}, want: oauth2.UserInfo{ID: "175928847299117063", Name: "Discord", Email: strptr("di@example.com"), Image: "https://cdn.discordapp.com/embed/avatars/2.png", EmailVerified: true}},
		{id: "roblox", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://apis.roblox.com/oauth/v1/userinfo": jsonFixture(map[string]any{"sub": "ro1", "preferred_username": "roblox-user", "nickname": "Roblox", "picture": "https://img/ro"})}, want: oauth2.UserInfo{ID: "ro1", Name: "Roblox", Email: strptr("roblox-user"), Image: "https://img/ro"}},
		{id: "slack", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://slack.com/api/openid.connect.userInfo": jsonFixture(map[string]any{"https://slack.com/user_id": "sl1", "name": "Slack", "email": "sl@example.com", "email_verified": true, "https://slack.com/user_image_512": "https://img/sl"})}, want: oauth2.UserInfo{ID: "sl1", Name: "Slack", Email: strptr("sl@example.com"), Image: "https://img/sl", EmailVerified: true}},
		{id: "tiktok", options: Options{ClientKey: "key", ClientSecret: "secret"}, tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://open.tiktokapis.com/v2/user/info/?fields=open_id,avatar_large_url,display_name,username": jsonFixture(map[string]any{"data": map[string]any{"user": map[string]any{"open_id": "tt1", "username": "tiktok-user", "display_name": "TikTok", "avatar_large_url": "https://img/tt"}}})}, want: oauth2.UserInfo{ID: "tt1", Name: "TikTok", Email: strptr("tiktok-user"), Image: "https://img/tt"}},
		{id: "zoom", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://api.zoom.us/v2/users/me": jsonFixture(map[string]any{"id": "zo1", "display_name": "Zoom", "email": "zo@example.com", "pic_url": "https://img/zo", "verified": 1})}, want: oauth2.UserInfo{ID: "zo1", Name: "Zoom", Email: strptr("zo@example.com"), Image: "https://img/zo", EmailVerified: true}},
		{id: "notion", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://api.notion.com/v1/users/me": jsonFixture(map[string]any{"bot": map[string]any{"owner": map[string]any{"user": map[string]any{"id": "no1", "name": "Notion", "avatar_url": "https://img/no", "person": map[string]any{"email": "no@example.com"}}}}})}, want: oauth2.UserInfo{ID: "no1", Name: "Notion", Email: strptr("no@example.com"), Image: "https://img/no"}},
		{id: "linear", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://api.linear.app/graphql": jsonFixture(map[string]any{"data": map[string]any{"viewer": map[string]any{"id": "ln1", "name": "Linear", "email": "ln@example.com", "avatarUrl": "https://img/ln"}}})}, want: oauth2.UserInfo{ID: "ln1", Name: "Linear", Email: strptr("ln@example.com"), Image: "https://img/ln"}},
		{id: "vk", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://id.vk.com/oauth2/user_info": jsonFixture(map[string]any{"user": map[string]any{"user_id": "vk1", "first_name": "V", "last_name": "K", "email": "vk@example.com", "avatar": "https://img/vk"}})}, want: oauth2.UserInfo{ID: "vk1", Name: "V K", Email: strptr("vk@example.com"), Image: "https://img/vk"}},
		{id: "twitch", options: baseOptions(), tokens: oauth2.Tokens{IDToken: unsignedJWT(map[string]any{"sub": "tw1", "preferred_username": "Twitch", "email": "tw@example.com", "email_verified": true, "picture": "https://img/tw"})}, want: oauth2.UserInfo{ID: "tw1", Name: "Twitch", Email: strptr("tw@example.com"), Image: "https://img/tw", EmailVerified: true}},
		{id: "apple", options: baseOptions(), tokens: oauth2.Tokens{IDToken: unsignedJWT(map[string]any{"sub": "ap1", "email": "ap@example.com", "email_verified": "true"})}, callback: []AuthorizationUser{{FirstName: "Apple", LastName: "User"}}, want: oauth2.UserInfo{ID: "ap1", Name: "Apple User", Email: strptr("ap@example.com"), EmailVerified: true}},
		{id: "google", options: baseOptions(), tokens: oauth2.Tokens{IDToken: unsignedJWT(map[string]any{"sub": "go1", "name": "Google", "email": "go@example.com", "email_verified": true, "picture": "https://img/go"})}, want: oauth2.UserInfo{ID: "go1", Name: "Google", Email: strptr("go@example.com"), Image: "https://img/go", EmailVerified: true}},
		{id: "cognito", options: Options{ClientID: "client", ClientSecret: "secret", Domain: "tenant.auth.us-east-1.amazoncognito.com", Region: "us-east-1", UserPoolID: "pool"}, tokens: oauth2.Tokens{IDToken: unsignedJWT(map[string]any{"sub": "co1", "given_name": "Cognito", "email": "co@example.com", "email_verified": true, "picture": "https://img/co"})}, want: oauth2.UserInfo{ID: "co1", Name: "Cognito", Email: strptr("co@example.com"), Image: "https://img/co", EmailVerified: true}},
		{id: "microsoft", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a", IDToken: unsignedJWT(map[string]any{"sub": "ms1", "name": "Microsoft", "email": "ms@example.com", "verified_primary_email": []string{"ms@example.com"}})}, responses: fixtureTransport{"https://graph.microsoft.com/v1.0/me/photos/48x48/$value": {body: []byte("jpeg")}}, want: oauth2.UserInfo{ID: "ms1", Name: "Microsoft", Email: strptr("ms@example.com"), Image: "data:image/jpeg;base64, anBlZw==", EmailVerified: true}},
		{id: "line", options: baseOptions(), tokens: oauth2.Tokens{IDToken: unsignedJWT(map[string]any{"sub": "line1", "name": "LINE", "email": "line@example.com", "picture": "https://img/line"})}, want: oauth2.UserInfo{ID: "line1", Name: "LINE", Email: strptr("line@example.com"), Image: "https://img/line"}},
		{id: "facebook", options: baseOptions(), tokens: oauth2.Tokens{IDToken: unsignedJWT(map[string]any{"sub": "fb1", "name": "Facebook", "email": "fb@example.com", "picture": "https://img/fb"})}, want: oauth2.UserInfo{ID: "fb1", Name: "Facebook", Email: strptr("fb@example.com")}},
		{id: "paypal", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a", IDToken: unsignedJWT(map[string]any{"sub": "pp-sub"})}, responses: fixtureTransport{"https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1": jsonFixture(map[string]any{"sub": "pp-sub", "user_id": "pp1", "name": "PayPal", "email": "pp@example.com", "email_verified": true, "picture": "https://img/pp"})}, want: oauth2.UserInfo{ID: "pp1", Name: "PayPal", Email: strptr("pp@example.com"), Image: "https://img/pp", EmailVerified: true}},
		{id: "reddit", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://oauth.reddit.com/api/v1/me": jsonFixture(map[string]any{"id": "re1", "name": "Reddit", "icon_img": "https://img/re?size=64"})}, want: oauth2.UserInfo{ID: "re1", Name: "Reddit", Email: strptr("re1@reddit.invalid"), Image: "https://img/re"}},
		{id: "twitter", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://api.x.com/2/users/me?user.fields=profile_image_url": jsonFixture(map[string]any{"data": map[string]any{"id": "x1", "name": "X User", "username": "xuser", "profile_image_url": "https://img/x"}}), "https://api.x.com/2/users/me?user.fields=confirmed_email": jsonFixture(map[string]any{"data": map[string]any{"confirmed_email": "x@example.com"}})}, want: oauth2.UserInfo{ID: "x1", Name: "X User", Email: strptr("x@example.com"), Image: "https://img/x", EmailVerified: true}},
		{id: "github", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a"}, responses: fixtureTransport{"https://api.github.com/user": jsonFixture(map[string]any{"id": "gh1", "login": "github", "name": nil, "email": nil, "avatar_url": "https://img/gh"}), "https://api.github.com/user/emails": jsonFixture([]any{map[string]any{"email": "gh@example.com", "primary": true, "verified": true}})}, want: oauth2.UserInfo{ID: "gh1", Name: "github", Email: strptr("gh@example.com"), Image: "https://img/gh", EmailVerified: true}},
		{id: "wechat", options: baseOptions(), tokens: oauth2.Tokens{AccessToken: "a", Raw: map[string]any{"openid": "wc-open"}}, responses: fixtureTransport{"https://api.weixin.qq.com/sns/userinfo?access_token=a&openid=wc-open&lang=zh_CN": jsonFixture(map[string]any{"openid": "wc-open", "unionid": "wc-union", "nickname": "WeChat", "headimgurl": "https://img/wc"})}, want: oauth2.UserInfo{ID: "wc-union", Name: "WeChat", Email: strptr("wc-union@wechat.invalid"), Image: "https://img/wc"}},
	}

	if len(vectors) != 34 {
		t.Fatalf("test inventory has %d profiles, want 34", len(vectors))
	}
	for _, vector := range vectors {
		vector := vector
		t.Run(vector.id, func(t *testing.T) {
			vector.options.HTTPClient = &http.Client{Transport: vector.responses}
			provider, err := New(vector.id, vector.options)
			if err != nil {
				t.Fatal(err)
			}
			got, err := provider.GetUserInfo(context.Background(), vector.tokens, vector.callback...)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil {
				t.Fatal("got nil user info")
			}
			got.User.Extra = nil
			vector.want.Extra = nil
			if !reflect.DeepEqual(got.User, vector.want) {
				t.Fatalf("user mismatch\n got: %#v\nwant: %#v", got.User, vector.want)
			}
		})
	}
}

func TestMapProfileOverridesNormalizedFields(t *testing.T) {
	options := Options{ClientID: "client", ClientSecret: "secret", HTTPClient: &http.Client{Transport: fixtureTransport{"https://api.spotify.com/v1/me": jsonFixture(map[string]any{"id": "original", "display_name": "Original", "email": "old@example.com", "images": []any{}})}}, MapProfileToUser: func(_ context.Context, profile map[string]any) (map[string]any, error) {
		if profile["id"] != "original" {
			t.Fatalf("map callback received wrong profile: %#v", profile)
		}
		return map[string]any{"id": "mapped", "name": "Mapped", "email": "new@example.com", "image": "https://img/new", "emailVerified": true, "role": "admin"}, nil
	}}
	provider, _ := Spotify(options)
	got, err := provider.GetUserInfo(context.Background(), oauth2.Tokens{AccessToken: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if got.User.ID != "mapped" || got.User.Name != "Mapped" || got.User.Email == nil || *got.User.Email != "new@example.com" || got.User.Image != "https://img/new" || !got.User.EmailVerified || got.User.Extra["role"] != "admin" {
		t.Fatalf("map override was not applied: %#v", got.User)
	}
}
