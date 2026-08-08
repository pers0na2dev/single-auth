package providers

import "testing"

func TestAuthorizationURLsMatchReference126(t *testing.T) {
	expected := map[string]string{
		"apple":       "https://appleid.apple.com/auth/authorize?response_type=code+id_token&client_id=client&state=state&scope=email+name+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&response_mode=form_post&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"atlassian":   "https://auth.atlassian.com/authorize?response_type=code&client_id=client&state=state&scope=read%3Ajira-user+offline_access+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ&audience=api.atlassian.com",
		"cognito":     "https://tenant.auth.us-east-1.amazoncognito.com/oauth2/authorize?response_type=code&client_id=client&state=state&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ&scope=openid%20profile%20email%20extra",
		"discord":     "https://discord.com/api/oauth2/authorize?scope=identify+email+extra&response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=state&prompt=none",
		"facebook":    "https://www.facebook.com/v24.0/dialog/oauth?response_type=code&client_id=client&state=state&scope=email+public_profile+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&login_hint=person%40example.com&config_id=config",
		"figma":       "https://www.figma.com/oauth?response_type=code&client_id=client&state=state&scope=current_user%3Aread+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"github":      "https://github.com/login/oauth/authorize?response_type=code&client_id=client&state=state&scope=read%3Auser+user%3Aemail+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&login_hint=person%40example.com&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"microsoft":   "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&client_id=client&state=state&scope=openid+profile+email+User.Read+offline_access+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&login_hint=person%40example.com&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"google":      "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=client&state=state&scope=email+profile+openid+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&display=popup&login_hint=person%40example.com&hd=example.com&access_type=offline&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ&include_granted_scopes=true",
		"huggingface": "https://huggingface.co/oauth/authorize?response_type=code&client_id=client&state=state&scope=openid+profile+email+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"slack":       "https://slack.com/openid/connect/authorize?scope=openid+profile+email+extra&response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=state",
		"spotify":     "https://accounts.spotify.com/authorize?response_type=code&client_id=client&state=state&scope=user-read-email+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"twitch":      "https://id.twitch.tv/oauth2/authorize?response_type=code&client_id=client&state=state&scope=user%3Aread%3Aemail+openid+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&claims=%7B%22id_token%22%3A%7B%22email%22%3Anull%2C%22email_verified%22%3Anull%2C%22preferred_username%22%3Anull%2C%22picture%22%3Anull%7D%7D",
		"twitter":     "https://x.com/i/oauth2/authorize?response_type=code&client_id=client&state=state&scope=users.read+tweet.read+offline.access+users.email+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"dropbox":     "https://www.dropbox.com/oauth2/authorize?response_type=code&client_id=client&state=state&scope=account_info.read+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ&token_access_type=offline",
		"kick":        "https://id.kick.com/oauth/authorize?response_type=code&client_id=client&state=state&scope=user%3Aread+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"linear":      "https://linear.app/oauth/authorize?response_type=code&client_id=client&state=state&scope=read+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&login_hint=person%40example.com",
		"linkedin":    "https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=client&state=state&scope=profile+email+openid+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&login_hint=person%40example.com",
		"gitlab":      "https://gitlab.com/oauth/authorize?response_type=code&client_id=client&state=state&scope=read_user+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&login_hint=person%40example.com&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"tiktok":      "https://www.tiktok.com/v2/auth/authorize?scope=user.info.profile,extra&response_type=code&client_key=key&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=state",
		"reddit":      "https://www.reddit.com/api/v1/authorize?response_type=code&client_id=client&state=state&scope=identity+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&duration=permanent",
		"roblox":      "https://apis.roblox.com/oauth/v1/authorize?scope=openid+profile+extra&response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=state&prompt=select_account%20consent",
		"salesforce":  "https://login.salesforce.com/services/oauth2/authorize?response_type=code&client_id=client&state=state&scope=openid+email+profile+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"vk":          "https://id.vk.com/authorize?response_type=code&client_id=client&state=state&scope=email+phone+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"zoom":        "https://zoom.us/oauth/authorize?response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&client_id=client&state=state&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"notion":      "https://api.notion.com/v1/oauth/authorize?response_type=code&client_id=client&state=state&scope=extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&login_hint=person%40example.com&owner=user",
		"kakao":       "https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=client&state=state&scope=account_email+profile_image+profile_nickname+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback",
		"naver":       "https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id=client&state=state&scope=profile+email+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback",
		"line":        "https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id=client&state=state&scope=openid+profile+email+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&login_hint=person%40example.com&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"paybin":      "https://idp.paybin.io/oauth2/authorize?response_type=code&client_id=client&state=state&scope=openid+email+profile+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&login_hint=person%40example.com&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"paypal":      "https://www.sandbox.paypal.com/signin/authorize?response_type=code&client_id=client&state=state&scope=&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"railway":     "https://backboard.railway.com/oauth/auth?response_type=code&client_id=client&state=state&scope=openid+email+profile+extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"vercel":      "https://vercel.com/oauth/authorize?response_type=code&client_id=client&state=state&scope=extra&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_challenge_method=S256&code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
		"wechat":      "https://open.weixin.qq.com/connect/qrconnect?scope=snsapi_login%2Cextra&response_type=code&appid=client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=state&lang=en#wechat_redirect",
	}

	for _, id := range Builtins {
		id := id
		t.Run(id, func(t *testing.T) {
			options := Options{ClientID: "client", ClientSecret: "secret", ClientKey: "key"}
			switch id {
			case "cognito":
				options.Domain, options.Region, options.UserPoolID = "tenant.auth.us-east-1.amazoncognito.com", "us-east-1", "pool"
			case "discord":
				permissions := 8
				options.Permissions = &permissions
			case "dropbox":
				options.AccessType = "offline"
			case "facebook":
				options.ConfigID = "config"
			case "google":
				options.AccessType, options.HostedDomain = "offline", "example.com"
			case "reddit":
				options.Duration = "permanent"
			case "wechat":
				options.Language = "en"
			}
			provider, err := New(id, options)
			if err != nil {
				t.Fatal(err)
			}
			got, err := provider.CreateAuthorizationURL(AuthorizationInput{State: "state", CodeVerifier: "verifier", Scopes: []string{"extra"}, RedirectURI: "https://app.example/callback", Display: "popup", LoginHint: "person@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != expected[id] {
				t.Fatalf("authorization URL mismatch\n got: %s\nwant: %s", got, expected[id])
			}
		})
	}
}

func TestInventoryIsCompleteAndUnique(t *testing.T) {
	if len(Builtins) != 34 {
		t.Fatalf("got %d built-ins, want 34", len(Builtins))
	}
	seen := map[string]bool{}
	for _, id := range Builtins {
		if seen[id] {
			t.Fatalf("duplicate provider %q", id)
		}
		seen[id] = true
	}
}
