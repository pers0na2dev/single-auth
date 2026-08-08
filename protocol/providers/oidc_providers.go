package providers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

func Apple(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "apple", name: "Apple", authorizationEndpoint: "https://appleid.apple.com/auth/authorize", tokenEndpoint: "https://appleid.apple.com/auth/token", defaultScopes: []string{"email", "name"}, requireCredentials: true,
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) {
				args.ResponseMode = "form_post"
				args.ResponseType = "code id_token"
			})
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, authorizationUser *AuthorizationUser) (*UserInfoResult, error) {
			if tokens.IDToken == "" {
				return nil, nil
			}
			profile, err := decodeJWT(tokens.IDToken)
			if err != nil {
				return nil, nil
			}
			name := stringValue(profile["name"])
			if authorizationUser != nil {
				name = strings.TrimSpace(authorizationUser.FirstName + " " + authorizationUser.LastName)
			}
			profile["name"] = name
			verified := boolValue(profile["email_verified"]) || stringValue(profile["email_verified"]) == "true"
			return result(ctx, provider, profile, stringValue(profile["sub"]), name, profile["email"], "", verified)
		},
	})
	provider.Metadata.JWKSURI = "https://appleid.apple.com/auth/keys"
	provider.Metadata.SupportsIDToken = true
	provider.verifyIDToken = func(ctx context.Context, token, nonce string) (bool, error) {
		audience := audienceOptions(options.Audience)
		if len(audience) == 0 && options.AppBundleIdentifier != "" {
			audience = []string{options.AppBundleIdentifier}
		}
		if len(audience) == 0 {
			audience = clientIDs(options.ClientID)
		}
		claims, err := verifyRemoteJWT(ctx, provider, token, provider.Metadata.JWKSURI, jwtPolicy{issuers: []string{"https://appleid.apple.com"}, audiences: audience, maxAge: time.Hour})
		if err != nil {
			return false, nil
		}
		if nonce != "" {
			tokenNonce := stringValue(claims["nonce"])
			digest := sha256.Sum256([]byte(nonce))
			if tokenNonce != nonce && tokenNonce != fmt.Sprintf("%x", digest[:]) {
				return false, nil
			}
		}
		return true, nil
	}
	return provider, nil
}

func Google(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "google", name: "Google", authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth", tokenEndpoint: "https://oauth2.googleapis.com/token", defaultScopes: []string{"email", "profile", "openid"}, requireCredentials: true, requireCodeVerifier: true,
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) {
				args.Prompt = provider.Options.Prompt
				args.AccessType = provider.Options.AccessType
				args.Display = firstNonempty(input.Display, provider.Options.Display)
				args.LoginHint = input.LoginHint
				args.HostedDomain = provider.Options.HostedDomain
				args.AdditionalParams = []oauth2.Param{{Name: "include_granted_scopes", Value: "true"}}
			})
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			if tokens.IDToken == "" {
				return nil, nil
			}
			profile, err := decodeJWT(tokens.IDToken)
			if err != nil {
				return nil, nil
			}
			if !googleHostedDomainAllowed(provider.Options.HostedDomain, profile["hd"]) {
				return nil, nil
			}
			return result(ctx, provider, profile, stringValue(profile["sub"]), stringValue(profile["name"]), profile["email"], stringValue(profile["picture"]), boolValue(profile["email_verified"]))
		},
	})
	provider.Metadata.JWKSURI = "https://www.googleapis.com/oauth2/v3/certs"
	provider.Metadata.SupportsIDToken = true
	provider.verifyIDToken = func(ctx context.Context, token, nonce string) (bool, error) {
		claims, err := verifyRemoteJWT(ctx, provider, token, provider.Metadata.JWKSURI, jwtPolicy{issuers: []string{"https://accounts.google.com", "accounts.google.com"}, audiences: clientIDs(options.ClientID), maxAge: time.Hour})
		if err != nil {
			return false, nil
		}
		if nonce != "" && stringValue(claims["nonce"]) != nonce {
			return false, nil
		}
		return googleHostedDomainAllowed(options.HostedDomain, claims["hd"]), nil
	}
	return provider, nil
}

func googleHostedDomainAllowed(configured string, claim any) bool {
	if configured == "" {
		return true
	}
	value := stringValue(claim)
	if value == "" {
		return false
	}
	return configured == "*" || configured == value
}

func Cognito(options Options) (*Provider, error) {
	if options.Domain == "" || options.Region == "" || options.UserPoolID == "" {
		return nil, ErrDomainAndRegionRequired
	}
	domain := strings.TrimPrefix(strings.TrimPrefix(options.Domain, "https://"), "http://")
	provider := newStandard(options, standardSpec{
		id: "cognito", name: "Cognito", authorizationEndpoint: "https://" + domain + "/oauth2/authorize", tokenEndpoint: "https://" + domain + "/oauth2/token", userInfoEndpoint: "https://" + domain + "/oauth2/userinfo", defaultScopes: []string{"openid", "profile", "email"},
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			if primaryClientID(provider.Options.ClientID) == "" {
				return nil, ErrClientIDAndSecretRequired
			}
			if provider.Options.RequireClientSecret && provider.Options.ClientSecret == "" {
				return nil, ErrClientSecretRequired
			}
			built, err := createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) { args.Prompt = provider.Options.Prompt })
			if err != nil {
				return nil, err
			}
			scope := built.Query().Get("scope")
			if scope == "" {
				return built, nil
			}
			parts := strings.Split(built.RawQuery, "&")
			kept := parts[:0]
			for _, part := range parts {
				if !strings.HasPrefix(part, "scope=") {
					kept = append(kept, part)
				}
			}
			built.RawQuery = strings.Join(kept, "&")
			raw := built.String() + "&scope=" + encodeURIComponent(scope)
			return url.Parse(raw)
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			mapProfile := func(profile map[string]any, enrich bool) (*UserInfoResult, error) {
				name := stringValue(profile["name"])
				if name == "" {
					name = stringValue(profile["given_name"])
				}
				if name == "" {
					name = stringValue(profile["username"])
				}
				if enrich {
					profile["name"] = name
				}
				return result(ctx, provider, profile, stringValue(profile["sub"]), name, profile["email"], stringValue(profile["picture"]), boolValue(profile["email_verified"]))
			}
			if tokens.IDToken != "" {
				if profile, err := decodeJWT(tokens.IDToken); err == nil {
					return mapProfile(profile, true)
				}
			}
			if tokens.AccessToken != "" {
				profile, err := fetchProfile(ctx, provider, http.MethodGet, provider.Metadata.UserInfoEndpoint, bearer(tokens.AccessToken), nil)
				if err == nil {
					return mapProfile(profile, false)
				}
			}
			return nil, nil
		},
	})
	provider.Metadata.JWKSURI = fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", options.Region, options.UserPoolID)
	provider.Metadata.SupportsIDToken = true
	provider.verifyIDToken = func(ctx context.Context, token, nonce string) (bool, error) {
		issuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", options.Region, options.UserPoolID)
		claims, err := verifyRemoteJWT(ctx, provider, token, provider.Metadata.JWKSURI, jwtPolicy{issuers: []string{issuer}, audiences: clientIDs(options.ClientID), maxAge: time.Hour})
		if err != nil {
			return false, nil
		}
		if nonce != "" && stringValue(claims["nonce"]) != nonce {
			return false, nil
		}
		return true, nil
	}
	return provider, nil
}

const microsoftConsumerTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"

func Microsoft(options Options) (*Provider, error) {
	tenant := options.TenantID
	if tenant == "" {
		tenant = "common"
	}
	authority := options.Authority
	if authority == "" {
		authority = "https://login.microsoftonline.com"
	}
	authority = strings.TrimRight(authority, "/")
	provider := newStandard(options, standardSpec{
		id: "microsoft", name: "Microsoft EntraID", authorizationEndpoint: authority + "/" + tenant + "/oauth2/v2.0/authorize", tokenEndpoint: authority + "/" + tenant + "/oauth2/v2.0/token", defaultScopes: []string{"openid", "profile", "email", "User.Read", "offline_access"},
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			if primaryClientID(provider.Options.ClientID) == "" {
				return nil, ErrClientIDAndSecretRequired
			}
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) {
				args.Prompt = provider.Options.Prompt
				args.LoginHint = input.LoginHint
			})
		},
		refresh: func(ctx context.Context, provider *Provider, token string) (oauth2.Tokens, error) {
			scopes := combinedScopes(provider.Options, provider.Metadata.DefaultScopes, nil, false)
			return refresh(ctx, provider, token, oauth2.AuthenticationPost, oauth2.ProviderOptions{ClientID: provider.Options.ClientID, ClientSecret: provider.Options.ClientSecret}, oauth2.Param{Name: "scope", Value: strings.Join(scopes, " ")})
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			if tokens.IDToken == "" {
				return nil, nil
			}
			profile, err := decodeJWT(tokens.IDToken)
			if err != nil {
				return nil, nil
			}
			size := provider.Options.ProfilePhotoSize
			if size == 0 {
				size = 48
			}
			endpoint := fmt.Sprintf("https://graph.microsoft.com/v1.0/me/photos/%dx%d/$value", size, size)
			raw, photoErr := fetchBytes(ctx, provider, endpoint, bearer(tokens.AccessToken))
			if !provider.Options.DisableProfilePhoto && photoErr == nil {
				profile["picture"] = "data:image/jpeg;base64, " + base64.StdEncoding.EncodeToString(raw)
			}
			verified := boolValue(profile["email_verified"])
			if _, exists := profile["email_verified"]; !exists {
				email := stringValue(profile["email"])
				verified = email != "" && (stringArrayContains(profile["verified_primary_email"], email) || stringArrayContains(profile["verified_secondary_email"], email))
			}
			return result(ctx, provider, profile, stringValue(profile["sub"]), stringValue(profile["name"]), profile["email"], stringValue(profile["picture"]), verified)
		},
	})
	provider.Metadata.JWKSURI = authority + "/" + tenant + "/discovery/v2.0/keys"
	provider.Metadata.SupportsIDToken = true
	provider.verifyIDToken = func(ctx context.Context, token, nonce string) (bool, error) {
		policy := jwtPolicy{audiences: clientIDs(options.ClientID), maxAge: time.Hour}
		if tenant != "common" && tenant != "organizations" && tenant != "consumers" {
			policy.issuers = []string{authority + "/" + tenant + "/v2.0"}
		}
		claims, err := verifyRemoteJWT(ctx, provider, token, provider.Metadata.JWKSURI, policy)
		if err != nil {
			return false, nil
		}
		if nonce != "" && stringValue(claims["nonce"]) != nonce {
			return false, nil
		}
		tid, ok := claims["tid"].(string)
		if !ok || tid == "" || stringValue(claims["iss"]) != authority+"/"+tid+"/v2.0" {
			return false, nil
		}
		if tenant == "organizations" && tid == microsoftConsumerTenantID {
			return false, nil
		}
		if tenant == "consumers" && tid != microsoftConsumerTenantID {
			return false, nil
		}
		return true, nil
	}
	return provider, nil
}

func LINE(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "line", name: "LINE", authorizationEndpoint: "https://access.line.me/oauth2/v2.1/authorize", tokenEndpoint: "https://api.line.me/oauth2/v2.1/token", userInfoEndpoint: "https://api.line.me/oauth2/v2.1/userinfo", defaultScopes: []string{"openid", "profile", "email"},
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) { args.LoginHint = input.LoginHint })
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			var profile map[string]any
			if tokens.IDToken != "" {
				profile, _ = decodeJWT(tokens.IDToken)
			}
			if profile == nil {
				profile, _ = fetchProfile(ctx, provider, http.MethodGet, provider.Metadata.UserInfoEndpoint, bearer(tokens.AccessToken), nil)
			}
			if profile == nil {
				return nil, nil
			}
			id := stringValue(profile["sub"])
			if id == "" {
				id = stringValue(profile["userId"])
			}
			name := stringValue(profile["name"])
			if name == "" {
				name = stringValue(profile["displayName"])
			}
			image := stringValue(profile["picture"])
			if image == "" {
				image = stringValue(profile["pictureUrl"])
			}
			return result(ctx, provider, profile, id, name, profile["email"], image, false)
		},
	})
	provider.Metadata.SupportsIDToken = true
	provider.verifyIDToken = func(ctx context.Context, token, nonce string) (bool, error) {
		form := oauth2.NewForm()
		form.Set("id_token", token)
		form.Set("client_id", primaryClientID(options.ClientID))
		if nonce != "" {
			form.Set("nonce", nonce)
		}
		claims := map[string]any{}
		err := doJSON(ctx, provider.clientFor(ctx), http.MethodPost, "https://api.line.me/oauth2/v2.1/verify", map[string]string{"content-type": "application/x-www-form-urlencoded"}, strings.NewReader(form.Encode()), &claims)
		if err != nil {
			return false, nil
		}
		if stringValue(claims["aud"]) != primaryClientID(options.ClientID) {
			return false, nil
		}
		if tokenNonce := stringValue(claims["nonce"]); tokenNonce != "" && tokenNonce != nonce {
			return false, nil
		}
		return true, nil
	}
	return provider, nil
}

func Facebook(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "facebook", name: "Facebook", authorizationEndpoint: "https://www.facebook.com/v24.0/dialog/oauth", tokenEndpoint: "https://graph.facebook.com/v24.0/oauth/access_token", userInfoEndpoint: "https://graph.facebook.com/me", defaultScopes: []string{"email", "public_profile"}, requireCredentials: true,
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) {
				args.CodeVerifier = ""
				args.LoginHint = input.LoginHint
				if provider.Options.ConfigID != "" {
					args.AdditionalParams = []oauth2.Param{{Name: "config_id", Value: provider.Options.ConfigID}}
				}
			})
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			if tokens.IDToken != "" && len(strings.Split(tokens.IDToken, ".")) == 3 {
				profile, err := decodeJWT(tokens.IDToken)
				if err != nil {
					return nil, nil
				}
				picture := map[string]any{"data": map[string]any{"url": profile["picture"], "height": 100, "width": 100, "is_silhouette": false}}
				synthetic := map[string]any{"id": profile["sub"], "name": profile["name"], "email": profile["email"], "picture": picture, "email_verified": false}
				user, err := mappedUser(ctx, provider, synthetic, stringValue(profile["sub"]), stringValue(profile["name"]), profile["email"], "", false)
				if err != nil {
					return nil, err
				}
				if _, exists := user.Extra["picture"]; !exists {
					user.Extra["picture"] = picture
				}
				return &UserInfoResult{User: user, Data: profile}, nil
			}
			if tokens.AccessToken == "" {
				return nil, nil
			}
			tokenUserID, ok := verifyFacebookOpaque(ctx, provider, tokens.AccessToken)
			if !ok {
				return nil, nil
			}
			fields := append([]string{"id", "name", "email", "picture"}, provider.Options.Fields...)
			profileURL, err := url.Parse(provider.Metadata.UserInfoEndpoint)
			if err != nil {
				return nil, nil
			}
			query := profileURL.Query()
			query.Set("fields", strings.Join(fields, ","))
			profileURL.RawQuery = query.Encode()
			profile, err := fetchProfile(ctx, provider, http.MethodGet, profileURL.String(), bearer(tokens.AccessToken), nil)
			if err != nil || stringValue(profile["id"]) != tokenUserID {
				return nil, nil
			}
			return result(ctx, provider, profile, stringValue(profile["id"]), stringValue(profile["name"]), profile["email"], stringValue(at(profile, "picture", "data", "url")), boolValue(profile["email_verified"]))
		},
	})
	provider.Metadata.JWKSURI = "https://limited.facebook.com/.well-known/oauth/openid/jwks/"
	provider.Metadata.SupportsIDToken = true
	provider.verifyIDToken = func(ctx context.Context, token, nonce string) (bool, error) {
		if len(strings.Split(token, ".")) == 3 {
			claims, err := verifyRemoteJWT(ctx, provider, token, provider.Metadata.JWKSURI, jwtPolicy{algorithms: []string{"RS256"}, issuers: []string{"https://www.facebook.com"}, audiences: clientIDs(options.ClientID)})
			if err != nil {
				return false, nil
			}
			if nonce != "" && stringValue(claims["nonce"]) != nonce {
				return false, nil
			}
			return true, nil
		}
		_, ok := verifyFacebookOpaque(ctx, provider, token)
		return ok, nil
	}
	return provider, nil
}

func verifyFacebookOpaque(ctx context.Context, provider *Provider, token string) (string, bool) {
	primary := primaryClientID(provider.Options.ClientID)
	if primary == "" || provider.Options.ClientSecret == "" {
		return "", false
	}
	form := oauth2.NewForm()
	form.Set("input_token", token)
	form.Set("access_token", primary+"|"+provider.Options.ClientSecret)
	wrapper, err := fetchProfile(ctx, provider, http.MethodGet, "https://graph.facebook.com/debug_token?"+form.Encode(), nil, nil)
	if err != nil {
		return "", false
	}
	data := object(wrapper["data"])
	appID, userID := stringValue(data["app_id"]), stringValue(data["user_id"])
	if !boolValue(data["is_valid"]) || !contains(clientIDs(provider.Options.ClientID), appID) || userID == "" {
		return "", false
	}
	return userID, true
}

func PayPal(options Options) (*Provider, error) {
	sandbox := options.Environment == "" || options.Environment == "sandbox"
	webHost, apiHost, certHost := "www.paypal.com", "api-m.paypal.com", "api.paypal.com"
	if sandbox {
		webHost, apiHost, certHost = "www.sandbox.paypal.com", "api-m.sandbox.paypal.com", "api.sandbox.paypal.com"
	}
	provider := newStandard(options, standardSpec{
		id: "paypal", name: "PayPal", authorizationEndpoint: "https://" + webHost + "/signin/authorize", tokenEndpoint: "https://" + apiHost + "/v1/oauth2/token", userInfoEndpoint: "https://" + apiHost + "/v1/identity/oauth2/userinfo?schema=paypalv1.1", requireCredentials: true,
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			args := oauth2.AuthorizationURLOptions{ID: provider.ID, Options: providerOptions(provider.Options), AuthorizationEndpoint: provider.Metadata.AuthorizationEndpoint, RedirectURI: input.RedirectURI, State: input.State, CodeVerifier: input.CodeVerifier, Scopes: []string{}, Prompt: provider.Options.Prompt}
			return oauth2.CreateAuthorizationURL(args)
		},
		validate: func(ctx context.Context, provider *Provider, input CodeInput) (*oauth2.Tokens, error) {
			tokens, err := paypalToken(ctx, provider, "authorization_code", input.Code, input.RedirectURI)
			if err != nil {
				return nil, ErrFailedToGetAccessToken
			}
			return &tokens, nil
		},
		refresh: func(ctx context.Context, provider *Provider, token string) (oauth2.Tokens, error) {
			tokens, err := paypalToken(ctx, provider, "refresh_token", token, "")
			if err != nil {
				return oauth2.Tokens{}, ErrFailedToRefreshToken
			}
			return tokens, nil
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			if tokens.AccessToken == "" {
				return nil, nil
			}
			profile, err := fetchProfile(ctx, provider, http.MethodGet, provider.Metadata.UserInfoEndpoint, map[string]string{"Authorization": "Bearer " + tokens.AccessToken, "Accept": "application/json"}, nil)
			if err != nil {
				return nil, nil
			}
			if tokens.IDToken != "" {
				claims, err := decodeJWT(tokens.IDToken)
				if err != nil {
					return nil, nil
				}
				subject := stringValue(profile["sub"])
				if subject == "" {
					subject = stringValue(profile["user_id"])
				}
				if stringValue(claims["sub"]) == "" || subject != stringValue(claims["sub"]) {
					return nil, nil
				}
			}
			return result(ctx, provider, profile, stringValue(profile["user_id"]), stringValue(profile["name"]), profile["email"], stringValue(profile["picture"]), boolValue(profile["email_verified"]))
		},
	})
	provider.Metadata.JWKSURI = "https://" + certHost + "/v1/oauth2/certs"
	provider.Metadata.SupportsIDToken = true
	issuer := "https://" + webHost
	provider.verifyIDToken = func(ctx context.Context, token, nonce string) (bool, error) {
		parts, err := parseJWT(token)
		if err != nil {
			return false, nil
		}
		alg := stringValue(parts.header["alg"])
		policy := jwtPolicy{algorithms: []string{alg}, issuers: []string{issuer}, audiences: []string{primaryClientID(options.ClientID)}, maxAge: time.Hour}
		var claims map[string]any
		if alg == "HS256" {
			claims, err = verifyHMACJWT(token, options.ClientSecret, policy)
		} else if alg == "RS256" {
			claims, err = verifyRemoteJWT(ctx, provider, token, provider.Metadata.JWKSURI, policy)
		} else {
			return false, nil
		}
		if err != nil {
			return false, nil
		}
		if nonce != "" && stringValue(claims["nonce"]) != nonce {
			return false, nil
		}
		return true, nil
	}
	return provider, nil
}

func paypalToken(ctx context.Context, provider *Provider, grant, token, redirectURI string) (oauth2.Tokens, error) {
	form := oauth2.NewForm()
	form.Set("grant_type", grant)
	if grant == "authorization_code" {
		form.Set("code", token)
		form.Set("redirect_uri", redirectURI)
	} else {
		form.Set("refresh_token", token)
	}
	headers := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(primaryClientID(provider.Options.ClientID)+":"+provider.Options.ClientSecret)), "Accept": "application/json", "Accept-Language": "en_US", "Content-Type": "application/x-www-form-urlencoded"}
	data := map[string]any{}
	if err := doJSON(ctx, provider.clientFor(ctx), http.MethodPost, provider.Metadata.TokenEndpoint, headers, strings.NewReader(form.Encode()), &data); err != nil {
		return oauth2.Tokens{}, err
	}
	tokens := oauth2.Tokens{AccessToken: stringValue(data["access_token"]), RefreshToken: stringValue(data["refresh_token"])}
	if seconds, err := strconv.ParseFloat(stringValue(data["expires_in"]), 64); err == nil && seconds != 0 {
		expires := time.Now().Add(time.Duration(seconds * float64(time.Second)))
		tokens.AccessTokenExpiresAt = &expires
	}
	if grant == "authorization_code" {
		tokens.IDToken = stringValue(data["id_token"])
	}
	return tokens, nil
}

func audienceOptions(value any) []string { return clientIDs(value) }

func fetchBytes(ctx context.Context, provider *Provider, endpoint string, headers map[string]string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := provider.clientFor(ctx).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", response.StatusCode)
	}
	return io.ReadAll(response.Body)
}

func stringArrayContains(value any, wanted string) bool {
	for _, item := range array(value) {
		if stringValue(item) == wanted {
			return true
		}
	}
	if values, ok := value.([]string); ok {
		return contains(values, wanted)
	}
	return false
}
