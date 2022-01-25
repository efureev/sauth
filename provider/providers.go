// Package provider implements all oauth2, oauth1 as well as custom and direct providers
package provider

import (
	"context"
	"crypto/sha1" //nolint
	"encoding/json"

	"github.com/dghubble/oauth1"
	"github.com/dghubble/oauth1/twitter"
	"github.com/efureev/sauth/token"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// NewTwitter makes twitter oauth2 provider
func NewTwitter(p Params) Oauth1Handler {
	return initOauth1Handler(p, Oauth1Handler{
		name: "twitter",
		conf: oauth1.Config{
			Endpoint: twitter.AuthorizeEndpoint,
		},
		infoURL: "https://api.twitter.com/1.1/account/verify_credentials.json",
		mapUser: func(data UserRawData, _ []byte) token.User {
			userInfo := token.User{
				ID:      "twitter_" + token.HashID(sha1.New(), data.Value("id_str")),
				Name:    data.Value("screen_name"),
				Picture: data.Value("profile_image_url_https"),
			}
			if userInfo.Name == "" {
				userInfo.Name = data.Value("name")
			}
			return userInfo
		},
	})
}

// NewBattlenet makes Battle.net oauth2 provider
func NewBattlenet(p Params) Oauth2Handler {
	return initOauth2Handler(p, Oauth2Handler{
		name: "battlenet",
		endpoint: oauth2.Endpoint{
			AuthURL:   "https://eu.battle.net/oauth/authorize",
			TokenURL:  "https://eu.battle.net/oauth/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		scopes: []string{},
		infoUrlMappers: []Oauth2Mapper{
			NewOauth2Mapper(
				"https://eu.battle.net/oauth/userinfo",
				func(ctx context.Context, ud *token.UserData, raw interface{}, _ []byte) token.User {
					d, ok := raw.(map[string]interface{})
					if !ok {
						panic(`not UserData`)
					}
					userRawData := UserRawData(d)

					return token.User{
						ID:   "battlenet_" + token.HashID(sha1.New(), userRawData.Value("id")),
						Name: userRawData.Value("battletag"),
					}
				},
				UserRawData{},
			),
		},
	})
}

// NewMicrosoft makes microsoft azure oauth2 provider
func NewMicrosoft(p Params) Oauth2Handler {
	return initOauth2Handler(p, Oauth2Handler{
		name:     "microsoft",
		endpoint: microsoft.AzureADEndpoint("consumers"),
		scopes:   []string{"User.Read"},
		infoUrlMappers: []Oauth2Mapper{
			NewOauth2Mapper(
				"https://graph.microsoft.com/v1.0/me",
				func(ctx context.Context, ud *token.UserData, raw interface{}, _ []byte) token.User {
					d, ok := raw.(map[string]interface{})
					if !ok {
						panic(`not UserData`)
					}
					userRawData := UserRawData(d)

					return token.User{
						ID:      "microsoft_" + token.HashID(sha1.New(), userRawData.Value("id")),
						Name:    userRawData.Value("displayName"),
						Picture: "https://graph.microsoft.com/beta/me/photo/$value",
					}
				},
				UserRawData{},
			),
		},
	})
}

// NewPatreon makes patreon oauth2 provider
func NewPatreon(p Params) Oauth2Handler {
	type uinfo struct {
		Data struct {
			Attributes struct {
				FullName string `json:"full_name"`
				ImageURL string `json:"image_url"`
			} `json:"attributes"`
			ID            string `json:"id"`
			Relationships struct {
				Pledges struct {
					Data []struct {
						ID   string `json:"id"`
						Type string `json:"type"`
					} `json:"data"`
				} `json:"pledges"`
			} `json:"relationships"`
		} `json:"data"`
	}

	return initOauth2Handler(p, Oauth2Handler{
		name: "patreon",
		// see https://docs.patreon.com/?shell#oauth
		endpoint: oauth2.Endpoint{
			AuthURL:   "https://www.patreon.com/oauth2/authorize",
			TokenURL:  "https://api.patreon.com/oauth2/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		scopes: []string{},
		infoUrlMappers: []Oauth2Mapper{
			NewOauth2Mapper(
				"https://www.patreon.com/api/oauth2/api/current_user",
				func(ctx context.Context, ud *token.UserData, _ interface{}, bdata []byte) token.User {

					uinfoJSON := uinfo{}
					userInfo := ud.User

					if err := json.Unmarshal(bdata, &uinfoJSON); err == nil {
						userInfo.ID = "patreon_" + token.HashID(sha1.New(), userInfo.ID)
						userInfo.Name = uinfoJSON.Data.Attributes.FullName
						userInfo.Picture = uinfoJSON.Data.Attributes.ImageURL

						// check if the user is your subscriber
						if len(uinfoJSON.Data.Relationships.Pledges.Data) > 0 {
							userInfo.SetPaidSub(true)
						}
					}

					return userInfo
				},
				UserRawData{},
			),
		},

		/*infoURL: "https://www.patreon.com/api/oauth2/api/current_user",

		mapUser: func(data UserData, bdata []byte) token.User {
			userInfo := token.User{}

			uinfoJSON := uinfo{}
			if err := json.Unmarshal(bdata, &uinfoJSON); err == nil {
				userInfo.ID = "patreon_" + token.HashID(sha1.New(), userInfo.ID)
				userInfo.Name = uinfoJSON.Data.Attributes.FullName
				userInfo.Picture = uinfoJSON.Data.Attributes.ImageURL

				// check if the user is your subscriber
				if len(uinfoJSON.Data.Relationships.Pledges.Data) > 0 {
					userInfo.SetPaidSub(true)
				}
			}

			return userInfo
		},*/
	})
}
