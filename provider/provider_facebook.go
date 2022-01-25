// Package provider implements all oauth2, oauth1 as well as custom and direct providers
package provider

import (
	"context"
	"crypto/sha1" //nolint
	"encoding/json"

	"github.com/efureev/sauth/token"
	"golang.org/x/oauth2/facebook"
)

// NewFacebook makes facebook oauth2 provider
func NewFacebook(p Params) Oauth2Handler {
	// response format for fb /me call
	type uinfo struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}

	return initOauth2Handler(p, Oauth2Handler{
		name:     "facebook",
		endpoint: facebook.Endpoint,
		scopes:   []string{"public_profile"},
		infoUrlMappers: []Oauth2Mapper{
			NewOauth2Mapper(
				"https://graph.facebook.com/me?fields=id,name,picture",
				func(ctx context.Context, ud *token.UserData, raw interface{}, bdata []byte) token.User {
					d, ok := raw.(map[string]interface{})
					if !ok {
						panic(`not UserData`)
					}
					userRawData := UserRawData(d)

					userInfo := token.User{
						ID:   "facebook_" + token.HashID(sha1.New(), userRawData.Value("id")),
						Name: userRawData.Value("name"),
					}
					if userInfo.Name == "" {
						userInfo.Name = userInfo.ID[0:16]
					}

					uinfoJSON := uinfo{}
					if err := json.Unmarshal(bdata, &uinfoJSON); err == nil {
						userInfo.Picture = uinfoJSON.Picture.Data.URL
					}

					return userInfo
				},
				UserRawData{},
			),
		},
	})
}
