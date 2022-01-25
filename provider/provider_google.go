// Package provider implements all oauth2, oauth1 as well as custom and direct providers
package provider

import (
	"context"
	"crypto/sha1" //nolint

	"github.com/efureev/sauth/token"
	"golang.org/x/oauth2/google"
)

// NewGoogle makes google oauth2 provider
func NewGoogle(p Params) Oauth2Handler {
	return initOauth2Handler(p, Oauth2Handler{
		name:     "google",
		endpoint: google.Endpoint,
		scopes:   []string{"https://www.googleapis.com/auth/userinfo.profile"},
		// See https://tech.yandex.com/passport/doc/dg/reference/response-docpage/
		infoUrlMappers: []Oauth2Mapper{
			NewOauth2Mapper(
				"https://www.googleapis.com/oauth2/v3/userinfo",
				func(ctx context.Context, ud *token.UserData, raw interface{}, _ []byte) token.User {
					d, ok := raw.(map[string]interface{})
					if !ok {
						panic(`not UserData`)
					}
					userRawData := UserRawData(d)

					userInfo := token.User{
						// encode email with provider name to avoid collision if same id returned by other provider
						ID:      "google_" + token.HashID(sha1.New(), userRawData.Value("sub")),
						Name:    userRawData.Value("name"),
						Picture: userRawData.Value("picture"),
					}

					if userInfo.Name == "" {
						userInfo.Name = "noname_" + userInfo.ID[8:12]
					}

					return userInfo
				},
				UserRawData{},
			),
		},
	})
}
