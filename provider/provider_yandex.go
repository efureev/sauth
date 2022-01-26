// Package provider implements all oauth2, oauth1 as well as custom and direct providers
package provider

import (
	"context"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/efureev/sauth/token"
	"golang.org/x/oauth2/yandex"
)

// NewYandex makes yandex oauth2 provider
func NewYandex(p Params) Oauth2Handler {
	return initOauth2Handler(p, Oauth2Handler{
		name:     "yandex",
		endpoint: yandex.Endpoint,
		scopes:   []string{},
		// See https://tech.yandex.com/passport/doc/dg/reference/response-docpage/
		infoUrlMappers: []Oauth2Mapper{
			NewOauth2Mapper(
				"https://login.yandex.ru/info?format=json",
				func(ctx context.Context, ud *token.UserData, raw interface{}, _ []byte) token.User {
					d, ok := raw.(map[string]interface{})
					if !ok {
						panic(`not UserData`)
					}
					userRawData := UserRawData(d)
					spew.Dump(userRawData)
					ud.User.ID = userRawData.Value("id")
					ud.User.Email = userRawData.Value("default_email")

					ud.User.Name = userRawData.Value("display_name") // using Display Name by default

					if ud.User.Name == "" {
						ud.User.Name = userRawData.Value("real_name") // using Real Name (== full name) if Display Name is empty
					}
					if ud.User.Name == "" {
						ud.User.Name = userRawData.Value("login") // otherwise using login
					}

					if userRawData.Value("default_avatar_id") != "" {
						ud.User.Picture = fmt.Sprintf("https://avatars.yandex.net/get-yapic/%s/islands-200", userRawData.Value("default_avatar_id"))
					}

					if valEmails, ok := userRawData[`emails`]; ok && valEmails != nil {
						if emails, ok := valEmails.([]string); ok {
							for _, email := range emails {
								ud.SetEmailToAvailable(email, ud.User.Email == email)
							}
						}
					}

					if userRawData.Value("default_avatar_id") != "" {
						ud.User.Picture = fmt.Sprintf("https://avatars.yandex.net/get-yapic/%s/islands-200", userRawData.Value("default_avatar_id"))
					}

					return ud.User
				},
				UserRawData{},
			),
		},
	})
}
