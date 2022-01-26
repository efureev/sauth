// Package provider implements all oauth2, oauth1 as well as custom and direct providers
package provider

import (
	"context"
	"strconv"

	"github.com/efureev/sauth/token"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2/github"
)

type GitHubEmails []GitHubEmail
type GitHubEmail struct {
	Primary    bool
	Verified   bool
	Email      string
	Visibility string
}

// NewGithub makes github oauth2 provider
func NewGithub(p Params) Oauth2Handler {
	return initOauth2Handler(p, Oauth2Handler{
		name:     "github",
		endpoint: github.Endpoint,
		scopes:   []string{`user:email`},
		infoUrlMappers: []Oauth2Mapper{
			NewOauth2Mapper(
				"https://api.github.com/user",
				func(ctx context.Context, ud *token.UserData, raw interface{}, _ []byte) token.User {
					d, ok := raw.(map[string]interface{})
					if !ok {
						panic(`not UserData`)
					}

					userData := UserRawData(d)
					var idStr string

					if val, ok := userData[`id`]; ok && val != nil {
						idStr = strconv.FormatFloat(val.(float64), 'f', -1, 64)
					}

					if idStr == `` {
						panic(`runtime error: invalid ID`)
					}

					userInfo := token.User{
						ID:      idStr,
						Name:    userData.Value("name"),
						Picture: userData.Value("avatar_url"),
					}
					// github may have no user name, use login in this case
					if userInfo.Name == "" {
						userInfo.Name = userData.Value("login")
					}

					return userInfo
				},
				UserRawData{},
			),
			NewOauth2Mapper(
				"https://api.github.com/user/emails",
				func(ctx context.Context, ud *token.UserData, raw interface{}, _ []byte) token.User {
					dataEmails, dok := raw.([]interface{})
					if !dok {
						return ud.User
					}

					for _, email := range dataEmails {
						var ge = GitHubEmail{}

						if err := mapstructure.Decode(email, &ge); err != nil {
							continue
						}

						ud.SetEmailToAvailable(ge.Email, ge.Primary)

						if ge.Primary && ud.User.Email == `` {
							ud.User.Email = ge.Email
						}
					}

					return ud.User
				},
				GitHubEmails{},
			),
		},
	})
}
