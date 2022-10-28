package provider

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/efureev/sauth/redirect"
	"github.com/go-pkgz/rest"
	"github.com/golang-jwt/jwt"
	"golang.org/x/oauth2"

	"github.com/efureev/sauth/logger"
	"github.com/efureev/sauth/token"
)

// Oauth2Handler implements /login, /callback and /logout handlers from aouth2 flow
type Oauth2Handler struct {
	Params

	// all of these fields specific to particular oauth2 provider
	name string
	//infoURL        string
	endpoint       oauth2.Endpoint
	scopes         []string
	infoUrlMappers []Oauth2Mapper
	//mapUser        func(UserRawData, []byte) token.User // map info from InfoURL to User
	conf oauth2.Config
}

// Params to make initialized and ready to use provider
type Params struct {
	logger.L
	URL             string
	JwtService      TokenService
	Cid             string
	Csecret         string
	Issuer          string
	AvatarSaver     AvatarSaver
	AfterReceive    func(u *token.UserData) error
	RedirectBuilder redirect.RedirectBuilderFn

	Port int // relevant for providers supporting port customization, for example dev oauth2
}

// UserRawData is type for user information returned from oauth2 providers /info API method
type UserRawData map[string]interface{}

// Value returns value for key or empty string if not found
func (u UserRawData) Value(key string) string {
	// json.Unmarshal converts json "null" value to go's "nil", in this case return empty string
	if val, ok := u[key]; ok && val != nil {
		return fmt.Sprintf("%v", val)
	}
	return ""
}

// initOauth2Handler makes oauth2 handler for given provider
func initOauth2Handler(p Params, service Oauth2Handler) Oauth2Handler {
	if p.L == nil {
		p.L = logger.NoOp
	}
	p.Logf("[INFO] init oauth2 service %s", service.name)
	service.Params = p
	service.conf = oauth2.Config{
		ClientID:     service.Cid,
		ClientSecret: service.Csecret,
		Scopes:       service.scopes,
		Endpoint:     service.endpoint,
	}

	p.Logf("[DEBUG] created %s oauth2, id=%s, redir=%s, endpoint=%s",
		service.name, service.Cid, service.makeRedirURL("/{route}/"+service.name+"/"), service.endpoint)
	return service
}

// Name returns provider name
func (p Oauth2Handler) Name() string { return p.name }

// LoginHandler - GET /login?from=redirect-back-url&[site|aud]=siteID&session=1&noava=1
func (p Oauth2Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {

	p.Logf("[DEBUG] login with %s", p.Name())
	// make state (random) and store in session
	state, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to make oauth2 state")
		return
	}

	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to make claim's id")
		return
	}

	aud := r.URL.Query().Get("site") // legacy, for back compat
	if aud == "" {
		aud = r.URL.Query().Get("aud")
	}

	claims := token.Claims{
		Handshake: &token.Handshake{
			State: state,
			From:  r.URL.Query().Get("from"),
		},
		SessionOnly: r.URL.Query().Get("session") != "" && r.URL.Query().Get("session") != "0",
		StandardClaims: jwt.StandardClaims{
			Id:        cid,
			Audience:  aud,
			ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
			NotBefore: time.Now().Add(-1 * time.Minute).Unix(),
		},
		NoAva: r.URL.Query().Get("noava") == "1",
	}

	if _, err := p.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	// setting RedirectURL to rootURL/routingPath/provider/callback
	// e.g. http://localhost:8080/auth/github/callback
	p.conf.RedirectURL = p.makeRedirURL(r.URL.Path)

	// return login url
	loginURL := p.conf.AuthCodeURL(state)

	p.Logf("[DEBUG] login url %s, claims=%+v", loginURL, claims)
	p.performRedirect(w, r, loginURL)
}

func (p Oauth2Handler) performRedirect(w http.ResponseWriter, r *http.Request, loginURL string) {
	(p.RedirectBuilder)(w, r, loginURL)
}

// AuthHandler fills user info and redirects to "from" url. This is callback url redirected locally by browser
// GET /callback
func (p Oauth2Handler) AuthHandler(w http.ResponseWriter, r *http.Request) {
	oauthClaims, _, err := p.JwtService.Get(r)
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to get token")
		return
	}

	if oauthClaims.Handshake == nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusForbidden, nil, "invalid handshake token")
		return
	}

	retrievedState := oauthClaims.Handshake.State
	if retrievedState == "" || retrievedState != r.URL.Query().Get("state") {
		rest.SendErrorJSON(w, r, p.L, http.StatusForbidden, nil, "unexpected state")
		return
	}

	p.conf.RedirectURL = p.makeRedirURL(r.URL.Path)

	p.Logf("[DEBUG] token with state %s", retrievedState)

	tok, err := p.conf.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "exchange failed")
		return
	}

	client := p.conf.Client(context.Background(), tok)

	mapper := newMappers(client, p.Logf)

	err = mapper.adds(p.infoUrlMappers...).get()
	if err != nil {
		if e, ok := err.(CodeError); ok {
			rest.SendErrorJSON(w, r, p.L, e.code, e.err, e.message)
			return
		}
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "mappers failed")
		return
	}

	uData, err := getUserDataFromCtx(p, mapper.ctx)
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "context is empty")
		return
	}

	if oauthClaims.NoAva {
		uData.User.Picture = "" // reset picture on no avatar request
	}

	if !(p.AvatarSaver == nil || reflect.ValueOf(p.AvatarSaver).IsNil()) {
		uData.User, err = setAvatar(p.AvatarSaver, uData.User, client)
		if err != nil {
			rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to save avatar to proxy")
			return
		}
	}

	if p.AfterReceive != nil {
		if err := p.AfterReceive(uData); err != nil {
			if e, ok := err.(CodeError); ok {
				rest.SendErrorJSON(w, r, p.L, e.code, e.err, e.message)
				return
			}
			rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, err.Error())
			return
		}
	}

	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to make claim's id")
		return
	}
	claims := token.Claims{
		User: &uData.User,
		StandardClaims: jwt.StandardClaims{
			Issuer:   p.Issuer,
			Id:       cid,
			Audience: oauthClaims.Audience,
		},
		SessionOnly: oauthClaims.SessionOnly,
		NoAva:       oauthClaims.NoAva,
	}

	if _, err = p.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	p.Logf("[DEBUG] user info %+v", uData.User)

	// redirect to back url if presented in login query params
	if oauthClaims.Handshake != nil && oauthClaims.Handshake.From != "" {
		http.Redirect(w, r, oauthClaims.Handshake.From, http.StatusTemporaryRedirect)
		return
	}
	rest.RenderJSON(w, &uData.User)
}

func getUserDataFromCtx(p Oauth2Handler, ctx context.Context) (*token.UserData, error) {
	uData, err := token.GetUserDataFromCtx(ctx)
	if err != nil {
		return nil, err
	}
	uData.Social = p.Name()

	return &uData, nil
}

// LogoutHandler - GET /logout
func (p Oauth2Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if _, _, err := p.JwtService.Get(r); err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusForbidden, err, "logout not allowed")
		return
	}
	p.JwtService.Reset(w)
}

func (p Oauth2Handler) makeRedirURL(path string) string {
	elems := strings.Split(path, "/")
	newPath := strings.Join(elems[:len(elems)-1], "/")

	return strings.TrimSuffix(p.URL, "/") + strings.TrimSuffix(newPath, "/") + urlCallbackSuffix
}
