package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/efureev/sauth/token"
)

type Oauth2Mappers struct {
	mappers []Oauth2Mapper
	ctx     context.Context
	client  *http.Client
	l       func(format string, args ...interface{})
}

func newMappers(client *http.Client, l func(format string, args ...interface{})) *Oauth2Mappers {
	return &Oauth2Mappers{
		mappers: []Oauth2Mapper{},
		client:  client,
		ctx:     context.Background(),
		l:       l,
	}
}

func (mm *Oauth2Mappers) adds(maps ...Oauth2Mapper) *Oauth2Mappers {
	for _, m := range maps {
		mm.add(m)
	}

	return mm
}

func (mm *Oauth2Mappers) add(mapper Oauth2Mapper) *Oauth2Mappers {
	mm.mappers = append(mm.mappers, mapper)

	return mm
}

func (mm *Oauth2Mappers) get() error {
	for _, m := range mm.mappers {
		var err error
		if mm.ctx, err = m.get(mm.ctx, mm.client, mm.l); err != nil {
			return err
		}
	}

	return nil
}

type Oauth2Mapper struct {
	infoURL string
	mapFn   func(context.Context, *token.UserData, interface{}, []byte) token.User
	result  interface{}
}

func (m Oauth2Mapper) get(ctx context.Context, client *http.Client, l func(format string, args ...interface{})) (context.Context, error) {
	info, err := client.Get(m.infoURL)
	if err != nil {
		return nil, CodeError{http.StatusServiceUnavailable, "failed to get client info", err}
	}

	defer func() {
		if e := info.Body.Close(); e != nil {
			l("[WARN] failed to close response body, %s", e)
		}
	}()

	data, err := io.ReadAll(info.Body)
	if err != nil {
		return nil, CodeError{http.StatusInternalServerError, "failed to read user info", err}
	}

	if e := json.Unmarshal(data, &m.result); e != nil {
		return nil, CodeError{http.StatusInternalServerError, "failed to unmarshal user info", err}
	}

	l("[DEBUG] got raw info from [%s]  %+v", m.infoURL, m.result)

	ud, err := token.GetUserDataFromCtx(ctx)
	ud.SetRaw(m.infoURL, m.result)
	if err != nil {
		ctx = token.SetUserDataToCtx(ctx, ud)
	}

	user := m.mapFn(ctx, &ud, m.result, data)
	ud.User = user
	ud.SetEmailToAvailable(ud.User.Email, true)

	return token.SetUserDataToCtx(ctx, ud), nil
}

func NewOauth2Mapper(url string, fn func(context.Context, *token.UserData, interface{}, []byte) token.User, t interface{}) Oauth2Mapper {
	return Oauth2Mapper{
		infoURL: url,
		mapFn:   fn,
		result:  t,
	}
}
