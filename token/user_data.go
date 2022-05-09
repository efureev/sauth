package token

import (
	"context"
	"fmt"
)

type Collections map[string]*Collection

type Collection struct {
	Type  string                 `json:"type"`
	Items map[string]interface{} `json:"items"`
}

func (c *Collection) Add(name string, val interface{}) {
	c.Items[name] = val
}

type UserData struct {
	User        User                   `json:"user"`
	Social      string                 `json:"social"`
	Collections Collections            `json:"collections"`
	Raw         map[string]interface{} `json:"raw"`
}

func (ud *UserData) SetRaw(key string, val interface{}) {
	if ud.Raw == nil {
		ud.Raw = map[string]interface{}{}
	}
	ud.Raw[key] = val
}

func (ud *UserData) CreateCollection(name string) *Collection {
	if ud.Collections == nil {
		ud.Collections = map[string]*Collection{}
	}

	if _, ok := ud.Collections[name]; !ok {
		ud.Collections[name] = NewCollection(name)
	}

	return ud.Collections[name]
}

func (ud *UserData) CreateEmailCollection() *Collection {
	return ud.CreateCollection(`emails`)
}

func (ud *UserData) AddCollection(collection Collection) {
	if ud.Collections == nil {
		ud.Collections = map[string]*Collection{}
	}

	if _, ok := ud.Collections[collection.Type]; !ok {
		ud.Collections[collection.Type] = &collection
	}
}

func (ud *UserData) GetCollection(name string) *Collection {
	if v, ok := ud.Collections[name]; ok {
		return v
	}
	return nil
}

func NewCollection(name string) *Collection {
	return &Collection{Type: name, Items: map[string]interface{}{}}
}

func GetUserDataFromCtx(ctx context.Context) (user UserData, err error) {
	if ctx == nil {
		return UserData{User: User{}}, fmt.Errorf("no info about user")
	}
	if u, ok := ctx.Value(contextKey("userData")).(UserData); ok {
		return u, nil
	}

	return UserData{User: User{}}, fmt.Errorf("user can't be parsed")
}

func SetUserDataToCtx(ctx context.Context, user UserData) context.Context {
	return context.WithValue(ctx, contextKey("userData"), user)
}

func GetUserFromCtx(ctx context.Context) (user User, err error) {
	if ctx == nil {
		return User{}, fmt.Errorf("no info about user")
	}
	if u, ok := ctx.Value(contextKey("user")).(User); ok {
		return u, nil
	}

	return User{}, fmt.Errorf("user can't be parsed")
}

func SetUserToCtx(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, contextKey("user"), user)
}
