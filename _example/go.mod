module github.com/efureev/sauth/_example

go 1.15

replace github.com/efureev/sauth => ../

require (
	github.com/efureev/sauth v1.18.0
	github.com/go-chi/chi/v5 v5.0.7
	github.com/go-oauth2/oauth2/v4 v4.5.0
	github.com/go-pkgz/lgr v0.10.4
	github.com/go-pkgz/rest v1.14.0
	github.com/golang-jwt/jwt v3.2.2+incompatible
	golang.org/x/oauth2 v0.0.0-20220411215720-9780585627b5
)
