package redirect

import (
	"net/http"
)

type RedirectBuilderFn = func(w http.ResponseWriter, r *http.Request, loginURL string)

func DefaultRedirect() func(w http.ResponseWriter, r *http.Request, loginURL string) {
	return func(w http.ResponseWriter, r *http.Request, loginURL string) {
		http.Redirect(w, r, loginURL, http.StatusFound)
	}
}
