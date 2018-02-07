package rebbleHandlers

import (
	"log"
	"net/http"

	"pebble-dev/rebble-auth/db"
	"pebble-dev/rebble-auth/sso"
)

// HandlerContext is our struct for storing the data we want to inject in to each handler
// we can also add things like authorization level, user information, templates, etc.
type HandlerContext struct {
	Database *db.Handler
	SSos     []sso.Sso
}

// routeHandler is a struct that implements http.Handler, allowing us to inject a custom context
// and handle things like authorization and errors in a single place
// the handler should always return 2 variables, an integer, corrosponding to an HTTP status code
// and an error object containing whatever error happened (or nil, if no error)
type routeHandler struct {
	context *HandlerContext
	H       func(*HandlerContext, http.ResponseWriter, *http.Request) (int, error)
}

// AllowedDomains contains the list of Rebble-own domains for the Access-Control-Allow-Origin header
var AllowedDomains []string

func (rh routeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Write common headers
	// http://stackoverflow.com/a/24818638
	origin := r.Header.Get("Origin")
	w.Header().Set("Access-Control-Allow-Origin", "null")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST")
	for _, allowedDomain := range AllowedDomains {
		if allowedDomain == origin {
			w.Header().Set("Access-Control-Allow-Origin", allowedDomain)
		}
	}

	// In case of a preflight request caused by the use of an `Authorization` header, we specifically allow it
	// https://developer.mozilla.org/en-US/docs/Glossary/preflight_request
	if r.Method == "OPTIONS" {
		if r.Header.Get("Access-Control-Request-Headers") == "authorization" {
			w.Header().Set("Access-Control-Allow-Headers", "authorization")
			return
		}
		http.Error(w, "Invalid Access-Control-Request-Headers header", http.StatusBadRequest)
	}

	// we can process user verification/auth token parsing and authorization here

	// call the handler function
	status, err := rh.H(rh.context, w, r)

	// if the handler function returns an error, we log the error and send the appropriate error message
	if err != nil {
		log.Printf("HTTP %d: %q", status, err)
		switch status {
		case http.StatusNotFound:
			http.NotFound(w, r)
		case http.StatusInternalServerError:
			http.Error(w, http.StatusText(status), status)
		default:
			http.Error(w, http.StatusText(status), status)
		}
	}
}
