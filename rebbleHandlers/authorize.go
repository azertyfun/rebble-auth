package rebbleHandlers

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"pebble-dev/rebble-auth/auth"
	"pebble-dev/rebble-auth/common"
	"pebble-dev/rebble-auth/sso"

	"github.com/gorilla/mux"
)

func authorizationFail(message string, redirectURI string, err error, w *http.ResponseWriter, r *http.Request) error {
	http.Redirect(*w, r, redirectURI+"?error="+message, http.StatusFound)

	log.Println(err)

	return nil
}

// AuthorizeHandler provides the authorization page directly shown to the user
func AuthorizeHandler(ctx *HandlerContext, w http.ResponseWriter, r *http.Request) (int, error) {
	urlquery := r.URL.Query()

	callback := ""
	if c, ok := urlquery["redirect_uri"]; !ok {
		if len(c) != 1 {
			fmt.Fprintln(w, "Too many/few values for redirect_uri query parameter")
			return http.StatusBadRequest, nil
		}
	} else {
		callback = c[0]
	}

	rebbleState := ""
	if s, ok := urlquery["state"]; !ok {
		if len(s) != 1 {
			fmt.Fprintln(w, "Too many/few values for state query parameter")
			return http.StatusBadRequest, nil
		}
	} else {
		rebbleState = s[0]
	}

	accessToken := ""
	if t, ok := urlquery["access_token"]; ok {
		if len(t) > 1 {
			fmt.Fprintln(w, "Too many values for access_token query parameter")
			return http.StatusBadRequest, nil
		} else if len(t) == 1 {
			accessToken = t[0]
		}
	}

	addProvider := false
	if n, ok := urlquery["addProvider"]; ok {
		if len(n) > 1 {
			fmt.Fprintln(w, "Too many values for addProvider query parameter")
			return http.StatusBadRequest, nil
		} else if len(n) == 1 {
			addProvider = true
		}
	}

	if (accessToken != "" || addProvider) && !(accessToken != "" && addProvider) {
		fmt.Println(w, "Can't have `access_token` without `addProvider` query parameters")
		return http.StatusBadRequest, nil
	}

	data, err := ioutil.ReadFile("static/authorize.html")
	if err != nil {
		return http.StatusInternalServerError, err
	}

	nonce := common.GenerateString(20)
	state := common.GenerateString(50)

	// We want the callback to know what the redirect URI is, as well as the rebble `state` parameter. So, we encode the state to contain a random indentifier (to prevent cross-site forgery), a delimiter (|), the base-64 encoded callback URI, another delimiter, and the rebble state
	// The base64 encoding makes it safe to be used as a URL query parameter
	state += "|" + base64.URLEncoding.EncodeToString([]byte(callback)) + "|" + base64.URLEncoding.EncodeToString([]byte(rebbleState))

	if accessToken != "" && addProvider {
		state += "|" + accessToken
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "state",
		Value:   state,
		Expires: time.Now().Add(time.Minute).Add(time.Minute),
	})

	dataFormatted := string(data)
	dataFormatted = strings.Replace(dataFormatted, "{{nonce}}", nonce, -1)
	dataFormatted = strings.Replace(dataFormatted, "{{state}}", state, -1)
	for _, s := range ctx.SSos {
		dataFormatted = strings.Replace(dataFormatted, "{{"+s.Name+"_authorization_endpoint}}", s.Discovery.AuthorizationEndpoint, -1)
		dataFormatted = strings.Replace(dataFormatted, "{{"+s.Name+"_client_id}}", s.ClientID, -1)
		dataFormatted = strings.Replace(dataFormatted, "{{"+s.Name+"_redirect_uri}}", s.RedirectURI, -1)
		dataFormatted = strings.Replace(dataFormatted, "{{"+s.Name+"_scopes}}", s.Scopes, -1)
	}

	fmt.Fprintf(w, dataFormatted)

	return http.StatusOK, nil
}

// AuthorizeCallbackHandler is the callback for external OAuth authentication
func AuthorizeCallbackHandler(ctx *HandlerContext, w http.ResponseWriter, r *http.Request) (int, error) {
	urlquery := r.URL.Query()

	var state string
	if s, ok := urlquery["state"]; ok {
		if len(s) != 1 {
			fmt.Fprintln(w, "Multiple values for 'state'")
			return http.StatusBadRequest, nil
		}
		state = s[0]
	} else {
		fmt.Fprintln(w, "Missing query element: state")
		return http.StatusBadRequest, nil
	}

	state2 := strings.Split(state, "|")
	if len(state2) < 3 || len(state2) > 4 {
		fmt.Fprintf(w, "Invalid state: %v", state)
		return http.StatusBadRequest, nil
	}
	addProvider := len(state2) == 4
	rebbleAccessToken := ""
	if addProvider {
		rebbleAccessToken = state2[3]
	}

	redirectURIb, err := base64.URLEncoding.DecodeString(state2[1])
	if err != nil {
		fmt.Fprintf(w, "Invalid base64 encoded redirect_uri: %v", state2[1])
		return http.StatusBadRequest, nil
	}
	redirectURI := string(redirectURIb)

	rebbleStateb, err := base64.URLEncoding.DecodeString(state2[2])
	if err != nil {
		fmt.Fprintf(w, "Invalid base64 encoded state: %v", state2[2])
		return http.StatusBadRequest, nil
	}
	rebbleState := string(rebbleStateb)

	provider := mux.Vars(r)["provider"]

	legitProvider := false
	var sso sso.Sso
	for _, s := range ctx.SSos {
		if s.Name == provider {
			legitProvider = true
			sso = s
		}
	}

	if !legitProvider {
		return http.StatusFound, authorizationFail(fmt.Sprintf("Invalid provider: %v", provider), redirectURI, nil, &w, r)
	}

	var code string
	if c, ok := urlquery["code"]; ok {
		if len(c) != 1 {
			return http.StatusFound, authorizationFail("Multiple values for 'code'", redirectURI, nil, &w, r)
		}
		code = c[0]
	} else {
		return http.StatusFound, authorizationFail("Missing query element: code", redirectURI, nil, &w, r)
	}

	stateCookie, err := r.Cookie("state")
	if err != nil {
		return http.StatusFound, authorizationFail("Missing cookie: state", redirectURI, nil, &w, r)
	}

	if state != stateCookie.Value {
		return http.StatusFound, authorizationFail(fmt.Sprintf("Invalid state: expected %v, got %v", stateCookie.Value, state), redirectURI, nil, &w, r)
	}

	if addProvider {
		success, errorMessage, err := auth.AddProvider(ctx.SSos, ctx.Database, sso.Name, code, rebbleAccessToken, r.RemoteAddr)

		if err != nil {
			log.Println(err)
		}

		if success {
			http.Redirect(w, r, redirectURI+"?success", http.StatusFound)
		} else {
			http.Redirect(w, r, redirectURI+"?error="+errorMessage, http.StatusFound)
		}
	} else {
		success, errorMessage, accessToken, err := auth.Login(ctx.SSos, ctx.Database, sso.Name, code, r.RemoteAddr)

		if err != nil {
			log.Println(err)
		}

		if success {
			http.Redirect(w, r, redirectURI+"?access_token="+accessToken+"&state="+rebbleState, http.StatusFound)
		} else {
			http.Redirect(w, r, redirectURI+"?error="+errorMessage, http.StatusFound)
		}
	}

	return http.StatusFound, nil
}
