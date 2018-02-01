package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"pebble-dev/rebble-auth/db"
	"pebble-dev/rebble-auth/rebbleJwt"
	"pebble-dev/rebble-auth/sso"
	"strings"
)

// This is the response from the exchange of the authorization code for access and ID tokens
type tokensStatus struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Login attempts to log a user in given an auth provider and a corresponding code
// Returns success, errorMessage, accessToken, err
// err is only returned if the error was unexpected (internal server error vs bad request)
func Login(ssos []sso.Sso, database *db.Handler, authProvider string, code string, remoteAddr string) (bool, string, string, error) {
	var sso sso.Sso
	foundSso := false
	for _, s := range ssos {
		if s.Name == authProvider {
			sso = s
			foundSso = true
		}
	}

	if !foundSso {
		return false, "Invalid SSO provider", "", nil
	}

	v := url.Values{}
	v.Add("code", code)
	v.Add("client_id", sso.ClientID)
	v.Add("client_secret", sso.ClientSecret)
	v.Add("redirect_uri", sso.RedirectURI)
	v.Add("grant_type", "authorization_code")
	resp, err := http.Post(sso.Discovery.TokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(v.Encode()))
	if err != nil {
		return false, "Internal server error: Could not exchange tokens", "", err
	}

	decoder := json.NewDecoder(resp.Body)
	var tokensStatus tokensStatus
	err = decoder.Decode(&tokensStatus)
	if err != nil {
		return false, "Internal server error: Could not decode token information", "", err
	}
	defer resp.Body.Close()

	if tokensStatus.Error != "" {
		return false, "Internal server error: Could not exchange tokens", "", fmt.Errorf("Could not exchange tokens: %v (%v)", tokensStatus.Error, tokensStatus.ErrorDescription)
	}

	claims, err := rebbleJwt.ParseJwtToken(sso, tokensStatus.IdToken)
	if err != nil {
		return false, "Internal server error: Could not decode token information", "", err
	}

	var name string
	if n, ok := claims["name"]; ok {
		name = n.(string)
	}

	accessToken, userErr, err := database.AccountLoginOrRegister(sso.Name, claims["sub"].(string), name, tokensStatus.AccessToken, tokensStatus.RefreshToken, int64(claims["exp"].(float64)), remoteAddr)
	if err != nil {
		return false, userErr, "", err
	}

	return true, userErr, accessToken, nil
}
