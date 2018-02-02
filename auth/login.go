package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"pebble-dev/rebble-auth/common"
	"pebble-dev/rebble-auth/db"
	"pebble-dev/rebble-auth/rebbleJwt"
	"pebble-dev/rebble-auth/sso"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
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

// This is the response from the exchange of the authorization code for access and ID tokens
type facebookTokensStatus struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`

	Error facebookError `json:"error"`
}

type facebookTokenInformation struct {
	UserID string `json:"id"`
	Name   string `json:"name"`

	Error facebookError `json:"error"`
}

type facebookError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    int    `json:"code"`
	Trace   string `json:"fbtrace_id"`
}

type fitbitTokensStatus struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`

	Success bool          `json:"success"`
	Errors  []fitbitError `json:"errors"`
}

type fitbitTokenInformation struct {
	Active int            `json:"active"`
	UserID fitbitClientID `json:"userId"`
	Exp    int64          `json:"exp"`
}

type fitbitClientID struct {
	ID string `json:"id"`
}

type fitbitUserInformation struct {
	User fitbitUser `json:"user"`

	Errors []fitbitError `json:"error"`
}

type fitbitUser struct {
	DisplayName string `json:"displayName"`
}

type fitbitError struct {
	Type    string `json:"errorType`
	Message string `json:"message"`
}

func exchangeTokens(sso sso.Sso, code string) (bool, string, tokensStatus, jwt.MapClaims, error) {
	switch sso.Type {
	case "oidc":
		v := url.Values{}
		v.Add("code", code)
		v.Add("client_id", sso.ClientID)
		v.Add("client_secret", sso.ClientSecret)
		v.Add("redirect_uri", sso.RedirectURI)
		v.Add("grant_type", "authorization_code")
		var status tokensStatus
		err := common.Post(sso.Discovery.TokenEndpoint, &v, "", &status)
		if err != nil {
			return false, fmt.Sprintf("Internal server error: Could not exchange tokens: %v", err), tokensStatus{}, nil, err
		}

		if status.Error != "" {
			return false, "Internal server error: Could not exchange tokens", status, nil, fmt.Errorf("Could not exchange tokens: %v (%v)", status.Error, status.ErrorDescription)
		}

		claims, err := rebbleJwt.ParseJwtToken(sso, status.IdToken)
		if err != nil {
			return false, "Internal server error: Could not decode token information", status, nil, err
		}

		return true, "", status, claims, nil
	case "facebook":
		v := url.Values{}
		v.Add("code", code)
		v.Add("client_id", sso.ClientID)
		v.Add("client_secret", sso.ClientSecret)
		v.Add("redirect_uri", sso.RedirectURI)

		var status facebookTokensStatus
		err := common.Post(sso.Discovery.TokenEndpoint, &v, "", &status)
		if err != nil {
			return false, fmt.Sprintf("Internal server error: Could not exchange tokens: %v", err), tokensStatus{}, nil, err
		}
		if status.Error.Message != "" {
			return false, "Internal server error: Could not exchange tokens", tokensStatus{}, nil, fmt.Errorf("Could not exchange tokens: %v (%v %v)", status.Error.Message, status.Error.Type, status.Error.Code)
		}

		// Get token information
		v = url.Values{}
		v.Add("access_token", status.AccessToken)
		v.Add("fields", "id,name")
		var info facebookTokenInformation
		err = common.Get(sso.Discovery.UserinfoEndpoint, &v, "", &info)
		if err != nil {
			return false, fmt.Sprintf("Internal server error: Could not get token information: %v", err), tokensStatus{}, nil, err
		}
		if info.Error.Message != "" || info.UserID == "" {
			return false, "Internal server error: Could not get token information", tokensStatus{}, nil, fmt.Errorf("Could not get token information: %v (%v %v)", info.Error.Message, info.Error.Type, info.Error.Code)
		}

		claims := jwt.MapClaims{
			"sub":  info.UserID,
			"exp":  float64(time.Now().Unix() + int64(status.ExpiresIn)),
			"name": info.Name,
		}

		return true, "", tokensStatus{
			AccessToken:      status.AccessToken,
			RefreshToken:     status.RefreshToken,
			ExpiresIn:        status.ExpiresIn,
			Error:            status.Error.Message,
			ErrorDescription: status.Error.Message,
		}, claims, nil

	case "fitbit":
		bearer := "Basic " + base64.URLEncoding.EncodeToString([]byte(sso.ClientID+":"+sso.ClientSecret))

		v := url.Values{}
		v.Add("code", code)
		v.Add("clientId", sso.ClientID)
		v.Add("redirect_uri", sso.RedirectURI)
		v.Add("grant_type", "authorization_code")

		var status fitbitTokensStatus
		err := common.Post(sso.Discovery.TokenEndpoint, &v, bearer, &status)
		if err != nil {
			return false, fmt.Sprintf("Internal server error: Could not exchange tokens: %v", err), tokensStatus{}, nil, err
		}
		if len(status.Errors) != 0 {
			return false, "Internal server error: Could not exchange tokens", tokensStatus{}, nil, fmt.Errorf("Could not exchange tokens: %v", status.Errors)
		}

		// Get token information
		v = url.Values{}
		v.Add("access_token", status.AccessToken)
		v.Add("fields", "id,name")
		var user fitbitUserInformation
		err = common.Get(sso.Discovery.UserinfoEndpoint, &v, bearer, &user)
		if err != nil {
			return false, fmt.Sprintf("Internal server error: Could not get user information: %v", err), tokensStatus{}, nil, err
		}
		if len(user.Errors) != 0 {
			return false, "Internal server error: Could not get user information", tokensStatus{}, nil, fmt.Errorf("Could not get user information: %v", user.Errors)
		}

		// Get user ID
		v = url.Values{}
		v.Add("token", status.AccessToken)
		var info fitbitTokenInformation
		err = common.Post(sso.Discovery.TokenInfoEndpoint, &v, bearer, &info)
		if err != nil {
			return false, fmt.Sprintf("Internal server error: Could not get token information: %v", err), tokensStatus{}, nil, err
		}
		if info.Active != 1 {
			return false, fmt.Sprintf("Internal server error: Could not get token information: inactive"), tokensStatus{}, nil, errors.New("Token inactive")
		}

		claims := jwt.MapClaims{
			"sub":  info.UserID.ID,
			"exp":  float64(info.Exp / 1000),
			"name": user.User.DisplayName,
		}

		return true, "", tokensStatus{
			AccessToken:      status.AccessToken,
			RefreshToken:     status.RefreshToken,
			ExpiresIn:        status.ExpiresIn,
			Error:            "",
			ErrorDescription: "",
		}, claims, nil
	}
	return false, fmt.Sprintf("Internal server error: Invalid SSO provider type %v", sso.Type), tokensStatus{}, nil, fmt.Errorf("Invalid SSO provider type %v", sso.Type)
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

	success, errorMessage, status, claims, err := exchangeTokens(sso, code)

	if !success {
		return false, errorMessage, "", err
	}

	var name string
	if n, ok := claims["name"]; ok {
		name = n.(string)
	}

	accessToken, userErr, err := database.AccountLoginOrRegister(sso.Name, claims["sub"].(string), name, status.AccessToken, status.RefreshToken, int64(claims["exp"].(float64)), remoteAddr)
	if err != nil {
		return false, userErr, "", err
	}

	return true, userErr, accessToken, nil
}

// AddProvider attempts to add a provider to a user's account given an auth provider and a corresponding code
// Returns success, errorMessage, err
// err is only returned if the error was unexpected (internal server error vs bad request)
func AddProvider(ssos []sso.Sso, database *db.Handler, authProvider string, code string, rebbleAccessToken string, remoteAddr string) (bool, string, error) {
	var sso sso.Sso
	foundSso := false
	for _, s := range ssos {
		if s.Name == authProvider {
			sso = s
			foundSso = true
		}
	}

	if !foundSso {
		return false, "Invalid SSO provider", nil
	}

	// This would normally be handled by the AccountAddProvider function, but we don't want to exchange tokens if we aren't going to store them
	loggedIn, _, err := database.AccountInformation(rebbleAccessToken)
	if !loggedIn {
		return false, "Invalid access token", err
	}

	success, errorMessage, status, claims, err := exchangeTokens(sso, code)

	if !success {
		return false, errorMessage, err
	}

	userErr, err := database.AccountAddProvider(sso.Name, claims["sub"].(string), rebbleAccessToken, status.AccessToken, status.RefreshToken, int64(claims["exp"].(float64)), remoteAddr)
	if err != nil {
		return false, userErr, err
	}

	return true, userErr, nil
}
