package rebbleHandlers

import (
	"encoding/json"
	"log"
	"net/http"
	"pebble-dev/rebble-auth/auth"
)

type accountLogin struct {
	Code         string `json:"code"`
	AuthProvider string `json:"authProvider"`
}

type accountLoginStatus struct {
	AccessToken  string `json:"accessToken"`
	Success      bool   `json:"success"`
	ErrorMessage string `json:"errorMessage"`
}

type updateAccount struct {
	AccessToken string `json:"accessToken"`
	Name        string `json:"name"`
}

type updateAccountStatus struct {
	Success      bool   `json:"success"`
	ErrorMessage string `json:"errorMessage"`
}

type authInfo struct {
	AccessToken string `json:"accessToken"`
}

type accountInfo struct {
	LoggedIn     bool   `json:"loggedIn"`
	Name         string `json:"name"`
	ErrorMessage string `json:"errorMessage"`
}

func accountLoginFail(message string, err error, w *http.ResponseWriter) error {
	status := accountLoginStatus{
		Success:      false,
		ErrorMessage: message,
	}

	data, e := json.MarshalIndent(status, "", "\t")
	if e != nil {
		return e
	}

	// Send the JSON object back to the user
	(*w).Header().Add("content-type", "application/json")
	(*w).Write(data)

	log.Println(err)

	return nil
}

// AccountLoginHandler handles the login of a user
func AccountLoginHandler(ctx *HandlerContext, w http.ResponseWriter, r *http.Request) (int, error) {
	decoder := json.NewDecoder(r.Body)

	var loginInformation accountLogin
	err := decoder.Decode(&loginInformation)
	if err != nil {
		return http.StatusBadRequest, accountLoginFail("Internal server error: Server could not parse message", err, &w)
	}
	defer r.Body.Close()

	success, errorMessage, accessToken, err := auth.Login(ctx.SSos, ctx.Database, loginInformation.AuthProvider, loginInformation.Code, r.RemoteAddr)

	if err != nil {
		return http.StatusInternalServerError, accountLoginFail("Internal server error: "+errorMessage, err, &w)
	}

	status := accountLoginStatus{
		Success:      success,
		ErrorMessage: errorMessage,
		AccessToken:  accessToken,
	}
	data, err := json.MarshalIndent(status, "", "\t")
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Send the JSON object back to the user
	w.Header().Add("content-type", "application/json")
	w.Write(data)
	return http.StatusOK, nil
}

// AccountInfoHandler displays the account information for a given Session Key
func AccountInfoHandler(ctx *HandlerContext, w http.ResponseWriter, r *http.Request) (int, error) {
	decoder := json.NewDecoder(r.Body)

	var authInfo authInfo
	err := decoder.Decode(&authInfo)
	if err != nil {
		return http.StatusBadRequest, err
	}
	defer r.Body.Close()

	loggedIn, errorMessage, name, err := auth.Info(ctx.Database, authInfo.AccessToken)

	if err != nil {
		log.Println(err)
	}

	info := accountInfo{
		LoggedIn:     loggedIn,
		Name:         name,
		ErrorMessage: errorMessage,
	}
	data, err := json.MarshalIndent(info, "", "\t")
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Send the JSON object back to the user
	w.Header().Add("content-type", "application/json")
	w.Write(data)
	return http.StatusOK, nil
}

// AccountUpdateNameHandler updates a user's real name
func AccountUpdateNameHandler(ctx *HandlerContext, w http.ResponseWriter, r *http.Request) (int, error) {
	decoder := json.NewDecoder(r.Body)

	var info updateAccount
	err := decoder.Decode(&info)
	if err != nil {
		return http.StatusBadRequest, err
	}
	defer r.Body.Close()

	success, errorMessage, err := auth.UpdateName(ctx.Database, info.AccessToken, info.Name)

	if err != nil {
		log.Println(err)
	}

	status := updateAccountStatus{
		Success:      success,
		ErrorMessage: errorMessage,
	}
	data, err := json.MarshalIndent(status, "", "\t")
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Send the JSON object back to the user
	w.Header().Add("content-type", "application/json")
	w.Write(data)
	return http.StatusOK, nil
}
