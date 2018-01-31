package rebbleHandlers

import (
	"encoding/json"
	"log"
	"net/http"
	"pebble-dev/rebble-auth/auth"

	"github.com/gorilla/mux"
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

type nameStatus struct {
	Name         string `json:"name"`
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

// AccountInfoHandler displays the account information for a given access token
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

// AccountGetnameHandler returns a user's name
func AccountGetNameHandler(ctx *HandlerContext, w http.ResponseWriter, r *http.Request) (int, error) {
	name, errorMessage, err := ctx.Database.GetName(mux.Vars(r)["id"])

	if err != nil {
		log.Println(err)
	}

	status := nameStatus{
		Name:         name,
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
