package auth

import "pebble-dev/rebble-auth/db"

// Info returns information on the logged in user
// Returns success, errorMessage, name, err
// err is only returned if the error was unexpected (internal server error vs bad request)
func Info(database *db.Handler, accessToken string) (bool, string, string, error) {
	loggedIn, errorMessage, err := database.SessionInformation(accessToken)
	if err != nil {
		return false, "Internal Server Error: Could not query session information from database", "", err
	}

	if !loggedIn {
		return false, errorMessage, "", nil
	}

	loggedIn, name, err := database.AccountInformation(accessToken)
	if err != nil {
		return false, "Internal Server Error: Could not query account information from database", "", err
	}

	return loggedIn, "", name, nil
}
