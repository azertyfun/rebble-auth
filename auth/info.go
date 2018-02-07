package auth

import "pebble-dev/rebble-auth/db"

// Info returns information on the logged in user
// Returns success, errorMessage, name, email, linkedProviders, err
// err is only returned if the error was unexpected (internal server error vs bad request)
func Info(database *db.Handler, accessToken string) (bool, string, string, string, []string, error) {
	loggedIn, errorMessage, err := database.SessionInformation(accessToken)
	if err != nil {
		return false, "Internal Server Error: Could not query session information from database", "", "", []string{}, err
	}

	if !loggedIn {
		return false, errorMessage, "", "", []string{}, nil
	}

	loggedIn, name, email, linkedProviders, err := database.AccountInformation(accessToken)
	if err != nil {
		return false, "Internal Server Error: Could not query account information from database", "", "", []string{}, err
	}

	return loggedIn, "", name, email, linkedProviders, nil
}
