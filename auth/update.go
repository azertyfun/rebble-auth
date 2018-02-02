package auth

import (
	"pebble-dev/rebble-auth/db"
)

// UpdateName changes the name of a logged in user
// Returns success, errorMessage, err
// err is only returned if the error was unexpected (internal server error vs bad request)
func UpdateName(database *db.Handler, accessToken string, name string) (bool, string, error) {
	loggedIn, errorMessage, err := database.SessionInformation(accessToken)
	if err != nil {
		return false, "Internal server error: Could not query session information", err
	}

	if !loggedIn {
		return false, "Not logged in", nil
	}

	if name == "" {
		return false, "Name can't be empty", nil
	}

	errorMessage, err = database.UpdateName(accessToken, name)
	if err != nil {
		return false, "Internal server error: Could not update name", err
	}

	return true, errorMessage, err
}

// RemoveLinkedProvider removes a linked identity provider from a user's account
// Returns success, errorMessage, err
// err is only returned if the error was unexpected (internal server error vs bad request)
func RemoveLinkedProvider(database *db.Handler, accessToken string, provider string) (bool, string, error) {
	loggedIn, errorMessage, err := database.SessionInformation(accessToken)
	if err != nil {
		return false, "Internal server error: Could not query session information", err
	}

	if !loggedIn {
		return false, "Not logged in", nil
	}

	errorMessage, err = database.AccountRemoveProvider(provider, accessToken)
	if err != nil {
		return false, "Internal server error: Could not remove provider", err
	}

	return true, errorMessage, err
}
