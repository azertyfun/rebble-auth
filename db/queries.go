package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nu7hatch/gouuid"

	"pebble-dev/rebble-auth/common"
)

// Handler contains reference to the database client
type Handler struct {
	*sql.DB
}

func addProvider(tx *sql.Tx, provider string, sub string, userId string, ssoAccessToken string, ssoRefreshToken string, expires int64) error {
	count := 0
	row := tx.QueryRow("SELECT COUNT(*) FROM providerSessions WHERE provider=? AND sub=?", provider, sub)
	err := row.Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		_, err = tx.Exec("INSERT INTO providerSessions(userId, provider, sub, accessToken, refreshToken, expires) VALUES (?, ?, ?, ?, ?, ?)", userId, provider, sub, ssoAccessToken, ssoRefreshToken, expires)
		if err != nil {
			return err
		}
	} else if count == 1 {
		_, err = tx.Exec("UPDATE providerSessions SET accessToken=?, refreshToken=?, expires=? WHERE provider=? AND sub=?", ssoAccessToken, ssoRefreshToken, expires, provider, sub)
		if err != nil {
			return err
		}
	} else {
		return errors.New("Found multiple instances of provider session for one user")
	}

	return nil
}

func createSession(tx *sql.Tx, provider string, sub string, userId string, ssoAccessToken string, ssoRefreshToken string, expires int64) (string, error) {
	accessToken := common.GenerateString(50)

	_, err := tx.Exec("INSERT INTO userSessions(userId, accessToken) VALUES (?, ?)", userId, accessToken)
	if err != nil {
		return "", err
	}

	err = addProvider(tx, provider, sub, userId, ssoAccessToken, ssoRefreshToken, expires)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

// AccountLoginOrRegister attempts to login (or, if the user doesn't yet exist, create a user account)
// Returns accessToken, errorMessage, error
func (handler Handler) AccountLoginOrRegister(provider string, sub string, name string, email string, ssoAccessToken string, ssoRefreshToken string, expires int64, remoteIp string) (string, string, error) {
	tx, err := handler.DB.Begin()
	if err != nil {
		return "", "Internal server error", err
	}
	defer tx.Rollback()

	row := tx.QueryRow("SELECT users.id, users.disabled FROM providerSessions JOIN users ON users.id = providerSessions.userId WHERE providerSessions.provider=? AND providerSessions.sub=?", provider, sub)

	var userId string
	disabled := false
	err = row.Scan(&userId, &disabled)
	if err != nil && err != sql.ErrNoRows {
		return "", "Internal server error", err
	}

	if err != nil {
		// User doesn't exist, create account

		for {
			id, err := uuid.NewV4()
			if err != nil {
				return "", "Internal server error", err
			}
			userId = strings.Replace(id.String(), "-", "", -1)

			row = tx.QueryRow("SELECT id FROM users WHERE id=?", userId)
			if err := row.Scan(); err != nil {
				if err == sql.ErrNoRows {
					break
				} else {
					return "", "Internal server error", err
				}
			}
		}

		if name == "" {
			name = userId
		}

		// Create user
		_, err := tx.Exec("INSERT INTO users(id, name, email, type, pebbleMirror, disabled) VALUES (?, ?, ?, 'user', 0, 0)", userId, name, email)
		if err != nil {
			return "", "Internal server error", err
		}
	}

	if disabled {
		return "", "Account is disabled", errors.New("cannot login; account is disabled")
	}

	// Create user session

	accessToken, err := createSession(tx, provider, sub, userId, ssoAccessToken, ssoRefreshToken, expires)
	if err != nil {
		return "", "Internal server error", err
	}

	// Log successful login attempt
	_, err = tx.Exec("INSERT INTO userLoginLog(userId, remoteIp, time, success) VALUES (?, ?, ?, 1)", userId, remoteIp, time.Now().UnixNano())
	if err != nil {
		return "", "Internal server error", err
	}

	tx.Commit()

	return accessToken, "", nil
}

// AccountAddProvider attempts to add a provider to a user's account
// Returns errorMessage, error
func (handler Handler) AccountAddProvider(provider string, sub string, rebbleAccessToken string, ssoAccessToken string, ssoRefreshToken string, expires int64, remoteIp string) (string, error) {
	tx, err := handler.DB.Begin()
	if err != nil {
		return "Internal server error", err
	}
	defer tx.Rollback()

	loggedIn, _, _, _, err := handler.AccountInformation(rebbleAccessToken)
	if !loggedIn {
		return "Invalid access token", err
	}

	row := tx.QueryRow("SELECT users.id, users.disabled FROM userSessions JOIN users ON users.id = userSessions.userId WHERE accessToken=?", rebbleAccessToken)

	var userId string
	disabled := false
	err = row.Scan(&userId, &disabled)
	if err != nil && err != sql.ErrNoRows {
		if err == sql.ErrNoRows {
			return "User doesn't exist", nil
		}

		return "Internal server error", err
	}

	if disabled {
		return "Account is disabled", errors.New("cannot login; account is disabled")
	}

	err = addProvider(tx, provider, sub, userId, ssoAccessToken, ssoRefreshToken, expires)
	if err != nil {
		return "Internal server error", err
	}

	tx.Commit()

	return "", nil
}

// AccountRemoveProvider attempts to remove a provider from a user's account
// Returns errorMessage, error
func (handler Handler) AccountRemoveProvider(provider string, rebbleAccessToken string) (string, error) {
	tx, err := handler.DB.Begin()
	if err != nil {
		return "Internal server error", err
	}
	defer tx.Rollback()

	count := 0
	row := tx.QueryRow("SELECT COUNT(*) FROM providerSessions WHERE userId = (SELECT userId FROM userSessions WHERE accessToken=?)", rebbleAccessToken)
	err = row.Scan(&count)
	if err != nil {
		return "", err
	}

	if count == 1 {
		return "Can't remove last identity provider!", errors.New("Can't remove last identity provider")
	}

	loggedIn, _, _, _, err := handler.AccountInformation(rebbleAccessToken)
	if !loggedIn {
		return "Invalid access token", err
	}

	_, err = tx.Exec("DELETE FROM providerSessions WHERE providerSessions.userId = (SELECT userId FROM userSessions WHERE accessToken=?) AND provider=?", rebbleAccessToken, provider)

	tx.Commit()

	return "", nil
}

// AccountExists checks if an account exists
func (handler Handler) AccountExists(provider string, sub string) (bool, error) {
	var userId string
	row := handler.DB.QueryRow("SELECT id FROM users WHERE provider=? AND sub=?", provider, sub)
	err := row.Scan(&userId)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

func (handler Handler) getAccountId(accessToken string) (string, error) {
	var userId string
	row := handler.DB.QueryRow("SELECT userId FROM userSessions WHERE accessToken=?", accessToken)
	err := row.Scan(&userId)
	if err != nil {
		return "", err
	}

	return userId, nil
}

// AccountInformation returns information about the account associated to the given access token
// returns success, name, email, providers, err
func (handler Handler) AccountInformation(accessToken string) (bool, string, string, []string, error) {
	userId, err := handler.getAccountId(accessToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, "", "", []string{}, nil
		}

		return false, "", "", []string{}, err
	}

	var name string
	var email string
	row := handler.DB.QueryRow("SELECT name, email FROM users WHERE id=?", userId)
	err = row.Scan(&name, &email)
	if err != nil {
		return false, "", "", []string{}, err
	}

	var linkedProviders []string
	rows, err := handler.DB.Query("SELECT provider FROM providerSessions WHERE userid=?", userId)
	if err != nil {
		return false, "", "", []string{}, err
	}

	for rows.Next() {
		provider := ""
		err := rows.Scan(&provider)
		if err != nil {
			return false, "", "", []string{}, err
		}
		linkedProviders = append(linkedProviders, provider)
	}

	if name == "" {
		return true, userId, email, linkedProviders, nil
	}

	return true, name, email, linkedProviders, nil
}

// SessionInformation returns (loggedIn bool, errMessage string, err error) about the current user session
func (handler Handler) SessionInformation(accessToken string) (bool, string, error) {
	userId, err := handler.getAccountId(accessToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, "Invalid session", nil
		}

		return false, "Internal server error", err
	}

	var disabled bool
	rows, err := handler.DB.Query("SELECT users.disabled FROM userSessions JOIN users ON users.id = userSessions.userId WHERE users.id=? AND userSessions.accessToken=?", userId, accessToken)
	if err != nil {
		return false, "Internal server error", err
	}
	sessionFound := false
	for rows.Next() {
		sessionFound = true
		err = rows.Scan(&disabled)
		if err != nil {
			return false, "Internal server error", err
		}
	}

	if !sessionFound {
		return false, "Session not found (expired?)", nil
	}

	return true, "", nil
}

// UpdateName updates a user's name and returns a human-readable error as well as an actual error
func (handler Handler) UpdateName(accessToken string, name string) (string, error) {
	userId, err := handler.getAccountId(accessToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return "Invalid access token", errors.New("Invalid access token")
		}

		return "Internal server error", err
	}

	loggedIn, errorMessage, err := handler.SessionInformation(accessToken)
	if !loggedIn {
		if err != nil {
			return fmt.Sprintf("Internal Server Error: %v", errorMessage), err
		}

		return errorMessage, nil
	}

	tx, err := handler.DB.Begin()
	if err != nil {
		return "Internal server error", err
	}
	defer tx.Rollback()

	tx.Exec("UPDATE users SET name=? WHERE id=?", name, userId)
	if err != nil {
		return "Internal server error", err
	}

	err = tx.Commit()
	if err != nil {
		return "Internal server error", err
	}

	return "", nil
}

// GetName returns (name bool, errMessage string, err error) about the user's name for the given id
func (handler Handler) GetName(id string) (string, string, error) {
	var name string
	row := handler.DB.QueryRow("SELECT name FROM users WHERE id=?", id)
	err := row.Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "No user with this ID", nil
		}
		return "", "Internal Server Error", err
	}

	return name, "", nil
}
