package db

import (
	"database/sql"
	"errors"
	"math/rand"
	"time"
)

// Handler contains reference to the database client
type Handler struct {
	*sql.DB
}

func init() {
	// We need to seed the RNG which is used by generateSessionId()
	rand.Seed(time.Now().UnixNano())
}

// generateAccessToken() generates a pseudo-random fixed-length base64 string
func generateAccessToken() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"

	b := make([]byte, 50)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b)
}

func createSession(tx *sql.Tx, userId int, ssoAccessToken string, expires int64) (string, error) {
	accessToken := generateAccessToken()

	// We check that we have no more than 5 active sessions at a time (for security reasons). Otherwise, we delete the oldest one.
	var count int
	row := tx.QueryRow("SELECT count(*) FROM userSessions WHERE userId=?", userId)
	err := row.Scan(&count)
	if err != nil {
		return "", err
	}

	if count >= 5 {
		_, err = tx.Exec("DELETE FROM userSessions WHERE accessToken=(SELECT accessToken FROM userSessions WHERE userId=? ORDER BY expires ASC LIMIT 1)", userId)
		if err != nil {
			return "", err
		}
	}

	_, err = tx.Exec("INSERT INTO userSessions(accessToken, ssoAccessToken, userId, expires) VALUES (?, ?, ?, ?)", accessToken, ssoAccessToken, userId, expires)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

// AccountLoginOrRegister attempts to login (or, if the user doesn't yet exist, create a user account), and returns a user friendly error as well as an actual error (as not to display SQL statements to the user for example).
func (handler Handler) AccountLoginOrRegister(provider string, sub string, name string, ssoAccessToken string, expires int64, remoteIp string) (string, string, error) {
	tx, err := handler.DB.Begin()
	if err != nil {
		return "", "Internal server error", err
	}
	defer tx.Rollback()

	row := tx.QueryRow("SELECT id, disabled FROM users WHERE provider=? AND sub=?", provider, sub)

	var userId int64
	disabled := false
	err = row.Scan(&userId, &disabled)
	if err != nil {
		// User doesn't exist, create account

		// Create user
		res, err := tx.Exec("INSERT INTO users(provider, sub, name, pebbleMirror, disabled) VALUES (?, ?, ?, 0, 0)", provider, sub, name)
		if err != nil {
			return "", "Internal server error", err
		}
		userId, err = res.LastInsertId()
		if err != nil {
			return "", "Internal server error", err
		}
	}

	if disabled {
		return "", "Account is disabled", errors.New("cannot login; account is disabled")
	}

	// Create user session

	accessToken, err := createSession(tx, int(userId), ssoAccessToken, expires)
	if err != nil {
		return "", "Internal server error", err
	}

	// Log successful login attempt
	_, err = tx.Exec("INSERT INTO userLogins(userId, remoteIp, time, success) VALUES (?, ?, ?, 1)", userId, remoteIp, time.Now().UnixNano())
	if err != nil {
		return "", "Internal server error", err
	}

	tx.Commit()

	return accessToken, "", nil
}

// AccountExists checks if an account exists
func (handler Handler) AccountExists(provider string, sub string) (bool, error) {
	var userId int
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

func (handler Handler) getAccountId(accessToken string) (int, error) {
	var userId int
	row := handler.DB.QueryRow("SELECT userId FROM userSessions WHERE accessToken=?", accessToken)
	err := row.Scan(&userId)
	if err != nil {
		return 0, err
	}

	return userId, nil
}

// AccountInformation returns information about the account associated to the given access token
func (handler Handler) AccountInformation(accessToken string) (bool, string, error) {
	userId, err := handler.getAccountId(accessToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, "", nil
		}

		return false, "", err
	}

	var name, provider, sub string
	row := handler.DB.QueryRow("SELECT name, provider, sub FROM users WHERE id=?", userId)
	err = row.Scan(&name, &provider, &sub)
	if err != nil {
		return false, "", err
	}

	if name == "" {
		return true, provider + "_" + sub, nil
	}

	return true, name, nil
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

	var ssoAccessToken string
	var expires int64
	var provider string
	rows, err := handler.DB.Query("SELECT userSessions.ssoAccessToken, userSessions.expires, users.provider FROM userSessions JOIN users ON users.id = userSessions.userId WHERE users.id=?", userId)
	if err != nil {
		return false, "Internal server error", err
	}
	sessionFound := false
	sessionExpired := false
	for rows.Next() {
		sessionFound = true
		err = rows.Scan(&ssoAccessToken, &expires, &provider)
		if err != nil {
			return false, "Internal server error", err
		}

		if time.Now().Unix() > expires {
			sessionExpired = true
			continue
		}
	}

	if !sessionFound || sessionExpired {
		return false, "Session expired", nil
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