package rebbleJwt

import (
	"encoding/json"
	"errors"
	"net/http"
	"pebble-dev/rebble-auth/sso"

	jwt "github.com/dgrijalva/jwt-go"
)

func findKey(targetSso sso.Sso, kid string) (sso.Key, error) {
	foundKey := false
	var key sso.Key
	for _, k := range targetSso.Certs.Keys {
		if k.Kid == kid {
			foundKey = true
			key = k
			break
		}
	}

	if foundKey {
		return key, nil
	}

	return key, errors.New("Key not found")
}

// ParseJwtToken handles the verification and parsing of a given JWT token
func ParseJwtToken(targetSso sso.Sso, encodedToken string) (jwt.MapClaims, error) {
	resp, err := http.Get(targetSso.Discovery.JwksURI)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, err
	}

	token, err := jwt.Parse(encodedToken, func(token *jwt.Token) (interface{}, error) {
		key, err := findKey(targetSso, token.Header["kid"].(string))

		// We didn't found a suitable decryption key, but it might just be because they have been updated (should happen about once a day)
		if err != nil {
			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(&targetSso.Certs)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			key, err = findKey(targetSso, token.Header["kid"].(string))
			if err != nil {
				return nil, errors.New("Could not find suitable decryption key for JWT token")
			}
		}

		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("Expected RSA signing method for JWT token")
		}

		pub, err := key.GetPublicKey()
		if err != nil {
			return nil, err
		}

		return &pub, nil
	})

	if err != nil {
		return nil, err
	}

	return token.Claims.(jwt.MapClaims), nil
}
