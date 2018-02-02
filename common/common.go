package common

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

var (
	Buildstamp         string = "Unknown build timestamp"
	Buildgithash       string = "Unknown git hash"
	Buildhost          string = "Unknown build host"
	Buildversionstring string = "0.0.1"
)

// GenerateString generates a cryptographically random string made of at most 64 different characters
func GenerateString(length uint) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"

	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(fmt.Errorf("Could not generate random number: %v", err))
		}
		b[i] = letters[n.Int64()]
	}

	return string(b)
}

func decode(resp *http.Response, err error, out interface{}) error {
	if err != nil {
		return fmt.Errorf("Could not POST to remote server: %v", err)
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(out)
	if err != nil {
		return fmt.Errorf("Could not decode JSON information: %v", err)
	}

	return nil
}

// Post POSTs url-encoded values and saves the output to the corresponding json
// authorization is optional, is used for APIs that use the Authorization header instead of a `clientSecret` query parameter
func Post(uri string, values *url.Values, authorization string, out interface{}) error {
	client := &http.Client{}
	req, err := http.NewRequest("POST", uri, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := client.Do(req)

	return decode(resp, err, out)
}

// Get GETs url-encoded values and saves the output to the corresponding json
// authorization is optional, is used for APIs that use the Authorization header instead of a `clientSecret` query parameter
func Get(uri string, values *url.Values, authorization string, out interface{}) error {
	client := &http.Client{}
	req, err := http.NewRequest("GET", uri+"?"+values.Encode(), nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := client.Do(req)

	return decode(resp, err, out)
}
