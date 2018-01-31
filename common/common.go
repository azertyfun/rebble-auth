package common

import (
	"crypto/rand"
	"fmt"
	"math/big"
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
