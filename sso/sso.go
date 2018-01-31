package sso

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
)

// Sso is a JSON object containing information about a specific OpenID SSO provider
type Sso struct {
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	DiscoverURI  string `json:"discover_uri"`
	RedirectURI  string `json:"redirect_uri"`
	Scopes       string `json:"scopes"`

	Discovery Discovery
	Certs     Certs
}

// Discovery lists all the API endpoints for a given SSO
// https://developers.google.com/identity/protocols/OpenIDConnect#discovery
// Only the relevant fields will be filled
type Discovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

type Key struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type Certs struct {
	Keys []Key `json:"keys"`
}

func (key *Key) GetPublicKey() (rsa.PublicKey, error) {
	// Pad the base64 data if necessary
	if len(key.N)%4 != 0 {
		key.N = key.N + strings.Repeat("=", 4-(len(key.N)%4))
	}
	if len(key.E)%4 != 0 {
		key.E = key.E + strings.Repeat("=", 4-(len(key.E)%4))
	}

	nb := make([]byte, base64.URLEncoding.DecodedLen(len([]byte(key.N))))
	eb := make([]byte, base64.URLEncoding.DecodedLen(len([]byte(key.E))))
	n := big.NewInt(0)
	e := 0
	ln, err := base64.URLEncoding.Decode(nb, []byte(key.N))
	if err != nil {
		return rsa.PublicKey{}, err
	}
	le, err := base64.URLEncoding.Decode(eb, []byte(key.E))
	if err != nil {
		return rsa.PublicKey{}, err
	}

	i := 0
	for i < ln {
		z := big.NewInt(int64(nb[i]))
		z.Lsh(z, 8*uint(ln-i-1))
		n.Add(n, z)
		i++
	}
	i = 0
	for i < le {
		e += int(uint64(eb[i]) << (8 * uint64(le-i-1)))
		i++
	}

	return rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
