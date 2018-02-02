package sso

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

// Sso is a JSON object containing information about a specific OpenID SSO provider
type Sso struct {
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Type         string `json:"type"`
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

// Initialize populates all necessary fields in the Sso struct
func (sso Sso) Initialize() (Sso, error) {
	switch sso.Type {
	case "oidc":
		resp, err := http.Get(sso.DiscoverURI)
		if err != nil {
			return Sso{}, fmt.Errorf("Could not get discovery apge for SSO %v (HTTP GET failed): %v", sso.Name, err)
		}
		if resp.StatusCode/100 != 2 {
			return Sso{}, fmt.Errorf("Could not get discovery apge for SSO %v (invalid error code %v)", sso.Name, resp.StatusCode)
		}

		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&sso.Discovery)
		if err != nil {
			return Sso{}, fmt.Errorf("Could not get discovery apge for SSO %v (Could not decode JSON): %v", sso.Name, err)
		}
		defer resp.Body.Close()

		break
	case "facebook":
		sso.Discovery.AuthorizationEndpoint = "https://www.facebook.com/v2.12/dialog/oauth"
		sso.Discovery.TokenEndpoint = "https://graph.facebook.com/v2.12/oauth/access_token"
		sso.Discovery.UserinfoEndpoint = "https://graph.facebook.com/me"

		break
	default:
		return Sso{}, fmt.Errorf("Invalid SSO type '%v'", sso.Type)
	}

	return sso, nil
}
