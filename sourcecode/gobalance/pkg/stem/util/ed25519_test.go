package util

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBlindedSign(t *testing.T) {
	msg, _ := base64.StdEncoding.DecodeString(`AQgABvn+AUmtuF1+Nb/kJ67y1U0lI7HiDjRJwHHY+sQrHlBKomR3AQAgBAAtL5DBE1Moh7A+AGrzgWhcHOBo/W3lyhcLeip0LuI8Xw==`)
	identityKeyPem := `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMjdAAyeb8pU3CzRK2z+yKSgWi0R33mfeAPpVnktRrwA
-----END PRIVATE KEY-----`
	block, _ := pem.Decode([]byte(identityKeyPem))
	key, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	identityKey := key.(ed25519.PrivateKey)
	blindedKey, _ := base64.StdEncoding.DecodeString(`LS+QwRNTKIewPgBq84FoXBzgaP1t5coXC3oqdC7iPF8=`)
	blindingNonce, _ := base64.StdEncoding.DecodeString(`ljbKEFzZGbd3ZI29J67XTs6JV3Glp+uieQ5yORMhmdg=`)
	expected := `xIrhGFs3VZKbV36zqCcudaWN0+K8s6zRRr5qki1uz/HjBL80SQ0HEirDp4DnNBAeYDIjNJwmrgQe6IU8ESHzDg==`
	res := BlindedSign(msg, identityKey.Seed(), blindedKey, blindingNonce)
	assert.Equal(t, expected, base64.StdEncoding.EncodeToString(res))
}
