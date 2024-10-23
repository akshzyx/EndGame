package onionbalance

import (
	"bytes"
	"crypto/ed25519"
)

// LoadTorKeyFromDisk load a private identity key from little-t-tor.
func LoadTorKeyFromDisk(keyBytes []byte) ed25519.PrivateKey {
	if !bytes.Equal(keyBytes[:29], []byte("== ed25519v1-secret: type0 ==")) {
		panic("Tor key does not start with Tor header")
	}
	expandedSk := keyBytes[32:]

	// The rest should be 64 bytes (a,h):
	// 32 bytes for secret scalar 'a'
	// 32 bytes for PRF key 'h'
	if len(expandedSk) != 64 {
		panic("Tor private key has the wrong length")
	}
	return expandedSk
}
