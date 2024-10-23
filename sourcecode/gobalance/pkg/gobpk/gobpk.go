package gobpk

import (
	"crypto/ed25519"
	"gobalance/pkg/onionbalance/hs_v3/ext"
)

// gobpk == gobalance private key

// PrivateKey wrapper around ed25519 private key to handle both tor format or normal
type PrivateKey struct {
	isPrivKeyInTorFormat bool
	privateKey           ed25519.PrivateKey
}

// Public returns the public key bytes
func (k PrivateKey) Public() ed25519.PublicKey {
	if k.isPrivKeyInTorFormat {
		return ext.PublickeyFromESK(k.privateKey)
	}
	return k.privateKey.Public().(ed25519.PublicKey)
}

// Seed returns the underlying ed25519 private key seed
func (k PrivateKey) Seed() []byte {
	return k.privateKey.Seed()
}

// IsPrivKeyInTorFormat returns either or not the private key is in tor format
func (k PrivateKey) IsPrivKeyInTorFormat() bool {
	return k.isPrivKeyInTorFormat
}

// New created a new PrivateKey
func New(privateKey ed25519.PrivateKey, isPrivKeyInTorFormat bool) PrivateKey {
	return PrivateKey{
		privateKey:           privateKey,
		isPrivKeyInTorFormat: isPrivKeyInTorFormat,
	}
}
