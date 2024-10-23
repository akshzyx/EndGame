/*
Package x25519 implements Elliptic Curve Diffie-Hellman (ECDH) function over Curve25519
*/
package x25519

import (
	"crypto"
	"encoding/pem"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

// Key sizes
const (
	// GroupElementLength is the length of a ECDH group element in bytes.
	GroupElementLength = 32

	// PublicKeySize is the size of a serialized PublicKey in bytes.
	PublicKeySize = GroupElementLength

	// PrivateKeySize is the size of a serialized PrivateKey in bytes.
	PrivateKeySize = GroupElementLength
)

// PublicKey represents an X25519 public key.
type PublicKey struct {
	b [PublicKeySize]byte
}

// Bytes returns the raw public key.
func (pub *PublicKey) Bytes() []byte {
	return pub.b[:]
}

// SetBytes interprets b as the bytes of a big-endian public key.
func (pub *PublicKey) SetBytes(b []byte) {
	copy(pub.b[:], b)
}

// PrivateKey represents an X25519 private key.
type PrivateKey struct {
	PublicKey
	b [PrivateKeySize]byte
}

// Bytes returns the raw private key.
func (priv *PrivateKey) Bytes() []byte {
	return priv.b[:]
}

// SetBytes interprets b as the bytes of a big-endian private key.
func (priv *PrivateKey) SetBytes(b []byte) {
	copy(priv.b[:], b)
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// Shared computes the shared key corresponding to priv and peer's public key.
func (priv *PrivateKey) Shared(peer *PublicKey) []byte {
	var shared [32]byte
	curve25519.ScalarMult(&shared, &priv.b, &peer.b)
	return shared[:]
}

// GenerateKey generates an X25519 keypair using the random source random (for example, crypto/rand.Reader).
func GenerateKey(random io.Reader) (*PrivateKey, error) {
	privateKey := new(PrivateKey)
	if _, err := io.ReadFull(random, privateKey.b[:]); err != nil {
		return nil, err
	}

	// Masking X25519 key as documented at https://cr.yp.to/ecdh.html
	privateKey.b[0x00] &= 0xf8
	privateKey.b[0x1f] &= 0x7f
	privateKey.b[0x1f] |= 0x40

	// Calculate public key
	curve25519.ScalarBaseMult(&privateKey.PublicKey.b, &privateKey.b)

	return privateKey, nil
}

const pemPrivateKeyType = "X25519 PRIVATE KEY"

// MarshalPEM encodes a X25519 private key to PEM.
func (priv *PrivateKey) MarshalPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivateKeyType,
		Bytes: priv.b[:],
	})
}

// UnmarshalPEM decodes an X25519 private key PEM block.
func (priv *PrivateKey) UnmarshalPEM(data []byte) error {
	var block *pem.Block
	for {
		if block, data = pem.Decode(data); block == nil {
			return errors.New("x25519: no X25519 PRIVATE KEY block found")
		} else if block.Type == pemPrivateKeyType {
			priv.SetBytes(block.Bytes)
			return nil
		}
	}
}
