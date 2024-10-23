package ext

import "crypto/ed25519"

func PublickeyFromESK(h []byte) ed25519.PublicKey {
	a := decodeInt(h[:32])
	A := scalarmult(bB, a)
	return encodepoint(A)
}
