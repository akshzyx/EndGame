package descriptor

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEd25519CertificateToBase64(t *testing.T) {
	certRaw := `-----BEGIN ED25519 CERT-----
AQkABvnvASpbRl8c5Iwx+KYXIGHMA+66ZN88TppVrRqrwyZkv45UAQAgBABcfN7F
QCPKVVMMIsn/OMg/XEQjOhfiqBB7DDU36l7dR+vl8qUr8ApIEPse2nAPmz8EscmY
25grvptE/1o0mS1ynpEPmeFrGbUCVyWsntwLyn77bscvNdG8Mozov3bGFQU=
-----END ED25519 CERT-----`
	cert := Ed25519CertificateFromBase64(certRaw)
	newCert := cert.ToBase64()
	assert.Equal(t, certRaw, newCert)
}

func TestEd25519CertificateV1Pack(t *testing.T) {
	raw := "AQgABvnxAVx83sVAI8pVUwwiyf84yD9cRCM6F+KoEHsMNTfqXt1HAQAgBAB0tYzO/dvRZRujduw/KKmyulEhsEvjhVbhZ4ALCYkMgBpLO+hsNQqVdbTWvm5FrMZcyuCP4451WdpYlgOlsG8Mu3goFEM8B2KWQdzVpI69oq61geN5yzwnhO7zH/o1qwo="
	by1, _ := base64.StdEncoding.DecodeString(raw)
	cert := ed25519CertificateV1Unpack(by1)
	by2 := cert.pack()
	assert.Equal(t, by1, by2)
}

func TestEd25519ExtensionPack(t *testing.T) {
	raw := "ACAEAHS1jM7929FlG6N27D8oqbK6USGwS+OFVuFngAsJiQyA"
	by1, _ := base64.StdEncoding.DecodeString(raw)
	ext, _ := Ed25519ExtensionPop(by1)
	by2 := ext.Pack()
	assert.Equal(t, by1, by2)
}
