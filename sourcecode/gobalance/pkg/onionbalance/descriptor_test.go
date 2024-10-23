package onionbalance

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"gobalance/pkg/stem/descriptor"
	"testing"
)

func TestRecertify(t *testing.T) {
	signingKeyPem := `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOcEHVwEY9iXpRtgQ9V3gfRPxWnVLueY911dGZDmLsE5
-----END PRIVATE KEY-----`
	in := `-----BEGIN ED25519 CERT-----
AQkABvnyAeKc+JWLUCqeZ0PeYQMLB/s1x78MnHbaVJEJRydNiS4MAQAgBABcfN7F
QCPKVVMMIsn/OMg/XEQjOhfiqBB7DDU36l7dRyLU9kxujPUIBRUN229MYnIZE7iC
Bbtp5EM7G8R6GeX63anXSwcgldZJMa3hTq4QqhJf92nIOWakmAh9N++z+wo=
-----END ED25519 CERT-----`
	expected := `-----BEGIN ED25519 CERT-----
AQkABvnyAeKc+JWLUCqeZ0PeYQMLB/s1x78MnHbaVJEJRydNiS4MAQAgBADpdmL5
jB9FTH/efQdCjogJa4F2/Xh9qJNiWmKWQYHdFB0b6xL7WctQFkBPWX0E+wyBjN+s
kcA5N/9MA4vWHYTeR2NI10q48FfC/A3iXu1W9f+vaVhYGr2rsgWmqt86Ngc=
-----END ED25519 CERT-----`

	block, _ := pem.Decode([]byte(signingKeyPem))
	key, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	descriptorSigningKey := key.(ed25519.PrivateKey)
	edCert := descriptor.Ed25519CertificateFromBase64(in)
	out := recertifyEdCertificate(edCert, descriptorSigningKey)
	assert.Equal(t, expected, out.ToBase64())
}

func TestGetRevisionCounterDet(t *testing.T) {
	pk, _ := base64.StdEncoding.DecodeString(`5FPpKghcg2LnAuG8eO1n/+EwYKePXbxl1kFPp+iKbb8=`)
	now := int64(1645956370)
	srvStart := int64(1645833600)
	expected := int64(4033953644)
	expectedSSS := int64(122771)
	opeResult, sss := getRevisionCounterDet(pk, now, srvStart)
	assert.Equal(t, expectedSSS, sss)
	assert.Equal(t, expected, opeResult)
}
