package descriptor

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/btime"
	"strings"
	"time"
)

type Ed25519Certificate struct {
	Version uint8
}

// Ed25519CertificateV1 version 1 Ed25519 certificate, which sign tor server and hidden service v3
// descriptors.
type Ed25519CertificateV1 struct {
	Ed25519Certificate
	Typ        uint8
	typInt     int64
	Expiration time.Time
	KeyType    uint8
	Key        ed25519.PublicKey
	Extensions []Ed25519Extension
	Signature  []byte
}

func (c Ed25519CertificateV1) pack() (out []byte) {
	out = append(out, c.Version)
	out = append(out, c.Typ)
	expiration := c.Expiration.Unix() / 3600
	expirationBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expirationBytes, uint32(expiration))
	out = append(out, expirationBytes...)
	out = append(out, c.KeyType)
	out = append(out, c.Key...)
	out = append(out, uint8(len(c.Extensions)))
	for _, ext := range c.Extensions {
		out = append(out, ext.Pack()...)
	}
	if c.Signature != nil {
		out = append(out, c.Signature...)
	}
	return
}

// ToBase64 Base64 encoded certificate data.
func (c Ed25519CertificateV1) ToBase64() (out string) {
	b64 := strings.Join(splitByLength(base64.StdEncoding.EncodeToString(c.pack()), 64), "\n")
	out = fmt.Sprintf("-----BEGIN ED25519 CERT-----\n%s\n-----END ED25519 CERT-----", b64)
	return out
}

func splitByLength(msg string, size int) (out []string) {
	for i := 0; i < len(msg); i += size {
		upper := i + size
		if i+size > len(msg) {
			upper = len(msg)
		}
		out = append(out, msg[i:upper])
	}
	return
}

const DefaultExpirationHours = 54 // HSv3 certificate expiration of tor

func NewEd25519CertificateV1(certType uint8, expiration *time.Time, keyType uint8, key ed25519.PublicKey,
	extensions []Ed25519Extension, signingKey ed25519.PrivateKey, signature []byte) Ed25519CertificateV1 {
	c := Ed25519CertificateV1{}
	c.Version = 1
	if certType == 0 {
		panic("Certificate type is required")
	} else if key == nil {
		panic("Certificate key is required")
	}
	if certType == 8 {
		c.Typ, c.typInt = HsV3DescSigning, 8
	} else if certType == 9 {
		c.Typ, c.typInt = HsV3IntroAuth, 9
	} else if certType == 11 {
		c.Typ, c.typInt = HsV3NtorEnc, 11
	} else {
		panic("unknown cert type")
	}
	if expiration == nil {
		c.Expiration = btime.Clock.Now().UTC().Add(DefaultExpirationHours * time.Hour)
	} else {
		c.Expiration = expiration.UTC()
	}
	c.KeyType = keyType
	c.Key = key
	c.Extensions = extensions
	c.Signature = signature
	if signingKey != nil {
		calculatedSig := ed25519.Sign(signingKey, c.pack())
		/*
		   // if caller provides both signing key *and* signature then ensure they match
		   if self.signature and self.signature != calculated_sig:
		     raise ValueError("Signature calculated from its key (%s) mismatches '%s'" % (calculated_sig, self.signature))
		*/
		c.Signature = calculatedSig
	}
	if c.Typ == LINK || c.Typ == IDENTITY || c.Typ == AUTHENTICATE {
		logrus.Panicf("Ed25519 certificate cannot have a type of %d. This is reserved for CERTS cells.", c.typInt)
	} else if c.Typ == ED25519_IDENTITY {
		panic("Ed25519 certificate cannot have a type of 7. This is reserved for RSA identity cross-certification.")
	} else if c.Typ == 0 {
		logrus.Panicf("Ed25519 certificate type %d is unrecognized", c.typInt)
	}
	return c
}

func (c *Ed25519CertificateV1) SigningKey() ed25519.PublicKey {
	for _, ext := range c.Extensions {
		if ext.Typ == HasSigningKey {
			return ext.Data
		}
	}
	return nil
}

const (
	LINK = iota + 1
	IDENTITY
	AUTHENTICATE
	ED25519_SIGNING
	LINK_CERT
	ED25519_AUTHENTICATE
	ED25519_IDENTITY
	HsV3DescSigning
	HsV3IntroAuth
	NTOR_ONION_KEY
	HsV3NtorEnc
)

// Ed25519CertificateV1Unpack parses a byte encoded ED25519 certificate.
func Ed25519CertificateV1Unpack(content []byte) Ed25519CertificateV1 {
	if len(content) == 0 {
		logrus.Panicf("Failed to unpack ed25519 certificate")
	}
	version := content[0]
	if version != 1 {
		logrus.Panicf("Ed25519 certificate is version %c. Parser presently only supports version 1.", version)
	}
	return ed25519CertificateV1Unpack(content)
}

// Ed25519CertificateFromBase64 parses a base64 encoded ED25519 certificate.
func Ed25519CertificateFromBase64(content string) Ed25519CertificateV1 {
	if strings.HasPrefix(content, "-----BEGIN ED25519 CERT-----\n") &&
		strings.HasSuffix(content, "\n-----END ED25519 CERT-----") {
		content = strings.TrimPrefix(content, "-----BEGIN ED25519 CERT-----\n")
		content = strings.TrimSuffix(content, "\n-----END ED25519 CERT-----")
	}
	by, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		panic(err)
	} else if len(by) == 0 {
		return Ed25519CertificateV1{}
	}
	return Ed25519CertificateV1Unpack(by)
}

const (
	Ed25519KeyLength       = 32
	Ed25519HeaderLength    = 40
	Ed25519SignatureLength = 64
)

func ed25519CertificateV1Unpack(content []byte) Ed25519CertificateV1 {
	if len(content) < Ed25519HeaderLength+Ed25519SignatureLength {
		logrus.Panicf("Ed25519 certificate was %d bytes, but should be at least %d", len(content), Ed25519HeaderLength+Ed25519SignatureLength)
	}
	header, signature := content[:len(content)-Ed25519SignatureLength], content[len(content)-Ed25519SignatureLength:]

	version, header := header[0], header[1:]
	certType, header := header[0], header[1:]
	expirationHoursRaw, header := header[:4], header[4:]
	var expirationHours int64
	expirationHours |= int64(expirationHoursRaw[0]) << 24
	expirationHours |= int64(expirationHoursRaw[1]) << 16
	expirationHours |= int64(expirationHoursRaw[2]) << 8
	expirationHours |= int64(expirationHoursRaw[3])
	keyType, header := header[0], header[1:]
	key, header := header[:Ed25519KeyLength], header[Ed25519KeyLength:]
	extensionCount, extensionData := header[0], header[1:]
	if version != 1 {
		logrus.Panicf("Ed25519 v1 parser cannot read version %c certificates", version)
	}
	extensions := make([]Ed25519Extension, 0)
	for i := 0; i < int(extensionCount); i++ {
		var extension Ed25519Extension
		extension, extensionData = Ed25519ExtensionPop(extensionData)
		extensions = append(extensions, extension)
	}
	if len(extensionData) > 0 {
		logrus.Panicf("Ed25519 certificate had %d bytes of unused extension data", len(extensionData))
	}
	expiration := time.Unix(int64(expirationHours)*3600, 0)
	return NewEd25519CertificateV1(certType,
		&expiration,
		keyType, key, extensions, nil, signature)
}

type Ed25519Extension struct {
	Typ     uint8
	Flags   []string
	FlagInt uint8
	Data    []byte
}

func NewEd25519Extension(extType, flagVal uint8, data []byte) Ed25519Extension {
	e := Ed25519Extension{}
	e.Typ = extType
	e.Flags = make([]string, 0)
	e.FlagInt = flagVal
	e.Data = data
	if flagVal > 0 && flagVal%2 == 1 {
		e.Flags = append(e.Flags, "AFFECTS_VALIDATION")
		flagVal -= 1
	}
	if flagVal > 0 {
		e.Flags = append(e.Flags, "UNKNOWN")
	}
	if extType == HasSigningKey && len(data) != 32 {
		logrus.Panicf("Ed25519 HAS_SIGNING_KEY extension must be 32 bytes, but was %d.", len(data))
	}
	return e
}

func Ed25519ExtensionPop(content []byte) (Ed25519Extension, []byte) {
	if len(content) < 4 {
		panic("Ed25519 extension is missing header fields")
	}

	dataSizeRaw, content := content[:2], content[2:]
	var dataSize int64
	dataSize |= int64(dataSizeRaw[0]) << 8
	dataSize |= int64(dataSizeRaw[1])
	extType, content := content[0], content[1:]
	flags, content := content[0], content[1:]
	data, content := content[:dataSize], content[dataSize:]

	if int64(len(data)) != dataSize {
		logrus.Panicf("Ed25519 extension is truncated. It should have %d bytes of data but there's only %d.", dataSize, len(data))
	}

	return NewEd25519Extension(extType, flags, data), content
}

func (e Ed25519Extension) Pack() (out []byte) {
	dataSizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(dataSizeBytes, uint16(len(e.Data)))
	out = append(out, dataSizeBytes...)
	out = append(out, e.Typ)
	out = append(out, e.FlagInt)
	out = append(out, e.Data...)
	return
}
