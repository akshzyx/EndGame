package descriptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/brand"
	"gobalance/pkg/btime"
	"gobalance/pkg/gobpk"
	"gobalance/pkg/stem/util"
	"golang.org/x/crypto/sha3"
	"maze.io/x/crypto/x25519"
	"strconv"
	"strings"
)

// Descriptor common parent for all types of descriptors.
// https://github.com/torproject/torspec/blob/4da63977b86f4c17d0e8cf87ed492c72a4c9b2d9/rend-spec-v3.txt#L1057
type Descriptor struct {
	HsDescriptorVersion      int64
	descriptorLifetime       int64
	DescriptorSigningKeyCert string
	revisionCounter          int64
	superencrypted           string
	signature                string
}

func (d *Descriptor) FromStr(content string) {
	*d = *descFromStr(content)
}

func descFromStr(content string) *Descriptor {
	d := &Descriptor{}
	lines := strings.Split(content, "\n")
	startCert := false
	startSuperencrypted := false
	for idx, line := range lines {
		if idx == 0 {
			d.HsDescriptorVersion, _ = strconv.ParseInt(strings.TrimPrefix(line, "hs-descriptor "), 10, 64)
			continue
		} else if idx == 1 {
			d.descriptorLifetime, _ = strconv.ParseInt(strings.TrimPrefix(line, "descriptor-lifetime "), 10, 64)
			continue
		} else if line == "descriptor-signing-key-cert" {
			startCert = true
			continue
		} else if line == "superencrypted" {
			startSuperencrypted = true
			continue
		} else if strings.HasPrefix(line, "revision-counter ") {
			d.revisionCounter, _ = strconv.ParseInt(strings.TrimPrefix(line, "revision-counter "), 10, 64)
			continue
		} else if strings.HasPrefix(line, "signature ") {
			d.signature = strings.TrimPrefix(line, "signature ")
			continue
		}
		if startCert {
			d.DescriptorSigningKeyCert += line + "\n"
			if line == "-----END ED25519 CERT-----" {
				startCert = false
				d.DescriptorSigningKeyCert = strings.TrimSpace(d.DescriptorSigningKeyCert)
			}
		} else if startSuperencrypted {
			d.superencrypted += line + "\n"
			if line == "-----END MESSAGE-----" {
				startSuperencrypted = false
				d.superencrypted = strings.TrimSpace(d.superencrypted)
			}
		}
	}
	return d
}

// BaseHiddenServiceDescriptor hidden service descriptor.
type BaseHiddenServiceDescriptor struct {
	Descriptor
}

const (
	// ExtensionType
	HasSigningKey = 4
)

// HiddenServiceDescriptorV3 version 3 hidden service descriptor.
type HiddenServiceDescriptorV3 struct {
	BaseHiddenServiceDescriptor
	SigningCert Ed25519CertificateV1
	InnerLayer  *InnerLayer
	rawContents string
}

func (d HiddenServiceDescriptorV3) String() string {
	var sb strings.Builder
	sb.WriteString("hs-descriptor 3\n")
	sb.WriteString("descriptor-lifetime ")
	sb.WriteString(strconv.FormatInt(d.descriptorLifetime, 10))
	sb.WriteByte('\n')
	sb.WriteString("descriptor-signing-key-cert\n")
	sb.WriteString(d.DescriptorSigningKeyCert)
	sb.WriteByte('\n')
	sb.WriteString("revision-counter ")
	sb.WriteString(strconv.FormatInt(d.revisionCounter, 10))
	sb.WriteByte('\n')
	sb.WriteString("superencrypted\n")
	sb.WriteString(d.superencrypted)
	sb.WriteByte('\n')
	sb.WriteString("signature ")
	sb.WriteString(d.signature)
	return sb.String()
}

func blindedPubkey(identityKey gobpk.PrivateKey, blindingNonce []byte) ed25519.PublicKey {
	return util.BlindedPubkey(identityKey.Public(), blindingNonce)
}

func blindedSign(msg []byte, identityKey gobpk.PrivateKey, blindedKey, blindingNonce []byte) []byte {
	if identityKey.IsPrivKeyInTorFormat() {
		return util.BlindedSignWithTorKey(msg, identityKey.Seed(), blindedKey, blindingNonce)
	} else {
		return util.BlindedSign(msg, identityKey.Seed(), blindedKey, blindingNonce)
	}
}

func HiddenServiceDescriptorV3Content(blindingNonce []byte, identityKey gobpk.PrivateKey,
	descSigningKey ed25519.PrivateKey, innerLayer *InnerLayer, revCounter *int64) string {
	if innerLayer == nil {
		tmp := InnerLayerCreate(nil)
		innerLayer = &tmp
	}
	if descSigningKey == nil {
		_, descSigningKey, _ = ed25519.GenerateKey(brand.Reader())
	}
	if revCounter == nil {
		tmp := btime.Clock.Now().Unix()
		revCounter = &tmp
	}
	blindedKey := blindedPubkey(identityKey, blindingNonce)
	//if blinding_nonce != nil {
	//	blindedKey = onionbalance.BlindedPubkey(identityKey, blinding_nonce)
	//}
	pub := identityKey.Public()
	subcredential := subcredential(pub, blindedKey)

	//if outerLayer == nil {
	outerLayer := OuterLayerCreate(innerLayer, revCounter, subcredential, blindedKey)
	//}

	// if {
	signingCert := getSigningCert(blindedKey, descSigningKey, identityKey, blindingNonce)
	// }

	descContent := "hs-descriptor 3\n"
	descContent += fmt.Sprintf("descriptor-lifetime %d\n", 180)
	descContent += "descriptor-signing-key-cert\n"
	descContent += signingCert.ToBase64() + "\n"
	descContent += fmt.Sprintf("revision-counter %d\n", *revCounter)
	descContent += "superencrypted\n"
	descContent += outerLayer.encrypt(*revCounter, subcredential, blindedKey) + "\n"

	sigContent := SigPrefixHsV3 + descContent
	sig := ed25519.Sign(descSigningKey, []byte(sigContent))
	descContent += fmt.Sprintf("signature %s", strings.TrimRight(base64.StdEncoding.EncodeToString(sig), "="))

	return descContent
}

func priv2Pem(pk ed25519.PrivateKey) string {
	var identityKeyPem bytes.Buffer
	identityKeyBytes, _ := x509.MarshalPKCS8PrivateKey(pk)
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: identityKeyBytes}
	_ = pem.Encode(&identityKeyPem, block)
	return identityKeyPem.String()
}

func getSigningCert(blindedKey ed25519.PublicKey, descSigningKey ed25519.PrivateKey, identityKey gobpk.PrivateKey, blindingNonce []byte) Ed25519CertificateV1 {
	extensions := []Ed25519Extension{NewEd25519Extension(HasSigningKey, 0, blindedKey)}
	signingCert := NewEd25519CertificateV1(HsV3DescSigning, nil, 1, descSigningKey.Public().(ed25519.PublicKey), extensions, nil, nil)
	signingCert.Signature = blindedSign(signingCert.pack(), identityKey, blindedKey, blindingNonce)
	return signingCert
}

const SigPrefixHsV3 = "Tor onion service descriptor sig v3"

func HiddenServiceDescriptorV3Create(blindingNonce []byte, identityPrivKey gobpk.PrivateKey, descSigningKey ed25519.PrivateKey, v3DescInnerLayer InnerLayer, revCounter int64) *HiddenServiceDescriptorV3 {
	return NewHiddenServiceDescriptorV3(HiddenServiceDescriptorV3Content(blindingNonce, identityPrivKey, descSigningKey, &v3DescInnerLayer, &revCounter))
}

func NewHiddenServiceDescriptorV3(rawContents string) *HiddenServiceDescriptorV3 {
	d := &HiddenServiceDescriptorV3{}
	d.rawContents = rawContents
	d.Descriptor.FromStr(rawContents)
	d.SigningCert = Ed25519CertificateFromBase64(d.DescriptorSigningKeyCert)

	//lines := strings.Split(rawContents, "\n")
	//startCert := false
	//startSuperencrypted := false
	//for idx, line := range lines {
	//	if idx == 0 {
	//		d.HsDescriptorVersion, _ = strconv.ParseInt(strings.TrimPrefix(line, "hs-descriptor "), 10, 64)
	//		continue
	//	} else if idx == 1 {
	//		d.descriptorLifetime, _ = strconv.ParseInt(strings.TrimPrefix(line, "descriptor-lifetime "), 10, 64)
	//		continue
	//	} else if line == "descriptor-signing-key-cert" {
	//		startCert = true
	//		continue
	//	} else if line == "superencrypted" {
	//		startSuperencrypted = true
	//		continue
	//	} else if strings.HasPrefix(line, "revision-counter ") {
	//		d.revisionCounter, _ = strconv.ParseInt(strings.TrimPrefix(line, "revision-counter "), 10, 64)
	//		continue
	//	} else if strings.HasPrefix(line, "signature ") {
	//		d.signature = strings.TrimPrefix(line, "signature ")
	//		continue
	//	}
	//	if startCert {
	//		d.DescriptorSigningKeyCert += line + "\n"
	//		if line == "-----END ED25519 CERT-----" {
	//			startCert = false
	//			d.DescriptorSigningKeyCert = strings.TrimSpace(d.DescriptorSigningKeyCert)
	//		}
	//	} else if startSuperencrypted {
	//		d.superencrypted += line + "\n"
	//		if line == "-----END MESSAGE-----" {
	//			startSuperencrypted = false
	//			d.superencrypted = strings.TrimSpace(d.superencrypted)
	//		}
	//	}
	//}

	// TODO - n0tr1v
	return d
}

func (d *HiddenServiceDescriptorV3) Decrypt(onionAddress string) (i *InnerLayer, err error) {
	if d.InnerLayer == nil {
		descriptorSigningKeyCert := d.DescriptorSigningKeyCert
		cert := Ed25519CertificateFromBase64(descriptorSigningKeyCert)
		blindedKey := cert.SigningKey()
		if blindedKey == nil {
			return d.InnerLayer, errors.New("no signing key is present")
		}
		identityPublicKey := IdentityKeyFromAddress(onionAddress)
		subcredential := subcredential(identityPublicKey, blindedKey)
		outerLayer := outerLayerDecrypt(d.superencrypted, d.revisionCounter, subcredential, blindedKey)
		tmp := innerLayerDecrypt(outerLayer, d.revisionCounter, subcredential, blindedKey)
		d.InnerLayer = &tmp
	}
	return d.InnerLayer, nil
}

type InnerLayer struct {
	outer                      OuterLayer
	IntroductionPoints         []IntroductionPointV3
	unparsedIntroductionPoints string
	rawContents                string
}

func (l InnerLayer) encrypt(revisionCounter int64, subcredential, blindedKey []byte) string {
	// encrypt back into an outer layer's 'encrypted' field
	return encryptLayer(l.getBytes(), "hsdir-encrypted-data", revisionCounter, subcredential, blindedKey)
}

func (l InnerLayer) getBytes() []byte {
	return []byte(l.rawContents)
}

func InnerLayerContent(introductionPoints []IntroductionPointV3) string {
	var sb strings.Builder
	sb.WriteString("create2-formats 2")
	if introductionPoints != nil {
		for _, ip := range introductionPoints {
			sb.WriteByte('\n')
			sb.WriteString(ip.encode())
		}
	}
	return sb.String()
}

func InnerLayerCreate(introductionPoints []IntroductionPointV3) InnerLayer {
	return NewInnerLayer(InnerLayerContent(introductionPoints), OuterLayer{})
}

func NewInnerLayer(content string, outerLayer OuterLayer) InnerLayer {
	l := InnerLayer{}
	l.rawContents = content
	l.outer = outerLayer
	div := strings.Index(content, "\nintroduction-point ")
	if div != -1 {
		l.unparsedIntroductionPoints = content[div+1:]
		content = content[:div]
	} else {
		l.unparsedIntroductionPoints = ""
	}
	//entries := descriptor_components(content, validate)
	l.parseV3IntroductionPoints()
	return l
}

type IntroductionPointV3 struct {
	LinkSpecifiers []LinkSpecifier
	OnionKey       string
	EncKey         string
	AuthKeyCertRaw string
	EncKeyCertRaw  string
	AuthKeyCert    Ed25519CertificateV1
	EncKeyCert     Ed25519CertificateV1
	LegacyKeyRaw   any
}

func (i IntroductionPointV3) Equals(other IntroductionPointV3) bool {
	return i.encode() == other.encode()
}

// Descriptor representation of this introduction point.
func (i IntroductionPointV3) encode() string {
	var sb strings.Builder
	linkCount := uint8(len(i.LinkSpecifiers))
	linkSpecifiers := []byte{linkCount}
	for _, ls := range i.LinkSpecifiers {
		linkSpecifiers = append(linkSpecifiers, ls.pack()...)
	}
	sb.WriteString("introduction-point ")
	sb.WriteString(base64.StdEncoding.EncodeToString(linkSpecifiers))
	sb.WriteString("\n")

	sb.WriteString("onion-key ntor ")
	sb.WriteString(i.OnionKey)
	sb.WriteString("\n")

	sb.WriteString("auth-key\n")
	sb.WriteString(i.AuthKeyCertRaw)
	sb.WriteString("\n")

	if i.EncKey != "" {
		sb.WriteString("enc-key ntor ")
		sb.WriteString(i.EncKey)
		sb.WriteString("\n")
	}
	sb.WriteString("enc-key-cert\n")
	sb.WriteString(i.EncKeyCertRaw)
	return sb.String()
}

/**
// Descriptor representation of this introduction point.
func (i IntroductionPointV3) encode() string {
	out := strings.Builder{}
	linkCount := uint8(len(i.LinkSpecifiers))
	linkSpecifiers := []byte{linkCount}
	for _, ls := range i.LinkSpecifiers {
		linkSpecifiers = append(linkSpecifiers, ls.pack()...)
	}
	out.WriteString(fmt.Sprintf("introduction-point %s\n", base64.StdEncoding.EncodeToString(linkSpecifiers)))
	out.WriteString(fmt.Sprintf("onion-key ntor %s\n", i.OnionKey))
	out.WriteString(fmt.Sprintf("auth-key\n%s\n", i.AuthKeyCertRaw))
	if i.EncKey != "" {
		out.WriteString(fmt.Sprintf("enc-key ntor %s\n", i.EncKey))
	}
	out.WriteString(fmt.Sprintf("enc-key-cert\n%s", i.EncKeyCertRaw))
	return out.String()
}
*/

func parseLinkSpecifier(content string) []LinkSpecifier {
	decoded, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		logrus.Panicf("Unable to base64 decode introduction point (%v): %s", err, content)
	}
	content = string(decoded)
	linkSpecifiers := make([]LinkSpecifier, 0)
	count, content := content[0], content[1:]
	for i := 0; i < int(count); i++ {
		var linkSpecifier LinkSpecifier
		linkSpecifier, content = linkSpecifierPop(content)
		linkSpecifiers = append(linkSpecifiers, linkSpecifier)
	}
	if len(content) > 0 {
		logrus.Panicf("Introduction point had excessive data (%s)", content)
	}
	return linkSpecifiers
}

type LinkSpecifier struct {
	Typ   uint8
	Value []byte
}

func (l LinkSpecifier) String() string {
	return fmt.Sprintf("T:%d,V:%x", l.Typ, l.Value)
}

func (l LinkSpecifier) pack() (out []byte) {
	out = append(out, l.Typ)
	out = append(out, uint8(len(l.Value)))
	out = append(out, l.Value...)
	return
}

func linkSpecifierPop(packed string) (LinkSpecifier, string) {
	linkType, packed := packed[0], packed[1:]
	valueSize, packed := packed[0], packed[1:]
	if int(valueSize) > len(packed) {
		logrus.Panicf("Link specifier should have %d bytes, but only had %d remaining", valueSize, len(packed))
	}
	value, packed := packed[:valueSize], packed[valueSize:]
	if linkType == 0 {
		return LinkByIPv4Unpack(value).LinkSpecifier, packed
	} else if linkType == 1 {
		return LinkByIPv6Unpack(value).LinkSpecifier, packed
	} else if linkType == 2 {
		return NewLinkByFingerprint([]byte(value)).LinkSpecifier, packed
	} else if linkType == 3 {
		return NewLinkByEd25519([]byte(value)).LinkSpecifier, packed
	}
	return LinkSpecifier{Typ: linkType, Value: []byte(value)}, packed // unrecognized type
}

type LinkByIPv4 struct {
	LinkSpecifier
	Address string
	Port    uint16
}

func NewLinkByIPv4(address string, port uint16) LinkByIPv4 {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	l := LinkByIPv4{}
	l.Typ = 0
	l.Value = append(packIPV4Address(address), portBytes...)
	l.Address = address
	l.Port = port
	return l
}

func LinkByIPv4Unpack(value string) LinkByIPv4 {
	if len(value) != 6 {
		logrus.Panicf("IPv4 link specifiers should be six bytes, but was %d instead: %x", len(value), value)
	}
	addr, portRaw := value[:4], value[4:]
	port := binary.BigEndian.Uint16([]byte(portRaw))
	return NewLinkByIPv4(unpackIPV4Address([]byte(addr)), port)
}

func NewLinkByIPv6(address string, port uint16) LinkByIPv6 {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	l := LinkByIPv6{}
	l.Typ = 1
	l.Value = append(packIPV6Address(address), portBytes...)
	l.Address = address
	l.Port = port
	return l
}

func LinkByIPv6Unpack(value string) LinkByIPv6 {
	if len(value) != 18 {
		logrus.Panicf("IPv6 link specifiers should be eighteen bytes, but was %d instead: %x", len(value), value)
	}
	addr, portRaw := value[:16], value[16:]
	port := binary.BigEndian.Uint16([]byte(portRaw))
	return NewLinkByIPv6(unpackIPV6Address([]byte(addr)), port)
}

func packIPV4Address(address string) (out []byte) {
	parts := strings.Split(address, ".")
	for _, part := range parts {
		tmp, _ := strconv.ParseUint(part, 10, 8)
		out = append(out, uint8(tmp))
	}
	return
}

func unpackIPV4Address(value []byte) string {
	strs := make([]string, 0)
	for i := 0; i < 4; i++ {
		strs = append(strs, fmt.Sprintf("%d", value[i]))
	}
	return strings.Join(strs, ".")
}

func packIPV6Address(address string) (out []byte) {
	parts := strings.Split(address, ":")
	for _, part := range parts {
		tmp, _ := hex.DecodeString(part)
		out = append(out, tmp...)
	}
	return
}

func unpackIPV6Address(value []byte) string {
	strs := make([]string, 0)
	for i := 0; i < 8; i++ {
		strs = append(strs, fmt.Sprintf("%04x", value[i*2:(i+1)*2]))
	}
	return strings.Join(strs, ":")
}

type LinkByIPv6 struct {
	LinkSpecifier
	Address string
	Port    uint16
}

type LinkByFingerprint struct {
	LinkSpecifier
	Fingerprint []byte
}

type LinkByEd25519 struct {
	LinkSpecifier
	Fingerprint []byte
}

func NewLinkByFingerprint(value []byte) LinkByFingerprint {
	if len(value) != 20 {
		logrus.Panicf("Fingerprint link specifiers should be twenty bytes, but was %d instead: %x", len(value), value)
	}
	l := LinkByFingerprint{}
	l.Typ = 2
	l.Value = value
	l.Fingerprint = value
	return l
}

func NewLinkByEd25519(value []byte) LinkByEd25519 {
	if len(value) != 32 {
		logrus.Panicf("Fingerprint link specifiers should be thirty two bytes, but was %d instead: %x", len(value), value)
	}
	l := LinkByEd25519{}
	l.Typ = 3
	l.Value = value
	l.Fingerprint = value
	return l
}

func introductionPointV3Parse(content string) IntroductionPointV3 {
	ip := IntroductionPointV3{}
	authKeyCertContent := ""
	encKeyCertContent := ""
	lines := strings.Split(content, "\n")
	startAuthKey := false
	startEncKeyCert := false
	for _, line := range lines {
		if line == "auth-key" {
			startAuthKey = true
			continue
		} else if strings.HasPrefix(line, "introduction-point ") {
			ip.LinkSpecifiers = parseLinkSpecifier(strings.TrimPrefix(line, "introduction-point "))
			continue
		} else if strings.HasPrefix(line, "onion-key ntor ") {
			ip.OnionKey = strings.TrimPrefix(line, "onion-key ntor ")
			continue
		} else if strings.HasPrefix(line, "enc-key ntor ") {
			ip.EncKey = strings.TrimPrefix(line, "enc-key ntor ")
			continue
		} else if line == "enc-key-cert" {
			startEncKeyCert = true
			continue
		}
		if startAuthKey {
			authKeyCertContent += line + "\n"
			if line == "-----END ED25519 CERT-----" {
				startAuthKey = false
				authKeyCertContent = strings.TrimSpace(authKeyCertContent)
			}
		}
		if startEncKeyCert {
			encKeyCertContent += line + "\n"
			if line == "-----END ED25519 CERT-----" {
				startEncKeyCert = false
				encKeyCertContent = strings.TrimSpace(encKeyCertContent)
			}
		}
	}
	ip.AuthKeyCertRaw = authKeyCertContent
	ip.EncKeyCertRaw = encKeyCertContent
	ip.AuthKeyCert = Ed25519CertificateFromBase64(authKeyCertContent)
	ip.EncKeyCert = Ed25519CertificateFromBase64(encKeyCertContent)
	return ip
}

func (l *InnerLayer) parseV3IntroductionPoints() {
	introductionPoints := make([]IntroductionPointV3, 0)
	remaining := l.unparsedIntroductionPoints
	for remaining != "" {
		div := strings.Index(remaining, "\nintroduction-point ")
		var content string
		if div != -1 {
			content = remaining[:div]
			remaining = remaining[div+1:]
		} else {
			content = remaining
			remaining = ""
		}
		introductionPoints = append(introductionPoints, introductionPointV3Parse(content))
	}
	l.IntroductionPoints = introductionPoints
}

func innerLayerDecrypt(outerLayer OuterLayer, revisionCounter int64, subcredential, blindedKey ed25519.PublicKey) InnerLayer {
	plaintext := decryptLayer(outerLayer.encrypted, "hsdir-encrypted-data", revisionCounter, subcredential, blindedKey)
	return NewInnerLayer(plaintext, outerLayer)
}

type OuterLayer struct {
	encrypted  string
	rawContent string
}

func (l OuterLayer) encrypt(revisionCounter int64, subcredential, blindedKey []byte) string {
	// Spec mandated padding: "Before encryption the plaintext is padded with
	// NUL bytes to the nearest multiple of 10k bytes."
	content := append(l.getBytes(), bytes.Repeat([]byte("\x00"), len(l.getBytes())%10000)...)
	// encrypt back into a hidden service descriptor's 'superencrypted' field
	return encryptLayer(content, "hsdir-superencrypted-data", revisionCounter, subcredential, blindedKey)
}

func encryptLayer(plaintext []byte, constant string, revisionCounter int64, subcredential, blindedKey []byte) string {
	salt := make([]byte, 16)
	_, _ = brand.Read(salt)
	return encryptLayerDet(plaintext, constant, revisionCounter, subcredential, blindedKey, salt)
}

// Deterministic code for tests
func encryptLayerDet(plaintext []byte, constant string, revisionCounter int64, subcredential, blindedKey, salt []byte) string {
	ciphr, macFor := layerCipher(constant, revisionCounter, subcredential, blindedKey, salt)
	ciphertext := make([]byte, len(plaintext))
	ciphr.XORKeyStream(ciphertext, plaintext)
	encoded := base64.StdEncoding.EncodeToString([]byte(string(salt) + string(ciphertext) + string(macFor(ciphertext))))
	splits := splitByLength(encoded, 64)
	joined := strings.Join(splits, "\n")
	return fmt.Sprintf("-----BEGIN MESSAGE-----\n%s\n-----END MESSAGE-----", joined)
}

func (l OuterLayer) getBytes() []byte {
	return []byte(l.rawContent)
}

func OuterLayerCreate(innerLayer *InnerLayer, revisionCounter *int64, subcredential, blindedKey []byte) OuterLayer {
	return NewOuterLayer(OuterLayerContent(innerLayer, revisionCounter, subcredential, blindedKey))
}

// AuthorizedClient Client authorized to use a v3 hidden service.
// id: base64 encoded client id
// iv: base64 encoded randomized initialization vector
// cookie: base64 encoded authentication cookie
type AuthorizedClient struct {
	id     string
	iv     string
	cookie string
}

func NewAuthorizedClient() AuthorizedClient {
	a := AuthorizedClient{}
	idBytes := make([]byte, 8)
	_, _ = brand.Read(idBytes)
	a.id = strings.TrimRight(base64.StdEncoding.EncodeToString(idBytes), "=")
	ivBytes := make([]byte, 16)
	_, _ = brand.Read(ivBytes)
	a.iv = strings.TrimRight(base64.StdEncoding.EncodeToString(ivBytes), "=")
	cookieBytes := make([]byte, 16)
	_, _ = brand.Read(cookieBytes)
	a.cookie = strings.TrimRight(base64.StdEncoding.EncodeToString(cookieBytes), "=")
	return a
}

func OuterLayerContent(innerLayer *InnerLayer, revisionCounter *int64, subcredential, blindedKey []byte) string {
	if innerLayer == nil {
		tmp := InnerLayerCreate(nil)
		innerLayer = &tmp
	}

	authorizedClients := make([]AuthorizedClient, 0)
	for i := 0; i < 16; i++ {
		authorizedClients = append(authorizedClients, NewAuthorizedClient())
	}

	pk, _ := x25519.GenerateKey(brand.Reader())

	out := "desc-auth-type x25519\n"
	out += "desc-auth-ephemeral-key " + base64.StdEncoding.EncodeToString(pk.PublicKey.Bytes()) + "\n"
	for _, c := range authorizedClients {
		out += fmt.Sprintf("auth-client %s %s %s\n", c.id, c.iv, c.cookie)
	}
	out += "encrypted\n"
	out += innerLayer.encrypt(*revisionCounter, subcredential, blindedKey)
	return out
}

func NewOuterLayer(content string) OuterLayer {
	l := OuterLayer{}
	l.rawContent = content
	encrypted := parseOuterLayer(content)
	l.encrypted = encrypted
	return l
}

func parseOuterLayer(content string) string {
	out := ""
	lines := strings.Split(content, "\n")
	startEncrypted := false
	for _, line := range lines {
		if line == "encrypted" {
			startEncrypted = true
			continue
		}
		if startEncrypted {
			out += line + "\n"
			if line == "-----END MESSAGE-----" {
				startEncrypted = false
				out = strings.TrimSpace(out)
			}
		}
	}
	out = strings.ReplaceAll(out, "\r", "")
	out = strings.ReplaceAll(out, "\x00", "")
	return strings.TrimSpace(out)
}

func outerLayerDecrypt(encrypted string, revisionCounter int64, subcredential, blindedKey ed25519.PublicKey) OuterLayer {
	plaintext := decryptLayer(encrypted, "hsdir-superencrypted-data", revisionCounter, subcredential, blindedKey)
	return NewOuterLayer(plaintext)
}

func decryptLayer(encryptedBlock, constant string, revisionCounter int64, subcredential, blindedKey ed25519.PublicKey) string {
	if strings.HasPrefix(encryptedBlock, "-----BEGIN MESSAGE-----\n") &&
		strings.HasSuffix(encryptedBlock, "\n-----END MESSAGE-----") {
		encryptedBlock = strings.TrimPrefix(encryptedBlock, "-----BEGIN MESSAGE-----\n")
		encryptedBlock = strings.TrimSuffix(encryptedBlock, "\n-----END MESSAGE-----")
	}
	encrypted, err := base64.StdEncoding.DecodeString(encryptedBlock)
	if err != nil {
		panic("Unable to decode encrypted block as base64")
	}
	if len(encrypted) < SALT_LEN+MAC_LEN {
		logrus.Panicf("Encrypted block malformed (only %d bytes)", len(encrypted))
	}
	salt := encrypted[:SALT_LEN]
	ciphertext := encrypted[SALT_LEN : len(encrypted)-MAC_LEN]
	expectedMac := encrypted[len(encrypted)-MAC_LEN:]
	ciphr, macFor := layerCipher(constant, revisionCounter, subcredential, blindedKey, salt)

	if !bytes.Equal(expectedMac, macFor(ciphertext)) {
		logrus.Panicf("Malformed mac (expected %x, but was %x)", expectedMac, macFor(ciphertext))
	}

	plaintext := make([]byte, len(ciphertext))
	ciphr.XORKeyStream(plaintext, ciphertext)
	return string(plaintext)
}

func layerCipher(constant string, revisionCounter int64, subcredential []byte, blindedKey ed25519.PublicKey, salt []byte) (cipher.Stream, func([]byte) []byte) {
	keys := make([]byte, S_KEY_LEN+S_IV_LEN+MAC_LEN)
	data1 := make([]byte, 8)
	binary.BigEndian.PutUint64(data1, uint64(revisionCounter))
	data := []byte(string(blindedKey) + string(subcredential) + string(data1) + string(salt) + constant)
	sha3.ShakeSum256(keys, data)

	secretKey := keys[:S_KEY_LEN]
	secretIv := keys[S_KEY_LEN : S_KEY_LEN+S_IV_LEN]
	macKey := keys[S_KEY_LEN+S_IV_LEN:]

	block, _ := aes.NewCipher(secretKey)
	ciphr := cipher.NewCTR(block, secretIv)
	//cipher = Cipher(algorithms.AES(secret_key), modes.CTR(secret_iv), default_backend())
	data2 := make([]byte, 8)
	binary.BigEndian.PutUint64(data2, uint64(len(macKey)))
	data3 := make([]byte, 8)
	binary.BigEndian.PutUint64(data3, uint64(len(salt)))
	macPrefix := string(data2) + string(macKey) + string(data3) + string(salt)
	fn := func(ciphertext []byte) []byte {
		tmp := sha3.Sum256([]byte(macPrefix + string(ciphertext)))
		return tmp[:]
	}
	return ciphr, fn
}

const S_KEY_LEN = 32
const S_IV_LEN = 16
const SALT_LEN = 16
const MAC_LEN = 32

// IdentityKeyFromAddress converts a hidden service address into its public identity key.
func IdentityKeyFromAddress(onionAddress string) ed25519.PublicKey {
	if strings.HasSuffix(onionAddress, ".onion") {
		onionAddress = strings.TrimSuffix(onionAddress, ".onion")
	}
	decodedAddress, _ := base32.StdEncoding.DecodeString(strings.ToUpper(onionAddress))
	pubKey := decodedAddress[:32]
	expectedChecksum := decodedAddress[32:34]
	version := decodedAddress[34:35]
	checksumTmp := sha3.Sum256([]byte(".onion checksum" + string(pubKey) + string(version)))
	checksum := checksumTmp[:2]
	if !bytes.Equal(expectedChecksum, checksum) {
		logrus.Panicf("Bad checksum (expected %x but was %x)", expectedChecksum, checksum)
	}
	return pubKey
}

func AddressFromIdentityKey(pub ed25519.PublicKey) string {
	var checksumBytes bytes.Buffer
	checksumBytes.Write([]byte(".onion checksum"))
	checksumBytes.Write(pub)
	checksumBytes.Write([]byte{0x03})
	checksum := sha3.Sum256(checksumBytes.Bytes())
	var onionAddressBytes bytes.Buffer
	onionAddressBytes.Write(pub)
	onionAddressBytes.Write(checksum[:2])
	onionAddressBytes.Write([]byte{0x03})
	addr := strings.ToLower(base32.StdEncoding.EncodeToString(onionAddressBytes.Bytes()))
	return addr + ".onion"
}

func subcredential(identityKey, blindedKey ed25519.PublicKey) []byte {
	// credential = H('credential' | public - identity - key)
	// subcredential = H('subcredential' | credential | blinded - public - key)
	credential := sha3.Sum256([]byte("credential" + string(identityKey)))
	sub := sha3.Sum256([]byte("subcredential" + string(credential[:]) + string(blindedKey)))
	return sub[:]
}
