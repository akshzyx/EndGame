package onionbalance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/brand"
	"gobalance/pkg/btime"
	"gobalance/pkg/gobpk"
	"gobalance/pkg/stem/descriptor"
	"golang.org/x/crypto/sha3"
	"time"
)

// V3Descriptor a generic v3 descriptor.
// Serves as the base class for OBDescriptor and ReceivedDescriptor which
// implement more specific functionalities.
type V3Descriptor struct {
	onionAddress string
	v3Desc       *descriptor.HiddenServiceDescriptorV3
	introSet     *IntroductionPointSetV3
}

// GetIntroPoints get the raw intro points for this descriptor.
func (d *V3Descriptor) GetIntroPoints() []descriptor.IntroductionPointV3 {
	return d.introSet.getIntroPointsFlat()
}

// Extract and return the blinded key from the descriptor
func (d *V3Descriptor) getBlindedKey() ed25519.PublicKey {
	// The descriptor signing cert, signs the descriptor signing key using
	// the blinded key. So the signing key should be the one we want here.
	return d.v3Desc.SigningCert.SigningKey()
}

// ReceivedDescriptor an instance v3 descriptor received from the network.
// This class supports parsing descriptors.
type ReceivedDescriptor struct {
	V3Descriptor
	receivedTs *time.Time
}

// NewReceivedDescriptor parse a descriptor in 'desc_text' and return an ReceivedDescriptor object.
// Raises BadDescriptor if the descriptor cannot be used.
func NewReceivedDescriptor(descText, onionAddress string) (*ReceivedDescriptor, error) {
	d := &ReceivedDescriptor{}
	v3Desc := &descriptor.HiddenServiceDescriptorV3{}

	v3Desc.FromStr(descText)
	if _, err := v3Desc.Decrypt(onionAddress); err != nil {
		logrus.Warnf("Descriptor is corrupted (%s).", onionAddress)
		return nil, ErrBadDescriptor
	}
	tmp := btime.Clock.Now().UTC()
	d.receivedTs = &tmp
	logrus.Debugf("Successfuly decrypted descriptor for %s!", onionAddress)

	d.onionAddress = onionAddress
	d.v3Desc = v3Desc
	p := Params()
	nIntroduction := p.NIntroduction() + int64(len(d.v3Desc.InnerLayer.IntroductionPoints))
	p.SetNIntroduction(nIntroduction)
	// An IntroductionPointSetV3 object with the intros of this descriptor
	logrus.Debugf("New Descriptor Received for %s (%d introduction points)", onionAddress, len(d.v3Desc.InnerLayer.IntroductionPoints))
	d.introSet = NewIntroductionPointSetV3([][]descriptor.IntroductionPointV3{d.v3Desc.InnerLayer.IntroductionPoints})
	logrus.Debugf("Introduction count, %d", p.NIntroduction())
	return d, nil
}

// IsOld returns True if this received descriptor is old. If so, we should consider the
// instance as offline.
func (d *ReceivedDescriptor) IsOld() bool {
	p := Params()
	receivedAge := btime.Clock.Now().UTC().Sub(*d.receivedTs).Nanoseconds()
	if receivedAge > p.InstanceDescriptorTooOld() {
		return true
	}
	return false
}

type OBDescriptor struct {
	V3Descriptor
	lastPublishAttemptTs *time.Time
	lastUploadTs         *time.Time
	responsibleHsdirs    []string
	consensus            *ConsensusDoc
}

// NewOBDescriptor A v3 descriptor created by OnionBalance and meant to be published to the
// network.
// This class supports generating descriptors.
// Can raise BadDescriptor if we can't or should not generate a valid descriptor
func NewOBDescriptor(onionAddress string, identityPrivKey gobpk.PrivateKey, blindingParam []byte, introPoints []descriptor.IntroductionPointV3, isFirstDesc bool, consensus *ConsensusDoc) (*OBDescriptor, error) {
	d := &OBDescriptor{}
	d.consensus = consensus
	// Timestamp of the last attempt to assemble this descriptor
	d.lastPublishAttemptTs = nil
	// Timestamp we last uploaded this descriptor
	d.lastUploadTs = nil
	// Set of responsible HSDirs for last time we uploaded this descriptor
	d.responsibleHsdirs = nil

	// Start generating descriptor
	_, descSigningKey, _ := ed25519.GenerateKey(brand.Reader())

	// Get the intro points for this descriptor and recertify them!
	recertifiedIntroPoints := make([]descriptor.IntroductionPointV3, 0)

	for _, ip := range introPoints {
		rec := d.recertifyIntroPoint(ip, descSigningKey)
		recertifiedIntroPoints = append(recertifiedIntroPoints, rec)
	}

	revCounter := d.getRevisionCounter(identityPrivKey, isFirstDesc)

	v3DescInnerLayer := descriptor.InnerLayerCreate(recertifiedIntroPoints)
	v3Desc := descriptor.HiddenServiceDescriptorV3Create(blindingParam, identityPrivKey, descSigningKey, v3DescInnerLayer, revCounter)

	// TODO stem should probably initialize it itself so that it has balance
	// between descriptor creation (where this is not inted) and descriptor
	// parsing (where this is inited)
	v3Desc.InnerLayer = &v3DescInnerLayer

	// Check max size is within range
	if len(v3Desc.String()) > MaxDescriptorSize {
		logrus.Errorf("Created descriptor is too big (%d bytes [max 50000]). Consider relaxing the number of introduction points included in a descriptor (see NIntrosWanted)", len(v3Desc.String()))
		return nil, ErrBadDescriptor
	}

	d.onionAddress = onionAddress
	d.v3Desc = v3Desc
	d.introSet = NewIntroductionPointSetV3([][]descriptor.IntroductionPointV3{d.v3Desc.InnerLayer.IntroductionPoints})

	return d, nil
}

// MaxDescriptorSize Max descriptor size (in bytes) (see hs_cache_get_max_descriptor_size() in
// little-t-tor)
const MaxDescriptorSize = 50000

func (d *OBDescriptor) setLastPublishAttemptTs(lastPublishAttemptTs time.Time) {
	d.lastPublishAttemptTs = &lastPublishAttemptTs
}

func (d *OBDescriptor) setLastUploadTs(lastUploadTs time.Time) {
	d.lastUploadTs = &lastUploadTs
}

func (d *OBDescriptor) setResponsibleHsdirs(responsibleHsdirs []string) {
	d.responsibleHsdirs = responsibleHsdirs
}

// Get the revision counter using the order-preserving-encryption scheme from
// rend-spec-v3.txt section F.2.
func (d *OBDescriptor) getRevisionCounter(identityPrivKey gobpk.PrivateKey, isFirstDesc bool) int64 {
	now := btime.Clock.Now().Unix()

	// TODO: Mention that this is done with the private key instead of the blinded priv key
	// this means that this won't cooperate with normal tor
	privkeyBytes := identityPrivKey.Seed()

	var srvStart int64
	if isFirstDesc {
		srvStart = d.consensus.GetStartTimeOfPreviousSrvRun()
	} else {
		srvStart = d.consensus.GetStartTimeOfCurrentSrvRun()
	}

	opeResult, secondsSinceSrvStart := getRevisionCounterDet(privkeyBytes, now, srvStart)
	logrus.Debugf("Rev counter for descriptor (FirstDesc %t) (SRV secs %d, OPE %d)", isFirstDesc, secondsSinceSrvStart, opeResult)
	return opeResult
}

func getRevisionCounterDet(privkeyBytes []byte, now, srvStart int64) (opeResult int64, secondsSinceSrvStart int64) {
	cipherKeyTmp := sha3.Sum256([]byte("rev-counter-generation" + string(privkeyBytes))) // good
	cipherKey := cipherKeyTmp[:]

	secondsSinceSrvStart = now - srvStart
	// This must be strictly positive
	secondsSinceSrvStart += 1

	iv := make([]byte, 16)
	block, _ := aes.NewCipher(cipherKey)
	stream := cipher.NewCTR(block, iv)
	getOpeSchemeWords := func() int64 {
		v := make([]byte, 16)
		stream.XORKeyStream(v, []byte("\x00\x00"))
		return int64(v[0]) + 256*int64(v[1]) + 1
	}

	for i := int64(0); i < secondsSinceSrvStart; i++ {
		opeResult += getOpeSchemeWords()
	}

	return opeResult, secondsSinceSrvStart
}

func (d *OBDescriptor) recertifyIntroPoint(introPoint descriptor.IntroductionPointV3, descriptorSigningKey ed25519.PrivateKey) descriptor.IntroductionPointV3 {
	originalAuthKeyCert := introPoint.AuthKeyCert
	originalEncKeyCert := introPoint.EncKeyCert

	// We have already removed all the intros with legacy keys. Make sure that
	// no legacy intros sneaks up on us, becausey they would result in
	// unparseable descriptors if we don't recertify them (and we won't).
	// assert(not intro_point.legacy_key_cert)

	// Get all the certs we need to recertify
	// [we need to use the _replace method of namedtuples because there is no
	// setter for those attributes due to the way stem sets those fields. If we
	// attempt to normally replace the attributes we get the following
	// exception: AttributeError: can't set attribute]
	introPoint.AuthKeyCert = d.recertifyEdCertificate(originalAuthKeyCert, descriptorSigningKey)
	introPoint.EncKeyCert = d.recertifyEdCertificate(originalEncKeyCert, descriptorSigningKey)
	introPoint.AuthKeyCertRaw = introPoint.AuthKeyCert.ToBase64()
	introPoint.EncKeyCertRaw = introPoint.EncKeyCert.ToBase64()
	recertifiedIntroPoint := introPoint

	return recertifiedIntroPoint
}

// Recertify an HSv3 intro point certificate using the new descriptor signing
// key so that it can be accepted as part of a new descriptor.
// "Recertifying" means taking the certified key and signing it with a new
// key.
// Return the new certificate.
func (d *OBDescriptor) recertifyEdCertificate(edCert descriptor.Ed25519CertificateV1, descriptorSigningKey ed25519.PrivateKey) descriptor.Ed25519CertificateV1 {
	return recertifyEdCertificate(edCert, descriptorSigningKey)
}

func recertifyEdCertificate(edCert descriptor.Ed25519CertificateV1, descriptorSigningKey ed25519.PrivateKey) descriptor.Ed25519CertificateV1 {
	extensions := []descriptor.Ed25519Extension{descriptor.NewEd25519Extension(descriptor.HasSigningKey, 0, descriptorSigningKey.Public().(ed25519.PublicKey))}
	newCert := descriptor.NewEd25519CertificateV1(edCert.Typ, &edCert.Expiration, edCert.KeyType, edCert.Key, extensions, descriptorSigningKey, nil)
	return newCert
}
