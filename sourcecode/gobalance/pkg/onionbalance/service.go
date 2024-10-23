package onionbalance

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/btime"
	"gobalance/pkg/gobpk"
	"gobalance/pkg/onionbalance/hs_v3/ext"
	"gobalance/pkg/stem/descriptor"
	"gobalance/pkg/stem/util"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Service struct {
	controller       *Controller
	identityPrivKey  gobpk.PrivateKey
	OnionAddress     string
	Instances        []*Instance
	instancesMtx     sync.RWMutex
	firstDescriptor  *OBDescriptor
	secondDescriptor *OBDescriptor
	consensus        *Consensus
}

// NewService new with 'config_data' straight out of the config file, create the service and its instances.
// 'config_path' is the full path to the config file.
// Raise ValueError if the config file is not well formatted
func NewService(consensus *Consensus, controller *Controller, serviceConfigData ServiceConfig, configPath string) *Service {
	s := &Service{}
	s.controller = controller
	s.consensus = consensus

	// Load private key and onion address from config
	// (the onion_address also includes the ".onion")
	s.identityPrivKey, s.OnionAddress = s.loadServiceKeys(serviceConfigData, configPath)

	// Now load up the instances
	s.SetInstances(s.loadInstances(serviceConfigData))

	// First descriptor for this service (the one we uploaded last)
	s.firstDescriptor = nil
	// Second descriptor for this service (the one we uploaded last)
	s.secondDescriptor = nil

	return s
}

func (s *Service) GetInstances() []*Instance {
	s.instancesMtx.RLock()
	defer s.instancesMtx.RUnlock()
	return s.Instances
}

func (s *Service) SetInstances(newInstances []*Instance) {
	s.instancesMtx.Lock()
	defer s.instancesMtx.Unlock()
	s.Instances = newInstances
}

func (s *Service) loadServiceKeys(serviceConfigData ServiceConfig, configPath string) (gobpk.PrivateKey, string) {
	// First of all let's load up the private key
	keyFname := serviceConfigData.Key
	configDirectory := filepath.Dir(configPath)
	if !filepath.IsAbs(keyFname) {
		keyFname = filepath.Join(configDirectory, keyFname)
	}
	pemKeyBytes, err := os.ReadFile(keyFname)
	if err != nil {
		logrus.Fatalf("Unable to read service private key file ('%v')", err)
	}
	var identityPrivKey ed25519.PrivateKey
	blocks, rest := pem.Decode(pemKeyBytes)
	if len(rest) == 0 {
		identityPrivKey = ed25519.NewKeyFromSeed(blocks.Bytes[16 : 16+32])
	}
	isPrivKeyInTorFormat := false
	var privKey gobpk.PrivateKey
	if identityPrivKey == nil {
		identityPrivKey = LoadTorKeyFromDisk(pemKeyBytes)
		isPrivKeyInTorFormat = true
		privKey = gobpk.New(identityPrivKey, true)
	} else {
		privKey = gobpk.New(identityPrivKey, false)
	}

	// Get onion address
	identityPubKey := identityPrivKey.Public().(ed25519.PublicKey)

	onionAddress := descriptor.AddressFromIdentityKey(identityPubKey)
	if isPrivKeyInTorFormat {
		pub := ext.PublickeyFromESK(identityPrivKey)
		onionAddress = descriptor.AddressFromIdentityKey(pub)
	}

	logrus.Warnf("Loaded onion %s from %s", onionAddress, keyFname)

	return privKey, onionAddress
}

func (s *Service) loadInstances(serviceConfigData ServiceConfig) []*Instance {
	p := Params()
	instances := make([]*Instance, 0)
	for _, configInstance := range serviceConfigData.Instances {
		newInstance := NewInstance(s.controller, configInstance.Address)
		instances = append(instances, newInstance)
	}

	if p.AdaptWgEnabled() {
		p.AdaptWg().Add(len(instances))
		adaptWgCount := p.AdaptWgCount() + int64(len(instances))
		p.SetAdaptWgCount(adaptWgCount)
		logrus.Debugf("Adding more waitgroups... current count: %d", adaptWgCount)
		p.SetAdaptWgCount(int64(len(instances)))
	}

	// Some basic validation
	for _, inst := range instances {
		if s.hasOnionAddress(inst.OnionAddress) {
			logrus.Errorf("Config file error. Did you configure your frontend (%s) as an instance?", s.OnionAddress)
			panic("BadServiceInit")
		}
	}
	return instances
}

// Return True if this service has this onion address
func (s *Service) hasOnionAddress(onionAddress string) bool {
	// Strip the ".onion" part of the address if it exists since some
	// subsystems don't use it (e.g. Tor sometimes omits it from control
	// port responses)
	myOnionAddress := strings.Replace(s.OnionAddress, ".onion", "", 1)
	theirOnionAddress := strings.Replace(onionAddress, ".onion", "", 1)
	return myOnionAddress == theirOnionAddress
}

func (s *Service) PublishDescriptors() {
	s.publishDescriptor(true)
	s.publishDescriptor(false)
}

func getRollingSubArr[T any](arr []T, idx, count int) (out []T) {
	begin := (idx * count) % len(arr)
	for i := 0; i < count; i++ {
		out = append(out, arr[begin])
		begin = (begin + 1) % len(arr)
	}
	return
}

// Attempt to publish descriptor if needed.
// If 'is_first_desc' is set then attempt to upload the first descriptor
// of the service, otherwise the second.
func (s *Service) publishDescriptor(isFirstDesc bool) {
	p := Params()
	if p.AdaptDistinctDescriptors() == 1 {
		_, timePeriodNumber := GetSrvAndTimePeriod(isFirstDesc, *s.consensus.Consensus())
		blindingParam := s.consensus.consensus.GetBlindingParam(s.getIdentityPubkeyBytes(), timePeriodNumber)
		desc, err := NewOBDescriptor(s.OnionAddress, s.identityPrivKey, blindingParam, nil, isFirstDesc, s.consensus.Consensus())
		if err != nil {
			if err == ErrBadDescriptor {
				return
			}
			panic(err)
		}
		blindedKey := desc.getBlindedKey()
		responsibleHsdirs, err := GetResponsibleHsdirs(blindedKey, isFirstDesc, s.consensus)
		if err != nil {
			if err == ErrEmptyHashRing {
				logrus.Warning("Can't publish desc with no hash ring. Delaying...")
				return
			}
			panic(err)
		}

		introPointsForDistinctDesc, err := s.getIntrosForDistinctDesc()
		if err != nil {
			if err == ErrNotEnoughIntros {
				return
			}
			panic(err)
		}

		// Iterate all hsdirs, and create a distinct descriptor with a distinct set of intro points for each of them
		for idx, hsdir := range responsibleHsdirs {
			introPoints := getRollingSubArr(introPointsForDistinctDesc, idx, p.NIntrosWanted())
			desc, err := NewOBDescriptor(s.OnionAddress, s.identityPrivKey, blindingParam, introPoints, isFirstDesc, s.consensus.Consensus())
			if err != nil {
				if err == ErrBadDescriptor {
					return
				}
				panic(err)
			}
			s.uploadDescriptor(s.controller, desc, []string{hsdir})
		}
		return
	}

	if !s.shouldPublishDescriptorNow(isFirstDesc) {
		logrus.Infof("No reason to publish %t descriptor for %s", isFirstDesc, s.OnionAddress)
		return
	}

	introPoints, err := s.getIntrosForDesc()
	if err != nil {
		if err == ErrNotEnoughIntros {
			return
		}
		panic(err)
	}

	// Derive blinding parameter
	_, timePeriodNumber := GetSrvAndTimePeriod(isFirstDesc, *s.consensus.Consensus())
	blindingParam := s.consensus.consensus.GetBlindingParam(s.getIdentityPubkeyBytes(), timePeriodNumber)

	desc, err := NewOBDescriptor(s.OnionAddress, s.identityPrivKey, blindingParam, introPoints, isFirstDesc, s.consensus.Consensus())
	if err != nil {
		if err == ErrBadDescriptor {
			return
		}
		panic(err)
	}

	logrus.Infof("Service %s created %t descriptor (%d intro points) (blinding param: %x) (size: %d bytes). About to publish:",
		s.OnionAddress, isFirstDesc, desc.introSet.Len(), blindingParam, len(desc.v3Desc.String()))

	// When we do a v3 HSPOST on the control port, Tor decodes the
	// descriptor and extracts the blinded pubkey to be used when uploading
	// the descriptor. So let's do the same to compute the responsible
	// HSDirs:
	blindedKey := desc.getBlindedKey()

	// Calculate responsible HSDirs for our service
	responsibleHsdirs, err := GetResponsibleHsdirs(blindedKey, isFirstDesc, s.consensus)
	if err != nil {
		if err == ErrEmptyHashRing {
			logrus.Warning("Can't publish desc with no hash ring. Delaying...")
			return
		}
		panic(err)
	}

	desc.setLastPublishAttemptTs(btime.Clock.Now().UTC())

	logrus.Infof("Uploading descriptor for %s to %s", s.OnionAddress, responsibleHsdirs)

	// Upload descriptor
	s.uploadDescriptor(s.controller, desc, responsibleHsdirs)

	// It would be better to set last_upload_ts when an upload succeeds and
	// not when an upload is just attempted. Unfortunately the HS_DESC #
	// UPLOADED event does not provide information about the service and
	// so it can't be used to determine when descriptor upload succeeds
	desc.setLastUploadTs(btime.Clock.Now().UTC())
	desc.setResponsibleHsdirs(responsibleHsdirs)

	// Set the descriptor
	if isFirstDesc {
		s.firstDescriptor = desc
	} else {
		s.secondDescriptor = desc
	}
}

// Convenience method to upload a descriptor
// Handle some error checking and logging inside the Service class
func (s *Service) uploadDescriptor(controller *Controller, obDesc *OBDescriptor, hsdirs []string) {
	for {
		err := commonUploadDescriptor(controller, obDesc.v3Desc, hsdirs, obDesc.onionAddress)
		if err != nil {
			if err == ErrSocketClosed {
				logrus.Errorf("Error uploading descriptor for service %s.onion. Control port socket is closed.", obDesc.onionAddress)
				controller.ReAuthenticate()
				continue
			} else {
				logrus.Errorf("Error uploading descriptor for service %s.onion.: %v", obDesc.onionAddress, err)
				break
			}
		}
		break
	}
}

func commonUploadDescriptor(controller *Controller, signedDescriptor *descriptor.HiddenServiceDescriptorV3, hsdirs []string, v3OnionAddress string) error {
	logrus.Debug("Beginning service descriptor upload.")
	serverArgs := ""
	// Provide server fingerprints to control command if HSDirs are specified.
	if hsdirs != nil {
		strs := make([]string, 0)
		for _, hsDir := range hsdirs {
			strs = append(strs, "SERVER="+hsDir)
		}
		serverArgs += strings.Join(strs, " ")
	}
	if v3OnionAddress != "" {
		serverArgs += " HSADDRESS=" + strings.Replace(v3OnionAddress, ".onion", "", 1)
	}
	msg := fmt.Sprintf("+HSPOST %s\n%s\r\n.\r\n", serverArgs, signedDescriptor)
	res, err := controller.Msg(msg)
	if err != nil {
		return err
	}
	if res != "250 OK" {
		return fmt.Errorf("HSPOST returned unexpected response code: %s", res)
	}
	return nil
}

// Returns a slice of intro points where duplicates have been removed.
// Keep the original order.
func unique(arr []descriptor.IntroductionPointV3) []descriptor.IntroductionPointV3 {
	out := make([]descriptor.IntroductionPointV3, 0, len(arr))
	cache := make(map[string]struct{})
	for _, el := range arr {
		if _, ok := cache[el.OnionKey]; !ok {
			out = append(out, el)
			cache[el.OnionKey] = struct{}{}
		}
	}
	return out
}

var ErrEmptyHashRing = errors.New("EmptyHashRing")
var ErrBadDescriptor = errors.New("BadDescriptor")
var ErrNotEnoughIntros = errors.New("NotEnoughIntros")

// Get all unique intros in a flat array
func (s *Service) getIntrosForDistinctDesc() ([]descriptor.IntroductionPointV3, error) {
	allIntros := s.getAllIntrosForPublish()
	allIntrosFlat := allIntros.getIntroPointsFlat()
	uniqueIntros := unique(allIntrosFlat)
	finalIntros := uniqueIntros
	if len(finalIntros) == 0 {
		logrus.Info("Got no usable intro points from our instances. Delaying descriptor push...")
		return nil, ErrNotEnoughIntros
	}
	return finalIntros, nil
}

// Get the intros that should be included in a descriptor for this service.
func (s *Service) getIntrosForDesc() ([]descriptor.IntroductionPointV3, error) {
	p := Params()
	allIntros := s.getAllIntrosForPublish()

	// Get number of instances that contributed to final intro point list
	nIntros := len(allIntros.introPoints)
	nIntrosWanted := nIntros * p.NIntrosPerInstance()

	//Make sure not to pass the Tor process max of 20 introduction points
	if nIntrosWanted > 20 {
		nIntrosWanted = 20
	}

	//Make sure to require at least 3 introduction points to prevent gobalance from being obvious in low instance counts
	if nIntrosWanted < 3 {
		nIntrosWanted = 3
	}

	finalIntros := allIntros.choose(nIntrosWanted)
	if len(finalIntros) == 0 {
		logrus.Info("Got no usable intro points from our instances. Delaying descriptor push...")
		return nil, ErrNotEnoughIntros
	}

	logrus.Infof("We got %d intros from %d instances. We want %d intros ourselves (got: %d)", len(allIntros.getIntroPointsFlat()), nIntros, nIntrosWanted, len(finalIntros))

	return finalIntros, nil
}

// Return an IntroductionPointSetV3 with all the intros of all the instances
// of this service.
func (s *Service) getAllIntrosForPublish() *IntroductionPointSetV3 {
	allIntros := make([][]descriptor.IntroductionPointV3, 0)
	p := Params()

	// Sort instances to have newer descriptor received first.
	s.instancesMtx.Lock()
	sort.Slice(s.Instances, func(i, j int) bool {
		instIDescriptor := s.Instances[i].GetDescriptor()
		instJDescriptor := s.Instances[j].GetDescriptor()
		if instIDescriptor == nil || instIDescriptor.receivedTs == nil {
			return false
		}
		if instJDescriptor == nil || instJDescriptor.receivedTs == nil {
			return true
		}
		return instIDescriptor.receivedTs.After(*instJDescriptor.receivedTs)
	})
	s.instancesMtx.Unlock()

	p.SetAdaptUp(0)
	p.SetAdaptDown(0)
	p.SetAdaptDownNoDescriptor(0)
	p.SetAdaptDownInstanceOld(0)
	p.SetAdaptFetchFail(0)

	for _, inst := range s.GetInstances() {
		instanceIntros, err := inst.GetIntrosForPublish()
		if err != nil {
			if err == ErrInstanceHasNoDescriptor {
				logrus.Infof("Entirely missing a descriptor for instance %s. Continuing anyway if possible", inst.OnionAddress)
				continue
			} else if err == ErrInstanceIsOffline {
				logrus.Infof("Instance %s is offline. Ignoring its intro points...", inst.OnionAddress)
				continue
			}
		}
		allIntros = append(allIntros, instanceIntros)
	}
	adaptCount := p.AdaptUp() - p.AdaptDown()
	p.SetAdaptCount(adaptCount)
	logrus.Debugf("Current Adapt Count: %d", adaptCount)
	return NewIntroductionPointSetV3(allIntros)
}

type IntroductionPointSet struct {
}

type IntroductionPointSetV3 struct {
	IntroductionPointSet
	introPoints [][]descriptor.IntroductionPointV3
}

func NewIntroductionPointSetV3(introductionPoints [][]descriptor.IntroductionPointV3) *IntroductionPointSetV3 {
	for _, instanceIps := range introductionPoints {
		for i := len(instanceIps) - 1; i >= 0; i-- {
			if instanceIps[i].LegacyKeyRaw != nil {
				logrus.Info("Ignoring introduction point with legacy key.")
				instanceIps = append(instanceIps[:i], instanceIps[i+1:]...)
			}
		}
	}

	i := &IntroductionPointSetV3{}

	for idx, instanceIntroPoints := range introductionPoints {
		rand.Shuffle(len(instanceIntroPoints), func(i, j int) {
			introductionPoints[idx][i], introductionPoints[idx][j] = introductionPoints[idx][j], introductionPoints[idx][i]
		})
	}
	rand.Shuffle(len(introductionPoints), func(i, j int) {
		introductionPoints[i], introductionPoints[j] = introductionPoints[j], introductionPoints[i]
	})
	i.introPoints = introductionPoints
	// self._intro_point_generator = self._get_intro_point()
	return i
}

func (i IntroductionPointSetV3) Equals(other IntroductionPointSetV3) bool {
	aIntroPoints := i.getIntroPointsFlat()
	bIntroPoints := other.getIntroPointsFlat()
	sort.Slice(aIntroPoints, func(i, j int) bool { return aIntroPoints[i].OnionKey < aIntroPoints[j].OnionKey })
	sort.Slice(bIntroPoints, func(i, j int) bool { return bIntroPoints[i].OnionKey < bIntroPoints[j].OnionKey })
	if len(aIntroPoints) != len(bIntroPoints) {
		return false
	}
	for idx := 0; idx < len(aIntroPoints); idx++ {
		if !aIntroPoints[idx].Equals(bIntroPoints[idx]) {
			return false
		}
	}
	return true
}

func (i IntroductionPointSetV3) Len() (count int) {
	for _, ip := range i.introPoints {
		count += len(ip)
	}
	return
}

// Flatten the .intro_points list of list into a single list and return it
func (i IntroductionPointSetV3) getIntroPointsFlat() []descriptor.IntroductionPointV3 {
	flatten := make([]descriptor.IntroductionPointV3, 0)
	for _, ip := range i.introPoints {
		flatten = append(flatten, ip...)
	}
	return flatten
}

// Retrieve N introduction points from the set of IPs
// Where more than `count` IPs are available, introduction points are
// selected to try and achieve the greatest distribution of introduction
// points across all the available backend instances.
// Return a list of IntroductionPoints.
func (i IntroductionPointSetV3) choose(count int) []descriptor.IntroductionPointV3 {
	p := Params()
	choosenIps := i.getIntroPointsFlat()
	if p.AdaptShuffle() == 1 {
		rand.Shuffle(len(choosenIps), func(i, j int) { choosenIps[i], choosenIps[j] = choosenIps[j], choosenIps[i] })
	}
	if len(choosenIps) > count {
		choosenIps = choosenIps[:count]
	}
	return choosenIps
}

// Return True if we should publish a descriptor right now
func (s *Service) shouldPublishDescriptorNow(isFirstDesc bool) bool {
	p := Params()
	// If descriptor not yet uploaded, do it now!
	if isFirstDesc && s.firstDescriptor == nil {
		logrus.Debugf("Descriptor not uploaded!")
		return true
	}
	if !isFirstDesc && s.secondDescriptor == nil {
		logrus.Debugf("Second descriptor not uploaded!")
		return true
	}

	if p.AdaptForcePublish() == 1 {
		return true
	}

	if s.introSetModified(isFirstDesc) {
		logrus.Debugf("Intro set was modified!")
	}

	if s.descriptorHasExpired(isFirstDesc) {
		logrus.Debugf("Descriptor expired!")
	}

	if s.HsdirSetChanged(isFirstDesc) {
		logrus.Debugf("HSDIR set was changed!")
	}

	// OK this is not the first time we publish a descriptor. Check various
	// parameters to see if we should try to publish again:
	return s.introSetModified(isFirstDesc) ||
		s.descriptorHasExpired(isFirstDesc) ||
		s.HsdirSetChanged(isFirstDesc)
}

// Check if the introduction point set has changed since last publish.
func (s *Service) introSetModified(isFirstDesc bool) bool {
	var lastUploadTs *time.Time
	if isFirstDesc {
		lastUploadTs = s.firstDescriptor.lastUploadTs
	} else {
		lastUploadTs = s.secondDescriptor.lastUploadTs
	}
	if lastUploadTs == nil {
		logrus.Info("\t Descriptor never published before. Do it now!")
		return true
	}
	for _, inst := range s.GetInstances() {
		if inst.IntroSetModifiedTimestamp == nil {
			logrus.Info("\t Still dont have a descriptor for this instance")
			continue
		}
		if (*inst.IntroSetModifiedTimestamp).After(*lastUploadTs) {
			logrus.Info("\t Intro set modified")
			return true
		}
	}
	logrus.Info("\t Intro set not modified")
	return false
}

// Check if the descriptor has expired (hasn't been uploaded recently).
// If 'is_first_desc' is set then check the first descriptor of the
// service, otherwise the second.
func (s *Service) descriptorHasExpired(isFirstDesc bool) bool {
	var lastUploadTs *time.Time
	if isFirstDesc {
		lastUploadTs = s.firstDescriptor.lastUploadTs
	} else {
		lastUploadTs = s.secondDescriptor.lastUploadTs
	}
	descriptorAge := time.Now().Sub(*lastUploadTs).Seconds()
	if descriptorAge > s.getDescriptorLifetime().Seconds() {
		logrus.Infof("\t Our %t descriptor has expired (%g seconds old). Uploading new one.", isFirstDesc, descriptorAge)
		return true
	}
	logrus.Infof("\t Our %t descriptor is still fresh (%g seconds old).", isFirstDesc, descriptorAge)
	return false
}

// HsdirSetChanged return True if the HSDir has changed between the last upload of this
// descriptor and the current state of things
func (s *Service) HsdirSetChanged(isFirstDesc bool) bool {
	// Derive blinding parameter
	_, timePeriodNumber := GetSrvAndTimePeriod(isFirstDesc, *s.consensus.Consensus())
	blindedParam := s.consensus.Consensus().GetBlindingParam(s.getIdentityPubkeyBytes(), timePeriodNumber)

	// Get blinded key
	blindedKey := util.BlindedPubkey(s.getIdentityPubkeyBytes(), blindedParam)

	responsibleHsdirs, err := GetResponsibleHsdirs(blindedKey, isFirstDesc, s.consensus)
	if err != nil {
		if err == ErrEmptyHashRing {
			return false
		}
		panic(err)
	}

	var previousResponsibleHsdirs []string
	if isFirstDesc {
		previousResponsibleHsdirs = s.firstDescriptor.responsibleHsdirs
	} else {
		previousResponsibleHsdirs = s.secondDescriptor.responsibleHsdirs
	}

	sort.Strings(responsibleHsdirs)
	sort.Strings(previousResponsibleHsdirs)
	if len(responsibleHsdirs) != len(previousResponsibleHsdirs) {
		logrus.Infof("\t HSDir set changed (%s vs %s)", responsibleHsdirs, previousResponsibleHsdirs)
		return true
	}
	changed := false
	for i, el := range responsibleHsdirs {
		if previousResponsibleHsdirs[i] != el {
			changed = true
		}
	}
	if changed {
		logrus.Infof("\t HSDir set changed (%s vs %s)", responsibleHsdirs, previousResponsibleHsdirs)
		return true
	}

	logrus.Info("\t HSDir set remained the same")
	return false
}

func (s *Service) getIdentityPubkeyBytes() ed25519.PublicKey {
	return s.identityPrivKey.Public()
}

func (s *Service) getDescriptorLifetime() time.Duration {
	//if onionbalance.OnionBalance().IsTestnet {
	//	return param.FrontendDescriptorLifetimeTestnet
	//}
	p := Params()
	return time.Duration(p.FrontendDescriptorLifetime())
}
