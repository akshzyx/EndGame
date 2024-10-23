package onionbalance

import (
	"errors"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/btime"
	"gobalance/pkg/stem/descriptor"
	"strings"
	"sync"
	"time"
)

type Instance struct {
	controller                    *Controller
	OnionAddress                  string
	introSetChangedSincePublished bool
	descriptor                    *ReceivedDescriptor
	descriptorMtx                 sync.RWMutex
	IntroSetModifiedTimestamp     *time.Time
}

func NewInstance(controller *Controller, onionAddress string) *Instance {
	p := Params()
	i := &Instance{}
	i.controller = controller

	if onionAddress != "" {
		onionAddress = strings.Replace(onionAddress, ".onion", "", 1)
	}
	i.OnionAddress = onionAddress

	// Onion address does not contain the '.onion'.
	logrus.Warnf("Loaded instance %s", onionAddress)

	nInstances := p.NInstances()
	p.SetNInstances(nInstances + 1)
	i.introSetChangedSincePublished = false

	i.SetDescriptor(nil)

	// When was the intro set of this instance last modified?
	i.IntroSetModifiedTimestamp = nil
	return i
}

func (i *Instance) SetDescriptor(newDescriptor *ReceivedDescriptor) {
	i.descriptorMtx.Lock()
	defer i.descriptorMtx.Unlock()
	i.descriptor = newDescriptor
}

func (i *Instance) GetDescriptor() *ReceivedDescriptor {
	i.descriptorMtx.RLock()
	defer i.descriptorMtx.RUnlock()
	return i.descriptor
}

// Return True if this instance has this onion address
func (i *Instance) hasOnionAddress(onionAddress string) bool {
	// Strip the ".onion" part of the address if it exists since some
	// subsystems don't use it (e.g. Tor sometimes omits it from control
	// port responses)
	myOnionAddress := strings.TrimSuffix(i.OnionAddress, ".onion")
	theirOnionAddress := strings.TrimSuffix(onionAddress, ".onion")

	return myOnionAddress == theirOnionAddress
}

// FetchDescriptor try fetch a fresh descriptor for this service instance from the HSDirs
func (i *Instance) FetchDescriptor() error {
	logrus.Debugf("Trying to fetch a descriptor for instance %s.onion.", i.OnionAddress)
	return i.controller.GetHiddenServiceDescriptor(i.OnionAddress)
}

var ErrInstanceHasNoDescriptor = errors.New("InstanceHasNoDescriptor")
var ErrInstanceIsOffline = errors.New("InstanceIsOffline")

// GetIntrosForPublish get a list of stem.descriptor.IntroductionPointV3 objects for this descriptor
// Raise :InstanceHasNoDescriptor: if there is no descriptor for this instance
// Raise :InstanceIsOffline: if the instance is offline.
func (i *Instance) GetIntrosForPublish() ([]descriptor.IntroductionPointV3, error) {
	p := Params()
	instDescriptor := i.GetDescriptor()
	if instDescriptor == nil {
		adaptDown := p.AdaptDown()
		p.SetAdaptDown(adaptDown + 1)
		adaptDownNoDescriptor := p.AdaptDownNoDescriptor()
		p.SetAdaptDownNoDescriptor(adaptDownNoDescriptor + 1)
		return nil, ErrInstanceHasNoDescriptor
	}
	if instDescriptor.IsOld() {
		adaptDown := p.AdaptDown()
		p.SetAdaptDown(adaptDown + 1)

		adaptDownInstanceOld := p.AdaptDownInstanceOld()
		p.SetAdaptDownInstanceOld(adaptDownInstanceOld + 1)
		return nil, ErrInstanceIsOffline
	}
	adaptUp := p.AdaptUp()
	p.SetAdaptUp(adaptUp + 1)
	return instDescriptor.GetIntroPoints(), nil
}

// We received a descriptor (with 'descriptor_text') for 'onion_address'.
// Register it to this instance.
func (i *Instance) registerDescriptor(descriptorText, onionAddress string) {
	logrus.Debugf("Found instance %s for this new descriptor!", i.OnionAddress)
	p := Params()

	if onionAddress != i.OnionAddress {
		panic("onion_address != i.OnionAddress")
	}

	// Parse descriptor. If it parsed correctly, we know that this
	// descriptor is truly for this instance (since the onion address
	// matches)
	newDescriptor, err := NewReceivedDescriptor(descriptorText, onionAddress)
	if err != nil {
		if err == ErrBadDescriptor {
			logrus.Warningf("Received bad descriptor for %s. Ignoring.", i.OnionAddress)
			return
		}
		panic(err)
	}

	// Before replacing the current descriptor with this one, check if the
	// introduction point set changed:

	// If this is the first descriptor for this instance, the intro point set changed

	if i.GetDescriptor() == nil {
		logrus.Infof("This is the first time we seen a descriptor for instance %s!", i.OnionAddress)
		tmp := btime.Clock.Now().UTC()
		i.IntroSetModifiedTimestamp = &tmp
		i.SetDescriptor(newDescriptor)
		return
	}

	if i.GetDescriptor() == nil {
		panic("i.descriptor == nil")
	}
	if newDescriptor.introSet.Len() == 0 {
		panic("new_descriptor.introSet.Len() == 0")
	}

	// We already have a descriptor but this is a new one. Check the intro points!
	if !newDescriptor.introSet.Equals(*i.GetDescriptor().introSet) {
		logrus.Infof("We got a new descriptor for instance %s and the intro set changed!", i.OnionAddress)
		tmp := btime.Clock.Now().UTC()
		i.IntroSetModifiedTimestamp = &tmp
		adaptIntroChanged := p.AdaptIntroChanged()
		p.SetAdaptIntroChanged(adaptIntroChanged + 1)
	} else {
		logrus.Infof("We got a new descriptor for instance %s but the intro set did not change.", i.OnionAddress)
	}
	i.SetDescriptor(newDescriptor)

}
