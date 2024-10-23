package onionbalance

import (
	"github.com/sirupsen/logrus"
	"gobalance/pkg/btime"
	"gobalance/pkg/clockwork"
	"gopkg.in/yaml.v3"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var once sync.Once
var inst *Onionbalance

func OnionBalance() *Onionbalance {
	once.Do(func() {
		inst = &Onionbalance{
			IsTestnet: false,
		}
	})
	return inst
}

type Onionbalance struct {
	IsTestnet   bool
	configPath  string
	configData  ConfigData
	controller  *Controller
	consensus   *Consensus
	services    []*Service
	servicesMtx sync.RWMutex
}

func (b *Onionbalance) GetServices() []*Service {
	b.servicesMtx.RLock()
	defer b.servicesMtx.RUnlock()
	return b.services
}

func (b *Onionbalance) SetServices(newVal []*Service) {
	b.servicesMtx.Lock()
	defer b.servicesMtx.Unlock()
	b.services = newVal
}

func (b *Onionbalance) Consensus() *Consensus {
	return b.consensus
}

func (b *Onionbalance) Controller() *Controller {
	return b.controller
}

type InitSubsystemsParams struct {
	ConfigPath  string
	IP          string
	Port        int
	Socket      string
	TorPassword string
}

func (b *Onionbalance) InitSubsystems(args InitSubsystemsParams) error {
	btime.Clock = clockwork.NewRealClock()
	rand.Seed(time.Now().UnixNano())

	b.configPath, _ = filepath.Abs(args.ConfigPath)
	b.configData = b.LoadConfigFile()
	b.IsTestnet = false
	if b.IsTestnet {
		logrus.Warn("OnionBalance configured on a testnet!")
	}
	b.controller = NewController(args.IP, args.Port, args.TorPassword)
	b.consensus = NewConsensus(b.controller, true)

	// Initialize our service
	b.SetServices(b.initializeServicesFromConfigData())

	// Catch interesting events (like receiving descriptors etc.)
	if err := b.controller.SetEvents(); err != nil {
		return err
	}

	logrus.Warnf("OnionBalance initialized (tor version: %s)!", b.controller.GetVersion())
	logrus.Warn(strings.Repeat("=", 80))
	return nil
}

func (b *Onionbalance) initializeServicesFromConfigData() []*Service {
	services := make([]*Service, 0)

	p := Params()
	p.SetAdaptWgEnabled(true)
	for _, svc := range b.configData.Services {
		services = append(services, NewService(b.consensus, b.controller, svc, b.configPath))
	}
	p.SetAdaptWgEnabled(false)
	return services
}

func (b *Onionbalance) LoadConfigFile() (out ConfigData) {
	logrus.Infof("Loaded the config file '%s'.", b.configPath)
	by, err := os.ReadFile(b.configPath)
	if err != nil {
		panic(err)
	}
	if err := yaml.Unmarshal(by, &out); err != nil {
		panic(err)
	}
	logrus.Debugf("OnionBalance config data: %v", out)
	return
}

// PublishAllDescriptors for each service attempt to publish all descriptors
func (b *Onionbalance) PublishAllDescriptors() {
	logrus.Info("[*] PublishAllDescriptors() called [*]")

	if !b.consensus.IsLive() {
		logrus.Info("No live consensus. Wait for Tor to grab the consensus and try again.")
		return
	}

	for _, svc := range b.GetServices() {
		svc.PublishDescriptors()
	}
}

func (b *Onionbalance) FetchInstanceDescriptors() {
	p := Params()
	logrus.Info("[*] FetchInstanceDescriptors() called [*]")
	p.SetNIntroduction(0)
	p.SetNDescriptors(0)
	p.SetAdaptHSDirFailureCount(0)
	p.SetAdaptIntroChanged(0)

	if !b.consensus.IsLive() {
		logrus.Warn("No live consensus. Wait for Tor to grab the consensus and try again.")
		return
	}

	allInstances := b.getAllInstances()

	helperFetchAllInstanceDescriptors(b.controller, allInstances)
}

// Get all instances for all services
func (b *Onionbalance) getAllInstances() []*Instance {
	instances := make([]*Instance, 0)
	b.servicesMtx.Lock()
	for _, srv := range b.services {
		instances = append(instances, srv.GetInstances()...)
	}
	b.servicesMtx.Unlock()
	return instances
}

// Try fetch fresh descriptors for all HS instances
func helperFetchAllInstanceDescriptors(ctrl *Controller, instances []*Instance) {
	logrus.Info("Initiating fetch of descriptors for all service instances.")
	p := Params()

	for {
		// Clear Tor descriptor cache before making fetches by sending the NEWNYM singal
		if _, err := ctrl.Signal("NEWNYM"); err != nil {
			if err == ErrSocketClosed {
				logrus.Error("Failed to send NEWNYM signal, socket is closed.")
				ctrl.ReAuthenticate()
				continue
			} else {
				break
			}
		}
		//TODO: Find a way to check if NEWNYM did in fact clear the descriptors.
		//Checked to see if there was a way. There isn't. Made it configurable.
		time.Sleep(p.NewnymSleep())
		break
	}

	uniqueInstances := make(map[string]*Instance)
	for _, inst := range instances {
		uniqueInstances[inst.OnionAddress] = inst
	}

	if p.AdaptWgEnabled() {
		p.SetAdaptStartTime(time.Now().Unix())
	}

	for _, inst := range uniqueInstances {
		for {
			if err := inst.FetchDescriptor(); err != nil {
				if err == ErrSocketClosed {
					logrus.Error("Failed to fetch descriptor, socket is closed")
					ctrl.ReAuthenticate()
					continue
				} else {
					break
				}
			}
			break
		}
	}
}
