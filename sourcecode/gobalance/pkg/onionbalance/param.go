package onionbalance

import (
	"sync"
	"time"
)

var (
	params     *Param
	paramsOnce sync.Once
)

func Params() *Param {
	paramsOnce.Do(func() {
		params = new(Param)
		params.adaptWg = &sync.WaitGroup{}
		params.FetchChannel = make(chan bool)
		params.PublishChannel = make(chan bool)
	})
	return params
}

type Param struct {
	sync.Mutex

	initialCallbackDelay            int64
	fetchDescriptorFrequency        int64
	publishDescriptorCheckFrequency int64
	frontendDescriptorLifetime      int64
	instanceDescriptorTooOld        int64
	hsdirNReplicas                  int

	hsdirSpreadStore   int
	nIntrosPerInstance int
	nIntrosWanted      int
	tightTimings       bool
	newnymSleep        time.Duration

	// NInstances configures on boot. Don't change default value.
	nInstances    int64
	nDescriptors  int64
	nIntroduction int64

	adaptEnabled   bool
	adaptStrict    bool
	adaptWg        *sync.WaitGroup
	adaptWgCount   int64
	adaptWgEnabled bool
	FetchChannel   chan bool
	PublishChannel chan bool

	adaptDistinctDescriptors int64
	adaptStartTime           int64
	adaptDelay               int64
	adaptHSDirCount          int64
	adaptHSDirFailureCount   int64

	adaptCount            int64
	adaptUp               int64
	adaptDown             int64
	adaptDownNoDescriptor int64
	adaptDownInstanceOld  int64
	adaptIntroChanged     int64
	adaptDescriptorFail   int64
	adaptFetchFail        int64

	adaptForcePublish int64

	adaptShuffle int64

	dirStart int
	dirEnd   int
}

func (p *Param) InitialCallbackDelay() int64 {
	p.Lock()
	defer p.Unlock()
	return p.initialCallbackDelay
}

func (p *Param) SetInitialCallbackDelay(initialCallbackDelay int64) {
	p.Lock()
	defer p.Unlock()
	p.initialCallbackDelay = initialCallbackDelay
}

func (p *Param) FetchDescriptorFrequency() int64 {
	p.Lock()
	defer p.Unlock()
	return p.fetchDescriptorFrequency
}

func (p *Param) SetFetchDescriptorFrequency(fetchDescriptorFrequency int64) {
	p.Lock()
	defer p.Unlock()
	p.fetchDescriptorFrequency = fetchDescriptorFrequency
}

func (p *Param) PublishDescriptorCheckFrequency() int64 {
	p.Lock()
	defer p.Unlock()
	return p.publishDescriptorCheckFrequency
}

func (p *Param) SetPublishDescriptorCheckFrequency(publishDescriptorCheckFrequency int64) {
	p.Lock()
	defer p.Unlock()
	p.publishDescriptorCheckFrequency = publishDescriptorCheckFrequency
}

func (p *Param) FrontendDescriptorLifetime() int64 {
	p.Lock()
	defer p.Unlock()
	return p.frontendDescriptorLifetime
}

func (p *Param) SetFrontendDescriptorLifetime(frontendDescriptorLifetime int64) {
	p.Lock()
	defer p.Unlock()
	p.frontendDescriptorLifetime = frontendDescriptorLifetime
}

func (p *Param) InstanceDescriptorTooOld() int64 {
	p.Lock()
	defer p.Unlock()
	return p.instanceDescriptorTooOld
}

func (p *Param) SetInstanceDescriptorTooOld(instanceDescriptorTooOld int64) {
	p.Lock()
	defer p.Unlock()
	p.instanceDescriptorTooOld = instanceDescriptorTooOld
}

func (p *Param) HsdirNReplicas() int {
	p.Lock()
	defer p.Unlock()
	return p.hsdirNReplicas
}

func (p *Param) SetHsdirNReplicas(hsdirNReplicas int) {
	p.Lock()
	defer p.Unlock()
	p.hsdirNReplicas = hsdirNReplicas
}

func (p *Param) HsdirSpreadStore() int {
	p.Lock()
	defer p.Unlock()
	return p.hsdirSpreadStore
}

func (p *Param) SetHsdirSpreadStore(hsdirSpreadStore int) {
	p.Lock()
	defer p.Unlock()
	p.hsdirSpreadStore = hsdirSpreadStore
}

func (p *Param) NIntrosPerInstance() int {
	p.Lock()
	defer p.Unlock()
	return p.nIntrosPerInstance
}

func (p *Param) SetNIntrosPerInstance(nIntrosPerInstance int) {
	p.Lock()
	defer p.Unlock()
	p.nIntrosPerInstance = nIntrosPerInstance
}

func (p *Param) NIntrosWanted() int {
	p.Lock()
	defer p.Unlock()
	return p.nIntrosWanted
}

func (p *Param) SetNIntrosWanted(nIntrosWanted int) {
	p.Lock()
	defer p.Unlock()
	p.nIntrosWanted = nIntrosWanted
}

func (p *Param) TightTimings() bool {
	p.Lock()
	defer p.Unlock()
	return p.tightTimings
}

func (p *Param) SetTightTimings(tightTimings bool) {
	p.Lock()
	defer p.Unlock()
	p.tightTimings = tightTimings
}

func (p *Param) NewnymSleep() time.Duration {
	p.Lock()
	defer p.Unlock()
	return p.newnymSleep
}

func (p *Param) SetNewnymSleep(newnymSleep time.Duration) {
	p.Lock()
	defer p.Unlock()
	p.newnymSleep = newnymSleep
}

func (p *Param) NInstances() int64 {
	p.Lock()
	defer p.Unlock()
	return p.nInstances
}

func (p *Param) SetNInstances(nInstances int64) {
	p.Lock()
	defer p.Unlock()
	p.nInstances = nInstances
}

func (p *Param) NDescriptors() int64 {
	p.Lock()
	defer p.Unlock()
	return p.nDescriptors
}

func (p *Param) SetNDescriptors(nDescriptors int64) {
	p.Lock()
	defer p.Unlock()
	p.nDescriptors = nDescriptors
}

func (p *Param) NIntroduction() int64 {
	p.Lock()
	defer p.Unlock()
	return p.nIntroduction
}

func (p *Param) SetNIntroduction(nIntroduction int64) {
	p.Lock()
	defer p.Unlock()
	p.nIntroduction = nIntroduction
}

func (p *Param) AdaptEnabled() bool {
	p.Lock()
	defer p.Unlock()
	return p.adaptEnabled
}

func (p *Param) SetAdaptEnabled(adaptEnabled bool) {
	p.Lock()
	defer p.Unlock()
	p.adaptEnabled = adaptEnabled
}

func (p *Param) AdaptStrict() bool {
	p.Lock()
	defer p.Unlock()
	return p.adaptStrict
}

func (p *Param) SetAdaptStrict(adaptStrict bool) {
	p.Lock()
	defer p.Unlock()
	p.adaptStrict = adaptStrict
}

func (p *Param) AdaptWg() *sync.WaitGroup {
	p.Lock()
	defer p.Unlock()
	return p.adaptWg
}

func (p *Param) SetAdaptWg(adaptWg *sync.WaitGroup) {
	p.Lock()
	defer p.Unlock()
	p.adaptWg = adaptWg
}

func (p *Param) AdaptWgCount() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptWgCount
}

func (p *Param) SetAdaptWgCount(adaptWgCount int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptWgCount = adaptWgCount
}

func (p *Param) AdaptWgEnabled() bool {
	p.Lock()
	defer p.Unlock()
	return p.adaptWgEnabled
}

func (p *Param) SetAdaptWgEnabled(adaptWgEnabled bool) {
	p.Lock()
	defer p.Unlock()
	p.adaptWgEnabled = adaptWgEnabled
}

func (p *Param) AdaptDistinctDescriptors() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptDistinctDescriptors
}

func (p *Param) SetAdaptDistinctDescriptors(adaptDistinctDescriptors int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptDistinctDescriptors = adaptDistinctDescriptors
}

func (p *Param) AdaptStartTime() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptStartTime
}

func (p *Param) SetAdaptStartTime(adaptStartTime int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptStartTime = adaptStartTime
}

func (p *Param) AdaptDelay() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptDelay
}

func (p *Param) SetAdaptDelay(adaptDelay int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptDelay = adaptDelay
}

func (p *Param) AdaptHSDirCount() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptHSDirCount
}

func (p *Param) SetAdaptHSDirCount(adaptHSDirCount int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptHSDirCount = adaptHSDirCount
}

func (p *Param) AdaptHSDirFailureCount() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptHSDirFailureCount
}

func (p *Param) SetAdaptHSDirFailureCount(adaptHSDirFailureCount int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptHSDirFailureCount = adaptHSDirFailureCount
}

func (p *Param) AdaptCount() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptCount
}

func (p *Param) SetAdaptCount(adaptCount int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptCount = adaptCount
}

func (p *Param) AdaptUp() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptUp
}

func (p *Param) SetAdaptUp(adaptUp int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptUp = adaptUp
}

func (p *Param) AdaptDown() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptDown
}

func (p *Param) SetAdaptDown(adaptDown int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptDown = adaptDown
}

func (p *Param) AdaptDownNoDescriptor() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptDownNoDescriptor
}

func (p *Param) SetAdaptDownNoDescriptor(adaptDownNoDescriptor int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptDownNoDescriptor = adaptDownNoDescriptor
}

func (p *Param) AdaptDownInstanceOld() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptDownInstanceOld
}

func (p *Param) SetAdaptDownInstanceOld(adaptDownInstanceOld int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptDownInstanceOld = adaptDownInstanceOld
}

func (p *Param) AdaptIntroChanged() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptIntroChanged
}

func (p *Param) SetAdaptIntroChanged(adaptIntroChanged int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptIntroChanged = adaptIntroChanged
}

func (p *Param) AdaptDescriptorFail() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptDescriptorFail
}

func (p *Param) SetAdaptDescriptorFail(adaptDescriptorFail int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptDescriptorFail = adaptDescriptorFail
}

func (p *Param) AdaptFetchFail() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptFetchFail
}

func (p *Param) SetAdaptFetchFail(adaptFetchFail int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptFetchFail = adaptFetchFail
}

func (p *Param) AdaptForcePublish() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptForcePublish
}

func (p *Param) SetAdaptForcePublish(adaptForcePublish int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptForcePublish = adaptForcePublish
}

func (p *Param) AdaptShuffle() int64 {
	p.Lock()
	defer p.Unlock()
	return p.adaptShuffle
}

func (p *Param) SetAdaptShuffle(adaptShuffle int64) {
	p.Lock()
	defer p.Unlock()
	p.adaptShuffle = adaptShuffle
}

func (p *Param) DirStart() int {
	p.Lock()
	defer p.Unlock()
	return p.dirStart
}

func (p *Param) SetDirStart(dirStart int) {
	p.Lock()
	defer p.Unlock()
	p.dirStart = dirStart
}

func (p *Param) DirEnd() int {
	p.Lock()
	defer p.Unlock()
	return p.dirEnd
}

func (p *Param) SetDirEnd(dirEnd int) {
	p.Lock()
	defer p.Unlock()
	p.dirEnd = dirEnd
}

//const (
//	// FrontendDescriptorLifetime How long should we keep a frontend descriptor before we expire it (in
//	// seconds)?
//	FrontendDescriptorLifetime        = 60 * 60
//	FrontendDescriptorLifetimeTestnet = 20
//
//	// HsdirNReplicas Number of replicas per descriptor
//	HsdirNReplicas = 2
//
//	// HsdirSpreadStore How many uploads per replica
//	// [TODO: Get these from the consensus instead of hardcoded]
//	HsdirSpreadStore = 4
//
//	// InstanceDescriptorTooOld If we last received a descriptor for this instance more than
//	// INSTANCE_DESCRIPTOR_TOO_OLD seconds ago, consider the instance to be down.
//	InstanceDescriptorTooOld = 60 * 60
//
//	// NIntrosPerInstance How many intros should we use from each instance in the final frontend
//	// descriptor?
//	// [TODO: This makes no attempt to hide the use of onionbalance. In the future we
//	// should be smarter and sneakier here.]
//	NIntrosPerInstance = 2
//)
