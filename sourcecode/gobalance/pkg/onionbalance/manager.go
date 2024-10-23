package onionbalance

import (
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"time"
)

func loadDefaults() {
	p := Params()
	// InitialCallbackDelay How long to wait for onionbalance to bootstrap before starting periodic
	// events (in nanoseconds). 10 base plus 2 seconds here for every single front you have. (10 instances = 10 + (10X2) = 30) times 1 billion.
	p.SetInitialCallbackDelay(75 * 1000000000) //time is in nanoseconds
	// FetchDescriptorFrequency Every how often we should be fetching instance descriptors (in seconds)
	p.SetFetchDescriptorFrequency(20 * 1000000000)
	// PublishDescriptorCheckFrequency Every how often we should be checking whether we should publish our frontend
	// descriptor (in nanoseconds). Triggering this callback doesn't mean we will actually upload a descriptor.
	// We only upload a descriptor if it has expired, the intro points have changed, etc. Default
	p.SetPublishDescriptorCheckFrequency(30 * 1000000000)
	// FrontendDescriptorLifetime How long should we keep a frontend descriptor before we expire it (in
	// nanoseconds)?
	p.SetFrontendDescriptorLifetime(40 * 1000000000)
	// InstanceDescriptorTooOld If we last received a descriptor for this instance more than
	// INSTANCE_DESCRIPTOR_TOO_OLD seconds ago, consider the instance to be down.
	p.SetInstanceDescriptorTooOld(120 * 1000000000)
	// HsdirNReplicas Number of replicas per descriptor (generally only use 2!)
	p.SetHsdirNReplicas(2)
	// NIntrosPerInstance How many intros should we use from each instance in the final frontend
	// descriptor? Default 2 but we use 1 here.
	p.SetNIntrosPerInstance(1)
	// NIntrosWanted The amount of introduction points wanted for each individual descriptor
	p.SetNIntrosWanted(20)
	// NEWNYM is a tor control port command which clears the descriptors. Tor has a rate limit on this to about 8 seconds.
	// In the event that changes this variable can be adjusted. Otherwise, don't touch.
	p.SetNewnymSleep(8 * time.Second)

	// Below is the adaptive configuration area. Don't touch these!
	p.SetAdaptForcePublish(1)
	p.SetAdaptDistinctDescriptors(1)
}

// Main This is the entry point of v3 functionality.
// Initialize onionbalance, schedule future jobs and let the scheduler do its thing.
func Main(c *cli.Context) {
	loadDefaults()
	p := Params()
	if p.NIntrosWanted() > 20 {
		logrus.Fatal("You need to reduce the NIntrosWanted param value to 20 or below. " +
			"While it's possible to push more than 20 introduction points; the Tor clients, " +
			"at this time, will reject the descriptor. See tor's HS_CONFIG_V3_MAX_INTRO_POINTS in hs_config.h and function " +
			"desc_decode_encrypted_v3 in hs_descriptor.c")
	}
	p.SetAdaptEnabled(c.Bool("adaptive"))
	p.SetAdaptStrict(c.Bool("strict"))
	p.SetTightTimings(c.Bool("tight"))
	config := c.String("config")
	ip := c.String("ip")
	port := c.Int("port")
	quick := c.Bool("quick")
	torPassword := c.String("torPassword")
	start, end, err := parseRange(c.String("dirsplit"))
	if err != nil {
		logrus.Errorf("Your dirsplit value is invalid! Error: " + err.Error())
	}
	p.SetDirStart(start)
	p.SetDirEnd(end)
	MyOnionBalance := OnionBalance()
	if err := MyOnionBalance.InitSubsystems(InitSubsystemsParams{
		ConfigPath:  config,
		IP:          ip,
		Port:        port,
		TorPassword: torPassword,
	}); err != nil {
		panic(err)
	}
	initScheduler(quick)
}

func initScheduler(quick bool) {
	p := Params()
	instance := OnionBalance()

	// Tell Tor to be active and ready.
	go torActive(instance.Controller())

	//Check if Tor has live consensus before doing anything.
	if !instance.Consensus().IsLive() {
		logrus.Fatal("No live consensus. Wait for Tor to grab the consensus and try again.")
	}

	if p.AdaptEnabled() {
		adaptiveStart(*instance)
	} else {
		instance.FetchInstanceDescriptors()
		// Quick is a hack to quickly deploy a new descriptor. Used to fix a suck descriptor.
		if quick {
			time.Sleep(5 * time.Second)
		} else {
			time.Sleep(time.Duration(p.InitialCallbackDelay()))
		}
		instance.PublishAllDescriptors()
	}

	rand.Seed(time.Now().UnixNano())

	//individual async channel threads for both fetching and publishing descriptors.
	go func() {
		for {
			select {
			case <-time.After(time.Duration(p.FetchDescriptorFrequency())):
			case <-p.FetchChannel:
				continue
			}
			run := adaptFetch()
			if run {
				//variate timings to reduce correlation attacks
				rand.Seed(time.Now().UnixNano())
				millisecond := time.Duration(rand.Intn(2001)) * time.Millisecond
				time.Sleep(millisecond)
				instance.FetchInstanceDescriptors()
			}

		}
	}()

	go func() {
		for {
			select {
			case <-time.After(time.Duration(p.PublishDescriptorCheckFrequency())):
			case <-p.PublishChannel:
				continue
			}

			run := adaptPublish()
			if run {
				//variate timings to reduce correlation attacks
				rand.Seed(time.Now().UnixNano())
				millisecond := time.Duration(rand.Intn(2001)) * time.Millisecond
				time.Sleep(millisecond)
				instance.PublishAllDescriptors()
			}
		}
	}()
}

func torActive(instance *Controller) {
	_, err := instance.Signal("ACTIVE")
	if err != nil {
		logrus.Panicf("Sending 'Active' signal failed. Check if your Tor control process is still alive and able to be connected to!")
	}
	time.Sleep(5 * time.Second)
}

func adaptiveStart(instance Onionbalance) {
	p := Params()
	logrus.Infof("[ADAPTIVE] Waiting for %d instance descriptors.", p.NInstances())
	p.SetAdaptWgEnabled(true)
	instance.FetchInstanceDescriptors()
	p.AdaptWg().Wait()
	//need to get the channel and see how many instances have returned within the InitialCallbackDelay time. Hoping for all of them. Warn if not.
	adaptStartTime := p.AdaptStartTime()
	p.SetAdaptDelay(time.Since(time.Unix(adaptStartTime, 0)).Nanoseconds())
	logrus.Info("[ADAPTIVE] Adaptive Configured! It took ", p.AdaptDelay()/1000000000, " seconds to get all descriptors. Optimizing performance!")
	if p.AdaptStrict() {
		strictTest(p.AdaptDelay())
	}
	//Prevent Waitgroup Recounting. Sanity check as well.
	p.SetAdaptWgEnabled(false)

	logrus.Info("[ADAPTIVE] Adapting to network and instance conditions...")

	//Make sure that newnym has a chance to clear descriptors
	if p.AdaptDelay() < 8000000000 { //8 seconds
		p.SetAdaptDelay(80000000000)
	}

	adaptDelay := p.AdaptDelay()
	//We got all the descriptors within this timeframe so should be a good default.
	p.SetFetchDescriptorFrequency(adaptDelay)
	//If new descriptors are not received for 5 fetches (2 retries) count them as old.
	p.SetInstanceDescriptorTooOld(adaptDelay * 5)
	//Expire a descriptor after two fetches. This is not ideal for large amounts of instances.
	p.SetFrontendDescriptorLifetime(adaptDelay * 2)
	//Time the publishing checks with the fetch descriptors. Only publishes if needed.
	p.SetPublishDescriptorCheckFrequency(adaptDelay / 2)

	adaptFetch()
	//adaptPublish()
	//force publishing on first start
	p.SetAdaptIntroChanged(1)
}

// Adaptive Publish
//
// These functions changes the way onionbalance operates to prioritize introduction rotation
// onto the network in the most ideal timings (to increase reachability). It responds to the amount of
// active instances and changes the publishing timings to the network in hopes of not overloading
// the attached Tor process. The point is to help tune in the default parameters, based on the amount
// of instances, so that it maximizes the onion service uptime. It is heavily opinionated and is not
// a perfect alternative to manual refinement.
// However, it is far better than what the original python implementation does. Aka nothing.

func adaptPublish() bool {
	p := Params()
	if !p.AdaptEnabled() {
		return true
	}

	//If there is equal to or less than 20 Introduction points active disable distinct descriptors. The benefits of distinct descriptors
	//are only shown with more than 20 instances. We increase reachability with tighter timings on descriptor
	//pushes and better introduction point selection.
	if p.NIntroduction() <= 20 {
		p.SetAdaptDistinctDescriptors(1)
		p.SetAdaptShuffle(1)
		p := Params()
		adaptDelay := p.AdaptDelay()
		descriptorCheckFrequency := p.publishDescriptorCheckFrequency
		//If there has been no change in any introduction point with all instances being active do not proceed.
		if p.AdaptIntroChanged() == 0 && p.AdaptUp() == p.AdaptCount() {
			if adaptDelay < 800000000000 { //800 seconds max limit change
				logrus.Info("[ADAPTIVE] Slowing down descriptor publishing")
				p.SetPublishDescriptorCheckFrequency(adaptDelay * 2)
			}
			logrus.Info("[ADAPTIVE] Skipping descriptor push as there has been no introduction point change.")
			return false
		} else {
			if adaptDelay == descriptorCheckFrequency {
				logrus.Info("[ADAPTIVE] Speeding up descriptor publishing")
				p.SetPublishDescriptorCheckFrequency(adaptDelay / 2)
			}
		}
	} else {
		p.SetAdaptDistinctDescriptors(1)
		//If the number of introduction points are less than the amount it takes to fill all HSDIR descriptors,
		//configure the push of introduction points to prioritize the freshest descriptors received. Otherwise, treat all
		//introduction points as equal priority.
		maxintropoints := p.AdaptHSDirCount() * 20
		if maxintropoints > p.NIntroduction() {
			p.SetAdaptShuffle(1)
		} else {
			p.SetAdaptShuffle(0)
		}
	}

	//ADAPT TIMING ADJUSTMENTS REMOVED (correlation attack potential)

	return true
}

// Adaptive Fetching
func adaptFetch() bool {
	p := Params()
	if !p.AdaptEnabled() {
		return true
	}
	//warn if some instances are down
	if p.AdaptCount() != p.NInstances() {
		if p.AdaptDownNoDescriptor() != 0 {
			logrus.Infof("[ADAPTIVE] There are %d instances who have no returned Descriptors. If you see this message a lot "+
				"stop gobalance and remove the offline instances for better performance.", p.AdaptDownNoDescriptor())
		}

		if p.AdaptDownInstanceOld() != 0 {
			logrus.Infof("[ADAPTIVE] There are %d instances who have old descriptors. If you see this message a lot "+
				"stop gobalance, reset tor, and remove the offline instances for better performance.", p.AdaptDownInstanceOld())
		}
	}

	//ADAPT TIMING ADJUSTMENTS REMOVED. (correlation attack potential)

	return true
}

// strictTest Returns if adaptive timings are reasonable giving the number of instances. Runs only on start.
// Gracefully exits on failure. Configurable with the "strict" cli option. Defaults to true.
func strictTest(timings int64) {
	p := Params()
	//Check if there are failed services within the config.yaml which returned with no descriptors exit with warning.
	//Best to clear out the downed instances or wait for their recovery before doing anything else
	nInstances := p.NInstances()
	if nInstances < p.AdaptCount() {
		logrus.Infof("[STRICT] Some instances are down at start of this process. Wait for their recovery or remove " +
			"the downed instances.")
		if logrus.GetLevel().String() != "debug" {
			logrus.Infof("[STRICT] Set '--verbosity bebug' to see downed instances.")
		}
		os.Exit(0)
	}

	//Tor has a soft max of 32 general-purpose client circuits that can be pending.
	//If you go over that value it will wait until some finish. This means having more than 32 fronts will greatly limit
	//your circuit builds.
	if nInstances > 32 {
		logrus.Infof("[STRICT] You have over 32 active fronts. Tor has a soft limit of 32 general-purpose pending circuits." +
			"For the best performance split your fronts and descriptor push over multiple gobalance instances and Tor processes")
		logrus.Debugf("You have %d active fronts. You want under 32.", nInstances)
		os.Exit(0)
	}

	//From many tests the tolerance for a series of instances on a single Tor process is
	//a simple base of 10 plus 3 per instance. It takes in account the delay of the Tor network circuit building
	//The timings here was calculated when the Tor network was under DDOS with extreme latency build issues.
	//This will be probably inaccurate in times of peace and should be tightened further.
	maxTimings := (10 + (5 * nInstances)) * 1000000000
	if maxTimings < timings {
		logrus.Infof("[STRICT] The Tor process is too slow to handle %d instances in current network conditions. "+
			"Reduce the amount of instances on an individual onionbalance and tor process to pass strict test checks or "+
			"disable with cli --strict false.", nInstances)
		logrus.Debugf("strictTimings=%d and reported timings=%d in seconds", maxTimings/1000000000, timings/1000000000)
		os.Exit(0)
	}
}

func parseRange(input string) (int, int, error) {
	if input == "" {
		return 0, 0, nil
	}
	pattern := `^([1-8])(?:-([1-8]))?$`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(input)

	if matches == nil {
		logrus.Errorf("The dirsplit value is invalid. You need to have it within the range of 1-8!")
	}

	start, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, 0, err
	}

	end := start
	if matches[2] != "" {
		end, err = strconv.Atoi(matches[2])
		if err != nil {
			return 0, 0, err
		}
	}

	// Make sure the end is greater than or equal to the start
	if end < start {
		logrus.Errorf("End number should be greater than or equal to the start number. It's a assending range!")
	}

	return start, end, nil
}
