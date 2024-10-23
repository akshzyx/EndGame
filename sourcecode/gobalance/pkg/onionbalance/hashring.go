package onionbalance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"sort"
)

// GetSrvAndTimePeriod return SRV and time period based on current consensus time
func GetSrvAndTimePeriod(isFirstDescriptor bool, consensus ConsensusDoc) ([]byte, int64) {
	validAfter := consensus.ValidAfter.Unix()
	currentTp := consensus.GetTimePeriodNum(validAfter)
	previousTp := currentTp - 1
	nextTp := currentTp + 1
	// assert(previous_tp > 0)
	var srv []byte
	var tp int64
	var casee int
	if isFirstDescriptor {
		if timeBetweenTpAndSrv(validAfter, consensus) {
			srv = consensus.GetPreviousSrv(previousTp)
			tp = previousTp
			casee = 1
		} else {
			srv = consensus.GetPreviousSrv(currentTp)
			tp = currentTp
			casee = 2
		}
	} else {
		if timeBetweenTpAndSrv(validAfter, consensus) {
			srv = consensus.GetCurrentSrv(currentTp)
			tp = currentTp
			casee = 3
		} else {
			srv = consensus.GetCurrentSrv(nextTp)
			tp = nextTp
			casee = 4
		}
	}
	srvB64 := base64.StdEncoding.EncodeToString(srv)
	logrus.Debugf("For valid_after %d we got SRV %s and TP %d (case: #%d)\n", validAfter, srvB64, tp, casee)
	return srv, tp
}

func timeBetweenTpAndSrv(validAfter int64, consensus ConsensusDoc) bool {
	srvStartTime := consensus.GetStartTimeOfCurrentSrvRun()
	tpStartTime := consensus.GetStartTimeOfNextTimePeriod(srvStartTime)
	if validAfter >= srvStartTime && validAfter < tpStartTime {
		logrus.Debug("We are between SRV and TP")
		return false
	}
	logrus.Debugf("We are between TP and SRV (valid_after: %d, srv_start_time: %d -> tp_start_time: %d)\n", validAfter, srvStartTime, tpStartTime)
	return true
}

func GetResponsibleHsdirs(blindedPubkey ed25519.PublicKey, isFirstDescriptor bool, consensus *Consensus) ([]string, error) {
	p := Params()
	responsibleHsdirs := make([]string, 0)

	// dictionary { <node hsdir index> : Node , .... }
	nodeHashRing := getHashRingForDescriptor(isFirstDescriptor, consensus)
	if len(nodeHashRing) == 0 {
		return nil, ErrEmptyHashRing
	}

	sortedHashRingList := make([]string, 0)

	for k := range nodeHashRing {
		sortedHashRingList = append(sortedHashRingList, k)
	}
	sort.Slice(sortedHashRingList, func(i, j int) bool {
		return sortedHashRingList[i] < sortedHashRingList[j]
	})

	logrus.Infof("Initialized hash ring of size %d (blinded key: %s)", len(nodeHashRing), base64.StdEncoding.EncodeToString(blindedPubkey))

	hsdirSkip := 0
	for replicaNum := 1; replicaNum < p.HsdirNReplicas()+1; replicaNum++ {
		// The HSDirs that we are going to store this replica in
		replicaStoreHsdirs := make([]string, 0)

		hiddenServiceIndex := getHiddenServiceIndex(blindedPubkey, replicaNum, isFirstDescriptor, consensus)

		// Find position of descriptor ID in the HSDir list
		index := sort.SearchStrings(sortedHashRingList, string(hiddenServiceIndex))

		logrus.Infof("\t Tried with HS index %x got position %d", hiddenServiceIndex, index)

		for len(replicaStoreHsdirs) < p.HsdirSpreadStore() {
			var hsdirKey string
			if index < len(sortedHashRingList) {
				hsdirKey = sortedHashRingList[index]
				index += 1
			} else {
				// Wrap around when we reach the end of the HSDir list
				index = 0
				hsdirKey = sortedHashRingList[index]
			}
			hsdirNode := nodeHashRing[hsdirKey]

			// Check if we have already added this node to this
			// replica. This should never happen on the real network but
			// might happen in small testnets like chutney!
			found := false
			for _, el := range replicaStoreHsdirs {
				if el == string(hsdirNode.GetHexFingerprint()) {
					found = true
					hsdirSkip++
					break
				}
			}
			if found {
				logrus.Debug("Ignoring already added HSDir to this replica!")
				break
			}

			// Check if we have already added this node to the responsible
			// HSDirs. This can happen in the second replica, and we should
			// skip the node
			found = false
			for _, el := range responsibleHsdirs {
				if el == string(hsdirNode.GetHexFingerprint()) {
					found = true
					hsdirSkip++
					break
				}
			}
			if found {
				logrus.Debug("Ignoring already added HSDir!")
				continue
			}

			logrus.Debugf("%d: %s: %x", index, hsdirNode.GetHexFingerprint(), hsdirKey)

			replicaStoreHsdirs = append(replicaStoreHsdirs, string(hsdirNode.GetHexFingerprint()))
		}

		responsibleHsdirs = append(responsibleHsdirs, replicaStoreHsdirs...)
	}

	logrus.Debugf("Amount of Responsible HSDIR: %d.", len(responsibleHsdirs))
	responsibleHsdirsSpreadCount := p.HsdirNReplicas()*p.HsdirSpreadStore() - hsdirSkip
	if len(responsibleHsdirs) != responsibleHsdirsSpreadCount {
		logrus.Panicf("Got the wron*g number of responsible HSDirs: %d (should be %d). Aborting", len(responsibleHsdirs), responsibleHsdirsSpreadCount)
	}

	//For responsible HSDIR splitting
	start := p.DirStart()
	if start >= 1 {
		logrus.Debugf("[DIRSPLIT] RAN SPLIT!")
		end := p.DirEnd()
		start -= 1
		end -= 1
		if start >= 0 && end < len(responsibleHsdirs) && start <= end {
			responsibleHsdirs = responsibleHsdirs[start : end+1]
		}
	}

	p.SetAdaptHSDirCount(int64(len(responsibleHsdirs)))

	return responsibleHsdirs, nil
}

func getHiddenServiceIndex(blindedPubkey ed25519.PublicKey, replicaNum int, isFirstDescriptor bool, consensus *Consensus) []byte {
	periodLength := consensus.Consensus().GetTimePeriodLength()
	replicaNumInt8 := make([]byte, 8)
	binary.BigEndian.PutUint64(replicaNumInt8[len(replicaNumInt8)-8:], uint64(replicaNum))
	periodLengthInt8 := make([]byte, 8)
	binary.BigEndian.PutUint64(periodLengthInt8[len(periodLengthInt8)-8:], uint64(periodLength))
	_, timePeriodNum := GetSrvAndTimePeriod(isFirstDescriptor, *consensus.Consensus())
	logrus.Infof("Getting HS index with TP#%d for %t descriptor (%d replica) ", timePeriodNum, isFirstDescriptor, replicaNum)
	periodNumInt8 := make([]byte, 8)
	binary.BigEndian.PutUint64(periodNumInt8[len(periodNumInt8)-8:], uint64(timePeriodNum))

	hashBody := "store-at-idx" + string(blindedPubkey) + string(replicaNumInt8) + string(periodLengthInt8) + string(periodNumInt8)

	hsIndex := sha3.Sum256([]byte(hashBody))

	return hsIndex[:]
}

func getHashRingForDescriptor(isFirstDescriptor bool, consensus *Consensus) map[string]*TorNode {
	nodeHashRing := make(map[string]*TorNode)
	srv, timePeriodNum := GetSrvAndTimePeriod(isFirstDescriptor, *consensus.Consensus())
	logrus.Infof("Using srv %x and TP#%d (%t descriptor)", srv, timePeriodNum, isFirstDescriptor)
	for _, node := range consensus.GetNodes() {
		hsdirIndex, err := node.GetHsdirIndex(srv, timePeriodNum, consensus)
		if err != nil {
			if err == ErrNoHSDir || err == ErrNoEd25519Identity {
				logrus.Debugf("Could not find ed25519 for node %s (%s)", node.getRouterstatus().Fingerprint, err.Error())
				continue
			}
		}
		logrus.Debugf("%t: Node: %s,  index: %x", isFirstDescriptor, node.GetHexFingerprint(), hsdirIndex)
		nodeHashRing[string(hsdirIndex)] = node
	}
	return nodeHashRing
}
