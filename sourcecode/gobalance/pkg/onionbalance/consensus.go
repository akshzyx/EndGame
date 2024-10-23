package onionbalance

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/btime"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Consensus struct {
	Nodes      []*TorNode
	nodeMtx    sync.RWMutex
	consensus  *ConsensusDoc
	controller *Controller
}

func NewConsensus(controller *Controller, doRefreshConsensus bool) *Consensus {
	c := &Consensus{}
	c.controller = controller
	// A list of tor_node:Node objects contained in the current consensus
	c.SetNodes(nil)
	// A stem NetworkStatusDocumentV3 object representing the current consensus
	c.consensus = nil
	if !doRefreshConsensus {
		return c
	}
	c.refresh()
	return c
}

func (c *Consensus) GetNodes() []*TorNode {
	c.nodeMtx.RLock()
	defer c.nodeMtx.RUnlock()
	return c.Nodes
}

func (c *Consensus) SetNodes(newNodes []*TorNode) {
	c.nodeMtx.Lock()
	defer c.nodeMtx.Unlock()
	c.Nodes = newNodes
}

func (c *Consensus) Consensus() *ConsensusDoc {
	return c.consensus
}

// Attempt to refresh the consensus with the latest one available.
func (c *Consensus) refresh() {
	mdConsensusStr, err := c.controller.GetMdConsensus()
	if err != nil {
		logrus.Errorf("Failed to GetMdConsensus: %v", err)
		return
	}
	c.consensus, err = NetworkStatusDocumentV3(mdConsensusStr)
	if err != nil {
		logrus.Warn("No valid consensus received. Waiting for one...")
		return
	}
	if !c.IsLive() {
		logrus.Info("Loaded consensus is not live. Waiting for a live one.")
		return
	}
	c.SetNodes(c.initializeNodes())
}

// IsLive return True if the consensus is live.
// This function replicates the behavior of the little-t-tor
// networkstatus_get_reasonably_live_consensus() function.
func (c *Consensus) IsLive() bool {
	if c.consensus == nil {
		return false
	}
	reasonablyLiveTime := 24 * 60 * 60 * time.Second
	now := btime.Clock.Now().UTC()
	isLive := now.After(c.consensus.ValidAfter.Add(-reasonablyLiveTime)) &&
		now.Before(c.consensus.ValidUntil.Add(reasonablyLiveTime))
	return isLive
}

func (c *Consensus) initializeNodes() []*TorNode {
	nodes := make([]*TorNode, 0)
	microdescriptorsList, err := c.controller.GetMicrodescriptors()
	if err != nil {
		logrus.Warn("Can't get microdescriptors from Tor. Delaying...")
		return nodes
	}
	// Turn the mds into a dictionary indexed by the digest as an
	// optimization while matching them with routerstatuses.
	microdescriptorsDict := make(map[string]MicroDescriptor)
	for _, md := range microdescriptorsList {
		microdescriptorsDict[md.Digest()] = md
	}

	// Go through the routerstatuses and match them up with
	// microdescriptors, and create a Node object for each match. If there
	// is no match we don't register it as a node.
	for _, relayRouterStatusFn := range c.getRouterStatuses() {
		relayRouterStatus := relayRouterStatusFn()
		logrus.Debugf("Checking routerstatus with md digest %s", relayRouterStatus.Digest)
		nodeMicrodescriptor, found := microdescriptorsDict[relayRouterStatus.Digest]
		if !found {
			logrus.Debugf("Could not find microdesc for rs with fpr %s", relayRouterStatus.Fingerprint)
			continue
		}
		node := NewNode(nodeMicrodescriptor, relayRouterStatus)
		nodes = append(nodes, node)
	}
	return nodes
}

func (c *Consensus) getRouterStatuses() map[Fingerprint]GetStatus {
	if !c.IsLive() {
		panic("getRouterStatuses and not live")
	}
	return c.consensus.Routers
}

// NetworkStatusDocumentV3 parse a v3 network status document
func NetworkStatusDocumentV3(mdConsensusStr string) (*ConsensusDoc, error) {
	//fmt.Println(mdConsensusStr)
	cd := &ConsensusDoc{}

	var consensus = NewConsensus1()

	var statusParser func(string) (Fingerprint, GetStatus, error)
	statusParser = ParseRawStatus

	lines1 := strings.Split(mdConsensusStr, "\n")
	if len(lines1) < 2 {
		// TODO: the following line SOMETIMES returns "panic: runtime error: slice bounds out of range [2:1]" when new consensus is in, not sure why.
		logrus.Panic(mdConsensusStr)
	}
	br := bufio.NewReader(strings.NewReader(strings.Join(lines1[2:], "\n")))
	err := extractMetaInfo(br, consensus)
	if err != nil {
		return nil, fmt.Errorf("metadata info extraction failed: %w", err)
	}
	queue := make(chan QueueUnit)
	go DissectFile(br, extractStatusEntry, queue)

	// Parse incoming router statuses until the channel is closed by the remote
	// end.
	for unit := range queue {
		if unit.Err != nil {
			return nil, unit.Err
		}

		fingerprint, getStatus, err := statusParser(unit.Blurb)
		if err != nil {
			return nil, err
		}

		consensus.Routers[SanitiseFingerprint(fingerprint)] = getStatus
	}

	lines := strings.Split(mdConsensusStr, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "valid-after ") {
			validAfter := strings.TrimPrefix(line, "valid-after ")
			cd.ValidAfter, _ = time.Parse("2006-01-02 15:04:05", validAfter)
		} else if strings.HasPrefix(line, "valid-until ") {
			validUntil := strings.TrimPrefix(line, "valid-until ")
			cd.ValidUntil, _ = time.Parse("2006-01-02 15:04:05", validUntil)
		}
	}

	return consensus, nil
}

// NewConsensus serves as a constructor and returns a pointer to a freshly
// allocated and empty Consensus.
func NewConsensus1() *ConsensusDoc {
	return &ConsensusDoc{Routers: make(map[Fingerprint]GetStatus)}
}

// ParseRawStatus parses a raw router status (in string format) and returns the
// router's fingerprint, a function which returns a RouterStatus, and an error
// if there were any during parsing.
func ParseRawStatus(rawStatus string) (Fingerprint, GetStatus, error) {

	var status = new(RouterStatus)

	lines := strings.Split(rawStatus, "\n")

	// Go over raw statuses line by line and extract the fields we are
	// interested in.
	for _, line := range lines {

		words := strings.Split(line, " ")

		switch words[0] {

		case "r":
			status.Nickname = words[1]
			fingerprint, err := Base64ToString(words[2])
			if err != nil {
				return "", nil, err
			}
			status.Fingerprint = SanitiseFingerprint(Fingerprint(fingerprint))

			publish, _ := time.Parse(publishedTimeLayout, strings.Join(words[3:5], " "))
			status.Publication = publish
			status.Address.IPv4Address = net.ParseIP(words[5])
			status.Address.IPv4ORPort = StringToPort(words[6])
			status.Address.IPv4DirPort = StringToPort(words[7])

		case "a":
			status.Address.IPv6Address, status.Address.IPv6ORPort = parseIPv6AddressAndPort(words[1])

		case "m":
			status.Digest = words[1]

		case "s":
			status.Flags = *parseRouterFlags(words[1:])

		case "v":
			status.TorVersion = words[2]

		case "w":
			bwExpr := words[1]
			values := strings.Split(bwExpr, "=")
			status.Bandwidth, _ = strconv.ParseUint(values[1], 10, 64)

		case "p":
			if words[1] == "accept" {
				status.Accept = true
			} else {
				status.Accept = false
			}
			status.PortList = strings.Join(words[2:], " ")
		}
	}

	return status.Fingerprint, func() *RouterStatus { return status }, nil
}

const (
	// The layout of the "published" field.
	publishedTimeLayout = "2006-01-02 15:04:05"
)

// SanitiseFingerprint returns a sanitised version of the given fingerprint by
// making it upper case and removing leading and trailing white spaces.
func SanitiseFingerprint(fingerprint Fingerprint) Fingerprint {

	sanitised := strings.ToUpper(strings.TrimSpace(string(fingerprint)))

	return Fingerprint(sanitised)
}

func parseIPv6AddressAndPort(addressAndPort string) (address net.IP, port uint16) {
	var ipV6regex = regexp.MustCompile(`\[(.*?)\]`)
	var ipV6portRegex = regexp.MustCompile(`\]:(.*)`)
	address = net.ParseIP(ipV6regex.FindStringSubmatch(addressAndPort)[1])
	port = StringToPort(ipV6portRegex.FindStringSubmatch(addressAndPort)[1])

	return address, port
}

// Convert the given port string to an unsigned 16-bit integer.  If the
// conversion fails or the number cannot be represented in 16 bits, 0 is
// returned.
func StringToPort(portStr string) uint16 {

	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return uint16(0)
	}

	return uint16(portNum)
}

func parseRouterFlags(flags []string) *RouterFlags {

	var routerFlags = new(RouterFlags)

	for _, flag := range flags {
		switch flag {
		case "Authority":
			routerFlags.Authority = true
		case "BadExit":
			routerFlags.BadExit = true
		case "Exit":
			routerFlags.Exit = true
		case "Fast":
			routerFlags.Fast = true
		case "Guard":
			routerFlags.Guard = true
		case "HSDir":
			routerFlags.HSDir = true
		case "Named":
			routerFlags.Named = true
		case "Stable":
			routerFlags.Stable = true
		case "Running":
			routerFlags.Running = true
		case "Unnamed":
			routerFlags.Unnamed = true
		case "Valid":
			routerFlags.Valid = true
		case "V2Dir":
			routerFlags.V2Dir = true
		}
	}

	return routerFlags
}

// Base64ToString decodes the given Base64-encoded string and returns the resulting string.
// If there are errors during decoding, an error string is returned.
func Base64ToString(encoded string) (string, error) {

	// dir-spec.txt says that Base64 padding is removed so we have to account
	// for that here.
	if rem := len(encoded) % 4; rem != 0 {
		encoded += strings.Repeat("=", 4-rem)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(decoded), nil
}

type QueueUnit struct {
	Blurb string
	Err   error
}

// Fingerprint represents a relay's fingerprint as 40 hex digits.
type Fingerprint string

type GetStatus func() *RouterStatus

type RouterStatus struct {

	// The single fields of an "r" line.
	Nickname    string
	Fingerprint Fingerprint
	Digest      string
	Publication time.Time

	// The IPv4 and IPv6 fields of "a" line
	Address RouterAddress

	// The single fields of an "s" line.
	Flags RouterFlags

	// The single fields of a "v" line.
	TorVersion string

	// The single fields of a "w" line.
	Bandwidth  uint64
	Measured   uint64
	Unmeasured bool

	// The single fields of a "p" line.
	Accept   bool
	PortList string
}

type RouterFlags struct {
	Authority bool
	BadExit   bool
	Exit      bool
	Fast      bool
	Guard     bool
	HSDir     bool
	Named     bool
	Stable    bool
	Running   bool
	Unnamed   bool
	Valid     bool
	V2Dir     bool
}

type RouterAddress struct {
	IPv4Address net.IP
	IPv4ORPort  uint16
	IPv4DirPort uint16

	IPv6Address net.IP
	IPv6ORPort  uint16
}

type ConsensusDoc struct {
	// Generic map of consensus metadata
	MetaInfo map[string][]byte

	// Document validity period
	ValidAfter time.Time
	FreshUntil time.Time
	ValidUntil time.Time

	// Shared randomness
	sharedRandomnessPreviousValue []byte
	sharedRandomnessCurrentValue  []byte

	// A map from relay fingerprint to a function which returns the relay
	// status.
	Routers map[Fingerprint]GetStatus

	// The spread score for HSDIR selection
	SpreadScore int
}

// extractMetainfo extracts meta information of the open consensus document
// (such as its validity times) and writes it to the provided consensus struct.
// It assumes that the type annotation has already been read.
func extractMetaInfo(br *bufio.Reader, c *ConsensusDoc) error {

	c.MetaInfo = make(map[string][]byte)

	// Read the initial metadata. We'll later extract information of particular
	// interest by name. The weird Reader loop is because scanner reads too much.
	for line, err := br.ReadSlice('\n'); ; line, err = br.ReadSlice('\n') {
		if err != nil {
			return err
		}

		// splits to (key, value)
		split := bytes.SplitN(line, []byte(" "), 2)
		if len(split) != 2 {
			return errors.New("malformed metainfo line")
		}

		key := string(split[0])

		logrus.Debug("[Consensus] ", key)

		if key == "params" {
			splitParams := bytes.SplitAfter(line, []byte(" "))
			for _, v := range splitParams {
				if bytes.HasPrefix(v, []byte("hsdir_spread_store")) {
					splitInnerParams := bytes.SplitN(v, []byte("="), 2)
					if len(splitInnerParams) != 2 {
						return errors.New("malformed hsdir_spread_store param line! POTENTIAL CONSENSUS COMPROMISE")
					}
					c.SpreadScore, err = strconv.Atoi(strings.TrimSpace(string(splitInnerParams[1])))
					if err != nil {
						logrus.Panic("SpreadScore couldn't be parsed as int!", err)
					}
					p := Params()
					if c.SpreadScore != p.HsdirSpreadStore() {
						logrus.Debugf("[Consensus] Spread score set to %d", c.SpreadScore)
						p.SetHsdirSpreadStore(c.SpreadScore)
					}
				}
				logrus.Debugf("[Consensus][Params] %s", string(v))
			}
		} else {
			c.MetaInfo[key] = bytes.TrimSpace(split[1])
		}

		// Look ahead to check if we've reached the end of the unique keys.
		nextKey, err := br.Peek(11)
		if err != nil {
			return err
		}
		if bytes.HasPrefix(nextKey, []byte("dir-source")) || bytes.HasPrefix(nextKey, []byte("fingerprint")) {
			break
		}
	}

	var err error
	// Define a parser for validity timestamps
	parseTime := func(line []byte) (time.Time, error) {
		return time.Parse("2006-01-02 15:04:05", string(line))
	}

	// Extract the validity period of this consensus
	c.ValidAfter, err = parseTime(c.MetaInfo["valid-after"])
	if err != nil {
		return err
	}
	c.FreshUntil, err = parseTime(c.MetaInfo["fresh-until"])
	if err != nil {
		return err
	}
	c.ValidUntil, err = parseTime(c.MetaInfo["valid-until"])
	if err != nil {
		return err
	}

	// Reads a shared-rand line from the consensus and returns decoded bytes.
	parseRand := func(line []byte) ([]byte, error) {
		split := bytes.SplitN(line, []byte(" "), 2)
		if len(split) != 2 {
			return nil, errors.New("malformed shared random line")
		}
		// should split to (vote count, b64 bytes)
		_, rand := split[0], split[1]
		return base64.StdEncoding.DecodeString(string(rand))
	}

	// Only the newer consensus documents have these values.
	if line, ok := c.MetaInfo["shared-rand-previous-value"]; ok {
		val, err := parseRand(line)
		if err != nil {
			return err
		}
		c.sharedRandomnessPreviousValue = val
	}
	if line, ok := c.MetaInfo["shared-rand-current-value"]; ok {
		val, err := parseRand(line)
		if err != nil {
			return err
		}
		c.sharedRandomnessCurrentValue = val
	}

	return nil
}

// Dissects the given file into string chunks by using the given string
// extraction function.  The resulting string chunks are then written to the
// given queue where the receiving end parses them.
func DissectFile(r io.Reader, extractor bufio.SplitFunc, queue chan QueueUnit) {

	defer close(queue)

	scanner := bufio.NewScanner(r)
	scanner.Split(extractor)

	for scanner.Scan() {
		unit := scanner.Text()
		queue <- QueueUnit{unit, nil}
	}

	if err := scanner.Err(); err != nil {
		queue <- QueueUnit{"", err}
	}
}

// extractStatusEntry is a bufio.SplitFunc that extracts individual network
// status entries.
func extractStatusEntry(data []byte, atEOF bool) (advance int, token []byte, err error) {

	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	start := 0
	if !bytes.HasPrefix(data, []byte("r ")) {
		start = bytes.Index(data, []byte("\nr "))
		if start < 0 {
			if atEOF {
				return 0, nil, fmt.Errorf("cannot find beginning of status entry: \"\\nr \"")
			}
			// Request more data.
			return 0, nil, nil
		}
		start++
	}

	end := bytes.Index(data[start:], []byte("\nr "))
	if end >= 0 {
		return start + end + 1, data[start : start+end+1], nil
	}
	end = bytes.Index(data[start:], []byte("directory-signature"))
	if end >= 0 {
		// "directory-signature" means this is the last status; stop
		// scanning.
		return start + end, data[start : start+end], bufio.ErrFinalToken
	}
	if atEOF {
		return len(data), data[start:], errors.New("no status entry")
	}
	// Request more data.
	return 0, nil, nil
}
