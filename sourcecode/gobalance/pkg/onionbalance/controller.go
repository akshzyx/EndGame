package onionbalance

import (
	"bufio"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gobalance/pkg/brand"
	"golang.org/x/crypto/sha3"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//type Router struct {
//	RelayFpr              string
//	MicrodescriptorDigest string
//	Fingerprint           string
//	Protocols             map[string][]int64
//	Flags                 []string
//}
//
//type ConsensusDoc struct {
//	ValidAfter                    time.Time
//	ValidUntil                    time.Time
//	sharedRandomnessPreviousValue *string
//	sharedRandomnessCurrentValue  *string
//	Routers                       []Router
//}

var ErrSocketClosed = errors.New("socket closed")

// Return the start time of the upcoming time period
func (c ConsensusDoc) GetStartTimeOfNextTimePeriod(validAfter int64) int64 {
	// Get start time of next time period
	timePeriodLength := c.GetTimePeriodLength()
	nextTimePeriodNum := c.getNextTimePeriodNum(validAfter)
	startOfNextTpInMins := nextTimePeriodNum * timePeriodLength
	// Apply rotation offset as specified by prop224 section [TIME-PERIODS]
	timePeriodRotationOffset := getSrvPhaseDuration()
	return (startOfNextTpInMins + timePeriodRotationOffset) * 60
}

func (c ConsensusDoc) GetPreviousSrv(timePeriodNum int64) []byte {
	if c.sharedRandomnessPreviousValue != nil {
		return c.sharedRandomnessPreviousValue
	} else if timePeriodNum != 0 {
		logrus.Info("SRV not found so falling back to disaster mode")
		return c.getDisasterSrv(timePeriodNum)
	}
	return nil
}

func (c ConsensusDoc) GetCurrentSrv(timePeriodNum int64) []byte {
	if c.sharedRandomnessCurrentValue != nil {
		return c.sharedRandomnessCurrentValue
	} else if timePeriodNum != 0 {
		logrus.Info("SRV not found so falling back to disaster mode")
		return c.getDisasterSrv(timePeriodNum)
	}
	return nil
}

func (c ConsensusDoc) GetStartTimeOfCurrentSrvRun() int64 {
	beginningOfCurrentRound := c.ValidAfter.Unix()
	votingIntervalSecs := int64(60 * 60)
	currRoundSlot := (beginningOfCurrentRound / votingIntervalSecs) % 24
	timeElapsedSinceStartOfRun := currRoundSlot * votingIntervalSecs
	logrus.Debugf("Current SRV proto run: Start of current round: %d. Time elapsed: %d (%d)\n", beginningOfCurrentRound,
		timeElapsedSinceStartOfRun, votingIntervalSecs)
	return beginningOfCurrentRound - timeElapsedSinceStartOfRun
}

func (c ConsensusDoc) GetStartTimeOfPreviousSrvRun() int64 {
	startTimeOfCurrentRun := c.GetStartTimeOfCurrentSrvRun()
	return startTimeOfCurrentRun - 24*3600
}

func (c ConsensusDoc) GetBlindingParam(identityPubkey ed25519.PublicKey, timePeriodNumber int64) []byte {
	Ed25519Basepoint := "(15112221349535400772501151409588531511" +
		"454012693041857206046113283949847762202, " +
		"463168356949264781694283940034751631413" +
		"07993866256225615783033603165251855960)"
	BlindString := "Derive temporary signing key\x00"
	periodLength := c.GetTimePeriodLength()
	data1 := make([]byte, 8)
	binary.BigEndian.PutUint64(data1[len(data1)-8:], uint64(timePeriodNumber))
	data2 := make([]byte, 8)
	binary.BigEndian.PutUint64(data2[len(data2)-8:], uint64(periodLength))
	N := "key-blind" + string(data1) + string(data2)
	toEnc := []byte(BlindString + string(identityPubkey) + Ed25519Basepoint + N)
	tmp := sha3.Sum256(toEnc)
	return tmp[:]
}

// Return disaster SRV for 'timePeriodNum'.
func (c ConsensusDoc) getDisasterSrv(timePeriodNum int64) []byte {
	timePeriodLength := c.GetTimePeriodLength()
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data[len(data)-8:], uint64(timePeriodLength))
	data1 := make([]byte, 8)
	binary.BigEndian.PutUint64(data1[len(data1)-8:], uint64(timePeriodNum))
	disasterBody := "shared-random-disaster" + string(data) + string(data1)
	s := sha3.Sum256([]byte(disasterBody))
	return s[:]
}

func (c ConsensusDoc) getNextTimePeriodNum(validAfter int64) int64 {
	return c.GetTimePeriodNum(validAfter) + 1
}

// GetTimePeriodLength get the HSv3 time period length in minutes
func (c ConsensusDoc) GetTimePeriodLength() int64 {
	return 24 * 60
}

func getSrvPhaseDuration() int64 {
	return 12 * 60
}

// GetTimePeriodNum get time period number for this 'valid_after'.
//
// valid_after is a datetime (if not set, we get it ourselves)
// time_period_length set to default value of 1440 minutes == 1 day
func (c ConsensusDoc) GetTimePeriodNum(validAfter int64) int64 {
	timePeriodLength := c.GetTimePeriodLength()
	secondsSinceEpoch := validAfter
	minutesSinceEpoch := secondsSinceEpoch / 60
	// Calculate offset as specified in rend-spec-v3.txt [TIME-PERIODS]
	timePeriodRotationOffset := getSrvPhaseDuration()
	// assert(minutes_since_epoch > time_period_rotation_offset)
	minutesSinceEpoch -= timePeriodRotationOffset
	timePeriodNum := minutesSinceEpoch / timePeriodLength
	return timePeriodNum
}

type Controller struct {
	host     string
	port     int
	password string
	conn     net.Conn
	connMtx  sync.Mutex
	events   chan string
	msgs     chan string
}

func NewController(host string, port int, torPassword string) *Controller {
	c := new(Controller)
	c.host = host
	c.port = port
	c.password = torPassword
	c.MustDial()
	c.launchThreads()
	if err := c.protocolAuth(); err != nil {
		panic(err)
	}
	//_ = c.SetEvents()
	return c
}

var reauthMtx sync.Mutex

func (c *Controller) ReAuthenticate() {
	if !reauthMtx.TryLock() {
		logrus.Error("re-authenticate already in progress")
		time.Sleep(10 * time.Second)
		return
	}
	defer reauthMtx.Unlock()
	for {
		time.Sleep(10 * time.Second)
		var err error

		if err = c.Dial(); err != nil {
			logrus.Error("Failed to re-authenticate controller.")
			continue
		}

		go c.connScannerThread()
		if err := c.protocolAuth(); err != nil {
			logrus.Error("Failed to re-authenticate controller.")
			c.closeConn()
			continue
		}
		if err := c.SetEvents(); err != nil {
			logrus.Error("Failed to re-authenticate controller.")
			c.closeConn()
			continue
		}
		break
	}
}

func (c *Controller) protocolAuth() error {
	protocolInfo, err := c.ProtocolInfo()
	if err != nil {
		return err
	}
	if protocolInfo.IsHashedPassword {
		if err := c.Auth(c.password); err != nil {
			return err
		}
	} else if protocolInfo.CookieContent != nil {
		if err := c.AuthWithCookie(protocolInfo.CookieContent); err != nil {
			return err
		}
	} else {
		if err := c.Auth(c.password); err != nil {
			return err
		}
	}
	logrus.Debug("Successfully authenticated on the Tor control connection.")
	return nil
}

// Return True if 'onion_address' is one of our instances.
func (b *Onionbalance) addressIsInstance(onionAddress string) bool {
	for _, service := range b.GetServices() {
		for _, instance := range service.GetInstances() {
			if instance.hasOnionAddress(onionAddress) {
				return true
			}
		}
	}
	return false
}

func (b *Onionbalance) AddressIsFrontend(onionAddress string) bool {
	for _, service := range b.GetServices() {
		if service.hasOnionAddress(onionAddress) {
			return true
		}
	}
	return false
}

// A wrapper for this control port event (see above)
// https://github.com/torproject/torspec/blob/4da63977b86f4c17d0e8cf87ed492c72a4c9b2d9/control-spec.txt#L3594
func (b *Onionbalance) handleNewDescEventWrapper(statusEvent string) {
	// HS_DESC Action HSAddress AuthType HsDir
	// HS_DESC RECEIVED o5fke5yq63krmfy5nxqatnykru664qgohrvhzalielqavpo4sut6kvad NO_AUTH $3D1BBDB539FAACA19EC27334DC6D08FD68D82775~alan 35D0MMu7YxXqhlV/u4uQ26qdT/jZXH1Ua2eYDXnavFs
	// HS_DESC UPLOADED o5fke5yq63krmfy5nxqatnykru664qgohrvhzalielqavpo4sut6kvad UNKNOWN $6A51575EFF4DC40CE8D97169E0F0AC9DE97E8B69~a9RelayMIA
	// HS_DESC REQUESTED dkforestseeaaq2dqz2uflmlsybvnq2irzn4ygyvu53oazyorednviid NO_AUTH $B7327B559CA1531D182386E21B4868FCB7F0F456~Maine obnMXJfQ9YhQ2ekm6uLiAu4TICHx1EeM5+DYVvvo480 HSDIR_INDEX=04F61F2A8367AED55A6E7FC1906AAFA8FC2610D9A8E96A02E9792FC53857D10D
	// HS_DESC FAILED xa5mofmlp2iwsapc6cskc4uflvcon2f4j2fbklycjk55e4bkqmxblyyd NO_AUTH $12CB4C0E78A71C846069605361B1E1FF528E1AF0~bammbamm OnxmaOKfU5mbR02QgVXrLh16/33MsrZmt7URcL0sffI REASON=UPLOAD_REJECTED
	p := Params()
	words := strings.Split(statusEvent, " ")
	action := words[1]
	hsAddress := words[2]
	// authType := words[3]
	hsDir := words[4]
	if action == "RECEIVED" {
		return // We already log in HS_DESC_CONTENT so no need to do it here too
	} else if action == "UPLOADED" {
		logrus.Infof("Successfully uploaded descriptor for %s to %s", hsAddress, hsDir)
	} else if action == "FAILED" {
		adaptHSDirFailureCount := p.AdaptHSDirFailureCount()
		p.SetAdaptHSDirFailureCount(adaptHSDirFailureCount + 1)
		reason := "REASON NULL"
		if len(words) >= 6 {
			reason = words[6]
		}

		if b.addressIsInstance(hsAddress) {
			adaptFetchFail := p.AdaptFetchFail()
			p.SetAdaptFetchFail(adaptFetchFail + 1)
			logrus.Infof("Descriptor fetch failed for instance %s from %s (%s)", hsAddress, hsDir, reason)
		} else if b.AddressIsFrontend(hsAddress) {
			adaptDescriptorFail := p.AdaptDescriptorFail()
			p.SetAdaptDescriptorFail(adaptDescriptorFail + 1)
			logrus.Warningf("Descriptor upload failed for frontend %s to %s (%s)", hsAddress, hsDir, reason)
		} else {
			logrus.Warningf("Descriptor action failed for unknown service %s to %s (%s)", hsAddress, hsDir, reason)
		}
	} else if action == "REQUESTED" {
		logrus.Debugf("Requested descriptor for %s from %s...", hsAddress, hsDir)
	}
}

// https://github.com/torproject/torspec/blob/4da63977b86f4c17d0e8cf87ed492c72a4c9b2d9/control-spec.txt#L3664
func (b *Onionbalance) handleNewDescContentEventWrapper(statusEvent string) {
	/*
		o5fke5yq63krmfy5nxqatnykru664qgohrvhzalielqavpo4sut6kvad 35D0MMu7YxXqhlV/u4uQ26qdT/jZXH1Ua2eYDXnavFs $14A1D6B6F417DEC38BB05A3FFAD566F6E003E0D9~quartzyrelay
		hs-descriptor 3
		descriptor-lifetime 180
		descriptor-signing-key-cert
		-----BEGIN ED25519 CERT-----
		AQgABvm2AU9N5AzUVIwCITJ2J4Cj/EbgUPKA74jCUsSG3a6Dg+BuAQAgBADfkPQw
		y7tjFeqGVX+7i5Dbqp1P+NlcfVRrZ5gNedq8W/V3lx6ZWy4kSjsHUPz5mJjEnay/
		yxBpz2MPh7Key9TtMX3kkOV+YSdVVEj3RYZDFO3L2d41pfsOyofmSVscEg0=
		-----END ED25519 CERT-----
		revision-counter 3767530536
		superencrypted
		-----BEGIN MESSAGE-----
		4irIE1RXoopvgBEHohhUfv4s1p0wKRK0CJ86fB9CoxkAO6MkJl/QQMvM4XvLbTe+
		IsvKSujhPsrMxeJywS02wUrKNyEPYsb229l7mYLsHCTcp/Yr4EjFVlgt9QC7x7p0
		4h3EsUT1izNY8p72LV5k7A==
		-----END MESSAGE-----
		signature ivnFALhtO63SlCUj6sZDzllUGGZzuh9MnqOGyr3tU6O2MXVsQpQL7QJLavU1/4c5ITUsX90Bov20mCHSwKNODw
	*/
	p := Params()
	if p.AdaptWgEnabled() {
		p.AdaptWg().Done()
		adaptWgCount := p.AdaptWgCount()
		p.SetAdaptWgCount(adaptWgCount - 1)
		logrus.Debugf("Adapt waitgroup count: %d", p.AdaptWgCount())
	}
	lines := strings.SplitN(statusEvent, "\n", 2)
	descriptorText := lines[1]
	words := strings.Split(lines[0], " ")
	hsAddress := words[1]
	//DescId := words[2]
	//HsDir := words[3]
	//Descriptor := words[4:]
	for _, inst := range b.getAllInstances() {
		if inst.OnionAddress == hsAddress {
			inst.registerDescriptor(descriptorText, hsAddress)
		}
	}
}

// Parse Tor status events such as "STATUS_GENERAL"
// STATUS_CLIENT NOTICE CONSENSUS_ARRIVED
func (b *Onionbalance) handleNewStatusEventWrapper(statusEvent string) {
	p := Params()
	words := strings.Split(statusEvent, " ")
	action := words[2]
	if action == "CONSENSUS_ARRIVED" {
		logrus.Debug("Received new consensus!")
		b.consensus.refresh()
		// Call all callbacks to pull from the latest consensus!
		p.FetchChannel <- true
		time.Sleep(10 * time.Second)
		p.PublishChannel <- true
	}
}

// https://github.com/torproject/torspec/blob/4da63977b86f4c17d0e8cf87ed492c72a4c9b2d9/dir-spec.txt#L1642
func (c *Controller) launchThreads() {
	c.events = make(chan string, 1000)
	c.msgs = make(chan string, 1000)
	go c.eventsHandlerThread()
	go c.connScannerThread()
}

func (c *Controller) closeConn() {
	c.connMtx.Lock()
	defer c.connMtx.Unlock()
	if err := c.conn.Close(); err != nil {
		logrus.Error(err)
	}
}

func (c *Controller) connWrite(msg string) error {
	c.connMtx.Lock()
	defer c.connMtx.Unlock()
	if _, err := c.conn.Write([]byte(msg)); err != nil {
		return ErrSocketClosed
	}
	return nil
}

func (c *Controller) Msg(msg string) (string, error) {
	if err := c.connWrite(msg); err != nil {
		return "", err
	}

	var res string
	select {
	case res = <-c.msgs:
	case <-time.After(5 * time.Second):
		logrus.Error("timed out trying to receive message from Tor control")
		return "", ErrSocketClosed
	}
	return res, nil
}

func (c *Controller) eventsHandlerThread() {
	for msg := range c.events {
		if strings.HasPrefix(msg, "650 ") {
			msg = strings.TrimPrefix(msg, "650 ")
		} else if strings.HasPrefix(msg, "650+") {
			msg = strings.TrimPrefix(msg, "650+")
		}
		words := strings.Split(msg, " ")
		if words[0] == "HS_DESC" {
			OnionBalance().handleNewDescEventWrapper(msg)
		} else if words[0] == "HS_DESC_CONTENT" {
			OnionBalance().handleNewDescContentEventWrapper(msg)
		} else if words[0] == "STATUS_CLIENT" {
			OnionBalance().handleNewStatusEventWrapper(msg)
		}
	}
}

func (c *Controller) connScannerThread() {
	clb := func(msg string) {
		if strings.HasPrefix(msg, "650") {
			c.events <- msg
		} else {
			c.msgs <- msg
		}
	}
	connScannerThread(c.conn, clb)
	logrus.Error("Tor control connection lost")
	c.closeConn()
}

func connScannerThread(r io.Reader, clb func(string)) {
	scanner := bufio.NewScanner(r)
	firstLine := true
	firstLineCode := ""
	var sb strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if firstLine {
			sb.WriteString(line)
			sb.WriteString("\n")
			firstLineCode = line[0:3]
			if line[3] != ' ' { // "650 " "650+" "250 " "250-"
				firstLine = false
				continue
			}
		} else if line != firstLineCode+" OK" {
			sb.WriteString(line)
			sb.WriteString("\n")
			continue
		}

		res := strings.TrimSpace(sb.String())
		clb(res)
		firstLine = true
		sb.Reset()
	}
}

func (c *Controller) MustDial() {
	if err := c.Dial(); err != nil {
		logrus.Fatalf("Unable to connect to Tor control port: %s:%d; %v", c.host, c.port, err)
	}
}

func (c *Controller) Dial() error {
	conn, err := dial(c.host, c.port)
	if err != nil {
		return err
	}

	logrus.Debug("Successfully connected to the Tor control port.")

	c.connMtx.Lock()
	defer c.connMtx.Unlock()
	c.conn = conn

	return nil
}

func dial(host string, port int) (net.Conn, error) {
	conn, err := net.Dial("tcp", host+":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Controller) Auth(password string) error {
	msg, err := c.Msg(fmt.Sprintf("AUTHENTICATE \"%s\"\n", password))
	if err != nil {
		return err
	}
	if msg != "250 OK" {
		return fmt.Errorf("failed to AUTHENTICATE: %s", msg)
	}
	return nil
}

func (c *Controller) AuthWithCookie(cookieContent []byte) error {
	clientNonceBytes := make([]byte, 32)
	_, _ = brand.Read(clientNonceBytes)
	clientNonce := strings.ToUpper(hex.EncodeToString(clientNonceBytes))
	msg, err := c.Msg(fmt.Sprintf("AUTHCHALLENGE SAFECOOKIE %s\n", clientNonce))
	if err != nil {
		return err
	}
	rgx := regexp.MustCompile(`SERVERNONCE=(\S+)`)
	m := rgx.FindStringSubmatch(msg)
	if len(m) != 2 {
		panic("failed to get server nonce")
	}
	serverNonce := m[1]
	cookieString := strings.ToUpper(hex.EncodeToString(cookieContent))
	toHash := fmt.Sprintf("%s%s%s\n", cookieString, clientNonce, serverNonce)
	toHashBytes, _ := hex.DecodeString(toHash)
	h := hmac.New(sha256.New, []byte("Tor safe cookie authentication controller-to-server hash"))
	h.Write(toHashBytes)
	sha := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	msg, err = c.Msg(fmt.Sprintf("AUTHENTICATE %s\n", sha))
	if err != nil {
		return err
	}
	if msg != "250 OK" {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func (c *Controller) SetEvents() error {
	_, err := c.Msg("SETEVENTS SIGNAL CONF_CHANGED STATUS_SERVER STATUS_CLIENT HS_DESC HS_DESC_CONTENT\n")
	return err
}

func (c *Controller) GetInfo(s string) (string, error) {
	return c.Msg(fmt.Sprintf("GETINFO %s\n", s))
}

func (c *Controller) Ip2Country(ip string) (string, error) {
	line, err := c.Msg(fmt.Sprintf("GETINFO ip-to-country/%s\n", ip))
	if err != nil {
		return "", err
	}
	rgx := regexp.MustCompile(`^250-ip-to-country/[^=]+=(\w+)$`)
	m := rgx.FindStringSubmatch(line)
	if len(m) != 2 {
		return "", errors.New("failed to get country: " + string(line))
	}
	return m[1], nil
}

func (c *Controller) HSFetch(addr string) error {
	line, err := c.Msg(fmt.Sprintf("HSFETCH %s\n", addr))
	if err != nil {
		return err
	}
	if line != "250 OK" {
		return errors.New(line)
	}
	return nil
}

func (c *Controller) HSPost(addr string) error {
	_, err := c.Msg(fmt.Sprintf("+HSPOST HSADDRESS=%s\r\n%s\r\n.\r\n", strings.TrimRight(addr, ".onion"), "descriptor"))
	return err
}

func (c *Controller) GetMdConsensus() (string, error) {
	return c.GetInfo("dir/status-vote/current/consensus-microdesc")
}

type MicroDescriptor struct {
	Identifiers map[string]string // string -> base64

	raw string
}

func (m *MicroDescriptor) Digest() string {
	h := sha256.New()
	h.Write([]byte(m.raw))
	src := h.Sum(nil)
	return strings.TrimRight(base64.StdEncoding.EncodeToString(src), "=")
}

func (c *Controller) GetMicrodescriptors() ([]MicroDescriptor, error) {
	out := make([]MicroDescriptor, 0)

	mdAll, err := c.GetInfo("md/all")
	if err != nil {
		return out, err
	}
	lines := strings.Split(mdAll, "\n")
	lines = lines[1 : len(lines)-1]
	_ = os.WriteFile("logs/mdAll.txt", []byte(strings.Join(lines, "\n")), 0644)

	desc := ""
	for _, line := range lines {
		if line == "onion-key" {
			if desc != "" {
				out = append(out, MicroDescriptor{raw: desc, Identifiers: make(map[string]string)})
			}
			desc = line + "\n"
		} else {
			desc += line + "\n"
		}
	}
	out = append(out, MicroDescriptor{raw: desc, Identifiers: make(map[string]string)})

	for idx := range out {
		lines := strings.Split(out[idx].raw, "\n")
		for _, line := range lines {
			// id ed25519 ufqCAi2Oqasmu67Dm0Ugru+Nk4xxCADXFj6RwdQk4WY
			if strings.HasPrefix(line, "id ed25519 ") {
				out[idx].Identifiers["ed25519"] = strings.TrimPrefix(line, "id ed25519 ")
			}
		}
	}

	return out, nil
}

type ProtocolInfoStruct struct {
	IsHashedPassword bool
	CookieContent    []byte
}

func (c *Controller) ProtocolInfo() (out ProtocolInfoStruct, err error) {
	msg, err := c.Msg("PROTOCOLINFO\n")
	if err != nil {
		return out, err
	}
	lines := strings.Split(msg, "\n")
	if len(lines) != 3 {
		panic(msg)
	}
	if strings.Contains(lines[1], "NULL") {
	} else if strings.Contains(lines[1], "HASHEDPASSWORD") {
		out.IsHashedPassword = true
	} else if strings.Contains(lines[1], "COOKIE") {
		rgx := regexp.MustCompile(`250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="([^"]+)"`)
		m := rgx.FindStringSubmatch(lines[1])
		if len(m) != 2 {
			panic("failed to get cookie path")
		}
		cookiePath := m[1]
		cookieBytes, err := os.ReadFile(cookiePath)
		if err != nil {
			panic(err)
		}
		out.CookieContent = cookieBytes
	}
	return
}

func (c *Controller) GetVersion() string {
	versionStr, _ := c.GetInfo("version")
	versionStr = strings.TrimPrefix(versionStr, "250-version=")
	return versionStr
}

func (c *Controller) Signal(signal string) (string, error) {
	return c.Msg(fmt.Sprintf("SIGNAL %s\n", signal))
}

func (c *Controller) MarkTorAsActive() {
	_, _ = c.Signal("ACTIVE")
}

// GetHiddenServiceDescriptor We need a way to await these results.
func (c *Controller) GetHiddenServiceDescriptor(address string) error {
	return c.HSFetch(address)
}
