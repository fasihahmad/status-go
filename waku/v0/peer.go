package v0

import (
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set"
	"go.uber.org/zap"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"

	types "github.com/status-im/status-go/waku/types"
)

// Peer represents a waku protocol peer connection.
type Peer struct {
	host   types.WakuHost
	peer   *p2p.Peer
	ws     p2p.MsgReadWriter
	logger *zap.Logger

	trusted        bool
	powRequirement float64
	// bloomMu is to allow thread safe access to
	// the bloom filter
	bloomMu     sync.Mutex
	bloomFilter []byte
	// topicInterestMu is to allow thread safe access to
	// the map of topic interests
	topicInterestMu sync.Mutex
	topicInterest   map[types.TopicType]bool
	// fullNode is used to indicate that the node will be accepting any
	// envelope. The opposite is an "empty node" , which is when
	// a bloom filter is all 0s or topic interest is an empty map (not nil).
	// In that case no envelope is accepted.
	fullNode             bool
	confirmationsEnabled bool
	rateLimitsMu         sync.Mutex
	rateLimits           types.RateLimits

	known mapset.Set // Messages already known by the peer to avoid wasting bandwidth

	quit chan struct{}
}

func Init() {
	initRLPKeyFields()

}

// newPeer creates a new waku peer object, but does not run the handshake itself.
func NewPeer(host types.WakuHost, remote *p2p.Peer, rw p2p.MsgReadWriter, logger *zap.Logger) types.WakuPeer {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Peer{
		host:           host,
		peer:           remote,
		ws:             rw,
		logger:         logger,
		trusted:        false,
		powRequirement: 0.0,
		known:          mapset.NewSet(),
		quit:           make(chan struct{}),
		bloomFilter:    types.MakeFullNodeBloom(),
		fullNode:       true,
	}
}

// Start initiates the peer updater, periodically broadcasting the waku packets
// into the network.
func (p *Peer) Start() {
	go p.update()
	p.logger.Debug("starting peer", zap.Binary("peerID", p.ID()))
}

// Stop terminates the peer updater, stopping message forwarding to it.
func (p *Peer) Stop() {
	close(p.quit)
	p.logger.Debug("stopping peer", zap.Binary("peerID", p.ID()))
}

func (p *Peer) SetPeerTrusted(trusted bool) {
	p.trusted = trusted
}

func (p *Peer) Trusted() bool {
	return p.trusted
}

func (p *Peer) EnodeID() enode.ID {
	return p.peer.ID()
}

func (p *Peer) IP() net.IP {
	return p.peer.Node().IP()
}

func (p *Peer) RequestHistoricMessages(envelope *types.Envelope) error {
	return p2p.Send(p.ws, p2pRequestCode, envelope)
}

func (p *Peer) SendMessagesRequest(request types.MessagesRequest) error {
	return p2p.Send(p.ws, p2pRequestCode, request)

}

func (p *Peer) SendHistoricMessageResponse(payload []byte) error {
	size, r, err := rlp.EncodeToReader(payload)
	if err != nil {
		return err
	}

	return p.ws.WriteMsg(p2p.Msg{Code: p2pRequestCompleteCode, Size: uint32(size), Payload: r})

}

func (p *Peer) SendP2PMessages(envelopes []*types.Envelope) error {
	return p2p.Send(p.ws, p2pMessageCode, envelopes)
}

func (p *Peer) SendP2PDirect(envelopes []*types.Envelope) error {
	return p2p.Send(p.ws, p2pMessageCode, envelopes)
}

func (p *Peer) SendRawP2PDirect(envelopes []rlp.RawValue) error {
	return p2p.Send(p.ws, p2pMessageCode, envelopes)
}

func (p *Peer) HandleStatusUpdateCode(packet p2p.Msg) error {
	var StatusOptions StatusOptions
	err := packet.Decode(&StatusOptions)
	if err != nil {
		p.logger.Error("failed to decode status-options", zap.Error(err))
		types.EnvelopesRejectedCounter.WithLabelValues("invalid_settings_changed").Inc()
		return err
	}

	return p.setOptions(StatusOptions)
}

// handshake sends the protocol initiation status message to the remote peer and
// verifies the remote status too.
func (p *Peer) Handshake() error {
	// Send the handshake status message asynchronously
	errc := make(chan error, 1)
	opts := p.host.ToStatusOptions()
	go func() {
		errc <- p2p.SendItems(p.ws, statusCode, ProtocolVersion, opts)
	}()

	// Fetch the remote status packet and verify protocol match
	packet, err := p.ws.ReadMsg()
	if err != nil {
		return err
	}
	if packet.Code != statusCode {
		return fmt.Errorf("p [%x] sent packet %x before status packet", p.ID(), packet.Code)
	}

	var (
		peerProtocolVersion uint64
		peerOptions         StatusOptions
	)
	s := rlp.NewStream(packet.Payload, uint64(packet.Size))
	if _, err := s.List(); err != nil {
		return fmt.Errorf("p [%x]: failed to decode status packet: %v", p.ID(), err)
	}
	// Validate protocol version.
	if err := s.Decode(&peerProtocolVersion); err != nil {
		return fmt.Errorf("p [%x]: failed to decode peer protocol version: %v", p.ID(), err)
	}
	if peerProtocolVersion != ProtocolVersion {
		return fmt.Errorf("p [%x]: protocol version mismatch %d != %d", p.ID(), peerProtocolVersion, ProtocolVersion)
	}
	// Decode and validate other status packet options.
	if err := s.Decode(&peerOptions); err != nil {
		return fmt.Errorf("p [%x]: failed to decode status options: %v", p.ID(), err)
	}
	if err := s.ListEnd(); err != nil {
		return fmt.Errorf("p [%x]: failed to decode status packet: %v", p.ID(), err)
	}
	if err := p.setOptions(peerOptions.WithDefaults()); err != nil {
		return fmt.Errorf("p [%x]: failed to set options: %v", p.ID(), err)
	}
	if err := <-errc; err != nil {
		return fmt.Errorf("p [%x] failed to send status packet: %v", p.ID(), err)
	}
	return nil
}

func (p *Peer) setOptions(peerOptions StatusOptions) error {

	p.logger.Debug("settings options", zap.Binary("peerID", p.ID()), zap.Any("Options", peerOptions))

	if err := peerOptions.Validate(); err != nil {
		return fmt.Errorf("p [%x]: sent invalid options: %v", p.ID(), err)
	}
	// Validate and save peer's PoW.
	pow := peerOptions.PoWRequirementF()
	if pow != nil {
		if math.IsInf(*pow, 0) || math.IsNaN(*pow) || *pow < 0.0 {
			return fmt.Errorf("p [%x]: sent bad status message: invalid pow", p.ID())
		}
		p.powRequirement = *pow
	}

	if peerOptions.TopicInterestExport != nil {
		p.setTopicInterest(peerOptions.TopicInterestExport)
	} else if peerOptions.BloomFilterExport != nil {
		// Validate and save peer's bloom filters.
		bloom := peerOptions.BloomFilterExport
		bloomSize := len(bloom)
		if bloomSize != 0 && bloomSize != types.BloomFilterSize {
			return fmt.Errorf("p [%x] sent bad status message: wrong bloom filter size %d", p.ID(), bloomSize)
		}
		p.setBloomFilter(bloom)
	}

	if peerOptions.LightNodeEnabledExport != nil {
		// Validate and save other peer's options.
		if *peerOptions.LightNodeEnabledExport && p.host.LightClientMode() && p.host.LightClientModeConnectionRestricted() {
			return fmt.Errorf("p [%x] is useless: two light client communication restricted", p.ID())
		}
	}
	if peerOptions.ConfirmationsEnabledExport != nil {
		p.confirmationsEnabled = *peerOptions.ConfirmationsEnabledExport
	}
	if peerOptions.RateLimitsExport != nil {
		p.setRateLimits(*peerOptions.RateLimitsExport)
	}

	return nil
}

// update executes periodic operations on the peer, including message transmission
// and expiration.
func (p *Peer) update() {
	// Start the tickers for the updates
	expire := time.NewTicker(types.ExpirationCycle)
	transmit := time.NewTicker(types.TransmissionCycle)

	// Loop and transmit until termination is requested
	for {
		select {
		case <-expire.C:
			p.expire()

		case <-transmit.C:
			if err := p.broadcast(); err != nil {
				p.logger.Debug("broadcasting failed", zap.Binary("peer", p.ID()), zap.Error(err))
				return
			}

		case <-p.quit:
			return
		}
	}
}

// mark marks an envelope known to the peer so that it won't be sent back.
func (p *Peer) Mark(envelope *types.Envelope) {
	p.known.Add(envelope.Hash())
}

// marked checks if an envelope is already known to the remote peer.
func (p *Peer) Marked(envelope *types.Envelope) bool {
	return p.known.Contains(envelope.Hash())
}

// expire iterates over all the known envelopes in the host and removes all
// expired (unknown) ones from the known list.
func (p *Peer) expire() {
	unmark := make(map[common.Hash]struct{})
	p.known.Each(func(v interface{}) bool {
		if !p.host.IsEnvelopeCached(v.(common.Hash)) {
			unmark[v.(common.Hash)] = struct{}{}
		}
		return true
	})
	// Dump all known but no longer cached
	for hash := range unmark {
		p.known.Remove(hash)
	}
}

// broadcast iterates over the collection of envelopes and transmits yet unknown
// ones over the network.
func (p *Peer) broadcast() error {
	envelopes := p.host.Envelopes()
	bundle := make([]*types.Envelope, 0, len(envelopes))
	for _, envelope := range envelopes {
		if !p.Marked(envelope) && envelope.PoW() >= p.powRequirement && p.topicOrBloomMatch(envelope) {
			bundle = append(bundle, envelope)
		}
	}

	if len(bundle) == 0 {
		return nil
	}

	batchHash, err := types.SendBundle(p.ws, bundle)
	if err != nil {
		p.logger.Debug("failed to deliver envelopes", zap.Binary("peer", p.ID()), zap.Error(err))
		return err
	}

	// mark envelopes only if they were successfully sent
	for _, e := range bundle {
		p.Mark(e)
		event := types.EnvelopeEvent{
			Event: types.EventEnvelopeSent,
			Hash:  e.Hash(),
			Peer:  p.peer.ID(),
		}
		if p.confirmationsEnabled {
			event.Batch = batchHash
		}
		p.host.SendEnvelopeEvent(event)
	}
	p.logger.Debug("broadcasted bundles successfully", zap.Binary("peer", p.ID()), zap.Int("count", len(bundle)))
	return nil
}

// ID returns a peer's id
func (p *Peer) ID() []byte {
	id := p.peer.ID()
	return id[:]
}

func (p *Peer) PoWRequirement() float64 {
	return p.powRequirement
}

func (p *Peer) NotifyAboutPowRequirementChange(pow float64) error {
	i := math.Float64bits(pow)
	return p2p.Send(p.ws, statusUpdateCode, StatusOptions{PoWRequirementExport: &i})
}

func (p *Peer) NotifyAboutBloomFilterChange(bloom []byte) error {
	return p2p.Send(p.ws, statusUpdateCode, StatusOptions{BloomFilterExport: bloom})
}

func (p *Peer) NotifyAboutTopicInterestChange(topics []types.TopicType) error {
	return p2p.Send(p.ws, statusUpdateCode, StatusOptions{TopicInterestExport: topics})
}

func (p *Peer) bloomMatch(env *types.Envelope) bool {
	p.bloomMu.Lock()
	defer p.bloomMu.Unlock()
	return p.fullNode || types.BloomFilterMatch(p.bloomFilter, env.Bloom())
}

func (p *Peer) BloomFilter() []byte {
	p.bloomMu.Lock()
	defer p.bloomMu.Unlock()

	bloomFilterCopy := make([]byte, len(p.bloomFilter))
	copy(bloomFilterCopy, p.bloomFilter)
	return bloomFilterCopy
}

func (p *Peer) topicInterestMatch(env *types.Envelope) bool {
	p.topicInterestMu.Lock()
	defer p.topicInterestMu.Unlock()

	if p.topicInterest == nil {
		return false
	}

	return p.topicInterest[env.Topic]
}

// topicOrBloomMatch matches against topic-interest if topic interest
// is not nil. Otherwise it will match against the bloom-filter.
// If the bloom-filter is nil, or full, the node is considered a full-node
// and any envelope will be accepted. An empty topic-interest (but not nil)
// signals that we are not interested in any envelope.
func (p *Peer) topicOrBloomMatch(env *types.Envelope) bool {
	p.topicInterestMu.Lock()
	topicInterestMode := p.topicInterest != nil
	p.topicInterestMu.Unlock()

	if topicInterestMode {
		return p.topicInterestMatch(env)
	}
	return p.bloomMatch(env)
}

func (p *Peer) setBloomFilter(bloom []byte) {
	p.bloomMu.Lock()
	defer p.bloomMu.Unlock()
	p.bloomFilter = bloom
	p.fullNode = types.IsFullNode(bloom)
	if p.fullNode && p.bloomFilter == nil {
		p.bloomFilter = types.MakeFullNodeBloom()
	}
	p.topicInterest = nil
}

func (p *Peer) setTopicInterest(topicInterest []types.TopicType) {
	p.topicInterestMu.Lock()
	defer p.topicInterestMu.Unlock()
	if topicInterest == nil {
		p.topicInterest = nil
		return
	}
	p.topicInterest = make(map[types.TopicType]bool)
	for _, topic := range topicInterest {
		p.topicInterest[topic] = true
	}
	p.fullNode = false
	p.bloomFilter = nil
}

func (p *Peer) setRateLimits(r types.RateLimits) {
	p.rateLimitsMu.Lock()
	p.rateLimits = r
	p.rateLimitsMu.Unlock()
}
