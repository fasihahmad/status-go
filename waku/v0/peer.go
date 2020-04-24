package v0

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	mapset "github.com/deckarep/golang-set"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/status-im/status-go/waku/types"
)

type Peer struct {
	host    types.WakuHost
	rw      p2p.MsgReadWriter
	p2pPeer *p2p.Peer
	logger  *zap.Logger

	quit chan struct{}

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
}

func (p *Peer) Start() error {
	if err := p.handshake(); err != nil {
		return err
	}
	go p.update()
	p.logger.Debug("starting peer", zap.Binary("peerID", p.ID()))
	return nil
}

func (p *Peer) Stop() {
	close(p.quit)
	p.logger.Debug("stopping peer", zap.Binary("peerID", p.ID()))
}

func (p *Peer) NotifyAboutPowRequirementChange(pow float64) error {
	i := math.Float64bits(pow)
	return p2p.Send(p.rw, statusUpdateCode, StatusOptions{PoWRequirementExport: &i})
}

func (p *Peer) NotifyAboutBloomFilterChange(bloom []byte) error {
	return p2p.Send(p.rw, statusUpdateCode, StatusOptions{BloomFilterExport: bloom})
}

func (p *Peer) NotifyAboutTopicInterestChange(topics []types.TopicType) error {
	return p2p.Send(p.rw, statusUpdateCode, StatusOptions{TopicInterestExport: topics})
}

func (p *Peer) SetPeerTrusted(trusted bool) {
	p.trusted = trusted
}

func (p *Peer) RequestHistoricMessages(envelope *types.Envelope) error {
	return p2p.Send(p.rw, p2pRequestCode, envelope)
}

func (p *Peer) SendMessagesRequest(request types.MessagesRequest) error {
	return p2p.Send(p.rw, p2pRequestCode, request)
}
func (p *Peer) SendHistoricMessageResponse(payload []byte) error {
	size, r, err := rlp.EncodeToReader(payload)
	if err != nil {
		return err
	}

	return p.rw.WriteMsg(p2p.Msg{Code: p2pRequestCompleteCode, Size: uint32(size), Payload: r})

}

func (p *Peer) SendP2PMessages(envelopes []*types.Envelope) error {
	return p2p.Send(p.rw, p2pMessageCode, envelopes)
}

func (p *Peer) SendRawP2PDirect(envelopes []rlp.RawValue) error {
	return p2p.Send(p.rw, p2pMessageCode, envelopes)
}

func (p *Peer) SetRWWriter(rw p2p.MsgReadWriter) {
	p.rw = rw
}

// ID returns a peer's id
func (p *Peer) ID() []byte {
	id := p.p2pPeer.ID()
	return id[:]
}

func (p *Peer) EnodeID() enode.ID {
	return p.p2pPeer.ID()
}

func (p *Peer) IP() net.IP {
	return p.p2pPeer.Node().IP()
}

func (p *Peer) Run() error {
	logger := p.logger.Named("Run")

	for {
		// fetch the next packet
		packet, err := p.rw.ReadMsg()
		if err != nil {
			logger.Info("failed to read a message", zap.Binary("peer", p.ID()), zap.Error(err))
			return err
		}

		if packet.Size > p.host.MaxMessageSize() {
			logger.Warn("oversize message received", zap.Binary("peer", p.ID()), zap.Uint32("size", packet.Size))
			return errors.New("oversize message received")
		}

		if err := p.HandlePacket(packet); err != nil {
			logger.Warn("failed to handle packet message, peer will be disconnected", zap.Binary("peer", p.ID()), zap.Error(err))
		}
		_ = packet.Discard()
	}
}

func (p *Peer) HandlePacket(packet p2p.Msg) error {
	switch packet.Code {
	case messagesCode:
		if err := p.HandleMessagesCode(packet); err != nil {
			p.logger.Warn("failed to handle messagesCode message, peer will be disconnected", zap.Binary("peer", p.ID()), zap.Error(err))
			return err
		}
	case messageResponseCode:
		if err := p.HandleMessageResponseCode(packet); err != nil {
			p.logger.Warn("failed to handle messageResponseCode message, peer will be disconnected", zap.Binary("peer", p.ID()), zap.Error(err))
			return err
		}
	case batchAcknowledgedCode:
		if err := p.HandleBatchAcknowledgeCode(packet); err != nil {
			p.logger.Warn("failed to handle batchAcknowledgedCode message, peer will be disconnected", zap.Binary("peer", p.ID()), zap.Error(err))
			return err
		}
	case statusUpdateCode:
		if err := p.HandleStatusUpdateCode(packet); err != nil {
			p.logger.Warn("failed to decode status update message, peer will be disconnected", zap.Binary("peer", p.ID()), zap.Error(err))
			return err
		}
	case p2pMessageCode:
		if err := p.HandleP2PMessageCode(packet); err != nil {
			p.logger.Warn("failed to decode direct message, peer will be disconnected", zap.Binary("peer", p.ID()), zap.Error(err))
			return err
		}
	case p2pRequestCode:
		if err := p.HandleP2PRequestCode(packet); err != nil {
			p.logger.Warn("failed to decode p2p request message, peer will be disconnected", zap.Binary("peer", p.ID()), zap.Error(err))
			return err
		}
	case p2pRequestCompleteCode:
		if err := p.HandleP2PRequestCompleteCode(packet); err != nil {
			p.logger.Warn("failed to decode p2p request complete message, peer will be disconnected", zap.Binary("peer", p.ID()), zap.Error(err))
			return err
		}
	default:
		// New message types might be implemented in the future versions of Waku.
		// For forward compatibility, just ignore.
		p.logger.Debug("ignored packet with message code", zap.Uint64("code", packet.Code))
	}

	return nil
}

func Init() {
	initRLPKeyFields()
}

func NewProtocol(host types.WakuHost, p2pPeer *p2p.Peer, rw p2p.MsgReadWriter, logger *zap.Logger) *Peer {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Peer{
		host:           host,
		p2pPeer:        p2pPeer,
		logger:         logger,
		rw:             rw,
		trusted:        false,
		powRequirement: 0.0,
		known:          mapset.NewSet(),
		quit:           make(chan struct{}),
		bloomFilter:    types.MakeFullNodeBloom(),
		fullNode:       true,
	}
}

func (p *Peer) HandleMessagesCode(packet p2p.Msg) error {
	// decode the contained envelopes
	data, err := ioutil.ReadAll(packet.Payload)
	if err != nil {
		types.EnvelopesRejectedCounter.WithLabelValues("failed_read").Inc()
		return fmt.Errorf("failed to read packet payload: %v", err)
	}

	var envelopes []*types.Envelope
	if err := rlp.DecodeBytes(data, &envelopes); err != nil {
		types.EnvelopesRejectedCounter.WithLabelValues("invalid_data").Inc()
		return fmt.Errorf("invalid payload: %v", err)
	}

	envelopeErrors, err := p.host.OnNewEnvelopes(envelopes, p)

	if p.host.ConfirmationsEnabled() {
		go p.sendConfirmation(data, envelopeErrors) // nolint: errcheck
	}

	return err
}

func (p *Peer) HandleMessageResponseCode(packet p2p.Msg) error {
	var resp MultiVersionResponse
	if err := packet.Decode(&resp); err != nil {
		types.EnvelopesRejectedCounter.WithLabelValues("failed_read").Inc()
		return fmt.Errorf("invalid response message: %v", err)
	}
	if resp.Version != 1 {
		p.logger.Info("received unsupported version of MultiVersionResponse for messageResponseCode packet", zap.Uint("version", resp.Version))
		return nil
	}

	response, err := resp.DecodeResponse1()
	if err != nil {
		types.EnvelopesRejectedCounter.WithLabelValues("invalid_data").Inc()
		return fmt.Errorf("failed to decode response message: %v", err)
	}

	return p.host.OnMessagesResponse(response, p)
}

func (p *Peer) HandleP2PRequestCode(packet p2p.Msg) error {
	// Must be processed if mail server is implemented. Otherwise ignore.
	if !p.host.Mailserver() {
		return nil
	}

	// Read all data as we will try to decode it possibly twice.
	data, err := ioutil.ReadAll(packet.Payload)
	if err != nil {
		return fmt.Errorf("invalid p2p request messages: %v", err)
	}
	r := bytes.NewReader(data)
	packet.Payload = r

	// As we failed to decode the request, let's set the offset
	// to the beginning and try decode it again.
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("invalid p2p request message: %v", err)
	}

	var request types.MessagesRequest
	errReq := packet.Decode(&request)
	if errReq == nil {
		return p.host.OnMessagesRequest(request, p)
	}
	p.logger.Info("failed to decode p2p request message", zap.Binary("peer", p.ID()), zap.Error(errReq))

	return errors.New("invalid p2p request message")
}

func (p *Peer) HandleBatchAcknowledgeCode(packet p2p.Msg) error {
	var batchHash common.Hash
	if err := packet.Decode(&batchHash); err != nil {
		return fmt.Errorf("invalid batch ack message: %v", err)
	}
	return p.host.OnBatchAcknowledged(batchHash, p)
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

func (p *Peer) HandleP2PMessageCode(packet p2p.Msg) error {
	// peer-to-peer message, sent directly to peer bypassing PoW checks, etc.
	// this message is not supposed to be forwarded to other peers, and
	// therefore might not satisfy the PoW, expiry and other requirements.
	// these messages are only accepted from the trusted peer.
	if !p.trusted {
		return nil
	}

	var (
		envelopes []*types.Envelope
		err       error
	)

	if err = packet.Decode(&envelopes); err != nil {
		return fmt.Errorf("invalid direct message payload: %v", err)
	}

	return p.host.OnNewP2PEnvelopes(envelopes, p)
}

func (p *Peer) HandleP2PRequestCompleteCode(packet p2p.Msg) error {
	if !p.trusted {
		return nil
	}

	var payload []byte
	if err := packet.Decode(&payload); err != nil {
		return fmt.Errorf("invalid p2p request complete message: %v", err)
	}
	return p.host.OnP2PRequestCompleted(payload, p)
}

// sendConfirmation sends messageResponseCode and batchAcknowledgedCode messages.
func (p *Peer) sendConfirmation(data []byte, envelopeErrors []types.EnvelopeError) (err error) {
	batchHash := crypto.Keccak256Hash(data)
	err = p2p.Send(p.rw, messageResponseCode, NewMessagesResponse(batchHash, envelopeErrors))
	if err != nil {
		return
	}
	err = p2p.Send(p.rw, batchAcknowledgedCode, batchHash) // DEPRECATED
	return
}

// handshake sends the protocol initiation status message to the remote peer and
// verifies the remote status too.
func (p *Peer) handshake() error {
	// Send the handshake status message asynchronously
	errc := make(chan error, 1)
	opts := p.host.ToStatusOptions()
	go func() {
		errc <- p2p.SendItems(p.rw, statusCode, ProtocolVersion, opts)
	}()

	// Fetch the remote status packet and verify protocol match
	packet, err := p.rw.ReadMsg()
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

	batchHash, err := SendBundle(p.rw, bundle)
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
			Peer:  p.EnodeID(),
		}
		if p.confirmationsEnabled {
			event.Batch = batchHash
		}
		p.host.SendEnvelopeEvent(event)
	}
	p.logger.Debug("broadcasted bundles successfully", zap.Binary("peer", p.ID()), zap.Int("count", len(bundle)))
	return nil
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

// Marked checks if an envelope is already known to the remote peer.
func (p *Peer) Marked(envelope *types.Envelope) bool {
	return p.known.Contains(envelope.Hash())
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

func (p *Peer) topicInterestMatch(env *types.Envelope) bool {
	p.topicInterestMu.Lock()
	defer p.topicInterestMu.Unlock()

	if p.topicInterest == nil {
		return false
	}

	return p.topicInterest[env.Topic]
}

// mark marks an envelope known to the peer so that it won't be sent back.
func (p *Peer) Mark(envelope *types.Envelope) {
	p.known.Add(envelope.Hash())
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

func (p *Peer) PoWRequirement() float64 {
	return p.powRequirement
}
