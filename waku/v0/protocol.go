package v0

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/status-im/status-go/waku/types"
	"io"
	"io/ioutil"

	"go.uber.org/zap"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
)

type Protocol struct {
	peer   types.WakuPeer
	host   types.WakuHost
	rw     p2p.MsgReadWriter
	logger *zap.Logger
}

func (p *Protocol) Start() error {
	if err := p.peer.Handshake(); err != nil {
		return err
	}
	p.peer.Start()
	return nil
}

func (p *Protocol) Stop() {
	p.peer.Stop()
}

func (p *Protocol) NotifyAboutPowRequirementChange(pow float64) error {
	return p.peer.NotifyAboutPowRequirementChange(pow)
}

func (p *Protocol) NotifyAboutBloomFilterChange(bloom []byte) error {
	return p.peer.NotifyAboutBloomFilterChange(bloom)
}

func (p *Protocol) NotifyAboutTopicInterestChange(topics []types.TopicType) error {
	return p.peer.NotifyAboutTopicInterestChange(topics)
}

func (p *Protocol) SetPeerTrusted(trusted bool) {
	p.peer.SetPeerTrusted(trusted)
}

func (p *Protocol) RequestHistoricMessages(envelope *types.Envelope) error {
	return p.peer.RequestHistoricMessages(envelope)
}

func (p *Protocol) SendMessagesRequest(request types.MessagesRequest) error {
	return p.peer.SendMessagesRequest(request)
}
func (p *Protocol) SendHistoricMessageResponse(payload []byte) error {
	return p.peer.SendHistoricMessageResponse(payload)
}

func (p *Protocol) SendP2PMessages(envelopes []*types.Envelope) error {
	return p.peer.SendP2PMessages(envelopes)
}

func (p *Protocol) SendRawP2PDirect(envelopes []rlp.RawValue) error {
	return p.peer.SendRawP2PDirect(envelopes)
}

func (p *Protocol) SetRWWriter(rw p2p.MsgReadWriter) {
	p.rw = rw
}

func (p *Protocol) Run() error {
	logger := p.logger.Named("Run")

	for {
		// fetch the next packet
		packet, err := p.rw.ReadMsg()
		if err != nil {
			logger.Info("failed to read a message", zap.Binary("peer", p.peer.ID()), zap.Error(err))
			return err
		}

		if packet.Size > p.host.MaxMessageSize() {
			logger.Warn("oversize message received", zap.Binary("peer", p.peer.ID()), zap.Uint32("size", packet.Size))
			return errors.New("oversize message received")
		}

		if err := p.HandlePacket(packet); err != nil {
			logger.Warn("failed to handle packet message, peer will be disconnected", zap.Binary("peer", p.peer.ID()), zap.Error(err))
		}
		_ = packet.Discard()
	}
}

func (p *Protocol) HandlePacket(packet p2p.Msg) error {
	switch packet.Code {
	case messagesCode:
		if err := p.HandleMessagesCode(packet); err != nil {
			p.logger.Warn("failed to handle messagesCode message, peer will be disconnected", zap.Binary("peer", p.peer.ID()), zap.Error(err))
			return err
		}
	case messageResponseCode:
		if err := p.HandleMessageResponseCode(packet); err != nil {
			p.logger.Warn("failed to handle messageResponseCode message, peer will be disconnected", zap.Binary("peer", p.peer.ID()), zap.Error(err))
			return err
		}
	case batchAcknowledgedCode:
		if err := p.HandleBatchAcknowledgeCode(packet); err != nil {
			p.logger.Warn("failed to handle batchAcknowledgedCode message, peer will be disconnected", zap.Binary("peer", p.peer.ID()), zap.Error(err))
			return err
		}
	case statusUpdateCode:
		if err := p.HandleStatusUpdateCode(packet); err != nil {
			p.logger.Warn("failed to decode status update message, peer will be disconnected", zap.Binary("peer", p.peer.ID()), zap.Error(err))
			return err
		}
	case p2pMessageCode:
		if err := p.HandleP2PMessageCode(packet); err != nil {
			p.logger.Warn("failed to decode direct message, peer will be disconnected", zap.Binary("peer", p.peer.ID()), zap.Error(err))
			return err
		}
	case p2pRequestCode:
		if err := p.HandleP2PRequestCode(packet); err != nil {
			p.logger.Warn("failed to decode p2p request message, peer will be disconnected", zap.Binary("peer", p.peer.ID()), zap.Error(err))
			return err
		}
	case p2pRequestCompleteCode:
		if err := p.HandleP2PRequestCompleteCode(packet); err != nil {
			p.logger.Warn("failed to decode p2p request complete message, peer will be disconnected", zap.Binary("peer", p.peer.ID()), zap.Error(err))
			return err
		}
	default:
		// New message types might be implemented in the future versions of Waku.
		// For forward compatibility, just ignore.
		p.logger.Debug("ignored packet with message code", zap.Uint64("code", packet.Code))
	}

	return nil
}

func (p *Protocol) Peer() types.WakuPeer {
	return p.peer
}

func (p *Protocol) RW() p2p.MsgReadWriter {
	return p.rw
}

func NewProtocol(host types.WakuHost, p2pPeer *p2p.Peer, rw p2p.MsgReadWriter, logger *zap.Logger) *Protocol {
	if logger == nil {
		logger = zap.NewNop()
	}

	peer := NewPeer(host, p2pPeer, rw, logger.Named("waku/peer"))

	return &Protocol{
		host:   host,
		peer:   peer,
		logger: logger,
		rw:     rw,
	}
}

func (p *Protocol) HandleMessagesCode(packet p2p.Msg) error {
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

func (p *Protocol) HandleMessageResponseCode(packet p2p.Msg) error {
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

func (p *Protocol) HandleP2PRequestCode(packet p2p.Msg) error {
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
	p.logger.Info("failed to decode p2p request message", zap.Binary("peer", p.peer.ID()), zap.Error(errReq))

	return errors.New("invalid p2p request message")
}

func (p *Protocol) HandleBatchAcknowledgeCode(packet p2p.Msg) error {
	var batchHash common.Hash
	if err := packet.Decode(&batchHash); err != nil {
		return fmt.Errorf("invalid batch ack message: %v", err)
	}
	return p.host.OnBatchAcknowledged(batchHash, p)
}

func (p *Protocol) HandleStatusUpdateCode(packet p2p.Msg) error {
	return p.peer.HandleStatusUpdateCode(packet)
}

func (p *Protocol) HandleP2PMessageCode(packet p2p.Msg) error {
	// peer-to-peer message, sent directly to peer bypassing PoW checks, etc.
	// this message is not supposed to be forwarded to other peers, and
	// therefore might not satisfy the PoW, expiry and other requirements.
	// these messages are only accepted from the trusted peer.
	if !p.peer.Trusted() {
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

func (p *Protocol) HandleP2PRequestCompleteCode(packet p2p.Msg) error {
	if !p.peer.Trusted() {
		return nil
	}

	var payload []byte
	if err := packet.Decode(&payload); err != nil {
		return fmt.Errorf("invalid p2p request complete message: %v", err)
	}
	return p.host.OnP2PRequestCompleted(payload, p)
}

// sendConfirmation sends messageResponseCode and batchAcknowledgedCode messages.
func (p *Protocol) sendConfirmation(data []byte, envelopeErrors []types.EnvelopeError) (err error) {
	batchHash := crypto.Keccak256Hash(data)
	err = p2p.Send(p.rw, messageResponseCode, NewMessagesResponse(batchHash, envelopeErrors))
	if err != nil {
		return
	}
	err = p2p.Send(p.rw, batchAcknowledgedCode, batchHash) // DEPRECATED
	return
}
