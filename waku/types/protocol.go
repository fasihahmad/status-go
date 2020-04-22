package types

import (
	"fmt"
	"io/ioutil"

	"go.uber.org/zap"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	ProtocolVersion    = uint64(0) // Protocol version number
	ProtocolVersionStr = "0"       // The same, as a string
	ProtocolName       = "waku"    // Nickname of the protocol

	// Waku protocol message codes, according to https://github.com/vacp2p/specs/blob/master/waku.md
	messagesCode          = 1  // regular message
	batchAcknowledgedCode = 11 // confirmation that batch of envelopes was received
	messageResponseCode   = 12 // includes confirmation for delivery and information about errors

)

type MessagesResponse struct {
	// Hash is a hash of all envelopes sent in the single batch.
	Hash common.Hash
	// Per envelope error.
	Errors []EnvelopeError
}

// Version1MessageResponse first version of the message response.
type Version1MessageResponse struct {
	Version  uint
	Response MessagesResponse
}

// NewMessagesResponse returns instance of the version messages response.
func NewMessagesResponse(batch common.Hash, errors []EnvelopeError) Version1MessageResponse {
	return Version1MessageResponse{
		Version: 1,
		Response: MessagesResponse{
			Hash:   batch,
			Errors: errors,
		},
	}
}

type Protocol struct {
	them   WakuPeer
	us     WakuPeer
	host   WakuHost
	rw     p2p.MsgReadWriter
	logger *zap.Logger
}

func (p *Protocol) HandlePacket(packet *p2p.Msg) error {
	return nil
}

func (p *Protocol) Them() WakuPeer {
	return p.them
}

func (p *Protocol) Us() WakuPeer {
	return p.us
}

func (p *Protocol) RW() p2p.MsgReadWriter {
	return p.rw
}

func NewProtocol(host WakuHost, us WakuPeer, them WakuPeer, rw p2p.MsgReadWriter, logger *zap.Logger) *Protocol {
	return &Protocol{
		host:   host,
		us:     us,
		them:   them,
		logger: logger,
		rw:     rw,
	}
}

// OnNewEnvelopes
func (p *Protocol) HandleMessagesCode(packet p2p.Msg) error {
	// decode the contained envelopes
	data, err := ioutil.ReadAll(packet.Payload)
	if err != nil {
		EnvelopesRejectedCounter.WithLabelValues("failed_read").Inc()
		return fmt.Errorf("failed to read packet payload: %v", err)
	}

	var envelopes []*Envelope
	if err := rlp.DecodeBytes(data, &envelopes); err != nil {
		EnvelopesRejectedCounter.WithLabelValues("invalid_data").Inc()
		return fmt.Errorf("invalid payload: %v", err)
	}

	envelopeErrors, err := p.host.OnNewEnvelopes(envelopes, p)

	if p.host.ConfirmationsEnabled() {
		go p.sendConfirmation(data, envelopeErrors) // nolint: errcheck
	}

	return err
}

// sendConfirmation sends messageResponseCode and batchAcknowledgedCode messages.
func (p *Protocol) sendConfirmation(data []byte, envelopeErrors []EnvelopeError) (err error) {
	batchHash := crypto.Keccak256Hash(data)
	err = p2p.Send(p.rw, messageResponseCode, NewMessagesResponse(batchHash, envelopeErrors))
	if err != nil {
		return
	}
	err = p2p.Send(p.rw, batchAcknowledgedCode, batchHash) // DEPRECATED
	return
}
