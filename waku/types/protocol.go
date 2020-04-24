package types

import (
	"net"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

type Protocol interface {
	// Peer returns the remote peer involved in the protocol
	Peer() WakuPeer
	RW() p2p.MsgReadWriter
	HandlePacket(packet p2p.Msg) error
}

// WakuHost is the local instance of waku, which both interacts with remote clients
// (peers) and local clients (through RPC API)
type WakuHost interface {
	ToStatusOptions() StatusOption
	// LightClientMode returns whether the host is running in light client mode
	LightClientMode() bool
	// Mailserver returns whether the host is running a mailserver
	Mailserver() bool
	// LightClientModeConnectionRestricted indicates that connection to light client in light client mode not allowed
	LightClientModeConnectionRestricted() bool
	// ConfirmationsEnabled returns true if message confirmations are enabled.
	ConfirmationsEnabled() bool
	// isEnvelopeCached checks if envelope with specific hash has already been received and cached.
	IsEnvelopeCached(common.Hash) bool
	// Envelopes returns all the envelopes queued
	Envelopes() []*Envelope
	SendEnvelopeEvent(EnvelopeEvent) int
	// OnNewEnvelopes handles newly received envelopes from a peer
	OnNewEnvelopes([]*Envelope, Protocol) ([]EnvelopeError, error)
	// OnNewP2PEnvelopes handles envelopes received though the P2P
	// protocol (i.e from a mailserver in most cases)
	OnNewP2PEnvelopes([]*Envelope, Protocol) error
	// OnMessagesResponse handles when the peer receive a message response
	// from a mailserver
	OnMessagesResponse(MessagesResponse, Protocol) error
	// OnMessagesRequest handles when the peer receive a message request
	// this only works if the peer is a mailserver
	OnMessagesRequest(MessagesRequest, Protocol) error
	OnBatchAcknowledged(common.Hash, Protocol) error
	OnP2PRequestCompleted([]byte, Protocol) error
}

type WakuPeer interface {
	Start()
	Stop()
	Handshake() error
	NotifyAboutPowRequirementChange(float64) error
	NotifyAboutBloomFilterChange([]byte) error
	NotifyAboutTopicInterestChange([]TopicType) error
	RequestHistoricMessages(*Envelope) error
	SendMessagesRequest(MessagesRequest) error
	SendHistoricMessageResponse([]byte) error
	SendP2PMessages([]*Envelope) error
	SendP2PDirect([]*Envelope) error
	SendRawP2PDirect([]rlp.RawValue) error

	HandleStatusUpdateCode(packet p2p.Msg) error

	Mark(*Envelope)
	Marked(*Envelope) bool

	PoWRequirement() float64
	BloomFilter() []byte

	// SetPeerTrusted sets the value of trusted, meaning we will
	// allow p2p messages from them, which is necessary to interact
	// with mailservers.
	SetPeerTrusted(bool)
	// Trusted returns whether the peer has been marked as trusted
	Trusted() bool
	ID() []byte
	IP() net.IP
	EnodeID() enode.ID
}
