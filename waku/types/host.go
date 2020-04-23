package types

import (
	"github.com/ethereum/go-ethereum/common"
)

type WakuHost interface {
	ToStatusOptions() StatusOption
	LightClientMode() bool
	Mailserver() bool
	LightClientModeConnectionRestricted() bool
	ConfirmationsEnabled() bool
	IsEnvelopeCached(common.Hash) bool
	Envelopes() []*Envelope
	SendEnvelopeEvent(EnvelopeEvent) int
	OnNewEnvelopes([]*Envelope, *Protocol) ([]EnvelopeError, error)
	OnNewP2PEnvelopes([]*Envelope, *Protocol) error
	OnMessagesResponse(MessagesResponse, *Protocol) error
	OnMessagesRequest(MessagesRequest, *Protocol) error
	OnBatchAcknowledged(common.Hash, *Protocol) error
	OnP2PRequestCompleted([]byte, *Protocol) error
}
