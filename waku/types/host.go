package types

import (
	"github.com/ethereum/go-ethereum/common"
)

type WakuHost interface {
	ToStatusOptions() StatusOption
	LightClientMode() bool
	LightClientModeConnectionRestricted() bool
	ConfirmationsEnabled() bool
	IsEnvelopeCached(common.Hash) bool
	Envelopes() []*Envelope
	SendEnvelopeEvent(EnvelopeEvent) int
	OnNewEnvelopes([]*Envelope, *Protocol) ([]EnvelopeError, error)
}
