package types

import (
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	TopicLength          = 4 // in bytes
	EnvelopeHeaderLength = 20
	BloomFilterSize      = 64                     // in bytes
	signatureLength      = crypto.SignatureLength // in bytes
	aesKeyLength         = 32                     // in bytes
	aesNonceLength       = 12                     // in bytes; for more info please see cipher.gcmStandardNonceSize & aesgcm.NonceSize()
	flagsLength          = 1
	padSizeLimit         = 256 // just an arbitrary number, could be changed without breaking the protocol
	DefaultTTL           = 50  // seconds
	signatureFlag        = byte(4)
	SizeMask             = byte(3) // mask used to extract the size of payload size field from the flags
	KeyIDSize            = 32      // in bytes

	ExpirationCycle   = time.Second
	TransmissionCycle = 300 * time.Millisecond

	MaxLimitInMessagesRequest = 1000
)

// MessagesRequest contains details of a request of historic messages.
type MessagesRequest struct {
	// ID of the request. The current implementation requires ID to be 32-byte array,
	// however, it's not enforced for future implementation.
	ID []byte `json:"id"`

	// From is a lower bound of time range.
	From uint32 `json:"from"`

	// To is a upper bound of time range.
	To uint32 `json:"to"`

	// Limit determines the number of messages sent by the mail server
	// for the current paginated request.
	Limit uint32 `json:"limit"`

	// Cursor is used as starting point for paginated requests.
	Cursor []byte `json:"cursor"`

	// Bloom is a filter to match requested messages.
	Bloom []byte `json:"bloom"`

	// Topics is a list of topics. A returned message should
	// belong to one of the topics from the list.
	Topics [][]byte `json:"topics"`
}

func (r MessagesRequest) Validate() error {
	if len(r.ID) != common.HashLength {
		return errors.New("invalid 'ID', expected a 32-byte slice")
	}

	if r.From > r.To {
		return errors.New("invalid 'From' value which is greater than To")
	}

	if r.Limit > MaxLimitInMessagesRequest {
		return fmt.Errorf("invalid 'Limit' value, expected value lower than %d", MaxLimitInMessagesRequest)
	}

	if len(r.Bloom) == 0 && len(r.Topics) == 0 {
		return errors.New("invalid 'Bloom' or 'Topics', one must be non-empty")
	}

	return nil
}

// RateLimits contains information about rate limit settings.
// It is exchanged using rateLimitingCode packet or in the handshake.
type RateLimits struct {
	IPLimits     uint64 // messages per second from a single IP (default 0, no limits)
	PeerIDLimits uint64 // messages per second from a single peer ID (default 0, no limits)
	TopicLimits  uint64 // messages per second from a single topic (default 0, no limits)
}

func (r RateLimits) IsZero() bool {
	return r == (RateLimits{})
}

type StatusOption interface {
	PoWRequirement() *uint64
	BloomFilter() []byte
	LightNodeEnabled() *bool
	ConfirmationsEnabled() *bool
	RateLimits() *RateLimits
	TopicInterest() []TopicType
}

func IsFullNode(bloom []byte) bool {
	if bloom == nil {
		return true
	}
	for _, b := range bloom {
		if b != 255 {
			return false
		}
	}
	return true
}

func BloomFilterMatch(filter, sample []byte) bool {
	if filter == nil {
		return true
	}

	for i := 0; i < BloomFilterSize; i++ {
		f := filter[i]
		s := sample[i]
		if (f | s) != f {
			return false
		}
	}

	return true
}

// EnvelopeError code and optional description of the error.
type EnvelopeError struct {
	Hash        common.Hash
	Code        uint
	Description string
}
