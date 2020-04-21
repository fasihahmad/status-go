// Copyright 2019 The Waku Library Authors.
//
// The Waku library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Waku library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty off
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Waku library. If not, see <http://www.gnu.org/licenses/>.
//
// This software uses the go-ethereum library, which is licensed
// under the GNU Lesser General Public Library, version 3 or any later.

package waku

import (
	"github.com/status-im/status-go/waku/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// Waku protocol parameters
const (
	ProtocolVersion    = uint64(0) // Protocol version number
	ProtocolVersionStr = "0"       // The same, as a string
	ProtocolName       = "waku"    // Nickname of the protocol

	// Waku protocol message codes, according to https://github.com/vacp2p/specs/blob/master/waku.md
	statusCode             = 0   // used in the handshake
	messagesCode           = 1   // regular message
	statusUpdateCode       = 22  // update of settings
	batchAcknowledgedCode  = 11  // confirmation that batch of envelopes was received
	messageResponseCode    = 12  // includes confirmation for delivery and information about errors
	p2pRequestCompleteCode = 125 // peer-to-peer message, used by Dapp protocol
	p2pRequestCode         = 126 // peer-to-peer message, used by Dapp protocol
	p2pMessageCode         = 127 // peer-to-peer message (to be consumed by the peer, but not forwarded any further)
	NumberOfMessageCodes   = 128

	signatureLength  = crypto.SignatureLength // in bytes
	aesKeyLength     = 32                     // in bytes
	aesNonceLength   = 12                     // in bytes; for more info please see cipher.gcmStandardNonceSize & aesgcm.NonceSize()
	MaxTopicInterest = 10000
	flagsLength      = 1

	MaxMessageSize        = uint32(10 * 1024 * 1024) // maximum accepted size of a message.
	DefaultMaxMessageSize = uint32(1024 * 1024)
	DefaultMinimumPoW     = 0.2

	padSizeLimit      = 256 // just an arbitrary number, could be changed without breaking the protocol
	messageQueueLimit = 1024

	DefaultTTL           = 50 // seconds
	DefaultSyncAllowance = 10 // seconds

	MaxLimitInSyncMailRequest = 1000

	EnvelopeTimeNotSynced uint = iota + 1
	EnvelopeOtherError

	MaxLimitInMessagesRequest = 1000
)

// MailServer represents a mail server, capable of
// archiving the old messages for subsequent delivery
// to the peers. Any implementation must ensure that both
// functions are thread-safe. Also, they must return ASAP.
// DeliverMail should use p2pMessageCode for delivery,
// in order to bypass the expiry checks.
type MailServer interface {
	Archive(env *types.Envelope)
	DeliverMail(peerID []byte, request *types.Envelope) // DEPRECATED; use Deliver()
	Deliver(peerID []byte, request types.MessagesRequest)
}

// MessagesResponse sent as a response after processing batch of envelopes.
type MessagesResponse struct {
	// Hash is a hash of all envelopes sent in the single batch.
	Hash common.Hash
	// Per envelope error.
	Errors []EnvelopeError
}

// EnvelopeError code and optional description of the error.
type EnvelopeError struct {
	Hash        common.Hash
	Code        uint
	Description string
}

// MultiVersionResponse allows to decode response into chosen version.
type MultiVersionResponse struct {
	Version  uint
	Response rlp.RawValue
}

// DecodeResponse1 decodes response into first version of the messages response.
func (m MultiVersionResponse) DecodeResponse1() (resp MessagesResponse, err error) {
	return resp, rlp.DecodeBytes(m.Response, &resp)
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

// ErrorToEnvelopeError converts common golang error into EnvelopeError with a code.
func ErrorToEnvelopeError(hash common.Hash, err error) EnvelopeError {
	code := EnvelopeOtherError
	switch err.(type) {
	case TimeSyncError:
		code = EnvelopeTimeNotSynced
	}
	return EnvelopeError{
		Hash:        hash,
		Code:        code,
		Description: err.Error(),
	}
}

// MailServerResponse is the response payload sent by the mailserver.
type MailServerResponse struct {
	LastEnvelopeHash common.Hash
	Cursor           []byte
	Error            error
}
