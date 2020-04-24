package common

import "github.com/ethereum/go-ethereum/common"

type MessagesResponse struct {
	// Hash is a hash of all envelopes sent in the single batch.
	Hash common.Hash
	// Per envelope error.
	Errors []EnvelopeError
}
