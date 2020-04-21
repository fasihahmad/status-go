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

package types

import (
	"bytes"
	"net"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

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

	Trusted() bool
	SetPeerTrusted(bool)
	ID() []byte
	IP() net.IP
	EnodeID() enode.ID
}

func MakeFullNodeBloom() []byte {
	bloom := make([]byte, BloomFilterSize)
	for i := 0; i < BloomFilterSize; i++ {
		bloom[i] = 0xFF
	}
	return bloom
}

func SendBundle(rw p2p.MsgWriter, bundle []*Envelope) (rst common.Hash, err error) {
	data, err := rlp.EncodeToBytes(bundle)
	if err != nil {
		return
	}
	err = rw.WriteMsg(p2p.Msg{
		Code:    messagesCode,
		Size:    uint32(len(data)),
		Payload: bytes.NewBuffer(data),
	})
	if err != nil {
		return
	}
	return crypto.Keccak256Hash(data), nil
}
