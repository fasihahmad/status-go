package types

import (
	"github.com/ethereum/go-ethereum/p2p"
)

type Protocol interface {
	Them() WakuPeer
	RW() p2p.MsgReadWriter
	HandlePacket(packet p2p.Msg) error
}
