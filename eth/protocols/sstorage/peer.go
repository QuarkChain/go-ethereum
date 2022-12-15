// Copyright 2020 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package sstorage

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
)

// Peer is a collection of relevant information we have about a `sstorage` peer.
type Peer struct {
	id string // Unique ID for the peer, cached

	*p2p.Peer                             // The embedded P2P package peer
	rw        p2p.MsgReadWriter           // Input/output streams for sstorage
	version   uint                        // Protocol version negotiated
	shards    map[common.Address][]uint64 // shards of this node support

	logger log.Logger // Contextual logger with the peer id injected
}

// NewPeer create a wrapper for a network connection and negotiated  protocol
// version.
func NewPeer(version uint, p *p2p.Peer, rw p2p.MsgReadWriter) *Peer {
	id := p.ID().String()
	return &Peer{
		id:      id,
		Peer:    p,
		rw:      rw,
		version: version,
		logger:  log.New("peer", id[:8]),
	}
}

// ID retrieves the peer's unique identifier.
func (p *Peer) ID() string {
	return p.id
}

// Version retrieves the peer's negoatiated `sstorage` protocol version.
func (p *Peer) Version() uint {
	return p.version
}

func (p *Peer) Shards() map[common.Address][]uint64 {
	return p.shards
}

func (p *Peer) SetShards(shards map[common.Address][]uint64) {
	p.shards = shards
}

// IsShardExist checks whether one specific shard is supported by this peer.
func (p *Peer) IsShardExist(contract common.Address, shardId uint64) bool {
	if ids, ok := p.shards[contract]; ok {
		for _, id := range ids {
			if id == shardId {
				return true
			}
		}
	}

	return false
}

// Log overrides the P2P logger with the higher level one containing only the id.
func (p *Peer) Log() log.Logger {
	return p.logger
}

// RequestKVs fetches a batch of kvs using a list of kv index
func (p *Peer) RequestKVs(id uint64, contract common.Address, shardId uint64, kvList []uint64) error {
	p.logger.Trace("Fetching KVs", "reqId", id, "contract", contract,
		"shardId", shardId, "count", len(kvList))

	requestTracker.Track(p.id, p.version, GetKVsMsg, KVsMsg, id)
	return p2p.Send(p.rw, GetKVsMsg, &GetKVsPacket{
		ID:       id,
		Contract: contract,
		ShardId:  shardId,
		KVList:   kvList,
	})
}

// RequestKVs fetches a batch of kvs using a list of kv index
func (p *Peer) RequestKVRange(id uint64, contract common.Address, shardId uint64, origin uint64, limit uint64) error {
	p.logger.Trace("Fetching KVs", "reqId", id, "contract", contract,
		"shardId", shardId, "origin", origin, "limit", limit)

	requestTracker.Track(p.id, p.version, GetKVRangeMsg, KVRangeMsg, id)
	return p2p.Send(p.rw, GetKVRangeMsg, &GetKVRangePacket{
		ID:       id,
		Contract: contract,
		ShardId:  shardId,
		Origin:   origin,
		Limit:    limit,
		Bytes:    maxMessageSize,
	})
}

// RequestShardList fetches shard list support by the peer
func (p *Peer) RequestShardList(shards map[common.Address][]uint64) error {
	p.logger.Trace("Fetching Shard list", "shards", shards)

	shardListPacket := newShardListPacket(shards)
	return p2p.Send(p.rw, GetShardsMsg, shardListPacket)
}
