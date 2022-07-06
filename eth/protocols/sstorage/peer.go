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
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
)

// Peer is a collection of relevant information we have about a `snap` peer.
type Peer struct {
	id string // Unique ID for the peer, cached

	*p2p.Peer                   // The embedded P2P package peer
	rw        p2p.MsgReadWriter // Input/output streams for snap
	version   uint              // Protocol version negotiated
	shardList []uint64

	logger log.Logger // Contextual logger with the peer id injected
}

// NewPeer create a wrapper for a network connection and negotiated  protocol
// version.
func NewPeer(version uint, shardList []uint64, p *p2p.Peer, rw p2p.MsgReadWriter) *Peer {
	id := p.ID().String()
	return &Peer{
		id:        id,
		Peer:      p,
		rw:        rw,
		version:   version,
		shardList: shardList,
		logger:    log.New("peer", id[:8]),
	}
}

// ID retrieves the peer's unique identifier.
func (p *Peer) ID() string {
	return p.id
}

// Version retrieves the peer's negoatiated `snap` protocol version.
func (p *Peer) Version() uint {
	return p.version
}

// Version retrieves the peer's negoatiated `snap` protocol version.
func (p *Peer) ShardList() []uint64 {
	return p.shardList
}

// Log overrides the P2P logget with the higher level one containing only the id.
func (p *Peer) Log() log.Logger {
	return p.logger
}

// RequestChunks fetches a batch of chunks rooted in a specific account
// trie, starting with the origin.
func (p *Peer) RequestChunks(id uint64, shardId, startIdx, endIdx uint64) error {
	p.logger.Trace("Fetching Chunks", "reqid", id, "shardId", shardId, "startIdx", startIdx, "endIdx", endIdx)

	requestTracker.Track(p.id, p.version, GetChunksMsg, ChunksMsg, id)
	return p2p.Send(p.rw, GetChunksMsg, &GetChunksPacket{
		ID:       id,
		ShardId:  shardId,
		StartIdx: startIdx,
		EndIdx:   endIdx,
	})
}
