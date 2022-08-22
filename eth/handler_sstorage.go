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

package eth

import (
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/eth/protocols/sstorage"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// sstorageHandler implements the sstorage.Backend interface to handle the various network
// packets that are sent as replies or broadcasts.
type sstorageHandler handler

func (h *sstorageHandler) Chain() *core.BlockChain { return h.chain }

// RunPeer is invoked when a peer joins on the `sstorage` protocol.
func (h *sstorageHandler) RunPeer(peer *sstorage.Peer, hand sstorage.Handler) error {
	return (*handler)(h).runSstorageExtension(peer, hand)
}

// PeerInfo retrieves all known `sstorage` information about a peer.
func (h *sstorageHandler) PeerInfo(id enode.ID) interface{} {
	if p := h.peers.peer(id.String()); p != nil {
		if p.sstorageExt != nil {
			return p.sstorageExt.Version()
		}
	}
	return nil
}

// Handle is invoked from a peer's message handler when it receives a new remote
// message that the handler couldn't consume and serve itself.
func (h *sstorageHandler) Handle(peer *sstorage.Peer, packet sstorage.Packet) error {
	return h.downloader.DeliverSstoragePacket(peer, packet)
}
