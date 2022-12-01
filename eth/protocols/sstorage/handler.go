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
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/sstorage"
)

// Handler is a callback to invoke from an outside runner after the boilerplate
// exchanges have passed.
type Handler func(peer *Peer) error

// Backend defines the Data retrieval methods to serve remote requests and the
// callback methods to invoke on remote deliveries.
type Backend interface {
	// Chain retrieves the blockchain object to serve Data.
	Chain() *core.BlockChain

	// RunPeer is invoked when a peer joins on the `eth` protocol. The handler
	// should do any peer maintenance work, handshakes and validations. If all
	// is passed, control should be given back to the `handler` to process the
	// inbound messages going forward.
	RunPeer(peer *Peer, handler Handler) error

	// PeerInfo retrieves all known `sstorage` information about a peer.
	PeerInfo(id enode.ID) interface{}

	// Handle is a callback to be invoked when a Data packet is received from
	// the remote peer. Only packets not consumed by the protocol handler will
	// be forwarded to the backend.
	Handle(peer *Peer, packet Packet) error
}

// MakeProtocols constructs the P2P protocol definitions for `sstorage`.
func MakeProtocols(backend Backend, shards map[common.Address][]uint64, dnsdisc enode.Iterator) []p2p.Protocol {
	// Filter the discovery iterator for nodes advertising sstorage support.
	dnsdisc = enode.Filter(dnsdisc, func(n *enode.Node) bool {
		var enr enrEntry
		return n.Load(&enr) == nil
	})

	protocols := make([]p2p.Protocol, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		version := version // Closure

		protocols[i] = p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  protocolLengths[version],
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				return backend.RunPeer(NewPeer(version, p, rw), func(peer *Peer) error {
					return Handle(backend, peer)
				})
			},
			NodeInfo: func() interface{} {
				return nodeInfo(backend.Chain(), shards)
			},
			PeerInfo: func(id enode.ID) interface{} {
				return backend.PeerInfo(id)
			},
			Attributes:     []enr.Entry{&enrEntry{}},
			DialCandidates: dnsdisc,
		}
	}
	return protocols
}

// Handle is the callback invoked to manage the life cycle of a `sstorage` peer.
// When this function terminates, the peer is disconnected.
func Handle(backend Backend, peer *Peer) error {
	for {
		if err := HandleMessage(backend, peer); err != nil {
			peer.Log().Debug("Message handling failed in `sstorage`", "err", err)
			return err
		}
	}
}

// HandleMessage is invoked whenever an inbound message is received from a
// remote peer on the `sstorage` protocol. The remote connection is torn down
// upon returning any error.
func HandleMessage(backend Backend, peer *Peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	msg, err := peer.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Size > maxMessageSize {
		return fmt.Errorf("%w: %v > %v", errMsgTooLarge, msg.Size, maxMessageSize)
	}
	defer msg.Discard()
	// Handle the message depending on its contents
	switch {
	case msg.Code == GetShardsMsg:
		// Decode trie node retrieval request
		req := new(ShardListPacket)
		if err := msg.Decode(req); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		peer.SetShards(convertShardList(req))
		peer.logger.Warn("HandleMessage: GetShardListMsg", "url", peer.Node().URLv4(), "shards", peer.shards)
		return p2p.Send(peer.rw, ShardsMsg, newShardListPacket(sstorage.Shards()))

		/*case msg.Code == ShardListMsg:
		// A batch of trie kvs arrived to one of our previous requests
		res := new(ShardListPacket)
		if err := msg.Decode(res); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		peer.SetShards(convertShardList(res))
		peer.logger.Warn("HandleMessage: ShardListMsg", "url", peer.Node().URLv4(), "shards", peer.shards)
		return nil*/
	case msg.Code == GetKVsMsg:
		// Decode trie node retrieval request
		var req GetKVsPacket
		if err := msg.Decode(&req); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		// Service the request, potentially returning nothing in case of errors
		kvs, err := ServiceGetKVsQuery(backend.Chain(), &req)
		if err != nil {
			return err
		}
		// Send back anything accumulated (or empty in case of errors)
		return p2p.Send(peer.rw, KVsMsg, &KVsPacket{
			ID:       req.ID,
			Contract: req.Contract,
			ShardId:  req.ShardId,
			KVs:      kvs,
		})

	case msg.Code == KVsMsg:
		// A batch of trie kvs arrived to one of our previous requests
		res := new(KVsPacket)
		if err := msg.Decode(res); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}

		return backend.Handle(peer, res)

	default:
		return fmt.Errorf("%w: %v", errInvalidMsgCode, msg.Code)
	}
}

// ServiceGetKVsQuery assembles the response to a kvs query.
// It is exposed to allow external packages to test protocol behavior.
func ServiceGetKVsQuery(chain *core.BlockChain, req *GetKVsPacket) ([]*KV, error) {
	sm := sstorage.ContractToShardManager[req.Contract]
	if sm == nil {
		return nil, fmt.Errorf("shard manager for contract %s is not support", req.Contract.Hex())
	}

	stateDB, err := chain.StateAt(chain.CurrentBlock().Root())
	if err != nil {
		return nil, err
	}
	res := make([]*KV, 0)
	for _, idx := range req.KVList {
		_, meta, err := getSstorageMetadata(stateDB, req.Contract, idx)
		if err != nil {
			continue
		}
		data, ok, err := sm.TryReadMaskedKV(idx, int(meta.kvSize), common.BytesToHash(meta.hashInMeta))
		if ok && err == nil {
			kv := KV{idx, data}
			res = append(res, &kv)
		}
	}

	return res, nil
}

// NodeInfo represents a short summary of the `sstorage` sub-protocol metadata
// known about the host peer.
type NodeInfo struct {
	Shards map[common.Address][]uint64
}

// nodeInfo retrieves some `sstorage` protocol metadata about the running host node.
func nodeInfo(chain *core.BlockChain, shards map[common.Address][]uint64) *NodeInfo {
	return &NodeInfo{
		shards,
	}
}
