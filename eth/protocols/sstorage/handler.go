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
	"time"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
)

const (
	// softResponseLimit is the target maximum size of replies to data retrievals.
	softResponseLimit = 2 * 1024 * 1024

	// maxEntryLookups is the maximum number of Entry to serve. This
	// number is there to limit the number of disk lookups.
	maxEntryLookups = 1024
)

// Handler is a callback to invoke from an outside runner after the boilerplate
// exchanges have passed.
type Handler func(peer *Peer) error

// Backend defines the data retrieval methods to serve remote requests and the
// callback methods to invoke on remote deliveries.
type Backend interface {
	// Chain retrieves the blockchain object to serve data.
	Chain() *core.BlockChain

	// RunPeer is invoked when a peer joins on the `eth` protocol. The handler
	// should do any peer maintenance work, handshakes and validations. If all
	// is passed, control should be given back to the `handler` to process the
	// inbound messages going forward.
	RunPeer(peer *Peer, handler Handler) error

	// PeerInfo retrieves all known `snap` information about a peer.
	PeerInfo(id enode.ID) interface{}

	// Handle is a callback to be invoked when a data packet is received from
	// the remote peer. Only packets not consumed by the protocol handler will
	// be forwarded to the backend.
	Handle(peer *Peer, packet Packet) error
}

// MakeProtocols constructs the P2P protocol definitions for `snap`.
func MakeProtocols(backend Backend, dnsdisc enode.Iterator) []p2p.Protocol {
	// Filter the discovery iterator for nodes advertising snap support.
	dnsdisc = enode.Filter(dnsdisc, func(n *enode.Node) bool {
		var snap enrEntry
		return n.Load(&snap) == nil
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
				return nodeInfo(backend.Chain())
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

// Handle is the callback invoked to manage the life cycle of a `snap` peer.
// When this function terminates, the peer is disconnected.
func Handle(backend Backend, peer *Peer) error {
	for {
		if err := HandleMessage(backend, peer); err != nil {
			peer.Log().Debug("Message handling failed in `snap`", "err", err)
			return err
		}
	}
}

// HandleMessage is invoked whenever an inbound message is received from a
// remote peer on the `snap` protocol. The remote connection is torn down upon
// returning any error.
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
	start := time.Now()
	// Track the emount of time it takes to serve the request and run the handler
	if metrics.Enabled {
		h := fmt.Sprintf("%s/%s/%d/%#02x", p2p.HandleHistName, ProtocolName, peer.Version(), msg.Code)
		defer func(start time.Time) {
			sampler := func() metrics.Sample {
				return metrics.ResettingSample(
					metrics.NewExpDecaySample(1028, 0.015),
				)
			}
			metrics.GetOrRegisterHistogramLazy(h, nil, sampler).Update(time.Since(start).Microseconds())
		}(start)
	}
	// Handle the message depending on its contents
	switch {
	case msg.Code == GetChunksMsg:
		// Decode trie node retrieval request
		var req GetChunksPacket
		if err := msg.Decode(&req); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		// Service the request, potentially returning nothing in case of errors
		nodes, err := ServiceGetChunksQuery(backend.Chain(), &req, start)
		if err != nil {
			return err
		}
		// Send back anything accumulated (or empty in case of errors)
		return p2p.Send(peer.rw, ChunksMsg, &ChunksPacket{
			ID:     req.ID,
			Chunks: nodes, // todo
		})

	case msg.Code == ChunksMsg:
		// A batch of trie nodes arrived to one of our previous requests
		res := new(ChunksPacket)
		if err := msg.Decode(res); err != nil {
			return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
		}
		requestTracker.Fulfil(peer.id, peer.version, ChunksMsg, res.ID)

		return backend.Handle(peer, res)

	default:
		return fmt.Errorf("%w: %v", errInvalidMsgCode, msg.Code)
	}
}

// ServiceGetChunksQuery assembles the response to a trie nodes query.
// It is exposed to allow external packages to test protocol behavior.
func ServiceGetChunksQuery(chain *core.BlockChain, req *GetChunksPacket, start time.Time) ([]*Chunk, error) {
	return nil, nil
	/*if req.Bytes > softResponseLimit {
		req.Bytes = softResponseLimit
	}
	// Make sure we have the state associated with the request
	triedb := chain.StateCache().TrieDB()

	accTrie, err := trie.NewSecure(req.Root, triedb)
	if err != nil {
		// We don't have the requested state available, bail out
		return nil, nil
	}
	snap := chain.Snapshots().Snapshot(req.Root)
	if snap == nil {
		// We don't have the requested state snapshotted yet, bail out.
		// In reality we could still serve using the account and storage
		// tries only, but let's protect the node a bit while it's doing
		// snapshot generation.
		return nil, nil
	}
	// Retrieve trie nodes until the packet size limit is reached
	var (
		nodes [][]byte
		bytes uint64
		loads int // Trie hash expansions to cound database reads
	)
	for _, pathset := range req.Paths {
		switch len(pathset) {
		case 0:
			// Ensure we penalize invalid requests
			return nil, fmt.Errorf("%w: zero-item pathset requested", errBadRequest)

		case 1:
			// If we're only retrieving an account trie node, fetch it directly
			blob, resolved, err := accTrie.TryGetNode(pathset[0])
			loads += resolved // always account database reads, even for failures
			if err != nil {
				break
			}
			nodes = append(nodes, blob)
			bytes += uint64(len(blob))

		default:
			// Storage slots requested, open the storage trie and retrieve from there
			account, err := snap.Account(common.BytesToHash(pathset[0]))
			loads++ // always account database reads, even for failures
			if err != nil || account == nil {
				break
			}
			stTrie, err := trie.NewSecure(common.BytesToHash(account.Root), triedb)
			loads++ // always account database reads, even for failures
			if err != nil {
				break
			}
			for _, path := range pathset[1:] {
				blob, resolved, err := stTrie.TryGetNode(path)
				loads += resolved // always account database reads, even for failures
				if err != nil {
					break
				}
				nodes = append(nodes, blob)
				bytes += uint64(len(blob))

				// Sanity check limits to avoid DoS on the store trie loads
				if bytes > req.Bytes || loads > maxEntryLookups || time.Since(start) > maxTrieNodeTimeSpent {
					break
				}
			}
		}
		// Abort request processing if we've exceeded our limits
		if bytes > req.Bytes || loads > maxEntryLookups || time.Since(start) > maxTrieNodeTimeSpent {
			break
		}
	}
	return nodes, nil*/
}

// NodeInfo represents a short summary of the `snap` sub-protocol metadata
// known about the host peer.
type NodeInfo struct{}

// nodeInfo retrieves some `snap` protocol metadata about the running host node.
func nodeInfo(chain *core.BlockChain) *NodeInfo {
	return &NodeInfo{}
}
