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
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
)

// Constants to match up protocol versions and messages
const (
	SSTORAGE1 = 1
)

// ProtocolName is the official short name of the `sstorage` protocol used during
// devp2p capability negotiation.
const ProtocolName = "sstorage"

// ProtocolVersions are the supported versions of the `sstorage` protocol (first
// is primary).
var ProtocolVersions = []uint{SSTORAGE1}

// protocolLengths are the number of implemented message corresponding to
// different protocol versions.
var protocolLengths = map[uint]uint64{SSTORAGE1: 6}

// maxMessageSize is the maximum cap on the size of a protocol message.
const maxMessageSize = 2 * 1024 * 1024

const (
	ShardsMsg     = 0x00
	GetKVRangeMsg = 0x01
	KVRangeMsg    = 0x02
	GetKVsMsg     = 0x03
	KVsMsg        = 0x04
)

var (
	errMsgTooLarge    = errors.New("message too long")
	errDecode         = errors.New("invalid message")
	errInvalidMsgCode = errors.New("invalid message code")
	errBadRequest     = errors.New("bad request")
)

// Packet represents a p2p message in the `sstorage` protocol.
type Packet interface {
	Name() string // Name returns a string corresponding to the message type.
	Kind() byte   // Kind returns the message type.
}

// GetKVsPacket represents a KVs query.
type GetKVsPacket struct {
	ID       uint64         // Request ID to match up responses with
	Contract common.Address // Contract of the sharded storage
	ShardId  uint64         // ShardId
	KVList   []uint64       // KVList index list to retrieve
}

// KVsPacket represents a KVs query response.
type KVsPacket struct {
	ID           uint64         // ID of the request this is a response for
	Contract     common.Address // Contract of the sharded storage
	ShardId      uint64
	ProviderAddr common.Address
	KVs          []*core.KV // List of the returning KVs data
}

// GetKVRangePacket represents a KVs query.
type GetKVRangePacket struct {
	ID       uint64         // Request ID to match up responses with
	Contract common.Address // Contract of the sharded storage
	ShardId  uint64         // ShardId
	Origin   uint64         // Index of the first kv to retrieve
	Limit    uint64         // Index of the last kv to retrieve
	Bytes    uint64         // Soft limit at which to stop returning data
}

// KVRangePacket represents a KVs query response.
type KVRangePacket struct {
	ID           uint64         // ID of the request this is a response for
	Contract     common.Address // Contract of the sharded storage
	ShardId      uint64
	ProviderAddr common.Address
	KVs          []*core.KV // List of the returning KVs data
}

type ShardListPacket struct {
	ContractShardsList []*ContractShards
}

type ContractShards struct {
	Contract common.Address
	ShardIds []uint64
}

func newShardListPacket(shards map[common.Address][]uint64) *ShardListPacket {
	shardListPacket := ShardListPacket{make([]*ContractShards, 0)}
	for contract, indexes := range shards {
		shardListPacket.ContractShardsList = append(shardListPacket.ContractShardsList, &ContractShards{contract, indexes})
	}

	return &shardListPacket
}

func convertShardList(shardList *ShardListPacket) map[common.Address][]uint64 {
	if shardList == nil {
		return nil
	}

	shards := make(map[common.Address][]uint64)
	for _, cs := range shardList.ContractShardsList {
		shards[cs.Contract] = cs.ShardIds
	}

	return shards
}

func (*GetKVsPacket) Name() string { return "GetKVsMsg" }
func (*GetKVsPacket) Kind() byte   { return GetKVsMsg }

func (*KVsPacket) Name() string { return "KVsMsg" }
func (*KVsPacket) Kind() byte   { return KVsMsg }

func (*GetKVRangePacket) Name() string { return "GetKVRangeMsg" }
func (*GetKVRangePacket) Kind() byte   { return GetKVRangeMsg }

func (*KVRangePacket) Name() string { return "KVRangeMsg" }
func (*KVRangePacket) Kind() byte   { return KVRangeMsg }
