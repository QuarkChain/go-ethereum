package sstorage

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

type ShardManager struct {
	shardMap        map[uint64]*DataShard
	contractAddress common.Address
	kvSize          uint64
	chunksPerKv     uint64
	kvEntries       uint64
	kvSizeBits      uint64
	chunksPerKvBits uint64
	kvEntriesBits   uint64
}

func NewShardManager(contractAddress common.Address, kvSizeBits uint64, kvEntriesBits uint64) *ShardManager {
	return &ShardManager{
		shardMap:        make(map[uint64]*DataShard),
		contractAddress: contractAddress,
		kvSize:          1 << kvSizeBits,
		chunksPerKv:     (1 << kvSizeBits) / CHUNK_SIZE,
		kvEntries:       1 << kvEntriesBits,
		kvSizeBits:      kvSizeBits,
		chunksPerKvBits: kvSizeBits - CHUNK_SIZE_BITS,
		kvEntriesBits:   kvEntriesBits,
	}
}

func (sm *ShardManager) ShardMap() map[uint64]*DataShard {
	return sm.shardMap
}

func (sm *ShardManager) ChunksPerKv() uint64 {
	return sm.chunksPerKv
}

func (sm *ShardManager) ChunksPerKvBits() uint64 {
	return sm.chunksPerKvBits
}

func (sm *ShardManager) KvEntries() uint64 {
	return sm.kvEntries
}

func (sm *ShardManager) KvEntriesBits() uint64 {
	return sm.kvEntriesBits
}

func (sm *ShardManager) MaxKvSize() uint64 {
	return sm.kvSize
}

func (sm *ShardManager) MaxKvSizeBits() uint64 {
	return sm.kvSizeBits
}

func (sm *ShardManager) AddDataShard(shardIdx uint64) error {
	if _, ok := sm.shardMap[shardIdx]; !ok {
		ds := NewDataShard(shardIdx, sm.kvSize, sm.kvEntries)
		sm.shardMap[shardIdx] = ds
		return nil
	} else {
		return fmt.Errorf("data shard already exists")
	}
}

func (sm *ShardManager) AddDataFile(df *DataFile) error {
	shardIdx := df.chunkIdxStart / sm.chunksPerKv / sm.kvEntries
	var ds *DataShard
	var ok bool
	if ds, ok = sm.shardMap[shardIdx]; !ok {
		return fmt.Errorf("data shard not found")
	}

	return ds.AddDataFile(df)
}

// TryWrite Encode a raw KV data, and write it to the underly storage file.
// Return error if the write IO fails.
// Return false if the data is not managed by the ShardManager.
func (sm *ShardManager) TryWrite(kvIdx uint64, b []byte, commit common.Hash) (bool, error) {
	shardIdx := kvIdx / sm.kvEntries
	if ds, ok := sm.shardMap[shardIdx]; ok {
		return true, ds.Write(kvIdx, b, commit)
	} else {
		return false, nil
	}
}

// TryRead Read the encoded KV data from storage file and decode it.
// Return error if the read IO fails.
// Return false if the data is not managed by the ShardManager.
func (sm *ShardManager) TryRead(kvIdx uint64, readLen int, commit common.Hash) ([]byte, bool, error) {
	shardIdx := kvIdx / sm.kvEntries
	if ds, ok := sm.shardMap[shardIdx]; ok {
		b, err := ds.Read(kvIdx, readLen, commit)
		return b, true, err
	} else {
		return nil, false, nil
	}
}

func (sm *ShardManager) GetShardMiner(shardIdx uint64) (common.Address, bool) {
	if ds, ok := sm.shardMap[shardIdx]; ok {
		return ds.Miner(), true
	}
	return common.Address{}, false
}

// Decode the encoded KV data.
func (sm *ShardManager) DecodeKV(kvIdx uint64, b []byte, hash common.Hash, providerAddr common.Address) ([]byte, bool, error) {
	return sm.DecodeOrEncodeKV(kvIdx, b, hash, providerAddr, false)
}

// Encode the raw KV data.
func (sm *ShardManager) EncodeKV(kvIdx uint64, b []byte, hash common.Hash, providerAddr common.Address) ([]byte, bool, error) {
	return sm.DecodeOrEncodeKV(kvIdx, b, hash, providerAddr, true)
}

func (sm *ShardManager) DecodeOrEncodeKV(kvIdx uint64, b []byte, hash common.Hash, providerAddr common.Address, encode bool) ([]byte, bool, error) {
	shardIdx := kvIdx / sm.kvEntries
	var data []byte
	if ds, ok := sm.shardMap[shardIdx]; ok {
		datalen := len(b)
		for i := uint64(0); i < ds.chunksPerKv; i++ {
			if datalen == 0 {
				break
			}

			chunkReadLen := datalen
			if chunkReadLen > int(CHUNK_SIZE) {
				chunkReadLen = int(CHUNK_SIZE)
			}
			datalen = datalen - chunkReadLen

			chunkIdx := kvIdx*ds.chunksPerKv + i
			encodeKey := calcEncodeKey(hash, chunkIdx, providerAddr)
			var cdata []byte
			if encode {
				cdata = encodeChunk(b[i*CHUNK_SIZE:i*CHUNK_SIZE+uint64(chunkReadLen)], ds.EncodeType(), encodeKey)
			} else {
				cdata = decodeChunk(b[i*CHUNK_SIZE:i*CHUNK_SIZE+uint64(chunkReadLen)], ds.EncodeType(), encodeKey)
			}
			data = append(data, cdata...)
		}
		return data, true, nil
	}
	return nil, false, nil
}

// TryReadEncoded Read the encoded KV data from storage file and return it.
// Return error if the read IO fails.
// Return false if the data is not managed by the ShardManager.
func (sm *ShardManager) TryReadEncoded(kvIdx uint64, readLen int) ([]byte, bool, error) {
	shardIdx := kvIdx / sm.kvEntries
	if ds, ok := sm.shardMap[shardIdx]; ok {
		b, err := ds.ReadEncoded(kvIdx, readLen) // read all the data
		return b[:readLen], true, err
	} else {
		return nil, false, nil
	}
}

// TryReadChunk Read the encoded KV data using chunkIdx from storage file and decode it.
// Return error if the read IO fails.
// Return false if the data is not managed by the ShardManager.
func (sm *ShardManager) TryReadChunk(chunkIdx uint64, commit common.Hash) ([]byte, bool, error) {
	kvIdx := chunkIdx / sm.chunksPerKv
	cIdx := chunkIdx % sm.chunksPerKv
	shardIdx := kvIdx / sm.kvEntries
	if ds, ok := sm.shardMap[shardIdx]; ok {
		b, err := ds.ReadChunk(kvIdx, cIdx, commit) // read all the data
		return b, true, err
	} else {
		return nil, false, nil
	}
}

// TryReadChunkEncoded Read the encoded KV data using chunkIdx from storage file and return it.
// Return error if the read IO fails.
// Return false if the data is not managed by the ShardManager.
func (sm *ShardManager) TryReadChunkEncoded(chunkIdx uint64) ([]byte, bool, error) {
	kvIdx := chunkIdx / sm.chunksPerKv
	cIdx := chunkIdx % sm.chunksPerKv
	shardIdx := kvIdx / sm.kvEntries
	if ds, ok := sm.shardMap[shardIdx]; ok {
		b, err := ds.ReadChunkEncoded(kvIdx, cIdx) // read all the data
		return b, true, err
	} else {
		return nil, false, nil
	}
}

func (sm *ShardManager) IsComplete() error {
	for _, ds := range sm.shardMap {
		if !ds.IsComplete() {
			return fmt.Errorf("shard %d is not complete", ds.shardIdx)
		}
	}
	return nil
}
