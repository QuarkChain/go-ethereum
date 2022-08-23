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
}

func NewShardManager(contractAddress common.Address, kvSize uint64, kvEntries uint64) *ShardManager {
	return &ShardManager{
		shardMap:        make(map[uint64]*DataShard),
		contractAddress: contractAddress,
		kvSize:          kvSize,
		chunksPerKv:     kvSize / CHUNK_SIZE,
		kvEntries:       kvEntries,
	}
}

func (sm *ShardManager) MaxKvSize() uint64 {
	return sm.kvSize
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

	ds.AddDataFile(df)
	return nil
}

func (sm *ShardManager) TryWrite(kvIdx uint64, b []byte) (bool, error) {
	shardIdx := kvIdx / sm.kvEntries
	if ds, ok := sm.shardMap[shardIdx]; ok {
		return true, ds.WriteUnmasked(kvIdx, b)
	} else {
		return false, nil
	}
}

func (sm *ShardManager) TryRead(kvIdx uint64, readLen int) ([]byte, bool, error) {
	shardIdx := kvIdx / sm.kvEntries
	if ds, ok := sm.shardMap[shardIdx]; ok {
		b, err := ds.ReadUnmasked(kvIdx, readLen)
		return b, true, err
	} else {
		return nil, false, nil
	}
}

func (sm *ShardManager) UnmaskKV(kvIdx uint64, b []byte) ([]byte, bool, error) {

}

func (sm *ShardManager) TryWriteMaskedKV(kvIdx uint64, b []byte) (bool, error) {
	shardIdx := kvIdx / sm.kvEntries
	if ds, ok := sm.shardMap[shardIdx]; ok {
		return true, ds.WriteMasked(kvIdx, b)
	} else {
		return false, nil
	}
}

func (sm *ShardManager) TryReadMaskedKV(kvIdx uint64) ([]byte, bool, error) {
	shardIdx := kvIdx / sm.kvEntries
	if ds, ok := sm.shardMap[shardIdx]; ok {
		b, err := ds.ReadMasked(kvIdx)
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
