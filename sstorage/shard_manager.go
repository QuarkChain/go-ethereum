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

func (sm *ShardManager) KvEntries() uint64 {
	return sm.kvEntries
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
		return true, ds.Write(kvIdx, b, false)
	} else {
		return false, nil
	}
}

func (sm *ShardManager) TryRead(kvIdx uint64, readLen int, hash common.Hash) ([]byte, bool, error) {
	shardIdx := kvIdx / sm.kvEntries
	if ds, ok := sm.shardMap[shardIdx]; ok {
		b, err := ds.Read(kvIdx, readLen, hash, false)
		return b, true, err
	} else {
		return nil, false, nil
	}
}

func (sm *ShardManager) UnmaskKV(kvIdx uint64, b []byte, hash common.Hash) ([]byte, bool, error) {
	return sm.MaskOrUnmaskKV(kvIdx, b, hash, false)
}

func (sm *ShardManager) MaskKV(kvIdx uint64, b []byte, hash common.Hash) ([]byte, bool, error) {
	return sm.MaskOrUnmaskKV(kvIdx, b, hash, true)
}

func (sm *ShardManager) MaskOrUnmaskKV(kvIdx uint64, b []byte, hash common.Hash, mask bool) ([]byte, bool, error) {
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
			df := ds.GetStorageFile(chunkIdx)
			if df == nil {
				return nil, false, fmt.Errorf("cannot find storage file for chunkIdx %d", chunkIdx)
			}
			if mask {
				cdata := MaskDataInPlace(getMaskData(chunkIdx, df.maskType), b[i*CHUNK_SIZE:i*CHUNK_SIZE+uint64(chunkReadLen)])
				data = append(data, cdata...)
			} else {
				cdata := UnmaskDataInPlace(b[i*CHUNK_SIZE:i*CHUNK_SIZE+uint64(chunkReadLen)], getMaskData(chunkIdx, df.maskType))
				data = append(data, cdata...)
			}
		}
		return data, true, nil
	} else {
		return nil, false, fmt.Errorf("cannot find storage shard for kvIdx %d", kvIdx)
	}
}

func (sm *ShardManager) TryWriteMaskedKV(kvIdx uint64, b []byte) (bool, error) {
	shardIdx := kvIdx / sm.kvEntries
	if ds, ok := sm.shardMap[shardIdx]; ok {
		return true, ds.Write(kvIdx, b, true)
	} else {
		return false, nil
	}
}

func (sm *ShardManager) TryReadMaskedKV(kvIdx uint64, readLen int, hash common.Hash) ([]byte, bool, error) {
	shardIdx := kvIdx / sm.kvEntries
	if ds, ok := sm.shardMap[shardIdx]; ok {
		b, err := ds.Read(kvIdx, readLen, hash, true) // read all the data
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
