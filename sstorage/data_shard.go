package sstorage

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
)

type DataShard struct {
	shardIdx    uint64
	kvSize      uint64
	chunksPerKv uint64
	kvEntries   uint64
	dataFiles   []*DataFile
}

func NewDataShard(shardIdx uint64, kvSize uint64, kvEntries uint64) *DataShard {
	if kvSize%CHUNK_SIZE != 0 {
		panic("kvSize must be CHUNK_SIZE at the moment")
	}

	return &DataShard{shardIdx: shardIdx, kvSize: kvSize, chunksPerKv: kvSize / CHUNK_SIZE, kvEntries: kvEntries}
}

func (ds *DataShard) AddDataFile(df *DataFile) {
	// TODO: May check if not overlapped?
	ds.dataFiles = append(ds.dataFiles, df)
}

// Returns whether the shard has all data files to cover all entries
func (ds *DataShard) IsComplete() bool {
	chunkIdx := ds.StartChunkIdx()
	chunkIdxEnd := (ds.shardIdx + 1) * ds.chunksPerKv * ds.kvEntries
	for chunkIdx < chunkIdxEnd {
		found := false
		for _, df := range ds.dataFiles {
			if df.Contains(chunkIdx) {
				chunkIdx = df.ChunkIdxEnd()
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (ds *DataShard) Contains(kvIdx uint64) bool {
	return kvIdx >= ds.shardIdx*ds.kvEntries && kvIdx < (ds.shardIdx+1)*ds.kvEntries
}

func (ds *DataShard) StartChunkIdx() uint64 {
	return ds.shardIdx * ds.chunksPerKv * ds.kvEntries
}

func (ds *DataShard) GetStorageFile(chunkIdx uint64) *DataFile {
	for _, df := range ds.dataFiles {
		if df.Contains(chunkIdx) {
			return df
		}
	}
	return nil
}

func (ds *DataShard) Read(kvIdx uint64, readLen int, hash common.Hash, isMasked bool) ([]byte, error) {
	if !ds.Contains(kvIdx) {
		return nil, fmt.Errorf("kv not found")
	}
	if readLen > int(ds.kvSize) {
		return nil, fmt.Errorf("read len too large")
	}
	var data []byte
	for i := uint64(0); i < ds.chunksPerKv; i++ {
		if readLen == 0 {
			break
		}

		chunkReadLen := readLen
		if chunkReadLen > int(CHUNK_SIZE) {
			chunkReadLen = int(CHUNK_SIZE)
		}
		readLen = readLen - chunkReadLen

		chunkIdx := kvIdx*ds.chunksPerKv + i
		cdata, err := ds.ReadChunk(chunkIdx, chunkReadLen, hash, isMasked)
		if err != nil {
			return nil, err
		}
		data = append(data, cdata...)
	}
	return data, nil
}

func (ds *DataShard) Write(kvIdx uint64, b []byte, isMasked bool) error {
	if !ds.Contains(kvIdx) {
		return fmt.Errorf("kv not found")
	}

	if uint64(len(b)) > ds.kvSize {
		return fmt.Errorf("write data too large")
	}

	for i := uint64(0); i < ds.chunksPerKv; i++ {
		off := int(i * CHUNK_SIZE)
		if off >= len(b) {
			break
		}
		writeLen := len(b) - off
		if writeLen > int(CHUNK_SIZE) {
			writeLen = int(CHUNK_SIZE)
		}

		chunkIdx := kvIdx*ds.chunksPerKv + i
		err := ds.WriteChunk(chunkIdx, b[off:off+writeLen], isMasked)
		if err != nil {
			return nil
		}
	}
	return nil
}

func (ds *DataShard) ReadChunk(chunkIdx uint64, readLen int, hash common.Hash, isMasked bool) ([]byte, error) {
	for _, df := range ds.dataFiles {
		if df.Contains(chunkIdx) {
			return df.Read(chunkIdx, readLen, hash, isMasked)
		}
	}
	return nil, fmt.Errorf("chunk not found: the shard is not completed?")
}

func (ds *DataShard) WriteChunk(chunkIdx uint64, b []byte, isMasked bool) error {
	for _, df := range ds.dataFiles {
		if df.Contains(chunkIdx) {
			return df.Write(chunkIdx, b, isMasked)
		}
	}
	return fmt.Errorf("chunk not found: the shard is not completed?")
}
