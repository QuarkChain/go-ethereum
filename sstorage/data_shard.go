package sstorage

import "fmt"

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
	chunkIdx := ds.ChunkIdx()
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

func (ds *DataShard) ChunkIdx() uint64 {
	return ds.shardIdx * ds.chunksPerKv * ds.kvEntries
}

func (ds *DataShard) ReadMasked(kvIdx uint64) ([]byte, error) {
	if !ds.Contains(kvIdx) {
		return nil, fmt.Errorf("kv not found")
	}
	var data []byte
	for i := uint64(0); i < ds.chunksPerKv; i++ {
		chunkIdx := ds.ChunkIdx() + kvIdx*ds.chunksPerKv + i
		cdata, err := ds.ReadChunkMasked(chunkIdx)
		if err != nil {
			return nil, err
		}
		data = append(data, cdata...)
	}
	return data, nil
}

func (ds *DataShard) ReadUnmasked(kvIdx uint64, readLen int) ([]byte, error) {
	if !ds.Contains(kvIdx) {
		return nil, fmt.Errorf("kv not found")
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

		chunkIdx := ds.ChunkIdx() + kvIdx*ds.chunksPerKv + i
		cdata, err := ds.ReadChunkUnmasked(chunkIdx, chunkReadLen)
		if err != nil {
			return nil, err
		}
		data = append(data, cdata...)
	}
	return data, nil
}

func (ds *DataShard) WriteUnmasked(kvIdx uint64, b []byte) error {
	if !ds.Contains(kvIdx) {
		return fmt.Errorf("kv not found")
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

		chunkIdx := ds.ChunkIdx() + kvIdx*ds.chunksPerKv + i
		err := ds.WriteChunkUnmasked(chunkIdx, b[off:off+writeLen])
		if err != nil {
			return nil
		}
	}
	return nil
}

func (ds *DataShard) ReadChunkMasked(chunkIdx uint64) ([]byte, error) {
	for _, df := range ds.dataFiles {
		if df.Contains(chunkIdx) {
			return df.ReadMasked(chunkIdx)
		}
	}
	return nil, fmt.Errorf("chunk not found: the shard is not completed?")
}

func (ds *DataShard) ReadChunkUnmasked(chunkIdx uint64, readLen int) ([]byte, error) {
	for _, df := range ds.dataFiles {
		if df.Contains(chunkIdx) {
			return df.ReadUnmasked(chunkIdx, readLen)
		}
	}
	return nil, fmt.Errorf("chunk not found: the shard is not completed?")
}

func (ds *DataShard) WriteChunkUnmasked(chunkIdx uint64, b []byte) error {
	for _, df := range ds.dataFiles {
		if df.Contains(chunkIdx) {
			return df.WriteUnmasked(chunkIdx, b)
		}
	}
	return fmt.Errorf("chunk not found: the shard is not completed?")
}
