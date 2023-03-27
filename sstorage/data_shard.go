package sstorage

import (
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/sstorage/pora"
)

// A DataShard is a logical shard that manages multiple DataFiles.
// It also manages the encoding/decoding, tranlation from KV read/write to chunk read/write,
// and sanity check of the data files.
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

func (ds *DataShard) AddDataFile(df *DataFile) error {
	if len(ds.dataFiles) != 0 {
		// Perform sanity check
		if ds.dataFiles[0].miner != df.miner {
			return fmt.Errorf("mismatched data file SP")
		}
		if ds.dataFiles[0].encodeType != df.encodeType {
			return fmt.Errorf("mismatched data file encode type")
		}
		if ds.dataFiles[0].maxKvSize != df.maxKvSize {
			return fmt.Errorf("mismatched data file max kv size")
		}
		// TODO: May check if not overlapped?
	}
	ds.dataFiles = append(ds.dataFiles, df)
	return nil
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

// Return the storage provider address (i.e., miner) of the shard.
func (ds *DataShard) Miner() common.Address {
	if len(ds.dataFiles) == 0 {
		return common.Address{}
	} else {
		return ds.dataFiles[0].miner
	}
}

func (ds *DataShard) EncodeType() uint64 {
	if len(ds.dataFiles) == 0 {
		return NO_ENCODE
	} else {
		return ds.dataFiles[0].encodeType
	}
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

// Read the encoded data from storage and return it.
func (ds *DataShard) ReadEncoded(kvIdx uint64, readLen int) ([]byte, error) {
	return ds.readWith(kvIdx, readLen, func(cdata []byte, chunkIdx uint64) []byte {
		return cdata
	})
}

// Read the encoded data from storage and return it.
func (ds *DataShard) ReadChunkEncoded(kvIdx uint64, chunkIdx uint64) ([]byte, error) {
	return ds.readChunkWith(kvIdx, chunkIdx, func(cdata []byte, chunkIdx uint64) []byte {
		return cdata
	})
}

// Read the encoded data from storage and decode it.
func (ds *DataShard) ReadChunk(kvIdx uint64, chunkIdx uint64, commit common.Hash) ([]byte, error) {
	return ds.readChunkWith(kvIdx, chunkIdx, func(cdata []byte, chunkIdx uint64) []byte {
		encodeKey := calcEncodeKey(commit, chunkIdx, ds.dataFiles[0].miner)
		return decodeChunk(cdata, ds.dataFiles[0].encodeType, encodeKey)
	})
}

// Read the encoded data from storage with a decoder.
func (ds *DataShard) readChunkWith(kvIdx uint64, chunkIdx uint64, decoder func([]byte, uint64) []byte) ([]byte, error) {
	if !ds.Contains(kvIdx) {
		return nil, fmt.Errorf("kv not found")
	}
	if chunkIdx >= ds.chunksPerKv {
		return nil, fmt.Errorf("chunkIdx out of range, chunkIdx： %d vs chunksPerKv %d", chunkIdx, ds.chunksPerKv)
	}
	idx := kvIdx*ds.chunksPerKv + chunkIdx
	data, err := ds.readChunk(idx, int(CHUNK_SIZE))
	if err != nil {
		return nil, err
	}
	data = decoder(data, idx)
	return data, nil
}

// Read the encoded data from storage and decode it.
func (ds *DataShard) Read(kvIdx uint64, readLen int, commit common.Hash) ([]byte, error) {
	return ds.readWith(kvIdx, readLen, func(cdata []byte, chunkIdx uint64) []byte {
		encodeKey := calcEncodeKey(commit, chunkIdx, ds.dataFiles[0].miner)
		return decodeChunk(cdata, ds.dataFiles[0].encodeType, encodeKey)
	})
}

// Read the encoded data from storage with a decoder.
func (ds *DataShard) readWith(kvIdx uint64, readLen int, decoder func([]byte, uint64) []byte) ([]byte, error) {
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
		cdata, err := ds.readChunk(chunkIdx, chunkReadLen)
		if err != nil {
			return nil, err
		}

		cdata = decoder(cdata, chunkIdx)
		data = append(data, cdata...)
	}
	return data, nil
}

// Obtain a unique encoding key with keccak256(chunkIdx || commit || miner).
// This will make sure the encoded data will be unique in terms of idx, storage provider, and data
func calcEncodeKey(commit common.Hash, chunkIdx uint64, miner common.Address) common.Hash {
	bb := make([]byte, 8)
	binary.BigEndian.PutUint64(bb, chunkIdx)
	bb = append(bb, commit.Bytes()...)
	bb = append(bb, miner.Bytes()...)
	return crypto.Keccak256Hash(bb)
}

func encodeChunk(bs []byte, encodeType uint64, encodeKey common.Hash) []byte {
	if len(bs) > int(CHUNK_SIZE) {
		panic("cannot encode chunk with size > CHUNK_SIZE")
	}
	if encodeType == ENCODE_KECCAK_256 {
		output := make([]byte, CHUNK_SIZE)
		j := 0
		for i := 0; i < int(CHUNK_SIZE); i++ {
			b := byte(0)
			if i < len(bs) {
				b = bs[i]
			}
			output[i] = b ^ encodeKey[j]
			j = j + 1
			if j >= len(encodeKey) {
				j = 0
			}
		}
		return output
	} else if encodeType == NO_ENCODE {
		return bs
	} else if encodeType == ENCODE_ETHASH {
		return MaskDataInPlace(pora.GetMaskData(0, encodeKey, int(CHUNK_SIZE), nil), bs)
	} else {
		panic("unsupported encode type")
	}
}

func decodeChunk(bs []byte, encodeType uint64, encodeKey common.Hash) []byte {
	if len(bs) > int(CHUNK_SIZE) {
		panic("cannot encode chunk with size > CHUNK_SIZE")
	}
	if encodeType == ENCODE_KECCAK_256 {
		output := make([]byte, len(bs))
		j := 0
		for i := 0; i < len(bs); i++ {
			b := byte(0)
			if i < len(bs) {
				b = bs[i]
			}
			output[i] = b ^ encodeKey[j]
			j = j + 1
			if j >= len(encodeKey) {
				j = 0
			}
		}
		return output
	} else if encodeType == NO_ENCODE {
		return bs
	} else if encodeType == ENCODE_ETHASH {
		return UnmaskDataInPlace(pora.GetMaskData(0, encodeKey, len(bs), nil), bs)
	} else {
		panic("unsupported encode type")
	}
}

// Write a value of the KV to the store.  The value will be encoded with kvIdx and SP address.
func (ds *DataShard) Write(kvIdx uint64, b []byte, commit common.Hash) error {
	if !ds.Contains(kvIdx) {
		return fmt.Errorf("kv not found")
	}

	if uint64(len(b)) > ds.kvSize {
		return fmt.Errorf("write data too large")
	}
	cb := make([]byte, ds.kvSize)
	copy(cb, b)
	for i := uint64(0); i < ds.chunksPerKv; i++ {
		chunkIdx := kvIdx*ds.chunksPerKv + i
		encodeKey := calcEncodeKey(commit, chunkIdx, ds.Miner())
		encodedChunk := encodeChunk(cb[int(i*CHUNK_SIZE):int((i+1)*CHUNK_SIZE)], ds.EncodeType(), encodeKey)
		err := ds.writeChunk(chunkIdx, encodedChunk)

		if err != nil {
			return nil
		}
	}
	return nil
}

func (ds *DataShard) readChunk(chunkIdx uint64, readLen int) ([]byte, error) {
	for _, df := range ds.dataFiles {
		if df.Contains(chunkIdx) {
			return df.Read(chunkIdx, readLen)
		}
	}
	return nil, fmt.Errorf("chunk not found: the shard is not completed?")
}

func (ds *DataShard) writeChunk(chunkIdx uint64, b []byte) error {
	for _, df := range ds.dataFiles {
		if df.Contains(chunkIdx) {
			return df.Write(chunkIdx, b)
		}
	}
	return fmt.Errorf("chunk not found: the shard is not completed?")
}
