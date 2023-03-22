package sstorage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/detailyang/go-fallocate"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

const (
	NO_ENCODE = iota
	ENCODE_KECCAK_256
	ENCODE_ETHASH
	ENCODE_END = ENCODE_ETHASH

	// keccak256(b'Web3Q Large Storage')[0:8]
	MAGIC   = uint64(0xcf20bd770c22b2e1)
	VERSION = uint64(1)

	CHUNK_SIZE      = uint64(4096)
	CHUNK_SIZE_BITS = uint64(12)
)

// A DataFile represents a local file for a consective chunks
type DataFile struct {
	file          *os.File
	chunkIdxStart uint64
	chunkIdxLen   uint64
	encodeType    uint64
	maxKvSize     uint64
	miner         common.Address // storage provider key
}

type DataFileHeader struct {
	magic         uint64
	version       uint64
	chunkIdxStart uint64
	chunkIdxLen   uint64
	encodeType    uint64
	maxKvSize     uint64
	miner         common.Address
	status        uint64
}

// Mask the data in place
func MaskDataInPlace(maskData []byte, userData []byte) []byte {
	if len(userData) > len(maskData) {
		panic("user data can not be larger than mask data")
	}
	for i := 0; i < len(userData); i++ {
		maskData[i] = maskData[i] ^ userData[i]
	}
	return maskData
}

// Unmask the data in place
func UnmaskDataInPlace(userData []byte, maskData []byte) []byte {
	if len(userData) > len(maskData) {
		panic("user data can not be larger than mask data")
	}
	for i := 0; i < len(userData); i++ {
		userData[i] = maskData[i] ^ userData[i]
	}
	return userData
}

func Create(filename string, chunkIdxStart uint64, chunkIdxLen uint64, epoch, maxKvSize uint64, encodeType uint64, miner common.Address) (*DataFile, error) {
	log.Info("Creating file", "filename", filename)
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	// actual initialization is done when synchronize
	err = fallocate.Fallocate(file, int64(CHUNK_SIZE*chunkIdxLen), int64(CHUNK_SIZE))
	if err != nil {
		return nil, err
	}
	dataFile := &DataFile{
		file:          file,
		chunkIdxStart: chunkIdxStart,
		chunkIdxLen:   chunkIdxLen,
		encodeType:    encodeType,
		maxKvSize:     maxKvSize,
		miner:         miner,
	}
	dataFile.writeHeader()
	return dataFile, nil
}

func OpenDataFile(filename string) (*DataFile, error) {
	file, err := os.OpenFile(filename, os.O_RDWR, 0755)
	if err != nil {
		return nil, err
	}
	dataFile := &DataFile{
		file: file,
	}
	return dataFile, dataFile.readHeader()
}

func (df *DataFile) Contains(chunkIdx uint64) bool {
	return chunkIdx >= df.chunkIdxStart && chunkIdx < df.ChunkIdxEnd()
}

func (df *DataFile) ChunkIdxEnd() uint64 {
	return df.chunkIdxStart + df.chunkIdxLen
}

// Read raw chunk data from the storage file.
func (df *DataFile) Read(chunkIdx uint64, len int) ([]byte, error) {
	if !df.Contains(chunkIdx) {
		return nil, fmt.Errorf("chunk not found")
	}
	if len > int(CHUNK_SIZE) {
		return nil, fmt.Errorf(("read too large"))
	}
	md := make([]byte, len)
	n, err := df.file.ReadAt(md, int64(chunkIdx+1)*int64(CHUNK_SIZE))
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("not full read")
	}
	return md, nil
}

// Write the chunk bytes to the file.
func (df *DataFile) Write(chunkIdx uint64, b []byte) error {
	if !df.Contains(chunkIdx) {
		return fmt.Errorf("chunk not found")
	}

	if len(b) > int(CHUNK_SIZE) {
		return fmt.Errorf("write data too large")
	}

	_, err := df.file.WriteAt(b, int64(chunkIdx+1)*int64(CHUNK_SIZE))
	return err
}

func (df *DataFile) writeHeader() error {
	header := DataFileHeader{
		magic:         MAGIC,
		version:       VERSION,
		chunkIdxStart: df.chunkIdxStart,
		chunkIdxLen:   df.chunkIdxLen,
		encodeType:    df.encodeType,
		maxKvSize:     df.maxKvSize,
		miner:         df.miner,
		status:        0,
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, header.magic); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, header.version); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, header.chunkIdxStart); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, header.chunkIdxLen); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, header.encodeType); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, header.maxKvSize); err != nil {
		return err
	}
	n, err := buf.Write(header.miner[:])
	if err != nil {
		return err
	}
	if n != len(header.miner) {
		return fmt.Errorf("short write for header.miner, n=%d", n)
	}
	if err := binary.Write(buf, binary.BigEndian, header.status); err != nil {
		return err
	}
	if _, err := df.file.WriteAt(buf.Bytes(), 0); err != nil {
		return err
	}
	return nil
}

func (df *DataFile) readHeader() error {
	header := DataFileHeader{}

	b := make([]byte, CHUNK_SIZE)
	n, err := df.file.ReadAt(b, 0)
	if err != nil {
		return err
	}
	if n != int(CHUNK_SIZE) {
		return fmt.Errorf("not full header read")
	}

	buf := bytes.NewBuffer(b)
	if err := binary.Read(buf, binary.BigEndian, &header.magic); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &header.version); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &header.chunkIdxStart); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &header.chunkIdxLen); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &header.encodeType); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &header.maxKvSize); err != nil {
		return err
	}
	n, err = buf.Read(header.miner[:])
	if err != nil {
		return err
	}
	if n != len(header.miner) {
		return fmt.Errorf("short read for header.miner, n=%d", n)
	}
	if err := binary.Read(buf, binary.BigEndian, &header.status); err != nil {
		return err
	}

	// Sanity check
	if header.magic != MAGIC {
		return fmt.Errorf("magic error")
	}
	if header.version > VERSION {
		return fmt.Errorf("unsupported version")
	}
	if header.encodeType > ENCODE_END {
		return fmt.Errorf("unknown mask type")
	}

	df.chunkIdxStart = header.chunkIdxStart
	df.chunkIdxLen = header.chunkIdxLen
	df.encodeType = header.encodeType
	df.maxKvSize = header.maxKvSize
	df.miner = header.miner

	return nil
}
