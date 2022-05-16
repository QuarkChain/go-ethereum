package sstorage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

const (
	NO_MASK         = iota
	MASK_KECCAK_256 = NO_MASK + 1
	MASK_END        = MASK_KECCAK_256
	// TODO: randomx

	// keccak256(b'Web3Q Large Storage')[0:8]
	MAGIC   = uint64(0xcf20bd770c22b2e1)
	VERSION = uint64(1)

	CHUNK_SIZE = uint64(4096)
)

type DataFile struct {
	file          *os.File
	chunkIdxStart uint64
	chunkIdxLen   uint64
	maskType      uint64
}

type DataFileHeader struct {
	magic         uint64
	version       uint64
	chunkIdxStart uint64
	chunkIdxLen   uint64
	maskType      uint64
	status        uint64
}

func getMaskData(chunkIdx uint64, maskType uint64) []byte {
	if maskType > MASK_END {
		panic("unsupported mask type")
	}

	if maskType == NO_MASK {
		return bytes.Repeat([]byte{0}, int(CHUNK_SIZE))
	}

	seed := make([]byte, 16)
	binary.BigEndian.PutUint64(seed, MAGIC)
	binary.BigEndian.PutUint64(seed[8:], chunkIdx)
	bs := crypto.Keccak256(seed)
	return bytes.Repeat(bs, int(CHUNK_SIZE)/len(bs))
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

func Create(filename string, chunkIdxStart uint64, chunkIdxLen uint64, maskType uint64) (*DataFile, error) {
	log.Info("Creating file", "filename", filename)
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < chunkIdxLen; i++ {
		chunkIdx := chunkIdxStart + i
		_, err := file.WriteAt(getMaskData(chunkIdx, maskType), int64((chunkIdx+1)*CHUNK_SIZE))
		if err != nil {
			return nil, err
		}
	}
	dataFile := &DataFile{
		file:          file,
		chunkIdxStart: chunkIdxStart,
		chunkIdxLen:   chunkIdxLen,
		maskType:      maskType,
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

// Reads the raw data without unmasking
func (df *DataFile) ReadMasked(chunkIdx uint64) ([]byte, error) {
	if !df.Contains(chunkIdx) {
		return nil, fmt.Errorf("chunk not found")
	}
	md := make([]byte, CHUNK_SIZE)
	n, err := df.file.ReadAt(md, int64(chunkIdx+1)*int64(CHUNK_SIZE))
	if err != nil {
		return nil, err
	}
	if n != int(CHUNK_SIZE) {
		return nil, fmt.Errorf("not full read")
	}
	return md, nil
}

func (df *DataFile) ReadUnmasked(chunkIdx uint64, len int) ([]byte, error) {
	if !df.Contains(chunkIdx) {
		return nil, fmt.Errorf("chunk not found")
	}
	ud := make([]byte, len)
	n, err := df.file.ReadAt(ud, int64(chunkIdx+1)*int64(CHUNK_SIZE))
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("not full read")
	}
	return UnmaskDataInPlace(ud, getMaskData(chunkIdx, df.maskType)), nil
}

func (df *DataFile) WriteUnmasked(chunkIdx uint64, b []byte) error {
	if !df.Contains(chunkIdx) {
		return fmt.Errorf("chunk not found")
	}

	if len(b) > int(CHUNK_SIZE) {
		return fmt.Errorf("write data too large")
	}

	md := MaskDataInPlace(getMaskData(chunkIdx, df.maskType), b)
	_, err := df.file.WriteAt(md, int64(chunkIdx+1)*int64(CHUNK_SIZE))
	return err
}

func (df *DataFile) writeHeader() error {
	header := DataFileHeader{
		magic:         MAGIC,
		version:       VERSION,
		chunkIdxStart: df.chunkIdxStart,
		chunkIdxLen:   df.chunkIdxLen,
		maskType:      df.maskType,
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
	if err := binary.Write(buf, binary.BigEndian, header.maskType); err != nil {
		return err
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
	header := DataFileHeader{
		magic:         MAGIC,
		version:       VERSION,
		chunkIdxStart: df.chunkIdxStart,
		chunkIdxLen:   df.chunkIdxLen,
		maskType:      df.maskType,
		status:        0,
	}

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
	if err := binary.Read(buf, binary.BigEndian, &header.maskType); err != nil {
		return err
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
	if header.maskType > MASK_END {
		return fmt.Errorf("unknown mask type")
	}

	df.chunkIdxStart = header.chunkIdxStart
	df.chunkIdxLen = header.chunkIdxLen
	df.maskType = header.maskType

	return nil
}
