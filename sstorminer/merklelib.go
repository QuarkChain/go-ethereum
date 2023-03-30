package sstorminer

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func expectedDiff(lastMineTime uint64, difficulty *big.Int, minedTime uint64, targetIntervalSec, cutoff, diffAdjDivisor, minDiff *big.Int) *big.Int {
	interval := new(big.Int).SetUint64(minedTime - lastMineTime)
	diff := difficulty
	if interval.Cmp(targetIntervalSec) < 0 {
		// diff = diff + (diff-interval*diff/cutoff)/diffAdjDivisor
		diff = new(big.Int).Add(diff, new(big.Int).Div(
			new(big.Int).Sub(diff, new(big.Int).Div(new(big.Int).Mul(interval, diff), cutoff)), diffAdjDivisor))
		if diff.Cmp(minDiff) < 0 {
			diff = minDiff
		}
	} else {
		// dec := (interval*diff/cutoff - diff) / diffAdjDivisor
		dec := new(big.Int).Div(new(big.Int).Div(new(big.Int).Mul(interval, diff), cutoff), diffAdjDivisor)
		if new(big.Int).Add(dec, minDiff).Cmp(diff) > 0 {
			diff = minDiff
		} else {
			diff = new(big.Int).Sub(diff, dec)
		}
	}

	return diff
}

func getProof(data []byte, chunkSize, nChunkBits, chunkIdx uint64) ([]common.Hash, error) {
	if len(data) == 0 {
		return nil, nil
	}
	nChunks := uint64(1) << nChunkBits
	if chunkIdx >= nChunks {
		return []common.Hash{}, fmt.Errorf("index out of scope")
	}
	nodes := make([]common.Hash, nChunks)
	for i := uint64(0); i < nChunks; i++ {
		off := i * chunkSize
		if off > uint64(len(data)) {
			break
		}
		l := uint64(len(data)) - off
		if l >= chunkSize {
			l = chunkSize
		}
		nodes[i] = crypto.Keccak256Hash(data[off : off+l])
	}
	n, proofIdx := nChunks, uint64(0)
	proofs := make([]common.Hash, nChunkBits)
	for n != 1 {
		proofs[proofIdx] = nodes[(chunkIdx/2)*2+1-chunkIdx%2]
		for i := uint64(0); i < n/2; i++ {
			nodes[i] = crypto.Keccak256Hash(nodes[i*2].Bytes(), nodes[i*2+1].Bytes())
		}
		n = n / 2
		chunkIdx = chunkIdx / 2
		proofIdx = proofIdx + 1
	}
	return proofs, nil
}

func calculateRootWithProof(dataHash common.Hash, chunkIdx uint64, proofs []common.Hash) (common.Hash, error) {
	if len(proofs) == 0 {
		return dataHash, nil
	}
	hash := dataHash
	nChunkBits := uint64(len(proofs))
	if chunkIdx >= uint64(1)<<nChunkBits {
		return common.Hash{}, fmt.Errorf("chunkId overflows")
	}
	for i := uint64(0); i < nChunkBits; i++ {
		if chunkIdx%2 == 0 {
			hash = crypto.Keccak256Hash(hash.Bytes(), proofs[i].Bytes())
		} else {
			hash = crypto.Keccak256Hash(proofs[i].Bytes(), hash.Bytes())
		}
		chunkIdx = chunkIdx / 2
	}
	return hash, nil
}

func verify(root []byte, dataHash common.Hash, chunkIdx uint64, proofs []common.Hash) bool {
	r, err := calculateRootWithProof(dataHash, chunkIdx, proofs)
	if err != nil {
		return false
	}

	return bytes.Compare(root[:24], r.Bytes()[:24]) == 0
}

func merkleRoot(data []byte, chunkPerKV uint64, chunkSize uint64) common.Hash {
	l := uint64(len(data))
	if l == 0 {
		return common.Hash{}
	}
	nodes := make([]common.Hash, chunkPerKV)
	for i := uint64(0); i < chunkPerKV; i++ {
		off := i * chunkSize
		if off >= l {
			// empty mean the leaf is zero
			break
		}
		size := l - off
		if size >= chunkSize {
			size = chunkSize
		}
		hash := crypto.Keccak256Hash(data[off : off+size])
		nodes[i] = hash
	}
	n := chunkPerKV
	for n != 1 {
		for i := uint64(0); i < n/2; i++ {
			nodes[i] = crypto.Keccak256Hash(nodes[i*2].Bytes(), nodes[i*2+1].Bytes())
		}

		n = n / 2
	}
	return nodes[0]
}

func findNChunk(dataLen, chunkSize uint64) (uint64, uint64) {
	if dataLen == 0 {
		return 0, 0
	}
	n := (dataLen+chunkSize-1)/chunkSize - 1
	nChunkBits := uint64(0)
	for n != 0 {
		nChunkBits++
		n = n >> 1
	}

	return uint64(1) << nChunkBits, nChunkBits
}

func getProofWithMinTree(data []byte, chunkSize, nChunkBits, chunkIdx uint64) ([]common.Hash, error) {
	if len(data) == 0 {
		return []common.Hash{}, nil
	}
	nChunks := uint64(1) << nChunkBits
	if chunkIdx >= nChunks {
		return []common.Hash{}, fmt.Errorf("index out of scope")
	}
	nMinChunks, nMinChunkBits := findNChunk(uint64(len(data)), chunkSize)
	if chunkIdx >= nMinChunks {
		return []common.Hash{}, nil
	}
	return getProof(data, chunkSize, nMinChunkBits, chunkIdx)
}

func verifyWithMinTree(root []byte, dataHash common.Hash, chunkIdx uint64, proofs []common.Hash) bool {
	nMinChunkBits := uint64(len(proofs))
	if chunkIdx >= uint64(1)<<nMinChunkBits {
		return bytes.Compare(dataHash.Bytes(), make([]byte, 32)) == 0
	}
	r, err := calculateRootWithProof(dataHash, chunkIdx, proofs)
	if err != nil {
		return false
	}

	return bytes.Compare(root[:24], r.Bytes()[:24]) == 0
}

func merkleRootWithMinTree(data []byte, chunkSize uint64) common.Hash {
	l := uint64(len(data))
	if l == 0 {
		return common.Hash{}
	}
	nChunk, _ := findNChunk(uint64(len(data)), chunkSize)
	return merkleRoot(data, nChunk, chunkSize)
}
