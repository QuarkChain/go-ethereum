package main

import (
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/consensus/tendermint/consensus"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/syndtr/goleveldb/leveldb"
)

type DefaultBlockStore struct {
	db *leveldb.DB
}

func NewDefaultBlockStore(db *leveldb.DB) consensus.BlockStore {
	return &DefaultBlockStore{
		db: db,
	}
}

func (bs *DefaultBlockStore) Height() uint64 {
	data, err := bs.db.Get([]byte("height"), nil)
	if err != nil {
		return 0
	}

	if len(data) != 8 {
		return 0
	}

	return binary.BigEndian.Uint64(data)
}

func (bs *DefaultBlockStore) Base() uint64 {
	return 0
}

func (bs *DefaultBlockStore) Size() uint64 {
	height := bs.Height()
	if height == 0 {
		return 0
	}
	return height + 1 - bs.Base()
}

func (bs *DefaultBlockStore) LoadBlock(height uint64) *consensus.FullBlock {
	hd := make([]byte, 8)
	binary.BigEndian.PutUint64(hd, height)
	bk := []byte("block")
	bk = append(bk, hd...)

	blockData, err := bs.db.Get(bk, nil)
	if err != nil {
		return nil
	}

	b := &consensus.FullBlock{}
	if rlp.DecodeBytes(blockData, b) != nil {
		panic(fmt.Errorf("error from block: %w", err))
	}
	return b
}

func (bs *DefaultBlockStore) LoadBlockCommit(height uint64) *consensus.Commit {
	hd := make([]byte, 8)
	binary.BigEndian.PutUint64(hd, height)
	ck := []byte("commit")
	ck = append(ck, hd...)

	commitData, err := bs.db.Get(ck, nil)
	if err != nil {
		return nil
	}

	c := &consensus.Commit{}
	if rlp.DecodeBytes(commitData, c) != nil {
		panic(fmt.Errorf("error from block: %w", err))
	}
	return c
}

func (bs *DefaultBlockStore) SaveBlock(b *consensus.FullBlock, c *consensus.Commit) {
	// sanity check?
	if b.NumberU64() != bs.Height()+1 {
		panic(fmt.Sprintf("BlockStore can only save contiguous blocks. Wanted %v, got %v", bs.Height()+1, b.NumberU64()))
	}

	hd := make([]byte, 8)
	binary.BigEndian.PutUint64(hd, b.NumberU64())
	bk := []byte("block")
	bk = append(bk, hd...)

	blockData, err := rlp.EncodeToBytes(b)
	if err != nil {
		// error?
		return
	}

	if err := bs.db.Put(bk, blockData, nil); err != nil {
		return
	}

	commitData, err := rlp.EncodeToBytes(c)
	if err != nil {
		return
	}

	ck := []byte("commit")
	ck = append(ck, hd...)
	if err := bs.db.Put(ck, commitData, nil); err != nil {
		return
	}

	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, b.NumberU64())
	if err := bs.db.Put([]byte("height"), data, nil); err != nil {
		return
	}
}

// LoadSeenCommit returns the last locally seen Commit before being
// cannonicalized. This is useful when we've seen a commit, but there
// has not yet been a new block at `height + 1` that includes this
// commit in its block.LastCommit.
func (bs *DefaultBlockStore) LoadSeenCommit() *consensus.Commit {
	commitData, err := bs.db.Get([]byte("seen_commit"), nil)
	if err != nil {
		return nil
	}

	c := &consensus.Commit{}
	if rlp.DecodeBytes(commitData, c) != nil {
		panic(fmt.Errorf("error from block: %w", err))
	}
	return c
}
