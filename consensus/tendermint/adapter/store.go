package adapter

import (
	"context"

	pbft "github.com/QuarkChain/go-minimal-pbft/consensus"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

type Store struct {
	chain            *core.BlockChain
	verifyHeaderFunc func(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error
	makeBlock        func() (block *types.FullBlock)
}

func NewStore(
	chain *core.BlockChain,
	verifyHeaderFunc func(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error,
	makeBlock func() (block *types.FullBlock)) *Store {
	return &Store{chain: chain, verifyHeaderFunc: verifyHeaderFunc, makeBlock: makeBlock}
}

func (s *Store) Base() uint64 {
	return 0
}

func (s *Store) Height() uint64 {
	return s.chain.CurrentHeader().Number.Uint64()
}

func (s *Store) Size() uint64 {
	return s.Height() + 1
}

func (s *Store) LoadBlock(height uint64) *types.FullBlock {
	block := s.chain.GetBlockByNumber(height)
	parent := s.chain.GetHeaderByHash(block.Header().ParentHash)
	if parent == nil {
		return &types.FullBlock{Block: block}
	}

	return &types.FullBlock{Block: block, LastCommit: parent.Commit}
}

func (s *Store) LoadBlockCommit(height uint64) *types.Commit {
	header := s.chain.GetHeaderByNumber(height)
	if header == nil {
		return nil
	}

	return header.Commit
}

func (s *Store) LoadSeenCommit() *types.Commit {
	header := s.chain.CurrentHeader()

	return header.Commit
}

func (s *Store) SaveBlock(block *types.FullBlock, commit *types.Commit) {
	bc := s.chain
	header := block.Header()
	header.Commit = commit

	n, err := bc.InsertChain(types.Blocks{block.WithSeal(header)})
	if n == 0 || err != nil {
		log.Warn("SaveBlock", "n", n, "err", err)
	}
}

func (s *Store) ValidateBlock(state pbft.ChainState, block *types.FullBlock) (err error) {
	err = s.verifyHeaderFunc(s.chain, block.Header(), false)
	if err != nil {
		return
	}

	err = s.chain.PreExecuteBlock(block.Block)
	return
}

func (s *Store) ApplyBlock(context.Context, pbft.ChainState, *types.FullBlock) (state pbft.ChainState, err error) {
	return
}

func (s *Store) MakeBlock() *types.FullBlock {
	return s.makeBlock()
}
