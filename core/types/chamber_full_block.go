package types

import (
	"bytes"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// A FullBlock contains the last commit of previous block.
// The last commit field is generally used for proposing a new block.
// However, once the block is signed/sealed by validators,
// verifying a block does not need LastCommit anymore.
// That means a non-validator node does not need LastCommit to sync and fully verify the chain.
type FullBlock struct {
	*Block
	LastCommit *Commit
}

func (b *FullBlock) HashTo(hash common.Hash) bool {
	if b == nil {
		return false
	}
	return b.Hash() == hash
}

func (b *FullBlock) EncodeRLP(w io.Writer) error {
	err := b.Block.EncodeRLP(w)
	if err != nil {
		return err
	}
	return rlp.Encode(w, b.LastCommit)
}

func (b *FullBlock) EncodeToRLPBytes() ([]byte, error) {
	var buf bytes.Buffer
	if err := b.EncodeRLP(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *FullBlock) DecodeRLP(s *rlp.Stream) error {
	if b.Block == nil {
		b.Block = &Block{}
	}
	err := b.Block.DecodeRLP(s)
	if err != nil {
		return err
	}
	b.LastCommit = &Commit{}
	return s.Decode(&b.LastCommit)
}

func (b *FullBlock) DecodeFromRLPBytes(bs []byte) error {
	s := rlp.NewStream(bytes.NewReader(bs), 0)
	return b.DecodeRLP(s)
}

func (b *FullBlock) WithCommit(commit *Commit) *FullBlock {
	cpy := *b.header

	cpy.Commit = commit

	return &FullBlock{
		Block: &Block{
			header:       &cpy,
			transactions: b.transactions,
			uncles:       b.uncles,
		},
		LastCommit: b.LastCommit}
}
